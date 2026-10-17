"""Public setup controller; native commands own all setup and payment authority."""
import base64
import collections
import concurrent.futures
import contextlib
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import threading
import time

import timing

FINGERPRINT_PHASES = ("roster_proposed", "agreement_saved", "acceptance_pending", "roster_accepted")
# UI phases that wait for this member's own action; the worker re-checks them every 5 s.
HUMAN_PHASES = ("compare_roster", "back_up", "final_backup")
ROSTER_MISMATCH = "The proposed roster does not match the admitted members. Do not confirm; contact the creator"


class HostedSetup:
    def __init__(self, wallet, bundle, key, enrollment=None, development=False, issuer=None):
        self.wallet = wallet
        self.bundle = Path(bundle).resolve()
        if not self.bundle.is_file() or not isinstance(key, str) or len(key) != 64:
            raise ValueError("Hosted setup needs an operator bundle and its trusted signing key")
        try:
            bytes.fromhex(key)
        except ValueError as error:
            raise ValueError("Invalid operator signing key") from error
        self.key = key
        self.enrollment = Path(enrollment).resolve() if enrollment else None
        self.issuer = Path(issuer).resolve() if issuer else None
        if self.issuer and (not self.issuer.is_file() or not os.access(self.issuer, os.X_OK)):
            raise ValueError("The enrollment issuer must be an executable")
        self.development = development
        self.stop_event = threading.Event()
        self.process_lock = threading.Lock()
        self.processes = set()
        self.worker = None
        self.information = {}
        self.information_at = {}
        self.errors = {}
        # One lock per saved setup folder: native `secrets/.setup.lock` refuses a second
        # process on the same root, so calls on one vault are serialized here while other
        # vaults proceed. A pending user action makes the worker skip that vault.
        self.meta_lock = threading.Lock()
        self.vault_locks = {}
        self.user_waiting = collections.Counter()
        self.local = threading.local()
        self.schedule = {}
        self.wake = threading.Event()

    def _key(self, root):
        return Path(root).resolve()

    def _vault_lock(self, root):
        with self.meta_lock:
            return self.vault_locks.setdefault(self._key(root), threading.RLock())

    @contextlib.contextmanager
    def user_action(self, root):
        """Run a signer-window action on `root` ahead of background steps."""
        key = self._key(root)
        with self.meta_lock:
            self.user_waiting[key] += 1
        depth = getattr(self.local, "user", 0)
        self.local.user = depth + 1
        try:
            with self._vault_lock(key):
                yield
        finally:
            self.local.user = depth
            with self.meta_lock:
                self.user_waiting[key] -= 1
                if not self.user_waiting[key]:
                    del self.user_waiting[key]
            # Whatever the member just did (agree, check a backup, ...) is new local work.
            self.poke(key.name)

    def poke(self, name):
        self.schedule.setdefault(name, {"due": 0.0})["due"] = 0.0
        self.wake.set()

    def user_pending(self, root):
        with self.meta_lock:
            return self.user_waiting.get(self._key(root), 0) > 0

    def native(self, action, root, *args, private=None, unlocked=True):
        with self._vault_lock(root):
            for attempt in range(4):
                try:
                    return self._native(action, root, *args, private=private, unlocked=unlocked)
                except ValueError as error:
                    # Another tool (or a stale worker) holds the vault's native lock.
                    if "setup_worker_locked" not in str(error) or not getattr(self.local, "user", 0):
                        raise
                    if attempt == 3:
                        raise ValueError("This vault is busy in another tool; try again shortly") from error
                    time.sleep(0.2 * (attempt + 1))

    def _native(self, action, root, *args, private=None, unlocked=True):
        if self.stop_event.is_set():
            raise ValueError("Signer is locked")
        if unlocked:
            self.wallet.require_profile()
            if not isinstance(self.wallet.passphrase, str):
                raise ValueError("Signer is locked")
        with tempfile.TemporaryDirectory(prefix=".hosted-command-", dir=self.wallet.data) as temporary:
            folder = Path(temporary)
            argv = [str(self.wallet.setup), action, str(root)]
            if unlocked:
                passfile = folder / "pass"
                # Consumed at once and unlinked with its directory: no fsync, so the
                # passphrase is not pushed to stable storage on every native call.
                self._write(passfile, self.wallet.passphrase.encode(), durable=False)
                if action == "identity":
                    argv.extend([str(args[0]), str(passfile)])
                    args = args[1:]
                else:
                    argv.append(str(passfile))
            for arg in args:
                if arg == "@private":
                    if private is None:
                        raise ValueError("Missing private setup input")
                    path = folder / "private"
                    self._write(path, private, durable=False)
                    argv.append(str(path))
                else:
                    argv.append(str(arg))
            with self.process_lock:
                if self.stop_event.is_set():
                    raise ValueError("Signer is locked")
                process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.processes.add(process)
            started = time.monotonic()
            try:
                stdout, stderr = process.communicate(timeout=120)
                timing.record(f"{self.wallet.setup.name} {action}", started, process.returncode, root, stderr=stderr)
                if process.returncode:
                    raise ValueError(stderr.decode(errors="replace").strip() or "Hosted setup could not advance")
                return stdout.decode().strip()
            except subprocess.TimeoutExpired as error:
                timing.record(f"{self.wallet.setup.name} {action}", started, "timeout", root)
                process.kill()
                process.communicate()
                raise ValueError("Hosted setup timed out; its saved state can be retried") from error
            finally:
                with self.process_lock:
                    self.processes.discard(process)

    @staticmethod
    def _write(path, raw, durable=True):
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(raw)
            output.flush()
            if durable:
                os.fsync(output.fileno())

    def start(self):
        if self.worker and self.worker.is_alive():
            return
        self.stop_event.clear()
        self.worker = threading.Thread(target=self.run, daemon=True)
        self.worker.start()

    def stop(self):
        self.stop_event.set()
        self.wake.set()
        with self.process_lock:
            for process in self.processes:
                if process.poll() is None:
                    process.terminate()
        if self.worker and self.worker is not threading.current_thread():
            self.worker.join(timeout=5)
        with self.process_lock:
            for process in self.processes:
                if process.poll() is None:
                    process.kill()
        self.information.clear()
        self.schedule.clear()

    def run(self):
        """Step each saved setup on its own timer, at most two vaults at a time."""
        running = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="hosted-step") as pool:
            while not self.stop_event.is_set():
                now = time.monotonic()
                with self.wallet.lock:
                    profile = self.wallet.profile_data["id"] if self.wallet.profile_data else None
                    folders = sorted((self.wallet.data / "vaults").glob("*")) if profile else []
                for folder, future in list(running.items()):
                    if future.done():
                        del running[folder]
                        self._reschedule(folder, future.result())
                for folder in folders:
                    if len(running) >= 2 or self.stop_event.is_set():
                        break
                    entry = self.schedule.setdefault(folder.name, {"due": 0.0})
                    if folder.name in running or entry["due"] > now or self.user_pending(folder):
                        continue
                    running[folder.name] = pool.submit(self._background_step, folder, profile)
                due = [self.schedule[name]["due"] for name in self.schedule
                       if name not in running and (self.wallet.data / "vaults" / name).exists()]
                wait = min([0.25, *(max(0.0, value - time.monotonic()) for value in due)])
                self.wake.wait(max(wait, 0.01) if running or due else 0.25)
                self.wake.clear()
            for future in running.values():
                future.cancel()

    def _background_step(self, folder, profile):
        lock = self._vault_lock(folder)
        if not lock.acquire(timeout=0.05):
            return ("busy", None)
        try:
            if self.user_pending(folder):
                return ("busy", None)
            return self.step_folder(folder, profile, classify=True)
        finally:
            lock.release()

    def _reschedule(self, name, outcome):
        """The Finding 3 cadence: immediate after progress, short backoff while peers work,
        5 s while this member's own action is pending, and 2 → 30 s after errors."""
        kind, _ = outcome
        entry = self.schedule.setdefault(name, {"due": 0.0})
        now = time.monotonic()
        if kind == "error":
            entry["error"] = min(30.0, entry.get("error", 1.0) * 2)
            entry["due"] = now + entry["error"]
            return
        entry.pop("error", None)
        if kind == "progress" and entry.get("burst", 0) < 20:
            entry["burst"] = entry.get("burst", 0) + 1
            entry["idle"] = 0.125
            entry["due"] = now
            return
        entry["burst"] = 0
        if kind == "busy":
            entry["due"] = now + 0.1
        elif kind == "human":
            entry["due"] = now + 5
        elif kind in ("skip", "ready"):
            entry["due"] = now + 5
        else:
            entry["idle"] = min(2.0, entry.get("idle", 0.125) * 2) if kind == "idle" else 0.25
            entry["due"] = now + entry["idle"]

    def step_folder(self, folder, profile, classify=False):
        """Advance one saved setup by one native step.

        Returns the native status, or with `classify` a `(kind, status)` pair for the
        scheduler: progress, idle, human, ready, skip or error."""
        def out(kind, result=None):
            return (kind, result) if classify else result
        try:
            pending = folder / "pending.json"
            if folder.name.startswith(".hosted-") and pending.is_file():
                metadata = json.loads(pending.read_text())
                if metadata["profile"] == profile and (folder / "secrets" / "hosted-context.sealed").is_file():
                    self._attach(folder, metadata["name"])
                    return out("progress")
                return out("skip")
            membership = folder / "membership.json"
            if not membership.is_file():
                return out("skip")
            local = json.loads(membership.read_text())
            if local.get("transport") != "hosted" or local.get("profile") != profile:
                return out("skip")
            prior = self._cached(folder)
            if prior.get("handoff") == "ready":
                return out("ready")
            result = json.loads(self.native("setup-step", folder))
            if self._needs_information(folder.name, prior.get("phase"), result.get("phase")):
                self._refresh_information(folder)
            self.errors.pop(folder.name, None)
            if not classify:
                return result
            changed = any(prior.get(field) != result.get(field) for field in
                          ("phase", "joined_slots", "missing_slots", "agreed_fingerprint", "handoff"))
            if result.get("progressed") or changed:
                return out("progress", result)
            if self._ui_phase(folder, result) in HUMAN_PHASES:
                return out("human", result)
            return out("idle", result)
        except (ValueError, OSError, KeyError, json.JSONDecodeError) as error:
            self.errors[folder.name] = self._error_message(error)
            return out("error")

    def _needs_information(self, vault, before, after):
        """The roster fingerprint arrives with a phase change, but a joiner whose first
        info read raced the proposal still needs it; refetch that at most every 5 s."""
        if vault not in self.information or before != after:
            return True
        return (after in FINGERPRINT_PHASES and self.information[vault].get("fingerprint") is None
                and time.monotonic() - self.information_at.get(vault, 0) >= 5)

    def _refresh_information(self, folder):
        self.information_at[folder.name] = time.monotonic()
        self.information[folder.name] = json.loads(self.native("setup-info", folder))

    @staticmethod
    def _error_message(error):
        if "setup_roster" in str(error):
            return ROSTER_MISMATCH
        return "Connection interrupted. Your saved setup will retry while unlocked."

    def _configuration_args(self):
        return [self.bundle, "--operator-key", self.key, *(["--development-http"] if self.development else [])]

    def _attach(self, folder, name):
        info = json.loads(self.native("setup-info", folder))
        vault = info["vault"]
        target = self.wallet.data / "vaults" / vault
        if target.exists() and target != folder:
            raise ValueError("This profile already has that vault; reopen its saved setup")
        membership = folder / "membership.json"
        value = {"vault": vault, "slot": info["own_slot"], "name": name,
                 "profile": self.wallet.require_profile()["id"], "members": info["member_count"],
                 "threshold": 2, "transport": "hosted"}
        if membership.exists():
            if json.loads(membership.read_text()) != value:
                raise ValueError("Saved hosted membership differs from native setup")
        else:
            self._write(membership, json.dumps(value).encode())
        if folder != target:
            folder.rename(target)
        descriptor = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self.information[vault] = info
        self.poke(vault)
        return {"vault": vault}

    def _pending(self, name, action, binding):
        root = self.wallet.data / "vaults"
        root.mkdir(mode=0o700, exist_ok=True)
        metadata = {"profile": self.wallet.require_profile()["id"], "name": name, "action": action, "binding": binding}
        for folder in sorted(root.iterdir()):
            path = folder / "pending.json"
            if path.is_file() and json.loads(path.read_text()) == metadata:
                return folder
        folder = root / (".hosted-" + secrets.token_hex(16))
        folder.mkdir(mode=0o700)
        self._write(folder / "pending.json", json.dumps(metadata).encode())
        descriptor = os.open(root, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return folder

    def create(self, policy, name):
        if policy not in ("2-of-3", "2-of-4") or not isinstance(name, str) or not 1 <= len(name.strip().encode()) <= 80:
            raise ValueError("Choose a supported policy and a vault name")
        if not self.issuer and (not self.enrollment or not self.enrollment.is_file()):
            raise ValueError("A scoped enrollment grant or configured issuer is required")
        folder = self._pending(name.strip(), "create", policy)
        with self.user_action(folder):
            if not (folder / "secrets" / "identity.sealed").is_file():
                self.native("identity", folder, 1)
            if (folder / "secrets" / "hosted-context.sealed").is_file():
                self.native("setup-step", folder)
                return self._attach(folder, name.strip())
            grant = self.enrollment
            if self.issuer:
                identity = json.loads(self.native("identity-public", folder))
                result = subprocess.run([str(self.issuer), "--device-key", identity["signing"],
                                         "--operator-bundle", str(self.bundle), "--policy", policy],
                                        capture_output=True, timeout=30)
                if result.returncode or not 1 <= len(result.stdout) <= 4096:
                    raise ValueError("Enrollment is unavailable; the saved identity is retained")
                raw = result.stdout
                if (folder / "secrets" / "hosted-context.sealed").is_file():
                    self.native("setup-step", folder)
                else:
                    self.native("setup-create", folder, self.bundle, "@private", policy,
                                "--operator-key", self.key, *(["--development-http"] if self.development else []), private=raw)
            else:
                self.native("setup-create", folder, self.bundle, grant, policy,
                            "--operator-key", self.key, *(["--development-http"] if self.development else []))
            return self._attach(folder, name.strip())

    def join(self, invite):
        if not isinstance(invite, str) or not invite.startswith("loki-hosted-v1:") or len(invite) > 8192:
            raise ValueError("Enter a hosted vault invitation")
        encoded = invite.split(":", 1)[1]
        try:
            raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
        except (ValueError, UnicodeError) as error:
            raise ValueError("Invalid hosted invitation") from error
        if not 1 <= len(raw) <= 4096:
            raise ValueError("Invalid hosted invitation")
        folder = self._pending("Joined vault", "join", hashlib.sha256(raw).hexdigest())
        with self.user_action(folder):
            self.native("setup-join", folder, "@private", *self._configuration_args(), private=raw)
            return self._attach(folder, "Joined vault")

    def agree(self, vault, fingerprint):
        folder, _ = self.wallet.vault_dir(vault)
        with self.user_action(folder):
            result = json.loads(self.native("setup-agree", folder, fingerprint))
            return {"agreed": result["agreed_fingerprint"]}

    def drive(self, vault):
        folder, _ = self.wallet.vault_dir(vault)
        with self.user_action(folder):
            return json.loads(self.native("setup-step", folder))

    @staticmethod
    def _cached(folder):
        path = folder / "setup-status.json"
        return json.loads(path.read_text()) if path.is_file() else {"phase": "admission_pending", "handoff": "pending", "joined_slots": [], "missing_slots": []}

    def _ui_phase(self, folder, native):
        phase = native["phase"]
        if phase in ("aborted", "checkpoint_conflict", "expired", "admission_rejected") or self.errors.get(folder.name) == ROSTER_MISMATCH:
            return "stopped"
        if phase in ("roster_proposed", "agreement_saved", "acceptance_pending", "roster_accepted"):
            return "creating_keys" if native.get("agreed_fingerprint") else "compare_roster"
        if phase in ("round1_saved", "round2_saved", "certificate_saved"):
            return "creating_keys"
        if phase == "awaiting_backups":
            return "waiting_for_backups" if (folder / "backup-checked").is_file() else "back_up"
        if phase in ("certified", "payment_handoff", "active"):
            return "final_backup" if not (folder / "final-backup-checked").is_file() else "active" if native.get("handoff") == "ready" else "connecting_relays"
        return "waiting_for_members"

    def status(self, vault):
        folder, local = self.wallet.vault_dir(vault)
        native = self._cached(folder)
        info = self.information.get(vault, {})
        phase = native["phase"]
        ui_phase = self._ui_phase(folder, native)
        all_agreed = phase in ("roster_accepted", "round1_saved", "round2_saved", "certificate_saved", "awaiting_backups", "certified", "payment_handoff", "active")
        confirmations = [{"slot": slot, "confirmed": all_agreed or (slot == local["slot"] and bool(native.get("agreed_fingerprint"))),
                          "matches": True} for slot in range(1, local["members"] + 1)]
        result = {"phase": ui_phase, "setup_phase": phase, "handoff": native.get("handoff", "pending"),
                  "transport": "hosted", "network": "regtest", "name": local["name"], "vault": vault,
                  "slot": local["slot"], "threshold": 2, "total_members": local["members"],
                  "members": len(native.get("joined_slots", [])), "missing_slots": native.get("missing_slots", []),
                  "fingerprint": info.get("fingerprint"), "confirmations": confirmations, "profile": self.wallet.profile_data,
                  "error": self.errors.get(vault), "account_linked": False, "invites": [],
                  "relay_setup": {"phase": "ready" if native.get("handoff") == "ready" else "waiting", "available": False,
                                  "detail": "Hosted relays are connected." if native.get("handoff") == "ready" else "Connecting hosted relays automatically."},
                  "funding": {"available": False, "phase": "unavailable", "detail": ""},
                  "final_card_created": (folder / "final-card" / "vault.card").is_file(),
                  "final_card_needs_words": not (folder / "secrets" / "backup-words.sealed").is_file()}
        if local["slot"] == 1 and phase in ("invites_ready", "waiting_joins", "joins_received", "proposal_pending", "roster_proposed"):
            invitations = folder / "hosted-invites"
            invitations.mkdir(mode=0o700, exist_ok=True)
            for slot in range(2, local["members"] + 1):
                path = invitations / str(slot)
                if not path.exists():
                    with self.user_action(folder):
                        self.native("setup-invite", folder, slot, path)
                code = "loki-hosted-v1:" + base64.urlsafe_b64encode(path.read_bytes()).decode().rstrip("=")
                result["invites"].append({"slot": slot, "code": code, "joined": slot in native.get("joined_slots", []), "origin": None})
        return result

    def backup(self, vault):
        folder, _ = self.wallet.vault_dir(vault)
        with self.user_action(folder):
            return {"words": self.native("setup-backup-create", folder, folder / "card")}

    def verify(self, vault, words, card_bytes=None, final=False):
        folder, _ = self.wallet.vault_dir(vault)
        with self.user_action(folder):
            if not isinstance(words, str):
                raise ValueError("Enter your recovery words")
            with tempfile.TemporaryDirectory(prefix=".hosted-card-", dir=folder) as temporary:
                check = Path(temporary)
                card = check / "card"
                card.mkdir(mode=0o700)
                raw = base64.b64decode(card_bytes, validate=True) if card_bytes is not None else (folder / "card" / "vault.card").read_bytes()
                if not 1 <= len(raw) <= 64 * 1024 or not raw.startswith(b"LOKISEAL\x01"):
                    raise ValueError("Invalid recovery card")
                self._write(card / "vault.card", raw)
                self._write(check / "words", words.encode())
                if final:
                    self.native("setup-backup-finalize", folder, folder / "card", card, check / "words")
                else:
                    self.native("setup-backup-verify", folder, card, check / "words")
            marker = folder / ("final-backup-checked" if final else "backup-checked")
            if not marker.exists():
                self._write(marker, b"checked\n")
            return {"verified": True}

    def finalize(self, vault, words=None):
        folder, _ = self.wallet.vault_dir(vault)
        with self.user_action(folder):
            if words is not None and not isinstance(words, str):
                raise ValueError("Enter your recovery words")
            if words:
                self.native("setup-backup-finalize", folder, folder / "card", folder / "final-card", "@private", private=words.encode())
            else:
                self.native("setup-backup-finalize", folder, folder / "card", folder / "final-card", "-")
            return {"created": True}
