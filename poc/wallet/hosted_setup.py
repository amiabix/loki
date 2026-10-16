"""Public setup controller; native commands own all setup and payment authority."""
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import threading


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
        self.command_lock = threading.Lock()
        self.process_lock = threading.Lock()
        self.process = None
        self.worker = None
        self.information = {}
        self.errors = {}

    def native(self, action, root, *args, private=None, unlocked=True):
        with self.command_lock:
            return self._native(action, root, *args, private=private, unlocked=unlocked)

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
                self._write(passfile, self.wallet.passphrase.encode())
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
                    self._write(path, private)
                    argv.append(str(path))
                else:
                    argv.append(str(arg))
            with self.process_lock:
                if self.stop_event.is_set():
                    raise ValueError("Signer is locked")
                process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.process = process
            try:
                stdout, stderr = process.communicate(timeout=120)
                if process.returncode:
                    raise ValueError(stderr.decode(errors="replace").strip() or "Hosted setup could not advance")
                return stdout.decode().strip()
            except subprocess.TimeoutExpired as error:
                process.kill()
                process.communicate()
                raise ValueError("Hosted setup timed out; its saved state can be retried") from error
            finally:
                with self.process_lock:
                    if self.process is process:
                        self.process = None

    @staticmethod
    def _write(path, raw):
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())

    def start(self):
        if self.worker and self.worker.is_alive():
            return
        self.stop_event.clear()
        self.worker = threading.Thread(target=self.run, daemon=True)
        self.worker.start()

    def stop(self):
        self.stop_event.set()
        with self.process_lock:
            process = self.process
            if process and process.poll() is None:
                process.terminate()
        if self.worker and self.worker is not threading.current_thread():
            self.worker.join(timeout=5)
        with self.process_lock:
            process = self.process
            if process and process.poll() is None:
                process.kill()
        self.information.clear()

    def run(self):
        while not self.stop_event.wait(1):
            with self.wallet.lock:
                if self.stop_event.is_set() or not self.wallet.profile_data:
                    continue
                profile = self.wallet.profile_data["id"]
                root = self.wallet.data / "vaults"
                folders = sorted(root.glob("*"))
            for folder in folders:
                if self.stop_event.is_set():
                    break
                try:
                    pending = folder / "pending.json"
                    if folder.name.startswith(".hosted-") and pending.is_file():
                        metadata = json.loads(pending.read_text())
                        if metadata["profile"] == profile and (folder / "secrets" / "hosted-context.sealed").is_file():
                            self._attach(folder, metadata["name"])
                        continue
                    membership = folder / "membership.json"
                    if not membership.is_file():
                        continue
                    local = json.loads(membership.read_text())
                    if local.get("transport") != "hosted" or local.get("profile") != profile:
                        continue
                    prior = self._cached(folder)
                    if prior.get("handoff") == "ready":
                        continue
                    result = json.loads(self.native("setup-step", folder))
                    if folder.name not in self.information or prior.get("phase") != result.get("phase"):
                        self.information[folder.name] = json.loads(self.native("setup-info", folder))
                    self.errors.pop(folder.name, None)
                except (ValueError, OSError, KeyError, json.JSONDecodeError):
                    self.errors[folder.name] = "Connection interrupted. Your saved setup will retry while unlocked."

    def _configuration_args(self):
        return [self.bundle, "--operator-key", self.key, *(["--development-http"] if self.development else [])]

    def _attach(self, folder, name):
        info = json.loads(self.native("setup-info", folder))
        if info.get("network") != self.wallet.network:
            raise ValueError("Hosted vault belongs to another network")
        vault = info["vault"]
        target = self.wallet.data / "vaults" / vault
        if target.exists() and target != folder:
            raise ValueError("This profile already has that vault; reopen its saved setup")
        membership = folder / "membership.json"
        value = {"vault": vault, "slot": info["own_slot"], "name": name,
                 "profile": self.wallet.require_profile()["id"], "members": info["member_count"],
                 "threshold": 2, "transport": "hosted", "network": self.wallet.network}
        if membership.exists():
            saved = json.loads(membership.read_text())
            if {**saved, "network": saved.get("network", "regtest")} != value:
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
        self.native("setup-join", folder, "@private", *self._configuration_args(), private=raw)
        return self._attach(folder, "Joined vault")

    def agree(self, vault, fingerprint):
        folder, _ = self.wallet.vault_dir(vault)
        result = json.loads(self.native("setup-agree", folder, fingerprint))
        return {"agreed": result["agreed_fingerprint"]}

    def drive(self, vault):
        folder, _ = self.wallet.vault_dir(vault)
        return json.loads(self.native("setup-step", folder))

    @staticmethod
    def _cached(folder):
        path = folder / "setup-status.json"
        return json.loads(path.read_text()) if path.is_file() else {"phase": "admission_pending", "handoff": "pending", "joined_slots": [], "missing_slots": []}

    def status(self, vault):
        folder, local = self.wallet.vault_dir(vault)
        native = self._cached(folder)
        info = self.information.get(vault, {})
        phase = native["phase"]
        if phase in ("aborted", "checkpoint_conflict", "expired", "admission_rejected"):
            ui_phase = "stopped"
        elif phase in ("roster_proposed", "agreement_saved", "acceptance_pending", "roster_accepted"):
            ui_phase = "creating_keys" if native.get("agreed_fingerprint") else "compare_roster"
        elif phase in ("round1_saved", "round2_saved", "certificate_saved"):
            ui_phase = "creating_keys"
        elif phase == "awaiting_backups":
            ui_phase = "waiting_for_backups" if (folder / "backup-checked").is_file() else "back_up"
        elif phase in ("certified", "payment_handoff", "active"):
            ui_phase = "final_backup" if not (folder / "final-backup-checked").is_file() else "active" if native.get("handoff") == "ready" else "connecting_relays"
        else:
            ui_phase = "waiting_for_members"
        all_agreed = phase in ("roster_accepted", "round1_saved", "round2_saved", "certificate_saved", "awaiting_backups", "certified", "payment_handoff", "active")
        confirmations = [{"slot": slot, "confirmed": all_agreed or (slot == local["slot"] and bool(native.get("agreed_fingerprint"))),
                          "matches": True} for slot in range(1, local["members"] + 1)]
        result = {"phase": ui_phase, "setup_phase": phase, "handoff": native.get("handoff", "pending"),
                  "transport": "hosted", "network": local.get("network", "regtest"), "name": local["name"], "vault": vault,
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
                    self.native("setup-invite", folder, slot, path)
                code = "loki-hosted-v1:" + base64.urlsafe_b64encode(path.read_bytes()).decode().rstrip("=")
                result["invites"].append({"slot": slot, "code": code, "joined": slot in native.get("joined_slots", []), "origin": None})
        return result

    def backup(self, vault):
        folder, _ = self.wallet.vault_dir(vault)
        return {"words": self.native("setup-backup-create", folder, folder / "card")}

    def verify(self, vault, words, card_bytes=None, final=False):
        folder, _ = self.wallet.vault_dir(vault)
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
        if words is not None and not isinstance(words, str):
            raise ValueError("Enter your recovery words")
        if words:
            self.native("setup-backup-finalize", folder, folder / "card", folder / "final-card", "@private", private=words.encode())
        else:
            self.native("setup-backup-finalize", folder, folder / "card", folder / "final-card", "-")
        return {"created": True}
