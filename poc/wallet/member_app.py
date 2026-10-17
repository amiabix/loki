#!/usr/bin/env python3
"""One-member, loopback-only regtest setup app. The exchange is an untrusted local courier."""

# shortcut: timed local courier and passphrase held in this process; use resumable relays and a native key handle before custody.

from __future__ import annotations

import argparse
import base64
import binascii
import fcntl
import hashlib
import http.client
import ipaddress
import json
import os
import re
import secrets
import shutil
import ssl
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from local_relays import configure_member, ensure_network, network_root, save as save_relay_state
from local_funding import fund_member, funding_status
import timing

HERE = Path(__file__).resolve().parent
BINARIES = ("loki_setup_member", "loki_member_payment", "loki_relay_member", "loki_seed_wallet")
BUILD = "cd poc && cargo build --release --locked --bins --features relay-communication"


def target_dir():
    configured = os.environ.get("CARGO_TARGET_DIR")
    return Path(configured).resolve() if configured else HERE.parent / "target"


def binary_profile(requested=None):
    """Release when every release binary is built, unless debug is requested explicitly.

    Debug builds keep the development-only fault injection; they are several times
    slower, so the default follows the README's release build."""
    requested = requested or os.environ.get("LOKI_POC_BIN_PROFILE")
    if requested:
        if requested not in ("release", "debug"):
            raise ValueError("Choose the release or debug binary profile")
        return requested
    release = target_dir() / "release"
    return "release" if all((release / name).is_file() for name in BINARIES) else "debug"


def binary(name, profile=None):
    return target_dir() / (profile or PROFILE) / name


def use_binaries(profile):
    """Select the native binaries for this process; the paths are read at call time."""
    global PROFILE, SETUP, PAYMENT, RELAY, SEED_WALLET
    PROFILE = profile
    SETUP, PAYMENT, RELAY, SEED_WALLET = (binary(name, profile) for name in BINARIES)


use_binaries(binary_profile())

# A peer's message that has not arrived yet, or a broadcast the node has not mined
# yet, is a normal outcome of asking too early rather than a failure to report.
PAYMENT_WAITING = re.compile(r"\bwaiting for member \d+\b|\btransaction is not mined\b"
                             r"|\bTransaction not found in mempool or best chain\b")


def encoded(value):
    return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode().rstrip("=")


def decoded(value):
    return json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))


def write_new(path, value, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as out:
        out.write(value)
        out.flush()
        os.fsync(out.fileno())


def write_replace(path, value, mode=0o600):
    """Write a file that may already exist, atomically. write_new refuses to
    overwrite, which is right for material that must never be rewritten; a
    member re-publishing their roster answer after a stopped round is not that."""
    with tempfile.NamedTemporaryFile(mode="wb", dir=path.parent, prefix=".tmp-", delete=False) as out:
        out.write(value)
        out.flush()
        os.fsync(out.fileno())
        name = out.name
    os.chmod(name, mode)
    os.replace(name, path)


def read_json(path):
    return json.loads(path.read_text())


INVITE_TTL = 24 * 60 * 60
COURIER_LIMIT = 256 * 1024
# one draft, one identity and one roster answer per member, one round-one, one
# certificate, backup and final-status wires each, and one round-two wire per ordered pair
COURIER_FILES = 1 + 4 * 6 + 4 * 3

# The setup courier carries a fixed, named set of files: the vault draft, each
# member's public identity, the roster answer each app published, and the signed
# DKG, backup and final-status wires. Anything else is refused, so a reachable
# courier cannot be used as general storage.
COURIER = (r"(?:join|confirm)-{slot}\.json"
           r"|{vault}-(?:r1|cert|backup|final-status)-{slot}\.bin|{vault}-r2-{slot}-[1-4]\.bin")


def courier_name(vault, name, slot="[1-4]"):
    """Whether this is a file member <slot> publishes for this vault."""
    return bool(re.fullmatch(COURIER.format(vault=vault, slot=slot), name))


def courier_carries(vault, name):
    """Whether the courier carries this name at all. The draft is the creator's."""
    return name == "draft.json" or courier_name(vault, name)


def courier_replaceable(name):
    """A DKG or backup wire is published once: a second version of one is a
    protocol failure, not an update. A roster answer is a claim a member can
    re-publish after a stopped round, so that one may be replaced."""
    return name.startswith("confirm-")


def courier_write(folder, name, body):
    (write_replace if courier_replaceable(name) else write_new)(folder / name, body)


def courier_digests(folder, vault):
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in folder.iterdir() if courier_carries(vault, path.name)}


def loopback(host):
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


def check_origin(value):
    """The address the other members' apps reach this creator's courier on.

    A joining member carries a bearer token for its invite slot on every
    request, so the channel has to be authenticated whenever it leaves this
    machine: plain HTTP is accepted only for a loopback address, and anything
    else must be HTTPS with a certificate this device already trusts. A LAN
    http:// address is refused rather than offered, because an observer on
    that network could take the token and claim the slot.

    The courier itself stays untrusted either way. Every DKG and backup wire it
    carries is signed and recipient-encrypted by the member apps, and the
    roster fingerprint is still compared out of band."""
    parts = urlsplit(value if isinstance(value, str) else "")
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username \
            or parts.password or parts.path or parts.query or parts.fragment:
        raise ValueError("Give an invite address like https://vault.example.org")
    if parts.scheme == "http" and not loopback(parts.hostname):
        raise ValueError("Use https for an invite another device can reach. Plain http is "
                         "accepted only for 127.0.0.1, because the invite token travels on "
                         "every request.")
    return f"{parts.scheme}://{parts.netloc}"


class Unreachable(ValueError):
    """The courier did not answer. Like Timeout, nothing is known to have
    failed: the next action is to wait and retry, not to repair anything. A
    refusal or a conflicting file is the opposite case and must not read as
    something that will clear on its own."""


def courier_error(payload, status):
    try:
        return str(json.loads(payload)["error"])
    except (ValueError, KeyError, TypeError):
        return f"The vault creator's app refused this request ({status})"


def courier_request(origin, method, path, token=None, body=None, timeout=15):
    """One plain HTTP request to the creator's courier. No redirect is followed
    and no proxy is used: the only address used is the one in the invite."""
    parts = urlsplit(origin)
    if parts.scheme == "https":
        # The platform trust store, fully verified. A courier that cannot prove
        # its name is not a courier this member will hand an invite token to.
        connection = http.client.HTTPSConnection(parts.hostname, parts.port, timeout=timeout,
                                                 context=ssl.create_default_context(cafile=os.environ.get("SSL_CERT_FILE") or None))
    else:
        connection = http.client.HTTPConnection(parts.hostname, parts.port, timeout=timeout)
    try:
        headers = {"X-Loki-Setup": token} if token else {}
        if body is not None:
            headers["Content-Type"] = "application/octet-stream"
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        payload = response.read(COURIER_LIMIT + 1024)
        if response.status != 200:
            raise ValueError(courier_error(payload, response.status))
    except (OSError, http.client.HTTPException) as error:
        raise Unreachable(f"Cannot reach the vault creator's app at {origin}") from error
    finally:
        connection.close()
    return payload


class Timeout(ValueError):
    """A helper binary ran past its deadline. Distinct from a refusal: nothing
    is known to have failed, so the next action is to retry, not to repair."""


def check_passphrase(value):
    if not isinstance(value, str) or len(value) < 12 or len(value) > 1024:
        raise ValueError("Use a passphrase of at least 12 characters")
    return value


class SignerSessions:
    """Scoped dashboard grants; the signer never exports its private app token."""

    def __init__(self, dashboard_origin, now=time.time):
        self.origin = dashboard_origin
        self.now = now
        self.records = {}
        self.actions = {}
        self.lock = threading.Lock()

    def _valid(self, key, origin):
        item = self.records.get(key)
        return bool(item and item["state"] == "approved" and item["origin"] == origin
                    and item["expires"] > self.now())

    def request(self, origin):
        if origin != self.origin:
            raise ValueError("Unexpected dashboard origin")
        with self.lock:
            self.records = {key: item for key, item in self.records.items() if item["expires"] > self.now()}
            if len(self.records) >= 16:
                raise ValueError("Too many connection requests")
            key = secrets.token_urlsafe(32)
            self.records[key] = {"origin": origin, "state": "pending", "expires": self.now() + 300}
            return key

    def pending(self):
        with self.lock:
            return [{"request": key, "origin": item["origin"], "network": "regtest",
                     "access": "View vault status, set up local relays for all eligible vaults, and fund your eligible vaults with 5 local test ZEC per click. Vault creation needs signer approval."}
                    for key, item in self.records.items()
                    if item["state"] == "pending" and item["expires"] > self.now()]

    def approve(self, key):
        with self.lock:
            item = self.records.get(key)
            if not item or item["state"] != "pending" or item["expires"] <= self.now():
                raise ValueError("Connection request missing or expired")
            item["state"] = "approved"
            item["expires"] = self.now() + 3600

    def reject(self, key):
        with self.lock:
            item = self.records.get(key)
            if not item or item["state"] != "pending":
                raise ValueError("Connection request missing")
            item["state"] = "rejected"

    def poll(self, key):
        with self.lock:
            item = self.records.get(key)
            if not item:
                return "missing"
            if item["expires"] <= self.now():
                return "expired"
            return item["state"]

    def valid(self, key, origin):
        with self.lock:
            return self._valid(key, origin)

    def request_action(self, key, origin, value):
        if not self.valid(key, origin):
            raise ValueError("Connect your signer")
        kind = value.get("kind")
        if kind not in ("create", "relay-setup"):
            raise ValueError("Unsupported vault request")
        if not isinstance(value.get("name"), str):
            raise ValueError("Unsupported vault request")
        name = value["name"].strip()
        if not 1 <= len(name.encode()) <= 80:
            raise ValueError("Enter a vault name of 1 to 80 UTF-8 bytes")
        members = value.get("members", 3)
        if type(members) is not int or members not in (3, 4):
            raise ValueError("Choose a 2-of-3 or 2-of-4 vault")
        if kind == "relay-setup" and (not isinstance(value.get("vault"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", value["vault"])):
            raise ValueError("Invalid vault ID")
        with self.lock:
            if not self._valid(key, origin):
                raise ValueError("Connect your signer")
            self.actions = {action: item for action, item in self.actions.items()
                            if item["expires"] > self.now()}
            if len(self.actions) >= 16:
                raise ValueError("Too many vault requests")
            action = secrets.token_urlsafe(32)
            self.actions[action] = {"session": key, "origin": origin, "kind": kind,
                                    "name": name, **({"vault": value["vault"]} if kind == "relay-setup" else
                                                     {"members": members}),
                                    "state": "pending", "expires": self.now() + 300}
            return action

    def pending_actions(self):
        with self.lock:
            return [{"action": action, "origin": item["origin"], "kind": item["kind"],
                     "name": item["name"], **{field: item[field] for field in ("vault", "members") if field in item}}
                    for action, item in self.actions.items()
                    if item["state"] == "pending" and item["expires"] > self.now()
                    and self._valid(item["session"], item["origin"])]

    def take_action(self, action):
        with self.lock:
            item = self.actions.get(action)
            if not item or item["state"] != "pending" or item["expires"] <= self.now() \
                    or not self._valid(item["session"], item["origin"]):
                raise ValueError("Vault request missing or expired")
            item["state"] = "executing"
            return {"kind": item["kind"], "name": item["name"],
                    **{field: item[field] for field in ("vault", "members") if field in item}}

    def finish_action(self, action, result=None, error=None):
        with self.lock:
            item = self.actions[action]
            item["state"] = "failed" if error else "done"
            item["result"] = result
            item["error"] = error
            item["expires"] = self.now() + 3600

    def reject_action(self, action):
        with self.lock:
            item = self.actions.get(action)
            if not item or item["state"] != "pending":
                raise ValueError("Vault request missing")
            item["state"] = "rejected"

    def poll_action(self, key, origin, action):
        with self.lock:
            item = self.actions.get(action)
            if not self._valid(key, origin) or not item or item["session"] != key:
                raise ValueError("Vault request missing")
            if item["expires"] <= self.now():
                return {"state": "expired"}
            response = {"state": item["state"]}
            if item["state"] == "done":
                response["result"] = item["result"]
            if item["state"] == "failed":
                response["error"] = item["error"]
            return response

    def disconnect(self, key, origin):
        if not self.valid(key, origin):
            raise ValueError("No connected signer session")
        with self.lock:
            self.records.pop(key, None)
            self.actions = {action: item for action, item in self.actions.items()
                            if item["session"] != key or item["state"] == "executing"}

    def clear(self):
        with self.lock:
            self.records.clear()
            self.actions.clear()


class Wallet:
    def __init__(self, data, exchange, setup=None, invite_origin=None, transport="local", operator_bundle=None, operator_key=None, enrollment_grant=None, development_http=False, enrollment_issuer=None):
        self.data = data.resolve()
        # Hosted vaults never use the local courier; an exchange given for script
        # compatibility is still checked and otherwise ignored.
        if exchange is None and transport != "hosted":
            raise ValueError("Local transport needs an --exchange directory")
        self.exchange = exchange.resolve() if exchange is not None else None
        if self.exchange and (self.data == self.exchange or self.data in self.exchange.parents or self.exchange in self.data.parents):
            raise ValueError("member data and exchange must be separate directories")
        if (self.data / "membership.json").exists():
            raise ValueError("Existing single-vault data root; keep using the previous setup app or choose a new root")
        self.data.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.exchange:
            self.exchange.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.data, 0o700)
        self.process_lock = open(self.data / ".app.lock", "a+b")
        try:
            fcntl.flock(self.process_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            self.process_lock.close()
            raise ValueError("This member data root is already open in another app") from error
        self.setup = setup or SETUP
        if transport not in ("local", "hosted"):
            raise ValueError("Choose local or hosted transport")
        self.transport = transport
        self.hosted = None
        if transport == "hosted":
            from hosted_setup import HostedSetup
            self.hosted = HostedSetup(self, operator_bundle, operator_key, enrollment_grant, development_http, enrollment_issuer)
        self.invite_origin = check_origin(invite_origin) if invite_origin else None
        self.lock = threading.Lock()
        self.claim_lock = threading.Lock()
        self.syncs = {}
        self.sync_done = set()
        self.sync_stop = threading.Event()
        self.transport_errors = {}
        self.passphrase = None
        self.profile_data = None
        self.workers = {}
        self.setup_errors = {}
        self.relay_payment_ready = False
        self.scan_height = {}
        self.relay_jobs = {}
        self.relay_binary = RELAY
        self.relay_attempts = {}
        self.relay_stop = threading.Event()
        self.relay_monitor = threading.Thread(target=self.monitor_relays, daemon=True)
        self.relay_monitor.start()

    def command(self, action, *args, passphrase=None, timeout=30, binary=None):
        binary = binary or self.setup
        if not binary.is_file():
            raise ValueError(f"Build {binary.name}: {BUILD}")
        passfile = None
        try:
            argv = [str(binary), action]
            for arg in args:
                if arg == "@pass":
                    fd, name = tempfile.mkstemp(prefix=".unlock-", dir=self.data)
                    passfile = Path(name)
                    with os.fdopen(fd, "w") as out:
                        out.write(check_passphrase(passphrase if passphrase is not None else self.passphrase))
                    argv.append(name)
                else:
                    argv.append(str(arg))
            started = time.monotonic()
            try:
                result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
            except subprocess.TimeoutExpired as error:
                timing.record(f"{binary.name} {action}", started, "timeout", *args)
                raise Timeout(f"{action} did not finish within {timeout} seconds") from error
            timing.record(f"{binary.name} {action}", started, result.returncode, *args, stderr=result.stderr)
            if result.returncode:
                raise ValueError(result.stderr.strip() or result.stdout.strip() or f"{action} failed")
            return result.stdout.strip()
        finally:
            if passfile:
                passfile.unlink(missing_ok=True)

    def create_profile(self, name, passphrase):
        if (self.data / "profile" / "profile.sealed").exists():
            raise ValueError("This profile already exists; unlock it")
        if not isinstance(name, str) or not 1 <= len(name.strip().encode()) <= 80:
            raise ValueError("Enter a profile name of 1 to 80 UTF-8 bytes")
        check_passphrase(passphrase)
        profile = json.loads(self.command("profile-create", self.data, "@pass", name.strip(),
                                          passphrase=passphrase))
        self.passphrase, self.profile_data = passphrase, profile
        if self.hosted:
            self.hosted.start()
        return {"profile": profile}

    def unlock(self, passphrase):
        check_passphrase(passphrase)
        try:
            profile = json.loads(self.command("profile-open", self.data, "@pass", passphrase=passphrase))
        except Timeout:
            raise
        except ValueError as error:
            # The binary reports "sealed file failed authentication", which is
            # accurate and unreadable, and names both causes without saying
            # which. Keep both causes, in words, on the form that can retry.
            raise ValueError("Could not open your profile with that passphrase. If you are "
                             "certain it is right, the profile file on this device may have "
                             "been changed.") from error
        self.passphrase, self.profile_data = passphrase, profile
        if self.hosted:
            self.hosted.start()
        return {"profile": profile}

    def lock_profile(self):
        if self.hosted:
            self.hosted.stop()
        if any(worker.is_alive() for worker in self.workers.values()):
            raise ValueError("Wait for key creation to finish before locking")
        self.passphrase = None
        self.profile_data = None
        return {"locked": True}

    def require_profile(self):
        if not self.profile_data:
            raise ValueError("Unlock your profile first")
        return self.profile_data

    def vault_dir(self, vault):
        folder = self.data / "vaults" / self.checked_vault_id(vault)
        local = folder / "membership.json"
        if not local.is_file():
            raise ValueError("This profile is not a member of that vault")
        membership = read_json(local)
        if membership.get("transport") == "hosted" and not self.hosted:
            raise ValueError("Open this profile with hosted transport and its trusted operator bundle")
        if membership.get("vault") != vault or membership.get("profile") != self.require_profile()["id"]:
            raise ValueError("Vault membership does not belong to this profile")
        return folder, membership

    def vaults(self):
        self.require_profile()
        root = self.data / "vaults"
        if not root.exists():
            return []
        return [{**self.vault_dir(path.name)[1], "relay_setup": self.relay_status(path.name)} for path in sorted(root.iterdir())
                if re.fullmatch(r"[0-9a-f]{64}", path.name) and (path / "membership.json").is_file()]

    def setup_relays(self, vault):
        if self.transport == "hosted":
            raise ValueError("Hosted vaults attach to relays automatically")
        member, local = self.vault_dir(vault)
        state_path = member / "relay-setup.json"
        if state_path.is_file() and read_json(state_path).get("mode") == "operator":
            raise ValueError("Use this vault's operator relay connection controls")
        if not (member / "final-backup-checked").is_file():
            raise ValueError("Check your final backup before setting up relays")
        if local.get("members") not in (3, 4):
            raise ValueError("Unsupported vault policy")
        if (member / "transport.json").exists():
            raise ValueError("Local test relays require all three apps to use the same local exchange directory")
        if not (self.exchange_vault(vault) / "draft.json").is_file():
            raise ValueError("Local test relays require the saved shared setup courier")
        worker = self.relay_jobs.get(vault)
        if worker and worker.is_alive():
            return {"vault": vault, "phase": "starting"}
        def run():
            with self.lock:
                try:
                    self.require_profile()
                    configure_member(self, vault)
                except Exception as error:
                    path = member / "relay-setup.json"
                    prior = read_json(path) if path.exists() else {}
                    save_relay_state(path, {**prior, "phase": "failed", "detail": str(error)})
        worker = threading.Thread(target=run, daemon=True)
        self.relay_jobs[vault] = worker
        worker.start()
        return {"vault": vault, "phase": "starting"}

    def relay_network_status(self):
        if self.transport == "hosted":
            return {"enabled": True, "transport": "hosted", "available": False, "detail": "Vaults connect to hosted relays automatically after setup and backup checks."}
        settings = self.exchange / '.payment-relays' / 'settings.json'
        enabled = settings.is_file() and read_json(settings).get('enabled') is True
        return {"enabled": enabled, "detail":
                "Automatic relay connection is enabled. Eligible vaults attach when their signers are unlocked."
                if enabled else "Set up local relays once to connect all eligible vaults automatically."}

    def setup_all_relays(self):
        if self.transport == "hosted":
            raise ValueError("Hosted vaults attach to relays automatically")
        self.require_profile()
        root = self.exchange / '.payment-relays'
        network = network_root(self.exchange)
        ensure_network(network)
        save_relay_state(root / 'settings.json', {"enabled": True, "revision": secrets.token_hex(16),
                                                "network": network.name})
        return {"relay_setup": True}

    def monitor_relays(self):
        while not self.relay_stop.wait(1):
            if self.transport == "hosted":
                continue
            try:
                settings = self.exchange / '.payment-relays' / 'settings.json'
                if not settings.is_file() or not self.profile_data:
                    continue
                policy = read_json(settings)
                if policy.get('enabled') is not True:
                    continue
                with self.lock:
                    if not self.profile_data or self.relay_stop.is_set():
                        continue
                    for item in self.vaults():
                        vault = item['vault']
                        state = item['relay_setup']
                        if not state['available'] or state['phase'] == 'starting':
                            continue
                        if self.relay_attempts.get(vault) == policy['revision']:
                            continue
                        self.relay_attempts[vault] = policy['revision']
                        self.setup_relays(vault)
            except Exception:
                continue

    def relay_status(self, vault):
        member, local = self.vault_dir(vault)
        if local.get("transport") == "hosted":
            native = self.hosted._cached(member)
            return {"phase": "ready" if native.get("handoff") == "ready" else "waiting", "available": False,
                    "detail": "Hosted relays are connected." if native.get("handoff") == "ready" else "Connecting hosted relays automatically."}
        if self.exchange is None:
            return {"phase": "unavailable", "available": False,
                    "detail": "This local vault needs the app started with local transport and its exchange."}
        state_path = member / "relay-setup.json"
        state = read_json(state_path) if state_path.is_file() else {}
        if state.get("mode") == "operator":
            return {"phase": state["phase"], "detail": state["detail"], "available": False}
        active = local.get("members") in (3, 4) and (member / "final-backup-checked").is_file()
        available = active and not (member / "transport.json").exists() and (self.exchange_vault(vault) / "draft.json").is_file()
        worker = self.relay_jobs.get(vault)
        if state.get("phase") == "waiting" and self.profile_data and not (worker and worker.is_alive()):
            networks = self.exchange / '.payment-relays'
            if any((networks / network / 'couriers' / str(local['slot']) /
                    f'{vault}-relay-config-{owner}-{local["slot"]}-1.bin').is_file()
                   for network in {network_root(self.exchange).name, vault}
                   for owner in set(range(1, local['members'] + 1)) - {local['slot']} - set(state.get('imported', []))):
                self.setup_relays(vault)
                worker = self.relay_jobs.get(vault)
        return {"phase": "starting" if worker and worker.is_alive() else state.get("phase", "not_configured"),
                "detail": state.get("detail", "Connecting automatically." if available and self.relay_network_status()['enabled'] else
                                    "Set up relays once from the dashboard." if available else
                                    "Local test relays require the shared local setup courier." if active else
                                    "Available after this member checks the final backup."),
                "available": available}

    @staticmethod
    def checked_vault_id(vault):
        if not isinstance(vault, str) or len(vault) != 64 or any(c not in "0123456789abcdef" for c in vault):
            raise ValueError("Invalid vault ID")
        return vault

    def exchange_vault(self, vault):
        self.checked_vault_id(vault)
        if self.exchange is None:
            raise ValueError("Not available with hosted transport")
        return self.exchange / vault

    # ── the creator's courier, reachable by the other members ───────────────
    # The same opaque files the local courier directory carried, served over
    # HTTP to whoever holds a token claimed with one of this vault's invites.
    # Nothing here can read the signer's private app token, a profile or a key.

    def courier_folder(self, vault):
        folder = self.exchange_vault(vault)
        if not (folder / "draft.json").is_file():
            raise ValueError("No vault setup is open for that ID")
        return folder

    def claim_invite(self, vault, slot, secret, token):
        """Spend one invite for one slot, for the app that presents this token.

        The joining app chooses and saves its own courier token before it asks,
        so asking twice is the same claim: a lost answer costs a retry, not the
        invitation. The slot is still spent by one app only — a copy of the code
        on a second device arrives with a different token and is refused."""
        if not isinstance(token, str) or len(token) < 32 or len(token) > 256:
            raise ValueError("The joining app did not present a courier token")
        draft = read_json(self.courier_folder(vault) / "draft.json")
        if type(slot) is not int or slot not in range(2, int(draft["members"]) + 1) \
                or not isinstance(secret, str) or not secrets.compare_digest(
                    draft["invites"].get(str(slot), ""),
                    hashlib.sha256(secret.encode()).hexdigest()):
            raise ValueError("This invite does not match this vault")
        claims = self.data / "vaults" / vault / "claims.json"
        presented = hashlib.sha256(token.encode()).hexdigest()
        with self.claim_lock:
            spent = read_json(claims) if claims.is_file() else {}
            if str(slot) in spent:
                # The same app asking again is the same claim, so the 24 hours
                # cannot strand a member whose answer was lost just before it.
                if not secrets.compare_digest(spent[str(slot)], presented):
                    raise ValueError("This invite was already used by another app. "
                                     "Ask the vault creator for a new one.")
            else:
                if int(draft["expires_at"]) < time.time():
                    raise ValueError("This invite expired. Ask the vault creator for a new one.")
                spent[str(slot)] = presented
                write_replace(claims, json.dumps(spent).encode())
        return {"draft": draft}

    def courier_slot(self, vault, token):
        claims = self.data / "vaults" / self.checked_vault_id(vault) / "claims.json"
        presented = hashlib.sha256((token or "").encode()).hexdigest()
        for slot, saved in (read_json(claims) if claims.is_file() else {}).items():
            if secrets.compare_digest(saved, presented):
                return int(slot)
        raise ValueError("Claim your invite first")

    def courier_list(self, vault):
        return courier_digests(self.courier_folder(vault), vault)

    def courier_read(self, vault, name):
        if not courier_carries(vault, name):
            raise ValueError("Unknown setup file")
        folder = self.courier_folder(vault)
        if not (folder / name).is_file():
            raise ValueError("Unknown setup file")
        return (folder / name).read_bytes()

    def courier_publish(self, vault, slot, name, body):
        """A member may publish only the files their own slot owns."""
        if not courier_name(vault, name, str(slot)):
            raise ValueError(f"Member {slot} cannot publish that setup file")
        if len(body) > COURIER_LIMIT:
            raise ValueError("Setup file too large")
        folder = self.courier_folder(vault)
        if (folder / name).exists() and not courier_replaceable(name):
            raise ValueError(f"{name} was already published; start a fresh vault session")
        courier_write(folder, name, body)
        return {"published": name}

    # ── a joined member's side of the same courier ──────────────────────────

    def ensure_sync(self, vault):
        """Keep this member's local courier directory and the creator's in step.

        The bytes are unchanged, so every signature, roster and ciphertext check
        the file courier already made happens exactly as before."""
        transport = self.data / "vaults" / self.checked_vault_id(vault) / "transport.json"
        worker = self.syncs.get(vault)
        if vault in self.sync_done or not transport.is_file() or (worker and worker.is_alive()):
            return
        worker = threading.Thread(target=self.sync_loop, args=(read_json(transport),), daemon=True)
        self.syncs[vault] = worker
        worker.start()

    def sync_loop(self, transport):
        vault = transport["vault"]
        while not self.sync_stop.is_set():
            try:
                self.sync_once(vault, transport["origin"], transport["token"], transport["slot"])
                self.transport_errors.pop(vault, None)
                checked = self.data / "vaults" / vault / "final-backup-checked"
                if checked.is_file() and all(report["reported"] for report in self.backup_reports(vault)):
                    self.sync_done.add(vault)
                    return
            except (ValueError, OSError, KeyError) as error:
                self.transport_errors[vault] = {"message": str(error),
                                                "waiting": isinstance(error, Unreachable)}
            self.sync_stop.wait(1)

    def sync_once(self, vault, origin, token, slot):
        """One pass in each direction.

        Nothing the courier says is taken on trust. It names the files it holds
        and their digests, and it is the other side of an untrusted channel, so
        every name is checked against the names this vault can have, every body
        is checked against the digest that was advertised for it, and a file
        this app already published is never overwritten by a different one."""
        folder = self.exchange_vault(vault)
        listed = json.loads(courier_request(origin, "GET", f"/setup/{vault}/files", token))
        remote = listed.get("files") if isinstance(listed, dict) else None
        if not isinstance(remote, dict) or len(remote) > COURIER_FILES:
            raise ValueError("The setup courier did not answer with this vault's file list")
        for name, digest in remote.items():
            if not courier_carries(vault, name) or not isinstance(digest, str):
                raise ValueError("The setup courier listed a file this vault cannot have. "
                                 "Stop and start a fresh vault session.")
        local = courier_digests(folder, vault)
        for name, digest in sorted(remote.items()):
            if name in local and local[name] != digest and not courier_replaceable(name):
                # A published wire is published once. Two different versions of
                # one is a failed round, not something to resolve by keeping
                # whichever copy arrived first.
                raise ValueError(f"The setup courier holds a different {name} than this app has. "
                                 "Stop and start a fresh vault session.")
            if name not in local or local[name] != digest:
                body = courier_request(origin, "GET", f"/setup/{vault}/files/{name}", token)
                if len(body) > COURIER_LIMIT or hashlib.sha256(body).hexdigest() != digest:
                    raise ValueError(f"The setup courier's {name} is not the file it listed. "
                                     "Stop and start a fresh vault session.")
                courier_write(folder, name, body)
        for name, digest in sorted(local.items()):
            if courier_name(vault, name, str(slot)) and (
                    name not in remote or (courier_replaceable(name) and remote[name] != digest)):
                courier_request(origin, "PUT", f"/setup/{vault}/files/{name}", token,
                                (folder / name).read_bytes())

    def create(self, name, members=3):
        if self.hosted:
            return self.hosted.create(f"2-of-{members}", name)
        profile = self.require_profile()
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80:
            raise ValueError("Enter a vault name of 1 to 80 characters")
        if type(members) is not int or members not in (3, 4):
            raise ValueError("Choose a 2-of-3 or 2-of-4 vault")
        vault = secrets.token_hex(32)
        folder = self.exchange_vault(vault)
        folder.mkdir(mode=0o700)
        local = self.data / "vaults" / vault
        local.mkdir(mode=0o700, parents=True)
        tokens = {slot: secrets.token_urlsafe(24) for slot in range(2, members + 1)}
        draft = {"vault": vault, "name": name.strip(), "threshold": 2,
                 "members": members,
                 "expires_at": int(time.time()) + INVITE_TTL,
                 "invites": {str(slot): hashlib.sha256(token.encode()).hexdigest() for slot, token in tokens.items()}}
        write_new(folder / "draft.json", json.dumps(draft).encode())
        identity = json.loads(self.command("identity", local, "1", "@pass"))
        write_new(folder / "join-1.json", json.dumps(identity).encode())
        write_new(local / "membership.json", json.dumps({"vault": vault, "slot": 1,
                                                          "name": name.strip(), "profile": profile["id"],
                                                          "threshold": 2, "members": members}).encode())
        invites = [encoded({"vault": vault, "slot": slot, "secret": token,
                            **({"url": self.invite_origin} if self.invite_origin else {})})
                   for slot, token in tokens.items()]
        write_new(local / "invites.json", json.dumps(invites).encode())
        return {"vault": vault, "invites": invites}

    def join(self, invite):
        if self.hosted:
            return self.hosted.join(invite)
        profile = self.require_profile()
        try:
            claim = decoded(invite)
            vault, slot, secret = claim["vault"], claim["slot"], claim["secret"]
        except (ValueError, KeyError, TypeError) as error:
            raise ValueError("Invalid invite") from error
        folder = self.exchange_vault(vault)
        local = self.data / "vaults" / vault
        if local.exists():
            raise ValueError("This profile already has a membership for this vault")
        origin = check_origin(claim["url"]) if claim.get("url") else None
        token, repeat = self.pending_claim(vault, slot, secret, origin) if origin else (None, False)
        if origin:
            self.claim_remote(vault, slot, secret, origin, token)
        draft = read_json(folder / "draft.json")
        # repeat is this app finishing a claim it already made and the creator's
        # app already recorded; the 24 hours gate the first claim, not that.
        if draft["vault"] != vault or (int(draft["expires_at"]) < time.time() and not repeat):
            raise ValueError("Invite expired or belongs to another vault")
        members = draft.get("members", 3)
        if draft.get("threshold") != 2 or type(members) is not int or members not in (3, 4) \
                or not isinstance(draft.get("name"), str) or not 1 <= len(draft["name"].encode()) <= 80:
            raise ValueError("Unsupported vault draft")
        if type(slot) is not int or slot not in range(2, members + 1) or not isinstance(secret, str) \
                or set(draft.get("invites", {})) != {str(id) for id in range(2, members + 1)} \
                or not secrets.compare_digest(
                    draft["invites"][str(slot)], hashlib.sha256(secret.encode()).hexdigest()
        ):
            raise ValueError("Invite does not match this vault")
        if (folder / f"join-{slot}.json").exists():
            raise ValueError("This invite slot has already been claimed")
        local.mkdir(mode=0o700, parents=True)
        identity = json.loads(self.command("identity", local, str(slot), "@pass"))
        write_new(folder / f"join-{slot}.json", json.dumps(identity).encode())
        write_new(local / "membership.json", json.dumps({"vault": vault, "slot": slot,
                                                          "name": draft["name"], "profile": profile["id"],
                                                          "threshold": 2, "members": members}).encode())
        if origin:
            write_new(local / "transport.json", json.dumps(
                {"vault": vault, "slot": slot, "origin": origin, "token": token}).encode())
            self.ensure_sync(vault)
        return {"vault": vault, "joined": True}

    def pending_claim(self, vault, slot, secret, origin):
        """This app's courier token for one invite, saved before it is used.

        It is written down first, so a claim whose answer never arrives can be
        repeated with the same token: the creator's app reads that repeat as the
        same claim, and a different app's token as a second device.

        It is bound to the exact invite. Repeating is only repeating if it is
        the same slot, the same secret and the same address; a second, different
        invite for this vault would otherwise reuse this token and claim another
        member's slot with it. There is no reissue in this build, so a different
        invite for a vault this app already claimed is refused outright."""
        held = {"slot": slot, "secret": hashlib.sha256(secret.encode()).hexdigest(),
                "origin": origin}
        path = self.data / "claim-tokens.json"
        with self.claim_lock:
            saved = read_json(path) if path.is_file() else {}
            claimed = saved.get(vault)
            if claimed and {key: claimed.get(key) for key in held} != held:
                raise ValueError(
                    f"This app already claimed the member {claimed['slot']} invite for that "
                    "vault. Paste that same invite again, or ask the vault creator to start "
                    "a new vault.")
            if not claimed:
                saved[vault] = {**held, "token": secrets.token_urlsafe(32)}
                write_replace(path, json.dumps(saved).encode())
            return saved[vault]["token"], bool(claimed)

    def claim_remote(self, vault, slot, secret, origin, token):
        """Spend the invite at the creator's courier and keep its vault draft.

        The draft is only a claim by that courier; the policy checks in join and
        the roster fingerprint every member compares by hand are unchanged."""
        answer = json.loads(courier_request(
            origin, "POST", f"/setup/{vault}/claim",
            body=json.dumps({"slot": slot, "secret": secret, "token": token}).encode()))
        folder = self.exchange_vault(vault)
        folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        draft = answer.get("draft") if isinstance(answer, dict) else None
        if not isinstance(draft, dict) or len(json.dumps(draft)) > 4096:
            raise ValueError("The vault creator's app did not return this vault's draft")
        if not (folder / "draft.json").exists():
            write_new(folder / "draft.json", json.dumps(draft).encode())

    def roster(self, vault):
        member_dir, local = self.vault_dir(vault)
        folder = self.exchange_vault(vault)
        draft = read_json(folder / "draft.json")
        total = local.get("members", 3)
        if draft.get("threshold") != local.get("threshold", 2) or draft.get("members", 3) != total:
            raise ValueError("Vault policy changed after joining")
        members = [read_json(folder / f"join-{slot}.json") for slot in range(1, total + 1)
                   if (folder / f"join-{slot}.json").exists()]
        if len(members) != total:
            return {"members": members, "fingerprint": None}
        if [member["id"] for member in members] != list(range(1, total + 1)):
            raise ValueError("Member slots do not match the roster")
        roster = {"vault": vault, "threshold": 2, "members": members}
        write_path = member_dir / "roster.json"
        if not write_path.exists():
            write_new(write_path, json.dumps(roster).encode())
        elif read_json(write_path) != roster:
            raise ValueError("Roster changed after it was recorded")
        fingerprint = self.command("fingerprint", write_path)
        return {"members": members, "fingerprint": fingerprint}

    def begin_link(self, vault):
        member_dir, local = self.vault_dir(vault)
        if (member_dir / "secrets" / "account-link.sealed").exists():
            raise ValueError("This vault membership already has an account link")
        identity = json.loads(self.command("identity-public", member_dir, "@pass"))
        challenge = {"version": 1, "network": "regtest", "vault": vault,
                     "member": local["slot"], "identity_signing": identity["signing"],
                     "nonce": secrets.token_hex(32), "expires_at": int(time.time()) + 600}
        path = member_dir / "account-challenge.json"
        with tempfile.NamedTemporaryFile(mode="w", dir=member_dir, prefix=".challenge-",
                                         delete=False) as out:
            json.dump(challenge, out)
            out.flush()
            os.fsync(out.fileno())
            name = out.name
        os.replace(name, path)
        return challenge

    def link(self, vault, proof):
        member_dir, _ = self.vault_dir(vault)
        challenge = member_dir / "account-challenge.json"
        if not challenge.is_file():
            raise ValueError("Begin account connection first")
        if not isinstance(proof, dict):
            raise ValueError("Enter the wallet's JSON proof")
        with tempfile.TemporaryDirectory(prefix=".proof-", dir=member_dir) as temp:
            path = Path(temp) / "proof.json"
            write_new(path, json.dumps(proof).encode())
            result = json.loads(self.command("bind", self.data, member_dir, "@pass", challenge,
                                             path, binary=SEED_WALLET))
        challenge.unlink()
        return result

    def account_link(self, vault):
        member_dir, _ = self.vault_dir(vault)
        if not (member_dir / "secrets" / "account-link.sealed").exists():
            raise ValueError("No Zcash account link for this vault")
        result = json.loads(self.command("check", self.data, member_dir, "@pass", binary=SEED_WALLET))
        if result["vault"] != vault:
            raise ValueError("Account link belongs to another vault")
        return result

    def agree(self, vault, fingerprint):
        if self.vault_dir(vault)[1].get("transport") == "hosted":
            return self.hosted.agree(vault, fingerprint)
        member_dir, local = self.vault_dir(vault)
        roster = self.roster(vault)
        if not roster["fingerprint"]:
            raise ValueError("Wait for all vault members")
        if not isinstance(fingerprint, str) or not secrets.compare_digest(fingerprint, roster["fingerprint"]):
            raise ValueError("Roster fingerprint does not match")
        own = json.loads(self.command("identity-public", member_dir, "@pass"))
        if own != roster["members"][local["slot"] - 1]:
            raise ValueError("Your identity differs from the agreed roster")
        if vault in self.workers and self.workers[vault].is_alive():
            raise ValueError("Key creation is already running")
        # Publish which fingerprint this app confirmed, so the other members can
        # see who is ready and, more usefully, see immediately if someone is
        # holding a different roster. The courier is untrusted, so this is a
        # coordination signal and never evidence: a matching entry proves
        # nothing, while a differing one is a reason to stop.
        write_replace(self.exchange_vault(vault) / f"confirm-{local['slot']}.json",
                      json.dumps({"slot": local["slot"], "fingerprint": fingerprint,
                                  "at": int(time.time())}).encode())
        self.setup_errors.pop(vault, None)
        passphrase = self.passphrase

        def run():
            try:
                self.command("run", member_dir, "@pass", member_dir / "roster.json",
                             self.exchange_vault(vault), fingerprint, passphrase=passphrase,
                             timeout=600)
            except Timeout:
                self.setup_errors[vault] = (
                    "Key creation ran out of time. Every member has to be on this step at "
                    "the same time. Ask the others to open their app and reach this step, "
                    "then confirm the roster again to start a fresh round.")
            except Exception as error:
                self.setup_errors[vault] = str(error)

        self.workers[vault] = threading.Thread(target=run, daemon=True)
        self.workers[vault].start()
        return {"started": True}

    def confirmations(self, vault, fingerprint):
        """What every member's app has published about the roster, compared with
        ours. Read from the shared courier, so treat every entry as a claim."""
        folder = self.exchange_vault(vault)
        draft = read_json(folder / "draft.json")
        total = int(draft.get("members", 3))
        found = []
        for slot in range(1, total + 1):
            path = folder / f"confirm-{slot}.json"
            if not path.exists():
                found.append({"slot": slot, "confirmed": False, "matches": None, "at": None})
                continue
            try:
                claim = read_json(path)
            except (ValueError, OSError):
                found.append({"slot": slot, "confirmed": False, "matches": False, "at": None})
                continue
            found.append({"slot": slot, "confirmed": True, "at": claim.get("at"),
                          "matches": bool(fingerprint) and claim.get("fingerprint") == fingerprint})
        return found

    def backup(self, vault):
        if self.vault_dir(vault)[1].get("transport") == "hosted":
            return self.hosted.backup(vault)
        member_dir, _ = self.vault_dir(vault)
        card = member_dir / "card"
        words = self.command("backup-create", member_dir, "@pass", card)
        return {"words": words}

    def verify(self, vault, words, card_bytes=None):
        if self.vault_dir(vault)[1].get("transport") == "hosted":
            return self.hosted.verify(vault, words, card_bytes)
        member_dir, _ = self.vault_dir(vault)
        if not isinstance(words, str):
            raise ValueError("Enter the 24 words you wrote down")
        if card_bytes is None:
            raw = (member_dir / "card" / "vault.card").read_bytes()
        else:
            if not isinstance(card_bytes, str):
                raise ValueError("Invalid backup card")
            raw = base64.b64decode(card_bytes, validate=True)
        if len(raw) > 64 * 1024 or not raw.startswith(b"LOKISEAL\x01"):
            raise ValueError("Invalid backup card")
        with tempfile.TemporaryDirectory(prefix=".check-", dir=member_dir) as temp:
            folder = Path(temp)
            card = folder / "card"
            card.mkdir(mode=0o700)
            write_new(card / "vault.card", raw)
            write_new(folder / "words", words.encode())
            self.command("backup-verify", member_dir, "@pass", card, folder / "words",
                         member_dir / "roster.json", self.exchange_vault(vault))
        return {"verified": True}

    def activate(self, vault):
        if self.vault_dir(vault)[1].get("transport") == "hosted":
            return {"final_backup": True}
        member_dir, _ = self.vault_dir(vault)
        self.command("address", member_dir, "@pass", member_dir / "roster.json",
                     self.exchange_vault(vault))
        return {"final_backup": True}

    def finalize_backup(self, vault, words=None):
        if self.vault_dir(vault)[1].get("transport") == "hosted":
            return self.hosted.finalize(vault, words)
        member_dir, _ = self.vault_dir(vault)
        if words is not None and not isinstance(words, str):
            raise ValueError("Enter your 24 backup words")
        with tempfile.TemporaryDirectory(prefix=".finalize-", dir=member_dir) as temp:
            words_file = "-"
            if words:
                words_file = Path(temp) / "words"
                write_new(words_file, words.encode())
            self.command("backup-finalize", member_dir, "@pass", member_dir / "card",
                         member_dir / "final-card", words_file, member_dir / "roster.json",
                         self.exchange_vault(vault))
        return {"created": True}

    def verify_final_backup(self, vault, words, card_bytes):
        if self.vault_dir(vault)[1].get("transport") == "hosted":
            return self.hosted.verify(vault, words, card_bytes, final=True)
        member_dir, _ = self.vault_dir(vault)
        if not isinstance(words, str) or not isinstance(card_bytes, str):
            raise ValueError("Load the final card and enter your 24 words")
        raw = base64.b64decode(card_bytes, validate=True)
        if len(raw) > 64 * 1024 or not raw.startswith(b"LOKISEAL\x01"):
            raise ValueError("Invalid final backup card")
        with tempfile.TemporaryDirectory(prefix=".final-check-", dir=member_dir) as temp:
            folder = Path(temp)
            card = folder / "card"
            card.mkdir(mode=0o700)
            write_new(card / "vault.card", raw)
            words_file = folder / "words"
            write_new(words_file, words.encode())
            self.command("backup-finalize", member_dir, "@pass", member_dir / "card", card,
                         words_file, member_dir / "roster.json", self.exchange_vault(vault))
        marker = member_dir / "final-backup-checked"
        if not marker.exists():
            write_new(marker, b"checked\n")
        _, local = self.vault_dir(vault)
        receipt = bytes.fromhex(self.command("backup-report", member_dir, "@pass",
                                            member_dir / "roster.json"))
        write_replace(self.exchange_vault(vault) / f"{vault}-final-status-{local['slot']}.bin", receipt)
        return {"verified": True}

    def backup_reports(self, vault):
        member_dir = self.data / "vaults" / self.checked_vault_id(vault)
        return json.loads(self.command("backup-reports", member_dir / "roster.json",
                                       self.exchange_vault(vault)))

    def restore_vault(self, name, words, card_bytes):
        profile = self.require_profile()
        if not isinstance(name, str) or not 1 <= len(name.strip().encode()) <= 80:
            raise ValueError("Enter a vault name of 1 to 80 UTF-8 bytes")
        if not isinstance(words, str) or not isinstance(card_bytes, str):
            raise ValueError("Enter your 24 words and load your final recovery card")
        raw = base64.b64decode(card_bytes, validate=True)
        if len(raw) > 64 * 1024 or not raw.startswith(b"LOKISEAL\x01"):
            raise ValueError("Invalid final recovery card")
        vaults = self.data / "vaults"
        vaults.mkdir(mode=0o700, exist_ok=True)
        restored = Path(tempfile.mkdtemp(prefix=".restore-", dir=vaults))
        try:
            with tempfile.TemporaryDirectory(prefix=".input-", dir=restored) as input_dir:
                input_dir = Path(input_dir)
                card = input_dir / "card"
                card.mkdir(mode=0o700)
                write_new(card / "vault.card", raw)
                words_file = input_dir / "words"
                write_new(words_file, words.encode())
                restored_address = self.command("restore", restored, "@pass", card, words_file)
            if not (restored / "roster.json").is_file() or not (restored / "secrets" / "activation.sealed").is_file():
                raise ValueError("Use the final recovery card; the first card cannot restore an active vault")
            roster = read_json(restored / "roster.json")
            vault = roster.get("vault")
            self.exchange_vault(vault)
            own = json.loads(self.command("identity-public", restored, "@pass"))
            members = roster.get("members")
            if not isinstance(members, list) or own not in members:
                raise ValueError("Restored identity is not in the certified roster")
            address = self.command("address", restored, "@pass")
            if address != restored_address:
                raise ValueError("Restored address differs from the recovery card")
            self.command("validate-roster", restored, "@pass", restored / "roster.json")
            destination = vaults / vault
            if destination.exists():
                raise ValueError("This profile already has a membership for this vault")
            final_card = restored / "final-card"
            final_card.mkdir(mode=0o700)
            write_new(final_card / "vault.card", raw)
            write_new(restored / "final-backup-checked", b"checked\n")
            write_new(restored / "membership.json", json.dumps({
                "vault": vault, "slot": own["id"], "name": name.strip(),
                "profile": profile["id"], "threshold": roster["threshold"],
                "members": len(members),
            }).encode())
            os.rename(restored, destination)
            return {"vault": vault, "slot": own["id"],
                    **({"address": address} if len(members) in (3, 4) else {})}
        finally:
            if restored.exists():
                shutil.rmtree(restored)

    def address(self, vault):
        member_dir, local = self.vault_dir(vault)
        if not (member_dir / "final-backup-checked").is_file():
            raise ValueError("Check your final backup card before showing the receive address")
        if local.get("members") not in (3, 4):
            raise ValueError("Unsupported vault policy")
        if local.get("transport") == "hosted" and not (member_dir / "secrets" / "activation.sealed").is_file():
            raise ValueError("Hosted payment activation is pending")
        return self.command("address", member_dir, "@pass")

    def balance(self, vault):
        member_dir, _ = self.vault_dir(vault)
        result = json.loads(self.command("balance", member_dir, "@pass", member_dir / "roster.json",
                                         binary=PAYMENT, timeout=120))
        if result.get("vault") != vault:
            raise ValueError("Chain scan returned another vault")
        self.scan_height[vault] = result.get("height")
        return result

    def fund_vault(self, vault, request_id):
        return fund_member(self, vault, request_id)

    def prepare_payment(self, vault, recipient, amount_zat, memo, pair=None):
        member_dir, local = self.vault_dir(vault)
        if not (member_dir / "final-backup-checked").is_file():
            raise ValueError("Vault is not active")
        if local.get("members") not in (3, 4):
            raise ValueError("Unsupported vault policy")
        if local.get("transport") == "hosted" and not (member_dir / "secrets" / "activation.sealed").is_file():
            raise ValueError("Hosted payment activation is pending")
        if not isinstance(recipient, str) or not recipient.strip():
            raise ValueError("Enter a recipient address")
        if not isinstance(amount_zat, str) or not 1 <= len(amount_zat) <= 20 \
                or not amount_zat.isascii() or not amount_zat.isdigit() or int(amount_zat) <= 0:
            raise ValueError("Enter a positive amount in zat")
        if not isinstance(memo, str) or not memo or len(memo.encode()) > 512:
            raise ValueError("Enter a memo of 1 to 512 bytes")
        labels = "ABCD"[:local["members"]]
        pairs = tuple(a + b for i, a in enumerate(labels) for b in labels[i + 1:])
        if pair is None:
            # The first pair that includes this member: no dropdown, same answer every time.
            pair = next((item for item in pairs
                         if chr(ord("A") + local["slot"] - 1) in item), None)
        if pair not in pairs:
            raise ValueError("Choose two members of this vault")
        drafts = member_dir / "payments"
        drafts.mkdir(mode=0o700, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix="payment-", dir=drafts))
        try:
            self.command("prepare", member_dir, "@pass", member_dir / "roster.json", work,
                         recipient.strip(), amount_zat, memo, pair, binary=PAYMENT, timeout=120)
            manifest = read_json(work / "payment.json")
            if manifest.get("vault") != vault or manifest.get("pair") != [ord(c) - ord("A") + 1 for c in pair] \
                    or manifest.get("amount_zat") != int(amount_zat):
                raise ValueError("Payment draft does not match this vault and request")
            attempt = manifest.get("attempt")
            if not isinstance(attempt, str) or not re.fullmatch(r"[0-9a-f]{64}", attempt):
                raise ValueError("Payment draft has no valid attempt ID")
            target = drafts / attempt
            if target.exists():
                raise ValueError("Payment attempt already exists")
            work.rename(target)
            work = target
            self.payment_status(work, "draft")
            return {"status": "draft_only", "payment": manifest["payment"],
                    "attempt": attempt,
                    "recipient": recipient.strip(), "amount_zat": str(manifest["amount_zat"]),
                    "fee_zat": str(manifest["fee_zat"]), "change_zat": str(manifest["change_zat"]),
                    "expiry_height": manifest["expiry_height"], "pair": manifest["pair"]}
        except Exception:
            shutil.rmtree(work)
            raise

    def payment(self, vault, attempt):
        member_dir, local = self.vault_dir(vault)
        if local.get("threshold", 2) != 2 or local.get("members") not in (3, 4):
            raise ValueError("Unsupported vault policy")
        if not (member_dir / "final-backup-checked").is_file():
            raise ValueError("Vault is not active")
        if not isinstance(attempt, str) or not re.fullmatch(r"[0-9a-f]{64}", attempt):
            raise ValueError("Invalid payment attempt")
        for work in (member_dir / "payments").glob("*/payment.json"):
            manifest = read_json(work)
            if manifest.get("attempt") == attempt and manifest.get("vault") == vault:
                if manifest.get("pair") not in ([a, b] for a in range(1, local["members"] + 1) for b in range(a + 1, local["members"] + 1)):
                    raise ValueError("Invalid payment pair")
                return member_dir, local, work.parent, manifest
        raise ValueError("Payment is not in this member's vault")

    def payments(self, vault):
        member_dir, local = self.vault_dir(vault)
        if not (member_dir / "final-backup-checked").is_file():
            raise ValueError("Vault is not active")
        items = []
        for path in sorted((member_dir / "payments").glob("*/payment.json")):
            manifest = read_json(path)
            attempt = manifest.get("attempt")
            if manifest.get("vault") != vault or not isinstance(attempt, str) \
                    or not re.fullmatch(r"[0-9a-f]{64}", attempt):
                continue
            status = self.payment_phase(path.parent)
            phase = status["phase"]
            ready_to_send = False
            is_signer = local["slot"] in manifest["pair"]
            if phase in ("published", "received", "commitments", "package", "approved") \
                    and (not is_signer or phase == "approved"):
                try:
                    _, _, _, checked = self.payment_command("finish-check", vault, attempt, timeout=30)
                    expected = r"\baggregate verified payment=" + re.escape(manifest["payment"]) + \
                               r" sighash=[0-9a-f]{64}\b"
                    if not re.search(expected, checked):
                        raise ValueError("Verified aggregate differs from this payment")
                    ready_to_send = True
                except ValueError as error:
                    missing_early_package = phase in ("published", "received", "commitments", "package") \
                        and "No such file or directory (os error 2)" in str(error)
                    if not (PAYMENT_WAITING.search(str(error)) or missing_early_package):
                        raise
            if phase == "confirmed":
                # shortcut: recheck each confirmed payment until the wallet has an indexed chain store.
                try:
                    _, _, _, output = self.payment_command("verify", vault, attempt, status["txid"])
                    if not re.search(r"\bverified mined txid=" + re.escape(status["txid"]) +
                                     r" confirmations=[1-9][0-9]*\b", output):
                        phase = "confirmation_needs_recheck"
                except (KeyError, ValueError, subprocess.TimeoutExpired):
                    phase = "confirmation_needs_recheck"
                if phase == "confirmation_needs_recheck":
                    self.payment_status(path.parent, phase, status.get("txid"))
            items.append({"attempt": attempt, "payment": manifest.get("payment"),
                          "pair": manifest.get("pair"), "phase": phase,
                          "ready_to_send": ready_to_send,
                          **({"txid": status["txid"]} if status.get("txid") else {})})
        relay_ready, relay_detail = self.payment_readiness()
        return {"payments": items,
                "readiness": {"relay_ready": relay_ready, "relay_detail": relay_detail,
                              "scan_height": self.scan_height.get(vault)}}

    def payment_phase(self, work):
        state = work / "payment-status.json"
        return read_json(state) if state.is_file() else {"phase": "received"}

    def payment_readiness(self):
        """Whether this device can reach the other members for signing. The payment
        tool answers it; a build without relay support cannot send or receive."""
        ready = "Payment build supports relay delivery. Check the relay connection above."
        if self.relay_payment_ready:
            return True, ready
        try:
            if self.command("features", binary=PAYMENT, timeout=5) != "relay-backed-signing=1":
                return False, "This payment build cannot reach the other members."
        except ValueError as error:
            return False, str(error)
        self.relay_payment_ready = True
        return True, ready

    def relay_args(self, vault):
        member_dir, local = self.vault_dir(vault)
        if self.transport == "hosted" or local.get("transport") == "hosted":
            raise ValueError("Hosted vaults attach to relays automatically")
        if local.get("threshold", 2) != 2 or local.get("members") not in (3, 4) \
                or not (member_dir / "final-backup-checked").is_file():
            raise ValueError("Relay setup requires an active 2-of-3 or 2-of-4 vault")
        return member_dir, local, ("--member-root", member_dir, "--passphrase-file", "@pass",
                                   "--roster", member_dir / "roster.json")

    def relay_provision(self, vault, bundle_path):
        member_dir, _, common = self.relay_args(vault)
        if not isinstance(bundle_path, str) or not Path(bundle_path).is_absolute():
            raise ValueError("Choose an absolute path to this member's relay kit")
        bundle = Path(bundle_path)
        manifests, capabilities = bundle / "manifests", bundle / "capabilities"
        if not manifests.is_dir() or not capabilities.is_dir():
            raise ValueError("Relay kit needs manifests and capabilities directories")
        write_replace(member_dir / "relay-setup.json", json.dumps({
            "mode": "operator", "phase": "waiting",
            "detail": "Provisioning operator-provided relays. Retry the same kit after an interruption."}).encode())
        self.command("provision", *common, "--relay-manifest", manifests,
                     "--provision-capability-files", capabilities, binary=RELAY, timeout=120)
        return {"provisioned": True}

    def relay_export(self, vault):
        member_dir, local, common = self.relay_args(vault)
        with tempfile.TemporaryDirectory(prefix="relay-export-", dir=member_dir) as temporary:
            directory = Path(temporary)
            self.command("export-config", *common, "--courier-directory", directory,
                         binary=RELAY, timeout=120)
            files = []
            for path in directory.iterdir():
                match = re.fullmatch(re.escape(vault) + rf"-relay-config-{local['slot']}-(\d+)-(\d+)\.bin",
                                     path.name)
                if not match or not path.is_file() or path.is_symlink():
                    raise ValueError("Relay export contained an unexpected file")
                wire = path.read_bytes()
                if not 0 < len(wire) <= 64 * 1024:
                    raise ValueError("Relay config file has an invalid size")
                files.append({"peer": int(match.group(1)), "name": path.name,
                              "data": base64.b64encode(wire).decode()})
            files.sort(key=lambda item: item["peer"])
            if [item["peer"] for item in files] != [slot for slot in range(1, local["members"] + 1)
                                                    if slot != local["slot"]]:
                raise ValueError("Relay export did not contain one file for each peer")
            return {"files": files}

    def relay_import(self, vault, encoded_wire, filename):
        member_dir, local, common = self.relay_args(vault)
        if not isinstance(filename, str) or len(filename) > 128:
            raise ValueError("Invalid relay config file")
        named = re.fullmatch(re.escape(vault) + rf"-relay-config-(\d+)-{local['slot']}-(\d+)\.bin",
                             filename)
        if not named or int(named.group(1)) not in range(1, local["members"] + 1) \
                or int(named.group(1)) == local["slot"] or int(named.group(2)) < 1:
            raise ValueError("Invalid relay config file")
        if not isinstance(encoded_wire, str) or not 0 < len(encoded_wire) <= 88 * 1024:
            raise ValueError("Invalid relay config file")
        try:
            wire = base64.b64decode(encoded_wire, validate=True)
        except (ValueError, binascii.Error) as error:
            raise ValueError("Invalid relay config file") from error
        if not 0 < len(wire) <= 64 * 1024:
            raise ValueError("Invalid relay config file")
        with tempfile.TemporaryDirectory(prefix="relay-import-", dir=member_dir) as temporary:
            path = Path(temporary) / filename
            write_new(path, wire)
            output = self.command("import-config", *common, "--courier-file", path,
                                  binary=RELAY, timeout=120)
        match = re.search(r"\bimported owner=(\d+) revision=\d+ digest=[0-9a-f]{64}\b", output)
        if not match or int(match.group(1)) != int(named.group(1)):
            raise ValueError("Relay did not confirm the peer config")
        return {"imported_from": int(match.group(1))}

    def relay_connection_status(self, vault):
        member_dir, local, common = self.relay_args(vault)
        report = self.command("readiness", *common, binary=RELAY, timeout=40)
        match = re.fullmatch(r"inboxes=(\d+) peers=(\d+) live=(\d+) routable=([01])", report.strip())
        if not match:
            raise ValueError("Relay readiness returned an unexpected result")
        inboxes, peers, live, routable = map(int, match.groups())
        configured = inboxes == 3 and peers == local["members"] - 1 and routable == 1
        state_path = member_dir / "relay-setup.json"
        saved = read_json(state_path) if state_path.is_file() else {}
        if saved.get("mode") == "operator":
            ready = configured and live >= 2
            write_replace(state_path, json.dumps({"mode": "operator", "phase": "ready" if ready else "waiting",
                "detail": "Operator-provided relays are connected." if ready else
                          "Check the operator relay connection after importing every peer config."}).encode())
        return {"configured": configured, "reachable": configured and live >= 2,
                "inboxes": inboxes, "peers": peers, "live_relays": live}

    def payment_status(self, work, phase, txid=None):
        # shortcut: this file is UI progress only; custody state remains in the Rust signer and chain.
        target = work / "payment-status.json"
        temporary = work / (".payment-status-" + secrets.token_hex(8))
        try:
            write_new(temporary, json.dumps({"phase": phase, **({"txid": txid} if txid else {})}).encode())
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)

    def payment_command(self, action, vault, attempt, *extra, timeout=120):
        member_dir, local, work, manifest = self.payment(vault, attempt)
        if not self.relay_payment_ready:
            if self.command("features", binary=PAYMENT, timeout=5) != "relay-backed-signing=1":
                raise ValueError("Build payment commands with --features relay-communication")
            self.relay_payment_ready = True
        output = self.command(action, member_dir, "@pass", member_dir / "roster.json", work,
                              *extra, binary=PAYMENT, timeout=timeout)
        return local, work, manifest, output

    def publish_payment(self, vault, attempt):
        member_dir, _, work, manifest = self.payment(vault, attempt)
        output = self.command("send-proposal", "--member-root", member_dir,
                              "--passphrase-file", "@pass", "--roster", member_dir / "roster.json",
                              "--proposal-file", work / "payment.json", binary=RELAY, timeout=120)
        if f"proposal={manifest['payment']} attempt={attempt}" not in output:
            raise ValueError("Relay did not accept this payment proposal")
        self.payment_status(work, "queued_for_delivery")
        return {"phase": "queued_for_delivery"}

    def sync_payments(self, vault):
        member_dir, local = self.vault_dir(vault)
        if local.get("threshold", 2) != 2 or local.get("members") not in (3, 4) \
                or not (member_dir / "final-backup-checked").is_file():
            raise ValueError("Relay payments require an active supported vault")
        if local.get("transport") == "hosted" and not (member_dir / "secrets" / "activation.sealed").is_file():
            raise ValueError("Hosted payment activation is still pending")
        roster = member_dir / "roster.json"
        common = ("--member-root", member_dir, "--passphrase-file", "@pass", "--roster", roster)

        def relay(action, *args):
            return self.command(action, *common, *args, binary=RELAY, timeout=120)

        works = sorted((member_dir / "payments").glob("*/payment.json"))
        proposals = {}
        for path in works:
            work = path.parent
            status = work / "payment-status.json"
            if status.is_file() and read_json(status).get("phase") == "queued_for_delivery":
                attempt = work.name
                published = relay("send-proposal", "--proposal-file", path)
                match = re.search(r"\brequest message=([0-9a-f]{64})\b", published)
                if not match:
                    raise ValueError("Relay did not identify the proposal")
                proposals[attempt] = match.group(1)
        relay("upload")
        relay("poll", "--once")
        relay("import-proposals", "--payments-dir", member_dir / "payments")

        works = sorted((member_dir / "payments").glob("*/payment.json"))
        approvals = {}
        for path in works:
            attempt = path.parent.name
            state = path.parent / "payment-status.json"
            if state.is_file() and read_json(state).get("phase") == "approval_pending_delivery":
                try:
                    self.payment_command("resend", vault, attempt)
                except ValueError:
                    # A consumed attempt with no saved share must not stall other payments.
                    self.payment_status(path.parent, "approval_interrupted")
                    continue
                approvals[attempt] = []
            _, work, _, output = self.payment_command("local-wires", vault, attempt)
            wires = json.loads(output)["wires"]
            for wire in wires:
                sent = relay("send-signing", "--payload-file", work / "mailbox" / wire,
                             "--attempt", attempt)
                if attempt in approvals:
                    match = re.search(r"\brequest message=([0-9a-f]{64})\b", sent)
                    if not match:
                        raise ValueError("Relay did not identify the saved approval message")
                    approvals[attempt].append(match.group(1))
        relay("upload")
        relay("poll", "--once")
        for path in works:
            relay("export-signing", "--work-dir", path.parent, "--attempt", path.parent.name)

        if proposals or approvals:
            report = relay("status")
            lines = {match.group(1): line for line in report.splitlines()
                     if (match := re.search(r"^message .*\bid=([0-9a-f]{64})\b", line))}
            for attempt, message in proposals.items():
                if re.search(r"\bstored_whole=1\b", lines.get(message, "")):
                    self.payment_status(member_dir / "payments" / attempt, "published")
            for attempt, messages in approvals.items():
                if messages and all(re.search(r"\bstored_whole=1\b", lines.get(message, ""))
                                    for message in messages):
                    self.payment_status(member_dir / "payments" / attempt, "approved")
        return self.payments(vault)

    def commit_payment(self, vault, attempt):
        _, local, _, manifest = self.payment(vault, attempt)
        if local["slot"] not in manifest["pair"]:
            raise ValueError("This member is not in the selected signing pair")
        if self.balance(vault)["height"] >= manifest["expiry_height"]:
            raise ValueError("This payment has expired on this member's chain view")
        _, work, _, _ = self.payment_command("commit", vault, attempt)
        self.payment_status(work, "commitments")
        return {"phase": "commitments"}

    def package_payment(self, vault, attempt):
        _, local, _, manifest = self.payment(vault, attempt)
        if local["slot"] != manifest["pair"][0]:
            raise ValueError("Only the first selected signer can build the package")
        _, work, _, _ = self.payment_command("package", vault, attempt)
        self.payment_status(work, "package")
        return {"phase": "package"}

    def review_payment(self, vault, attempt):
        _, _, manifest, output = self.payment_command("review", vault, attempt)
        review = json.loads(output)
        if review.get("vault") != vault or review.get("payment") != manifest.get("payment") \
                or review.get("attempt") != attempt or review.get("pair") != manifest.get("pair") \
                or review.get("authorization_required") is not True:
            raise ValueError("Verified review differs from this payment")
        return review

    def approve_payment(self, vault, attempt, review_token):
        if not isinstance(review_token, str) or not re.fullmatch(r"[0-9a-f]{64}", review_token):
            raise ValueError("Review this exact payment before approving")
        _, work, _, _ = self.payment_command("approve-reviewed", vault, attempt, review_token)
        self.payment_status(work, "approval_pending_delivery")
        return {"phase": "approval_pending_delivery"}

    def resend_payment(self, vault, attempt):
        _, local, work, manifest = self.payment(vault, attempt)
        if local["slot"] not in manifest["pair"]:
            raise ValueError("Only a selected signer can retry saved signing messages")
        self.payment_command("resend", vault, attempt)
        self.payment_status(work, "approval_pending_delivery")
        return {"phase": "approval_pending_delivery"}

    def finish_payment(self, vault, attempt):
        _, work, _, output = self.payment_command("finish", vault, attempt, timeout=600)
        txid = re.search(r"\bbroadcast txid=([0-9a-f]{64})\b", output)
        if not txid:
            raise ValueError("Finisher did not return a broadcast transaction ID")
        self.payment_status(work, "broadcast", txid.group(1))
        return {"phase": "broadcast", "txid": txid.group(1)}

    def verify_payment(self, vault, attempt, txid=None):
        if txid is None:
            txid = self.payment_phase(self.payment(vault, attempt)[2]).get("txid")
        if not isinstance(txid, str) or not re.fullmatch(r"[0-9a-f]{64}", txid):
            raise ValueError("Enter the broadcast transaction ID")
        _, work, _, output = self.payment_command("verify", vault, attempt, txid, timeout=120)
        match = re.search(r"\bverified mined txid=([0-9a-f]{64}) confirmations=([1-9][0-9]*)\b", output)
        if not match or match.group(1) != txid:
            raise ValueError("Chain verification did not confirm this payment")
        self.payment_status(work, "confirmed", txid)
        return {"phase": "confirmed", "txid": txid, "confirmations": int(match.group(2))}

    def advance_payment(self, vault, attempt):
        """Carry out every payment step that is possible now and needs no human
        judgement, then report where the payment stands. Approving is never such a
        step: it is this member's decision about the exact transaction bytes, so
        neither approve_payment nor an accepted review is ever reached from here."""
        _, local, work, manifest = self.payment(vault, attempt)
        slot, pair, did = local["slot"], manifest["pair"], []
        while True:
            state = self.payment_phase(work)
            phase = state["phase"]
            if phase == "confirmed" and not did:
                self.payments(vault)
                state = self.payment_phase(work)
                phase = state["phase"]
            if phase in ("published", "received") and slot in pair:
                step, run = "commit", self.commit_payment
            elif phase == "commitments" and slot == pair[0]:
                step, run = "package", self.package_payment
            elif phase in ("approval_pending_delivery", "approval_interrupted") and slot in pair:
                step, run = "resend", self.resend_payment
            elif phase in ("broadcast", "confirmation_needs_recheck") and state.get("txid"):
                step, run = "verify", self.verify_payment
            else:
                if phase in ("published", "received", "commitments", "package", "approved"):
                    _, _, _, found = self.payment_command("find-mined", vault, attempt, timeout=30)
                    mined = re.search(r"^mined txid=([0-9a-f]{64})$", found.strip())
                    if mined:
                        self.verify_payment(vault, attempt, mined.group(1))
                        did.append("verify")
                        return {"phase": "confirmed", "did": did}
                return {"phase": phase, "did": did}
            if step in did:
                return {"phase": phase, "did": did}
            try:
                run(vault, attempt)
            except ValueError as error:
                if not PAYMENT_WAITING.search(str(error)):
                    raise
                return {"phase": phase, "did": did}
            did.append(step)

    def status(self, vault=None):
        if not (self.data / "profile" / "profile.sealed").exists():
            return {"phase": "new_profile", "network": "regtest"}
        if not self.profile_data:
            return {"phase": "locked", "network": "regtest"}
        vaults = self.vaults()
        if vault is None:
            return {"phase": "home", "network": "regtest", "profile": self.profile_data,
                    "vaults": vaults, "relay_network": self.relay_network_status()}
        member_dir, local = self.vault_dir(vault)
        if local.get("transport") == "hosted":
            return {**self.hosted.status(vault), "vaults": vaults}
        active = (member_dir / "secrets" / "activation.sealed").is_file()
        if active:
            roster_path = member_dir / "roster.json"
            saved = read_json(roster_path)
            members = saved.get("members")
            total = local.get("members", 3)
            slot = local.get("slot")
            if saved.get("vault") != vault or saved.get("threshold") != local.get("threshold", 2) \
                    or local.get("threshold", 2) != 2 or type(total) is not int or total not in (3, 4) \
                    or not isinstance(members, list) or len(members) != total \
                    or any(not isinstance(member, dict) for member in members) \
                    or [member.get("id") for member in members] != list(range(1, total + 1)) \
                    or type(slot) is not int or slot not in range(1, total + 1):
                raise ValueError("Local roster differs from vault membership")
            roster = {"members": members,
                      "fingerprint": self.command("validate-roster", member_dir, "@pass", roster_path)}
        else:
            roster = self.roster(vault)
        state = {"phase": "waiting_for_members", "network": "regtest", "name": local["name"],
                 "slot": local["slot"], "vault": local["vault"], "members": len(roster["members"]),
                 "threshold": local.get("threshold", 2), "total_members": local.get("members", 3),
                 "fingerprint": roster["fingerprint"], "error": self.setup_errors.get(vault),
                 "profile": self.profile_data, "vaults": vaults}
        state["relay_setup"] = self.relay_status(vault)
        state["funding"] = funding_status(self, vault)
        state["account_linked"] = (member_dir / "secrets" / "account-link.sealed").exists()
        self.ensure_sync(vault)
        state["transport_error"] = self.transport_errors.get(vault)
        if local["slot"] == 1 and (member_dir / "invites.json").exists():
            # One row per other member: the code to hand over, whether that
            # member's app has published an identity, and where they reach this
            # courier. "Joined" is only ever the published identity.
            joined = {member["id"] for member in roster["members"]}
            codes = read_json(member_dir / "invites.json")
            state["invites"] = [{"slot": slot, "code": code, "joined": slot in joined,
                                 "origin": decoded(code).get("url")}
                                for slot, code in enumerate(codes, 2)]
            draft = self.exchange_vault(vault) / "draft.json"
            if draft.is_file():
                state["invites_expire_at"] = int(read_json(draft)["expires_at"])
        if roster["fingerprint"]:
            state["phase"] = "compare_roster"
            # who else has published a roster answer, and whether it agrees
            try:
                state["confirmations"] = self.confirmations(vault, roster["fingerprint"])
            except (OSError, ValueError):
                state["confirmations"] = []
        if state["account_linked"]:
            try:
                state["account_ak"] = self.account_link(vault)["account_ak"]
            except (ValueError, subprocess.TimeoutExpired, OSError):
                state["account_link_error"] = "Optional account link could not be verified"
        if (member_dir / "secrets" / "vault.sealed").exists():
            state["phase"] = "back_up"
        elif vault in self.workers and self.workers[vault].is_alive():
            state["phase"] = "creating_keys"
        if (self.exchange_vault(local["vault"]) / f"{local['vault']}-backup-{local['slot']}.bin").exists():
            state["phase"] = "waiting_for_backups"
            state["backup_checks_received"] = sum(
                (self.exchange_vault(vault) / f"{vault}-backup-{slot}.bin").is_file()
                for slot in range(1, local["members"] + 1))
        if active:
            state["phase"] = "active" if (member_dir / "final-backup-checked").is_file() else "final_backup"
            state["final_card_created"] = (member_dir / "final-card" / "vault.card").is_file()
            state["final_card_needs_words"] = not (member_dir / "secrets" / "backup-words.sealed").is_file()
            state["backups"] = self.backup_reports(vault)
        if self.setup_errors.get(vault):
            state["phase"] = "stopped"
        return state

    def close(self):
        if self.hosted:
            self.hosted.stop()
        self.relay_stop.set()
        self.relay_monitor.join(timeout=5)
        for worker in self.relay_jobs.values():
            worker.join(timeout=5)
        self.sync_stop.set()
        self.process_lock.close()


def make_setup_server(wallet, port):
    """The creator's setup courier, for the other members' apps only.

    It serves one thing: the opaque files of one open vault setup, to callers
    holding a token claimed with one of that vault's invites. It has no route
    to a profile, a passphrase, a key or the signer's private app token, and it
    is a separate listener from the signer app on its own port.

    It is bound to the loopback interface. Reaching it from another device means
    putting an HTTPS front with a certificate that device trusts in front of
    this port and passing that address as --invite-origin; a plain LAN address
    is refused when the invite is made, because the invite token travels on
    every request."""

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass

        def reply(self, status, value, raw=None):
            body = raw if raw is not None else json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/octet-stream" if raw is not None
                             else "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def route(self, kinds):
            parts = urlsplit(self.path).path.split("/")
            if len(parts) < 4 or len(parts) > 5 or parts[0] or parts[1] != "setup" \
                    or parts[3] not in kinds:
                raise LookupError("Not found")
            return parts[2], parts[3], parts[4] if len(parts) == 5 else None

        def body(self, limit):
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= limit:
                raise ValueError("Invalid request size")
            return self.rfile.read(size)

        def answer(self, run):
            try:
                self.reply(200, *run())
            except LookupError as error:
                self.reply(404, {"error": str(error)})
            except ValueError as error:
                self.reply(400, {"error": str(error)})
            except Exception:
                # Never pass an unexpected internal failure to a remote caller.
                self.reply(400, {"error": "The setup courier could not serve that request"})

        def slot(self, vault):
            return wallet.courier_slot(vault, self.headers.get("X-Loki-Setup", ""))

        def do_POST(self):
            def run():
                vault, _, name = self.route(("claim",))
                if name:
                    raise LookupError("Not found")
                value = json.loads(self.body(4096))
                return (wallet.claim_invite(vault, value.get("slot"), value.get("secret"),
                                            value.get("token")),)
            self.answer(run)

        def do_GET(self):
            def run():
                vault, _, name = self.route(("files",))
                self.slot(vault)
                if name is None:
                    return ({"files": wallet.courier_list(vault)},)
                return (None, wallet.courier_read(vault, name))
            self.answer(run)

        def do_PUT(self):
            def run():
                vault, _, name = self.route(("files",))
                if name is None:
                    raise LookupError("Not found")
                return (wallet.courier_publish(vault, self.slot(vault), name,
                                               self.body(COURIER_LIMIT)),)
            self.answer(run)

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


FONTS = ("/fonts/geist.woff2", "/fonts/geist-mono.woff2", "/fonts/young-serif.woff2")


def make_signer_server(wallet, port, dashboard_port=None):
    token = secrets.token_urlsafe(32)
    dashboard_origin = f"http://127.0.0.1:{dashboard_port}" if dashboard_port else None
    sessions = SignerSessions(dashboard_origin)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def trusted_host(self):
            return self.headers.get("Host") == f"127.0.0.1:{self.server.server_address[1]}"

        def dashboard_origin(self):
            return dashboard_origin is not None and self.headers.get("Origin") == dashboard_origin

        def reply(self, status, value):
            body = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            if self.path.startswith("/api/session/") and self.dashboard_origin():
                self.send_header("Access-Control-Allow-Origin", dashboard_origin)
                self.send_header("Vary", "Origin")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def authorized(self):
            return secrets.compare_digest(self.headers.get("X-Loki-Token", ""), token)

        def do_OPTIONS(self):
            if not self.trusted_host() or not self.path.startswith("/api/session/") or not self.dashboard_origin():
                return self.reply(403, {"error": "Unauthorized"})
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", dashboard_origin)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Loki-Session")
            self.send_header("Access-Control-Max-Age", "300")
            self.end_headers()

        def do_GET(self):
            if not self.trusted_host():
                return self.reply(403, {"error": "Unauthorized host"})
            path, _, query = self.path.partition("?")
            if path == "/":
                page = (HERE / "index.html").read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; connect-src 'self'")
                self.end_headers()
                self.wfile.write(page)
                return
            if path == "/app.js":
                self.send_response(200)
                self.send_header("Content-Type", "text/javascript; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write((HERE / "app.js").read_bytes())
                return
            if path == "/app.css":
                self.send_response(200)
                self.send_header("Content-Type", "text/css; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write((HERE / "app.css").read_bytes())
                return
            if path in FONTS:
                self.send_response(200)
                self.send_header("Content-Type", "font/woff2")
                self.send_header("Cache-Control", "max-age=86400")
                self.end_headers()
                self.wfile.write((HERE / path.lstrip("/")).read_bytes())
                return
            if path == "/api/session/vaults":
                key = self.headers.get("X-Loki-Session", "")
                if not self.dashboard_origin() or not sessions.valid(key, dashboard_origin):
                    return self.reply(403, {"error": "Connect your signer"})
                try:
                    with wallet.lock:
                        profile = wallet.require_profile()
                        vaults = []
                        for item in wallet.vaults():
                            state = wallet.status(item["vault"])
                            vaults.append({"vault": item["vault"], "name": item["name"], "slot": item["slot"],
                                           "phase": state["phase"],
                                           **{key: state[key] for key in ("total_members", "transport", "handoff", "missing_slots", "error") if key in state},
                                           **({"funding": state["funding"]} if "funding" in state else {}),
                                           **({"relay_setup": state["relay_setup"]} if "relay_setup" in state else {})})
                    return self.reply(200, {"profile": profile["name"], "vaults": vaults,
                                            "relay_network": wallet.relay_network_status()})
                except Exception as error:
                    return self.reply(400, {"error": str(error)})
            if not self.authorized():
                return self.reply(403, {"error": "Open the private local app link"})
            try:
                if path == "/api/session/pending":
                    return self.reply(200, {"requests": sessions.pending()})
                if path == "/api/session/actions":
                    return self.reply(200, {"actions": sessions.pending_actions()})
                values = parse_qs(query)
                vault = values.get("vault", [None])[0]
                if path == "/api/status":
                    return self.reply(200, wallet.status(vault))
                if path == "/api/payments":
                    with wallet.lock:
                        payments = wallet.payments(vault)
                    return self.reply(200, payments)
                if path == "/api/card":
                    member_dir, _ = wallet.vault_dir(vault)
                    card = (member_dir / "card" / "vault.card").read_bytes()
                    return self.reply(200, {"card": base64.b64encode(card).decode()})
                if path == "/api/final-card":
                    member_dir, _ = wallet.vault_dir(vault)
                    card = (member_dir / "final-card" / "vault.card").read_bytes()
                    return self.reply(200, {"card": base64.b64encode(card).decode()})
            except Exception as error:
                return self.reply(400, {"error": str(error)})
            self.reply(404, {"error": "Not found"})

        def do_POST(self):
            if not self.trusted_host():
                return self.reply(403, {"error": "Unauthorized host"})
            is_dashboard = self.path in ("/api/session/request", "/api/session/poll",
                                         "/api/session/disconnect", "/api/session/action",
                                         "/api/session/action-poll", "/api/session/fund",
                                         "/api/session/relay-setup-all")
            if is_dashboard:
                if not self.dashboard_origin():
                    return self.reply(403, {"error": "Unauthorized dashboard origin"})
            elif not self.authorized() or self.headers.get("Origin") not in (
                None, f"http://127.0.0.1:{self.server.server_address[1]}"):
                return self.reply(403, {"error": "Unauthorized"})
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= (4096 if is_dashboard else 128 * 1024):
                    raise ValueError("Invalid request size")
                value = json.loads(self.rfile.read(size))
                if is_dashboard:
                    if self.path == "/api/session/request":
                        return self.reply(200, {"request": sessions.request(dashboard_origin)})
                    key = self.headers.get("X-Loki-Session", "") or value.get("request", "")
                    if self.path == "/api/session/poll":
                        return self.reply(200, {"state": sessions.poll(key)})
                    if self.path == "/api/session/action":
                        return self.reply(200, {"action": sessions.request_action(key, dashboard_origin, value)})
                    if self.path == "/api/session/action-poll":
                        return self.reply(200, sessions.poll_action(key, dashboard_origin, value.get("action")))
                    if self.path in ("/api/session/fund", "/api/session/relay-setup-all"):
                        if not sessions.valid(key, dashboard_origin):
                            return self.reply(403, {"error": "Connect your signer"})
                        with wallet.lock:
                            if not sessions.valid(key, dashboard_origin):
                                return self.reply(403, {"error": "Connect your signer"})
                            result = wallet.setup_all_relays() if self.path == "/api/session/relay-setup-all" \
                                else wallet.fund_vault(value.get("vault"), value.get("request_id"))
                            return self.reply(200, result)
                    sessions.disconnect(key, dashboard_origin)
                    return self.reply(200, {"disconnected": True})
                if self.path == "/api/lock" and wallet.hosted:
                    wallet.hosted.stop()
                with wallet.lock:
                    if self.path == "/api/session/approve":
                        wallet.require_profile()
                        sessions.approve(value.get("request"))
                        return self.reply(200, {"approved": True})
                    if self.path == "/api/session/reject":
                        sessions.reject(value.get("request"))
                        return self.reply(200, {"rejected": True})
                    if self.path == "/api/session/action-approve":
                        wallet.require_profile()
                        action = value.get("action")
                        details = sessions.take_action(action)
                        try:
                            if details["kind"] == "relay-setup":
                                _, membership = wallet.vault_dir(details["vault"])
                                if membership["name"] != details["name"]:
                                    raise ValueError("Vault name changed; request relay setup again")
                                result = wallet.setup_relays(details["vault"])
                            else:
                                result = wallet.create(details["name"], details["members"])
                        except Exception as error:
                            sessions.finish_action(action, error=str(error))
                            raise
                        sessions.finish_action(action, result={"vault": result["vault"]})
                        return self.reply(200, {"created": result["vault"]})
                    if self.path == "/api/session/action-reject":
                        sessions.reject_action(value.get("action"))
                        return self.reply(200, {"rejected": True})
                    routes = {
                        "/api/profile-create": lambda: wallet.create_profile(value.get("name"), value.get("passphrase")),
                        "/api/unlock": lambda: wallet.unlock(value.get("passphrase")),
                        "/api/lock": wallet.lock_profile,
                        "/api/create": lambda: wallet.create(value.get("name"), value.get("members", 3)),
                        "/api/join": lambda: wallet.join(value.get("invite")),
                        "/api/begin-link": lambda: wallet.begin_link(value.get("vault")),
                        "/api/link": lambda: wallet.link(value.get("vault"), value.get("proof")),
                        "/api/agree": lambda: wallet.agree(value.get("vault"), value.get("fingerprint")),
                        "/api/backup": lambda: wallet.backup(value.get("vault")),
                        "/api/verify": lambda: wallet.verify(value.get("vault"), value.get("words"), value.get("card")),
                        "/api/activate": lambda: wallet.activate(value.get("vault")),
                        "/api/finalize-backup": lambda: wallet.finalize_backup(value.get("vault"), value.get("words")),
                        "/api/verify-final-backup": lambda: wallet.verify_final_backup(
                            value.get("vault"), value.get("words"), value.get("card")),
                        "/api/restore-vault": lambda: wallet.restore_vault(
                            value.get("name"), value.get("words"), value.get("card")),
                        "/api/address": lambda: {"address": wallet.address(value.get("vault"))},
                        "/api/balance": lambda: wallet.balance(value.get("vault")),
                        "/api/relay-setup": lambda: wallet.setup_relays(value.get("vault")),
                        "/api/relay-setup-all": wallet.setup_all_relays,
                        "/api/relay-provision": lambda: wallet.relay_provision(
                            value.get("vault"), value.get("bundle")),
                        "/api/relay-export": lambda: wallet.relay_export(value.get("vault")),
                        "/api/relay-import": lambda: wallet.relay_import(
                            value.get("vault"), value.get("data"), value.get("name")),
                        "/api/relay-status": lambda: wallet.relay_connection_status(value.get("vault")),
                        "/api/payment-draft": lambda: wallet.prepare_payment(
                            value.get("vault"), value.get("recipient"), value.get("amount_zat"),
                            value.get("memo"), value.get("pair")),
                        "/api/payment-publish": lambda: wallet.publish_payment(
                            value.get("vault"), value.get("attempt")),
                        "/api/payment-sync": lambda: wallet.sync_payments(value.get("vault")),
                        "/api/payment-commit": lambda: wallet.commit_payment(
                            value.get("vault"), value.get("attempt")),
                        "/api/payment-package": lambda: wallet.package_payment(
                            value.get("vault"), value.get("attempt")),
                        "/api/payment-review": lambda: wallet.review_payment(
                            value.get("vault"), value.get("attempt")),
                        "/api/payment-approve": lambda: wallet.approve_payment(
                            value.get("vault"), value.get("attempt"), value.get("review_token")),
                        "/api/payment-resend": lambda: wallet.resend_payment(
                            value.get("vault"), value.get("attempt")),
                        "/api/payment-finish": lambda: wallet.finish_payment(
                            value.get("vault"), value.get("attempt")),
                        "/api/payment-verify": lambda: wallet.verify_payment(
                            value.get("vault"), value.get("attempt"), value.get("txid")),
                        "/api/payment-advance": lambda: wallet.advance_payment(
                            value.get("vault"), value.get("attempt")),
                    }
                    if self.path not in routes:
                        return self.reply(404, {"error": "Not found"})
                    result = routes[self.path]()
                    if self.path == "/api/lock":
                        sessions.clear()
                    self.reply(200, result)
            except Exception as error:
                surface = self.path.rsplit("/", 1)[-1] if self.path.startswith("/api/") else ""
                self.reply(400, {"error": str(error), "surface": surface,
                                 "retry": isinstance(error, Timeout)})

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    return server, token


def make_dashboard_server(signer_port, port):
    signer_origin = f"http://127.0.0.1:{signer_port}"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            if self.headers.get("Host") != f"127.0.0.1:{self.server.server_address[1]}":
                self.send_error(403)
                return
            assets = {"/": ("dashboard.html", "text/html; charset=utf-8"),
                      "/dashboard.js": ("dashboard.js", "text/javascript; charset=utf-8"),
                      "/app.css": ("app.css", "text/css; charset=utf-8"),
                      **{font: (font.lstrip("/"), "font/woff2") for font in FONTS}}
            if self.path not in assets:
                self.send_error(404)
                return
            name, mime = assets[self.path]
            body = (HERE / name).read_bytes()
            if name == "dashboard.html":
                body = body.replace(b"{{SIGNER_ORIGIN}}", signer_origin.encode())
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; "
                             f"style-src 'self'; font-src 'self'; connect-src 'self' {signer_origin}")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def serve(wallet, port, dashboard_port=None, invite_port=None):
    server, token = make_signer_server(wallet, port, dashboard_port)
    dashboard = make_dashboard_server(port, dashboard_port) if dashboard_port else None
    setup = make_setup_server(wallet, invite_port) if invite_port else None
    if setup:
        threading.Thread(target=setup.serve_forever, daemon=True).start()
        print(f"Setup courier: 127.0.0.1:{invite_port} · invites say {wallet.invite_origin}",
              flush=True)
    if dashboard:
        threading.Thread(target=dashboard.serve_forever, daemon=True).start()
        print(f"Dashboard: http://127.0.0.1:{dashboard_port}/", flush=True)
    print(f"Signer: http://127.0.0.1:{port}/#{token}", flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        if dashboard:
            dashboard.shutdown()
            dashboard.server_close()
        if setup:
            setup.shutdown()
            setup.server_close()
        wallet.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="One member's regtest vault setup app")
    parser.add_argument("--data", type=Path, required=True, help="private directory for this member only")
    parser.add_argument("--exchange", type=Path, help="shared untrusted local setup courier (local transport only)")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--dashboard-port", type=int, help="serve a separate dashboard origin")
    parser.add_argument("--invite-port", type=int,
                        help="serve this vault's setup courier on 127.0.0.1 so invited "
                             "members' apps can reach it")
    parser.add_argument("--invite-origin",
                        help="address invited members reach that courier on. Defaults to "
                             "http://127.0.0.1:<invite-port>, which only works for another "
                             "app on this machine. Any other address must be https.")
    parser.add_argument("--transport", choices=("local", "hosted"), default="local")
    parser.add_argument("--operator-bundle", type=Path)
    parser.add_argument("--operator-key")
    parser.add_argument("--enrollment-grant", type=Path)
    parser.add_argument("--enrollment-issuer", type=Path)
    parser.add_argument("--development-http", action="store_true")
    parser.add_argument("--bin-profile", choices=("release", "debug"),
                        help="native binary profile; defaults to release when it is built")
    args = parser.parse_args()
    use_binaries(binary_profile(args.bin_profile))
    print(f"Native binaries: {PROFILE} ({SETUP.parent})", flush=True)
    if PROFILE == "debug":
        print(f"Warning: debug binaries are slow; build release with: {BUILD}", flush=True)
    if args.transport == "hosted" and (not args.operator_bundle or not args.operator_key):
        parser.error("Hosted transport needs --operator-bundle and --operator-key")
    if args.transport == "local" and not args.exchange:
        parser.error("Local transport needs --exchange")
    if args.transport == "hosted" and args.invite_port:
        parser.error("Hosted setup uses the admission service rather than --invite-port")
    origin = args.invite_origin
    if args.invite_port and not origin:
        origin = f"http://127.0.0.1:{args.invite_port}"
    if origin and not args.invite_port:
        parser.error("--invite-origin needs --invite-port to serve")
    serve(Wallet(args.data, args.exchange, invite_origin=origin, transport=args.transport,
                 operator_bundle=args.operator_bundle, operator_key=args.operator_key,
                 enrollment_grant=args.enrollment_grant, development_http=args.development_http, enrollment_issuer=args.enrollment_issuer), args.port,
          args.dashboard_port, args.invite_port)
