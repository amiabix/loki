#!/usr/bin/env python3
"""One-member, loopback-only regtest setup app. The exchange is an untrusted local courier."""

# shortcut: timed local courier and passphrase held in this process; use resumable relays and a native key handle before custody.

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

HERE = Path(__file__).resolve().parent
SETUP = HERE.parent / "target" / "debug" / "loki_setup_member"
PAYMENT = HERE.parent / "target" / "debug" / "loki_member_payment"
RELAY = HERE.parent / "target" / "debug" / "loki_relay_member"
SEED_WALLET = HERE.parent / "target" / "debug" / "loki_seed_wallet"


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


def read_json(path):
    return json.loads(path.read_text())


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
                     "access": "View vault status and request vault creation; each creation needs signer approval"}
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
        if value.get("kind") != "create" or not isinstance(value.get("name"), str):
            raise ValueError("Unsupported vault request")
        name = value["name"].strip()
        if not 1 <= len(name.encode()) <= 80:
            raise ValueError("Enter a vault name of 1 to 80 UTF-8 bytes")
        members = value.get("members", 3)
        if type(members) is not int or members not in (3, 4):
            raise ValueError("Choose a 2-of-3 or 2-of-4 vault")
        with self.lock:
            if not self._valid(key, origin):
                raise ValueError("Connect your signer")
            self.actions = {action: item for action, item in self.actions.items()
                            if item["expires"] > self.now()}
            if len(self.actions) >= 16:
                raise ValueError("Too many vault requests")
            action = secrets.token_urlsafe(32)
            self.actions[action] = {"session": key, "origin": origin, "kind": "create",
                                    "name": name, "members": members,
                                    "state": "pending", "expires": self.now() + 300}
            return action

    def pending_actions(self):
        with self.lock:
            return [{"action": action, "origin": item["origin"], "kind": item["kind"],
                     "name": item["name"], "members": item["members"]} for action, item in self.actions.items()
                    if item["state"] == "pending" and item["expires"] > self.now()
                    and self._valid(item["session"], item["origin"])]

    def take_action(self, action):
        with self.lock:
            item = self.actions.get(action)
            if not item or item["state"] != "pending" or item["expires"] <= self.now() \
                    or not self._valid(item["session"], item["origin"]):
                raise ValueError("Vault request missing or expired")
            item["state"] = "executing"
            return {"kind": item["kind"], "name": item["name"], "members": item["members"]}

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
    def __init__(self, data, exchange, setup=SETUP):
        self.data = data.resolve()
        self.exchange = exchange.resolve()
        if self.data == self.exchange or self.data in self.exchange.parents or self.exchange in self.data.parents:
            raise ValueError("member data and exchange must be separate directories")
        if (self.data / "membership.json").exists():
            raise ValueError("Existing single-vault data root; keep using the previous setup app or choose a new root")
        self.data.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.exchange.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.data, 0o700)
        self.process_lock = open(self.data / ".app.lock", "a+b")
        try:
            fcntl.flock(self.process_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            self.process_lock.close()
            raise ValueError("This member data root is already open in another app") from error
        self.setup = setup
        self.lock = threading.Lock()
        self.passphrase = None
        self.profile_data = None
        self.workers = {}
        self.setup_errors = {}
        self.relay_payment_ready = False

    def command(self, action, *args, passphrase=None, timeout=30, binary=None):
        binary = binary or self.setup
        if not binary.is_file():
            raise ValueError(f"Build {binary.name}: cd poc && cargo build --locked --bins")
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
            result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
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
        return {"profile": profile}

    def unlock(self, passphrase):
        check_passphrase(passphrase)
        profile = json.loads(self.command("profile-open", self.data, "@pass", passphrase=passphrase))
        self.passphrase, self.profile_data = passphrase, profile
        return {"profile": profile}

    def lock_profile(self):
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
        folder = self.data / "vaults" / self.exchange_vault(vault).name
        local = folder / "membership.json"
        if not local.is_file():
            raise ValueError("This profile is not a member of that vault")
        membership = read_json(local)
        if membership.get("vault") != vault or membership.get("profile") != self.require_profile()["id"]:
            raise ValueError("Vault membership does not belong to this profile")
        return folder, membership

    def vaults(self):
        self.require_profile()
        root = self.data / "vaults"
        if not root.exists():
            return []
        return [self.vault_dir(path.name)[1] for path in sorted(root.iterdir())
                if (path / "membership.json").is_file()]

    def exchange_vault(self, vault):
        if not isinstance(vault, str) or len(vault) != 64 or any(c not in "0123456789abcdef" for c in vault):
            raise ValueError("Invalid vault ID")
        return self.exchange / vault

    def create(self, name, members=3):
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
                 "expires_at": int(time.time()) + 24 * 60 * 60,
                 "invites": {str(slot): hashlib.sha256(token.encode()).hexdigest() for slot, token in tokens.items()}}
        write_new(folder / "draft.json", json.dumps(draft).encode())
        identity = json.loads(self.command("identity", local, "1", "@pass"))
        write_new(folder / "join-1.json", json.dumps(identity).encode())
        write_new(local / "membership.json", json.dumps({"vault": vault, "slot": 1,
                                                          "name": name.strip(), "profile": profile["id"],
                                                          "threshold": 2, "members": members}).encode())
        invites = [encoded({"vault": vault, "slot": slot, "secret": token}) for slot, token in tokens.items()]
        write_new(local / "invites.json", json.dumps(invites).encode())
        return {"vault": vault, "invites": invites}

    def join(self, invite):
        profile = self.require_profile()
        try:
            claim = decoded(invite)
            vault, slot, secret = claim["vault"], claim["slot"], claim["secret"]
        except (ValueError, KeyError, TypeError) as error:
            raise ValueError("Invalid invite") from error
        folder = self.exchange_vault(vault)
        draft = read_json(folder / "draft.json")
        if draft["vault"] != vault or int(draft["expires_at"]) < time.time():
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
        local = self.data / "vaults" / vault
        if local.exists():
            raise ValueError("This profile already has a membership for this vault")
        local.mkdir(mode=0o700, parents=True)
        identity = json.loads(self.command("identity", local, str(slot), "@pass"))
        write_new(folder / f"join-{slot}.json", json.dumps(identity).encode())
        write_new(local / "membership.json", json.dumps({"vault": vault, "slot": slot,
                                                          "name": draft["name"], "profile": profile["id"],
                                                          "threshold": 2, "members": members}).encode())
        return {"vault": vault, "joined": True}

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
        self.setup_errors.pop(vault, None)
        passphrase = self.passphrase

        def run():
            try:
                self.command("run", member_dir, "@pass", member_dir / "roster.json",
                             self.exchange_vault(vault), fingerprint, passphrase=passphrase,
                             timeout=600)
            except Exception as error:
                self.setup_errors[vault] = str(error)

        self.workers[vault] = threading.Thread(target=run, daemon=True)
        self.workers[vault].start()
        return {"started": True}

    def backup(self, vault):
        member_dir, _ = self.vault_dir(vault)
        card = member_dir / "card"
        words = self.command("backup-create", member_dir, "@pass", card)
        return {"words": words}

    def verify(self, vault, words, card_bytes):
        member_dir, _ = self.vault_dir(vault)
        if not isinstance(words, str) or not isinstance(card_bytes, str):
            raise ValueError("Load the words and saved card")
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
        member_dir, _ = self.vault_dir(vault)
        self.command("address", member_dir, "@pass", member_dir / "roster.json",
                     self.exchange_vault(vault))
        return {"final_backup": True}

    def finalize_backup(self, vault, words):
        member_dir, _ = self.vault_dir(vault)
        if not isinstance(words, str):
            raise ValueError("Enter your 24 backup words")
        with tempfile.TemporaryDirectory(prefix=".finalize-", dir=member_dir) as temp:
            words_file = Path(temp) / "words"
            write_new(words_file, words.encode())
            self.command("backup-finalize", member_dir, "@pass", member_dir / "card",
                         member_dir / "final-card", words_file, member_dir / "roster.json",
                         self.exchange_vault(vault))
        return {"created": True}

    def verify_final_backup(self, vault, words, card_bytes):
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
        return {"verified": True}

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
            return {"vault": vault, "slot": own["id"], "address": address}
        finally:
            if restored.exists():
                shutil.rmtree(restored)

    def address(self, vault):
        member_dir, _ = self.vault_dir(vault)
        if not (member_dir / "final-backup-checked").is_file():
            raise ValueError("Check your final backup card before showing the receive address")
        return self.command("address", member_dir, "@pass")

    def balance(self, vault):
        member_dir, _ = self.vault_dir(vault)
        result = json.loads(self.command("balance", member_dir, "@pass", member_dir / "roster.json",
                                         binary=PAYMENT, timeout=120))
        if result.get("vault") != vault:
            raise ValueError("Chain scan returned another vault")
        return result

    def prepare_payment(self, vault, recipient, amount_zat, memo, pair):
        member_dir, local = self.vault_dir(vault)
        if not (member_dir / "final-backup-checked").is_file():
            raise ValueError("Vault is not active")
        if not isinstance(recipient, str) or not recipient.strip():
            raise ValueError("Enter a recipient address")
        if not isinstance(amount_zat, str) or not 1 <= len(amount_zat) <= 20 \
                or not amount_zat.isascii() or not amount_zat.isdigit() or int(amount_zat) <= 0:
            raise ValueError("Enter a positive amount in zat")
        if not isinstance(memo, str) or not memo or len(memo.encode()) > 512:
            raise ValueError("Enter a memo of 1 to 512 bytes")
        if local.get("members") not in (3, 4):
            raise ValueError("Unsupported vault roster")
        pairs = ("AB", "AC", "BC") if local["members"] == 3 else ("AB", "AC", "AD", "BC", "BD", "CD")
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
        if local.get("threshold", 2) != 2 or local.get("members") != 3:
            raise ValueError("Relay payments currently require a 2-of-3 vault")
        if not (member_dir / "final-backup-checked").is_file():
            raise ValueError("Vault is not active")
        if not isinstance(attempt, str) or not re.fullmatch(r"[0-9a-f]{64}", attempt):
            raise ValueError("Invalid payment attempt")
        for work in (member_dir / "payments").glob("*/payment.json"):
            manifest = read_json(work)
            if manifest.get("attempt") == attempt and manifest.get("vault") == vault:
                if manifest.get("pair") not in ([1, 2], [1, 3], [2, 3]):
                    raise ValueError("Invalid payment pair")
                return member_dir, local, work.parent, manifest
        raise ValueError("Payment is not in this member's vault")

    def payments(self, vault):
        member_dir, _ = self.vault_dir(vault)
        if not (member_dir / "final-backup-checked").is_file():
            raise ValueError("Vault is not active")
        items = []
        for path in sorted((member_dir / "payments").glob("*/payment.json")):
            manifest = read_json(path)
            attempt = manifest.get("attempt")
            if manifest.get("vault") != vault or not isinstance(attempt, str) \
                    or not re.fullmatch(r"[0-9a-f]{64}", attempt):
                continue
            state = path.parent / "payment-status.json"
            status = read_json(state) if state.is_file() else {"phase": "received"}
            phase = status["phase"]
            if phase == "confirmed":
                # shortcut: recheck each confirmed payment until the wallet has an indexed chain store.
                try:
                    _, _, _, output = self.payment_command("verify", vault, attempt, status["txid"])
                    if not re.search(r"\bverified mined txid=" + re.escape(status["txid"]) +
                                     r" confirmations=[1-9][0-9]*\b", output):
                        phase = "confirmation_needs_recheck"
                except (KeyError, ValueError, subprocess.TimeoutExpired):
                    phase = "confirmation_needs_recheck"
            items.append({"attempt": attempt, "payment": manifest.get("payment"),
                          "pair": manifest.get("pair"), "phase": phase,
                          **({"txid": status["txid"]} if status.get("txid") else {})})
        return {"payments": items}

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
        if local.get("threshold", 2) != 2 or local.get("members") != 3 \
                or not (member_dir / "final-backup-checked").is_file():
            raise ValueError("Relay payments require an active 2-of-3 vault")
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
        for path in works:
            attempt = path.parent.name
            _, work, _, output = self.payment_command("local-wires", vault, attempt)
            wires = json.loads(output)["wires"]
            for wire in wires:
                relay("send-signing", "--payload-file", work / "mailbox" / wire,
                      "--attempt", attempt)
        relay("upload")
        relay("poll", "--once")
        for path in works:
            relay("export-signing", "--work-dir", path.parent, "--attempt", path.parent.name)

        if proposals:
            report = relay("status")
            for attempt, message in proposals.items():
                line = next((line for line in report.splitlines()
                             if line.startswith("message ") and f" id={message} " in line), "")
                if re.search(r"\bstored_whole=1\b", line):
                    self.payment_status(member_dir / "payments" / attempt, "published")
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
        status = work / "payment-status.json"
        return {"phase": read_json(status)["phase"] if status.is_file() else "received"}

    def finish_payment(self, vault, attempt):
        _, work, _, output = self.payment_command("finish", vault, attempt, timeout=600)
        txid = re.search(r"\bbroadcast txid=([0-9a-f]{64})\b", output)
        if not txid:
            raise ValueError("Finisher did not return a broadcast transaction ID")
        self.payment_status(work, "broadcast", txid.group(1))
        return {"phase": "broadcast", "txid": txid.group(1)}

    def verify_payment(self, vault, attempt, txid):
        if not isinstance(txid, str) or not re.fullmatch(r"[0-9a-f]{64}", txid):
            raise ValueError("Enter the broadcast transaction ID")
        _, work, _, output = self.payment_command("verify", vault, attempt, txid, timeout=120)
        match = re.search(r"\bverified mined txid=([0-9a-f]{64}) confirmations=([1-9][0-9]*)\b", output)
        if not match or match.group(1) != txid:
            raise ValueError("Chain verification did not confirm this payment")
        self.payment_status(work, "confirmed", txid)
        return {"phase": "confirmed", "txid": txid, "confirmations": int(match.group(2))}

    def status(self, vault=None):
        if not (self.data / "profile" / "profile.sealed").exists():
            return {"phase": "new_profile", "network": "regtest"}
        if not self.profile_data:
            return {"phase": "locked", "network": "regtest"}
        vaults = self.vaults()
        if vault is None:
            return {"phase": "home", "network": "regtest", "profile": self.profile_data,
                    "vaults": vaults}
        member_dir, local = self.vault_dir(vault)
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
        state["account_linked"] = (member_dir / "secrets" / "account-link.sealed").exists()
        if local["slot"] == 1 and (member_dir / "invites.json").exists():
            state["invites"] = read_json(member_dir / "invites.json")
        if roster["fingerprint"]:
            state["phase"] = "compare_roster"
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
        if active:
            state["phase"] = "active" if (member_dir / "final-backup-checked").is_file() else "final_backup"
        if self.setup_errors.get(vault):
            state["phase"] = "stopped"
        return state

    def close(self):
        self.process_lock.close()


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
                self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'")
                self.end_headers()
                self.wfile.write(page)
                return
            if path == "/app.js":
                self.send_response(200)
                self.send_header("Content-Type", "text/javascript; charset=utf-8")
                self.end_headers()
                self.wfile.write((HERE / "app.js").read_bytes())
                return
            if path == "/app.css":
                self.send_response(200)
                self.send_header("Content-Type", "text/css; charset=utf-8")
                self.end_headers()
                self.wfile.write((HERE / "app.css").read_bytes())
                return
            if path == "/api/session/vaults":
                key = self.headers.get("X-Loki-Session", "")
                if not self.dashboard_origin() or not sessions.valid(key, dashboard_origin):
                    return self.reply(403, {"error": "Connect your signer"})
                try:
                    with wallet.lock:
                        profile = wallet.require_profile()
                        vaults = [{"vault": item["vault"], "name": item["name"], "slot": item["slot"],
                                   "phase": wallet.status(item["vault"])["phase"]}
                                  for item in wallet.vaults()]
                    return self.reply(200, {"profile": profile["name"], "vaults": vaults})
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
                    return self.reply(200, wallet.payments(vault))
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
                                         "/api/session/action-poll")
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
                    sessions.disconnect(key, dashboard_origin)
                    return self.reply(200, {"disconnected": True})
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
                    }
                    if self.path not in routes:
                        return self.reply(404, {"error": "Not found"})
                    result = routes[self.path]()
                    if self.path == "/api/lock":
                        sessions.clear()
                    self.reply(200, result)
            except Exception as error:
                self.reply(400, {"error": str(error)})

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
                      "/app.css": ("app.css", "text/css; charset=utf-8")}
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
                             f"style-src 'self'; connect-src 'self' {signer_origin}")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def serve(wallet, port, dashboard_port=None):
    server, token = make_signer_server(wallet, port, dashboard_port)
    dashboard = make_dashboard_server(port, dashboard_port) if dashboard_port else None
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
        wallet.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="One member's regtest vault setup app")
    parser.add_argument("--data", type=Path, required=True, help="private directory for this member only")
    parser.add_argument("--exchange", type=Path, required=True, help="shared untrusted local setup courier")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--dashboard-port", type=int, help="serve a separate dashboard origin")
    args = parser.parse_args()
    serve(Wallet(args.data, args.exchange), args.port, args.dashboard_port)
