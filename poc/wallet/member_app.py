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
import secrets
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

    def create(self, name):
        profile = self.require_profile()
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80:
            raise ValueError("Enter a vault name of 1 to 80 characters")
        vault = secrets.token_hex(32)
        folder = self.exchange_vault(vault)
        folder.mkdir(mode=0o700)
        local = self.data / "vaults" / vault
        local.mkdir(mode=0o700, parents=True)
        tokens = {slot: secrets.token_urlsafe(24) for slot in (2, 3)}
        draft = {"vault": vault, "name": name.strip(), "threshold": 2,
                 "expires_at": int(time.time()) + 24 * 60 * 60,
                 "invites": {str(slot): hashlib.sha256(token.encode()).hexdigest() for slot, token in tokens.items()}}
        write_new(folder / "draft.json", json.dumps(draft).encode())
        identity = json.loads(self.command("identity", local, "1", "@pass"))
        write_new(folder / "join-1.json", json.dumps(identity).encode())
        write_new(local / "membership.json", json.dumps({"vault": vault, "slot": 1,
                                                          "name": name.strip(), "profile": profile["id"]}).encode())
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
        if draft.get("threshold") != 2 or not isinstance(draft.get("name"), str) or not 1 <= len(draft["name"].encode()) <= 80:
            raise ValueError("Unsupported vault draft")
        if slot not in (2, 3) or not isinstance(secret, str) or not secrets.compare_digest(
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
                                                          "name": draft["name"], "profile": profile["id"]}).encode())
        return {"vault": vault, "joined": True}

    def roster(self, vault):
        member_dir, local = self.vault_dir(vault)
        folder = self.exchange_vault(vault)
        members = [read_json(folder / f"join-{slot}.json") for slot in (1, 2, 3)
                   if (folder / f"join-{slot}.json").exists()]
        if len(members) != 3:
            return {"members": members, "fingerprint": None}
        if [member["id"] for member in members] != [1, 2, 3]:
            raise ValueError("Member slots do not match the roster")
        roster = {"vault": vault, "members": members}
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
            raise ValueError("Connect your Zcash account before key creation")
        result = json.loads(self.command("check", self.data, member_dir, "@pass", binary=SEED_WALLET))
        if result["vault"] != vault:
            raise ValueError("Account link belongs to another vault")
        return result

    def agree(self, vault, fingerprint):
        member_dir, local = self.vault_dir(vault)
        roster = self.roster(vault)
        if not roster["fingerprint"]:
            raise ValueError("Wait for all three members")
        if not isinstance(fingerprint, str) or not secrets.compare_digest(fingerprint, roster["fingerprint"]):
            raise ValueError("Roster fingerprint does not match")
        own = json.loads(self.command("identity-public", member_dir, "@pass"))
        if own != roster["members"][local["slot"] - 1]:
            raise ValueError("Your identity differs from the agreed roster")
        self.account_link(vault)
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

    def address(self, vault):
        member_dir, _ = self.vault_dir(vault)
        return self.command("address", member_dir, "@pass", member_dir / "roster.json",
                            self.exchange_vault(vault))

    def balance(self, vault):
        member_dir, _ = self.vault_dir(vault)
        result = json.loads(self.command("balance", member_dir, "@pass", member_dir / "roster.json",
                                         binary=PAYMENT, timeout=120))
        if result.get("vault") != vault:
            raise ValueError("Chain scan returned another vault")
        return result

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
        roster = self.roster(vault)
        state = {"phase": "waiting_for_members", "network": "regtest", "name": local["name"],
                 "slot": local["slot"], "vault": local["vault"], "members": len(roster["members"]),
                 "fingerprint": roster["fingerprint"], "error": self.setup_errors.get(vault),
                 "profile": self.profile_data, "vaults": vaults}
        state["account_linked"] = (member_dir / "secrets" / "account-link.sealed").exists()
        if local["slot"] == 1 and (member_dir / "invites.json").exists():
            state["invites"] = read_json(member_dir / "invites.json")
        if roster["fingerprint"]:
            state["phase"] = "compare_roster"
        if not state["account_linked"]:
            state["phase"] = "connect_account"
        else:
            state["account_ak"] = self.account_link(vault)["account_ak"]
        if (member_dir / "secrets" / "vault.sealed").exists():
            state["phase"] = "back_up"
        elif vault in self.workers and self.workers[vault].is_alive():
            state["phase"] = "creating_keys"
        if (self.exchange_vault(local["vault"]) / f"{local['vault']}-backup-{local['slot']}.bin").exists():
            state["phase"] = "waiting_for_backups"
        if (member_dir / "secrets" / "activation.sealed").exists():
            state["phase"] = "active"
        if self.setup_errors.get(vault):
            state["phase"] = "stopped"
        return state

    def close(self):
        self.process_lock.close()


def serve(wallet, port):
    token = secrets.token_urlsafe(32)

    class Handler(BaseHTTPRequestHandler):
        def reply(self, status, value):
            body = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def authorized(self):
            return secrets.compare_digest(self.headers.get("X-Loki-Token", ""), token)

        def do_GET(self):
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
            if not self.authorized():
                return self.reply(403, {"error": "Open the private local app link"})
            try:
                values = parse_qs(query)
                vault = values.get("vault", [None])[0]
                if path == "/api/status":
                    return self.reply(200, wallet.status(vault))
                if path == "/api/card":
                    member_dir, _ = wallet.vault_dir(vault)
                    card = (member_dir / "card" / "vault.card").read_bytes()
                    return self.reply(200, {"card": base64.b64encode(card).decode()})
            except Exception as error:
                return self.reply(400, {"error": str(error)})
            self.reply(404, {"error": "Not found"})

        def do_POST(self):
            if not self.authorized() or self.headers.get("Origin") not in (None, f"http://127.0.0.1:{port}"):
                return self.reply(403, {"error": "Unauthorized"})
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 128 * 1024:
                    raise ValueError("Invalid request size")
                value = json.loads(self.rfile.read(size))
                with wallet.lock:
                    routes = {
                        "/api/profile-create": lambda: wallet.create_profile(value.get("name"), value.get("passphrase")),
                        "/api/unlock": lambda: wallet.unlock(value.get("passphrase")),
                        "/api/lock": wallet.lock_profile,
                        "/api/create": lambda: wallet.create(value.get("name")),
                        "/api/join": lambda: wallet.join(value.get("invite")),
                        "/api/begin-link": lambda: wallet.begin_link(value.get("vault")),
                        "/api/link": lambda: wallet.link(value.get("vault"), value.get("proof")),
                        "/api/agree": lambda: wallet.agree(value.get("vault"), value.get("fingerprint")),
                        "/api/backup": lambda: wallet.backup(value.get("vault")),
                        "/api/verify": lambda: wallet.verify(value.get("vault"), value.get("words"), value.get("card")),
                        "/api/activate": lambda: {"address": wallet.address(value.get("vault"))},
                        "/api/balance": lambda: wallet.balance(value.get("vault")),
                    }
                    if self.path not in routes:
                        return self.reply(404, {"error": "Not found"})
                    self.reply(200, routes[self.path]())
            except Exception as error:
                self.reply(400, {"error": str(error)})

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"Open http://127.0.0.1:{port}/#{token}", flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        wallet.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="One member's regtest vault setup app")
    parser.add_argument("--data", type=Path, required=True, help="private directory for this member only")
    parser.add_argument("--exchange", type=Path, required=True, help="shared untrusted local setup courier")
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    serve(Wallet(args.data, args.exchange), args.port)
