#!/usr/bin/env python3
"""One-member, loopback-only regtest setup app. The exchange is an untrusted local courier."""

# shortcut: one vault and a timed local courier; add relay-backed resumable setup before custody.

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

HERE = Path(__file__).resolve().parent
SETUP = HERE.parent / "target" / "debug" / "loki_setup_member"


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
        self.worker = None
        self.setup_error = None

    def command(self, action, *args, passphrase=None, timeout=30):
        if not self.setup.is_file():
            raise ValueError("Build the setup binary: cd poc && cargo build --locked --bin loki_setup_member")
        passfile = None
        try:
            argv = [str(self.setup), action]
            for arg in args:
                if arg == "@pass":
                    fd, name = tempfile.mkstemp(prefix=".unlock-", dir=self.data)
                    passfile = Path(name)
                    with os.fdopen(fd, "w") as out:
                        out.write(check_passphrase(passphrase))
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

    def local(self):
        path = self.data / "membership.json"
        return read_json(path) if path.exists() else None

    def exchange_vault(self, vault):
        if not isinstance(vault, str) or len(vault) != 64 or any(c not in "0123456789abcdef" for c in vault):
            raise ValueError("Invalid vault ID")
        return self.exchange / vault

    def create(self, name, passphrase):
        if self.local():
            raise ValueError("This app already has a vault; use another member data root")
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80:
            raise ValueError("Enter a vault name of 1 to 80 characters")
        check_passphrase(passphrase)
        vault = secrets.token_hex(32)
        folder = self.exchange_vault(vault)
        folder.mkdir(mode=0o700)
        tokens = {slot: secrets.token_urlsafe(24) for slot in (2, 3)}
        draft = {"vault": vault, "name": name.strip(), "threshold": 2,
                 "expires_at": int(time.time()) + 24 * 60 * 60,
                 "invites": {str(slot): hashlib.sha256(token.encode()).hexdigest() for slot, token in tokens.items()}}
        write_new(folder / "draft.json", json.dumps(draft).encode())
        identity = json.loads(self.command("identity", self.data, "1", "@pass", passphrase=passphrase))
        write_new(folder / "join-1.json", json.dumps(identity).encode())
        write_new(self.data / "membership.json", json.dumps({"vault": vault, "slot": 1, "name": name.strip()}).encode())
        invites = [encoded({"vault": vault, "slot": slot, "secret": token}) for slot, token in tokens.items()]
        write_new(self.data / "invites.json", json.dumps(invites).encode())
        return {"invites": invites}

    def join(self, invite, passphrase):
        if self.local():
            raise ValueError("This app already has a vault; use another member data root")
        check_passphrase(passphrase)
        try:
            claim = decoded(invite)
            vault, slot, secret = claim["vault"], claim["slot"], claim["secret"]
        except (ValueError, KeyError, TypeError) as error:
            raise ValueError("Invalid invite") from error
        folder = self.exchange_vault(vault)
        draft = read_json(folder / "draft.json")
        if draft["vault"] != vault or int(draft["expires_at"]) < time.time():
            raise ValueError("Invite expired or belongs to another vault")
        if slot not in (2, 3) or not isinstance(secret, str) or not secrets.compare_digest(
            draft["invites"][str(slot)], hashlib.sha256(secret.encode()).hexdigest()
        ):
            raise ValueError("Invite does not match this vault")
        if (folder / f"join-{slot}.json").exists():
            raise ValueError("This invite slot has already been claimed")
        identity = json.loads(self.command("identity", self.data, str(slot), "@pass", passphrase=passphrase))
        write_new(folder / f"join-{slot}.json", json.dumps(identity).encode())
        write_new(self.data / "membership.json", json.dumps({"vault": vault, "slot": slot,
                                                                "name": draft["name"]}).encode())
        return {"joined": True}

    def roster(self):
        local = self.local()
        if not local:
            return None
        folder = self.exchange_vault(local["vault"])
        members = [read_json(folder / f"join-{slot}.json") for slot in (1, 2, 3)
                   if (folder / f"join-{slot}.json").exists()]
        if len(members) != 3:
            return {"members": members, "fingerprint": None}
        if [member["id"] for member in members] != [1, 2, 3]:
            raise ValueError("Member slots do not match the roster")
        roster = {"vault": local["vault"], "members": members}
        write_path = self.data / "roster.json"
        if not write_path.exists():
            write_new(write_path, json.dumps(roster).encode())
        elif read_json(write_path) != roster:
            raise ValueError("Roster changed after it was recorded")
        fingerprint = self.command("fingerprint", write_path)
        return {"members": members, "fingerprint": fingerprint}

    def agree(self, fingerprint, passphrase):
        roster = self.roster()
        if not roster or not roster["fingerprint"]:
            raise ValueError("Wait for all three members")
        if not isinstance(fingerprint, str) or not secrets.compare_digest(fingerprint, roster["fingerprint"]):
            raise ValueError("Roster fingerprint does not match")
        own = json.loads(self.command("identity-public", self.data, "@pass", passphrase=passphrase))
        if own != roster["members"][self.local()["slot"] - 1]:
            raise ValueError("Your identity differs from the agreed roster")
        if self.worker and self.worker.is_alive():
            raise ValueError("Key creation is already running")
        self.setup_error = None

        def run():
            try:
                self.command("run", self.data, "@pass", self.data / "roster.json",
                             self.exchange_vault(self.local()["vault"]), fingerprint,
                             passphrase=passphrase, timeout=600)
            except Exception as error:
                self.setup_error = str(error)

        self.worker = threading.Thread(target=run, daemon=True)
        self.worker.start()
        return {"started": True}

    def backup(self, passphrase):
        card = self.data / "card"
        words = self.command("backup-create", self.data, "@pass", card, passphrase=passphrase)
        return {"words": words}

    def verify(self, passphrase, words, card_bytes):
        if not isinstance(words, str) or not isinstance(card_bytes, str):
            raise ValueError("Load the words and saved card")
        raw = base64.b64decode(card_bytes, validate=True)
        if len(raw) > 64 * 1024 or not raw.startswith(b"LOKISEAL\x01"):
            raise ValueError("Invalid backup card")
        with tempfile.TemporaryDirectory(prefix=".check-", dir=self.data) as temp:
            folder = Path(temp)
            card = folder / "card"
            card.mkdir(mode=0o700)
            write_new(card / "vault.card", raw)
            write_new(folder / "words", words.encode())
            self.command("backup-verify", self.data, "@pass", card, folder / "words",
                         self.data / "roster.json", self.exchange_vault(self.local()["vault"]),
                         passphrase=passphrase)
        return {"verified": True}

    def address(self, passphrase):
        return self.command("address", self.data, "@pass", self.data / "roster.json",
                            self.exchange_vault(self.local()["vault"]), passphrase=passphrase)

    def status(self):
        local = self.local()
        if not local:
            return {"phase": "new", "network": "regtest"}
        roster = self.roster()
        state = {"phase": "waiting_for_members", "network": "regtest", "name": local["name"],
                 "slot": local["slot"], "vault": local["vault"], "members": len(roster["members"]),
                 "fingerprint": roster["fingerprint"], "error": self.setup_error}
        if local["slot"] == 1 and (self.data / "invites.json").exists():
            state["invites"] = read_json(self.data / "invites.json")
        if roster["fingerprint"]:
            state["phase"] = "compare_roster"
        if (self.data / "secrets" / "vault.sealed").exists():
            state["phase"] = "back_up"
        elif self.worker and self.worker.is_alive():
            state["phase"] = "creating_keys"
        if (self.exchange_vault(local["vault"]) / f"{local['vault']}-backup-{local['slot']}.bin").exists():
            state["phase"] = "waiting_for_backups"
        if (self.data / "secrets" / "activation.sealed").exists():
            state["phase"] = "active"
        if self.setup_error:
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
            if self.path == "/":
                page = (HERE / "index.html").read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; connect-src 'self'")
                self.end_headers()
                self.wfile.write(page)
                return
            if self.path == "/app.js":
                self.send_response(200)
                self.send_header("Content-Type", "text/javascript; charset=utf-8")
                self.end_headers()
                self.wfile.write((HERE / "app.js").read_bytes())
                return
            if self.path == "/app.css":
                self.send_response(200)
                self.send_header("Content-Type", "text/css; charset=utf-8")
                self.end_headers()
                self.wfile.write((HERE / "app.css").read_bytes())
                return
            if self.path in ("/fonts/geist.woff2", "/fonts/geist-mono.woff2", "/fonts/young-serif.woff2"):
                self.send_response(200)
                self.send_header("Content-Type", "font/woff2")
                self.send_header("Cache-Control", "max-age=86400")
                self.end_headers()
                self.wfile.write((HERE / self.path.lstrip("/")).read_bytes())
                return
            if not self.authorized():
                return self.reply(403, {"error": "Open the private local app link"})
            try:
                if self.path == "/api/status":
                    return self.reply(200, wallet.status())
                if self.path == "/api/card":
                    card = (wallet.data / "card" / "vault.card").read_bytes()
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
                        "/api/create": lambda: wallet.create(value.get("name"), value.get("passphrase")),
                        "/api/join": lambda: wallet.join(value.get("invite"), value.get("passphrase")),
                        "/api/agree": lambda: wallet.agree(value.get("fingerprint"), value.get("passphrase")),
                        "/api/backup": lambda: wallet.backup(value.get("passphrase")),
                        "/api/verify": lambda: wallet.verify(value.get("passphrase"), value.get("words"), value.get("card")),
                        "/api/activate": lambda: {"address": wallet.address(value.get("passphrase"))},
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
