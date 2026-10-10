#!/usr/bin/env python3
"""Loopback UI for one disposable, separately created 2-of-3 regtest payment."""

from __future__ import annotations

import fcntl
import hmac
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DEMO = Path(__file__).resolve().parent
POC = DEMO.parent
ROOT = DEMO / ".member-sandbox"
RUN = ROOT / "run"
STATIC = DEMO / "static"
sys.path.insert(0, str(POC))

from managed_ths import ManagedTHS, command  # noqa: E402


def binary(name: str) -> Path:
    target = Path(os.environ.get("CARGO_TARGET_DIR", POC / "target"))
    if not target.is_absolute():
        target = POC / target
    path = target / "debug" / name
    if not path.is_file() or not os.access(path, os.X_OK):
        raise RuntimeError(f"build {name} with: cd poc && cargo build --locked --bins")
    return path


class Flow:
    def __init__(self):
        self.lock = threading.RLock()
        self.cancel = threading.Event()
        self.chain = ManagedTHS(ROOT, lambda *_: None, self.cancel)
        self.phase = "interrupted" if RUN.exists() else "idle"
        self.error = None
        self.payment = None
        self.txid = None
        self.review = {"alice": None, "bob": None}
        self.signers = {"alice": "waiting", "bob": "waiting"}
        self.processes = {}
        self.signer_threads = []
        self.worker = None
        self.tokens = {role: secrets.token_urlsafe(32) for role in ("admin", "alice", "bob")}

    def role(self, token: str) -> str | None:
        return next((role for role, secret in self.tokens.items()
                     if hmac.compare_digest(token, secret)), None)

    def state(self, role: str, origin: str) -> dict:
        with self.lock:
            out = {
                "role": role, "phase": self.phase, "error": self.error,
                "payment": self.payment, "txid": self.txid,
                "signers": self.signers.copy(),
                "network": self.chain.snapshot(),
            }
            if role in self.review:
                out["review"] = self.review[role]
            if role == "admin":
                out["links"] = {name: f"{origin}/#{self.tokens[name]}"
                                for name in self.review}
            return out

    def _command(self, args: list[str], timeout: int = 300) -> str:
        result = command(args, self.cancel, timeout, cwd=str(POC),
                         env=self.chain.client.env() if self.chain.client else None)
        if result.returncode:
            raise RuntimeError((result.stderr or result.stdout).strip()[-1000:]
                               or f"{Path(args[0]).name} exited {result.returncode}")
        return result.stdout

    def start(self, amount: int, memo: str):
        if not isinstance(amount, int) or isinstance(amount, bool) or not 0 < amount < 100_000_000:
            raise ValueError("amount must be between 1 and 99,999,999 zat")
        if not isinstance(memo, str) or not 0 < len(memo.encode("utf-8")) <= 512:
            raise ValueError("memo must contain 1 to 512 UTF-8 bytes")
        with self.lock:
            if self.phase != "idle":
                raise ValueError("reset this demo before starting another payment")
            binary("loki_setup_member")
            binary("loki_member_payment")
            self.phase = "preparing"
            self.error = None
            self.worker = threading.Thread(target=self._prepare, args=(amount, memo), daemon=True)
            self.worker.start()

    def _prepare(self, amount: int, memo: str):
        try:
            self.chain.start()
            output = self._command([
                sys.executable, str(POC / "run-member-payment.py"),
                "--name", self.chain.name, "--state", str(RUN), "--manual",
                "--amount-zat", str(amount), f"--memo={memo}",
            ], timeout=1200)
            source = re.search(r"^Source vault: (uregtest\S+)$", output, re.M)
            recipient = re.search(r"^Independent recipient: (uregtest\S+)$", output, re.M)
            manifest = json.loads((RUN / "payment" / "payment.json").read_text())
            if not source or not recipient or manifest["amount_zat"] != amount:
                raise RuntimeError("setup output differs from the payment manifest")
            payment = {
                "id": manifest["payment"], "source": source.group(1),
                "recipient": recipient.group(1), "amount_zat": manifest["amount_zat"],
                "memo": bytes.fromhex(manifest["memo"]).decode("utf-8"),
                "fee_zat": manifest["fee_zat"], "change_zat": manifest["change_zat"],
                "expiry_height": manifest["expiry_height"],
            }
            with self.lock:
                self.payment = payment
                self.phase = "waiting_for_reviews"
            for name, number in (("alice", 1), ("bob", 2)):
                owner = RUN / "source" / f"member-{number}"
                args = [str(binary("loki_member_payment")), "sign", str(owner),
                        str(owner / "pass.txt"), str(RUN / "source" / "roster.json"),
                        str(RUN / "payment")]
                process = subprocess.Popen(args, cwd=POC, env=self.chain.client.env(),
                                           stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT, text=True, bufsize=1)
                with self.lock:
                    self.processes[name] = process
                reader = threading.Thread(target=self._read_signer, args=(name, process), daemon=True)
                self.signer_threads.append(reader)
                reader.start()
        except Exception as error:
            self._fail(error)

    def _read_signer(self, name: str, process: subprocess.Popen):
        lines = []
        try:
            for raw in process.stdout:
                line = raw.rstrip("\r\n")
                if line.startswith(("Vault: ", "Recipient: ", "Amount: ",
                                    "Fee: ", "Inputs: ")):
                    lines.append(line)
                if line == f"Type APPROVE {self.payment['id']} to sign:":
                    if len(lines) != 5:
                        raise RuntimeError(f"{name}'s review was incomplete")
                    with self.lock:
                        self.review[name] = "\n".join(lines)
                        self.signers[name] = "reviewing"
                if line.startswith("approved payment "):
                    lines.append(line)
            code = process.wait()
            with self.lock:
                if code == 0 and lines[-1:] == [
                    f"approved payment {self.payment['id']} as member {1 if name == 'alice' else 2}"
                ]:
                    self.signers[name] = "approved"
                    if all(value == "approved" for value in self.signers.values()):
                        self.phase = "ready_to_send"
                elif self.signers[name] == "declined":
                    self.phase = "declined"
                else:
                    self.signers[name] = "failed"
                    self.phase = "failed"
                    self.error = f"{name}'s signing process stopped (exit {code}); reset to retry"
        except Exception as error:
            process.terminate()
            self._fail(error)

    def decide(self, role: str, action: str):
        if role not in self.review or action not in ("approve", "decline"):
            raise ValueError("a signer must approve or decline")
        with self.lock:
            if self.phase != "waiting_for_reviews":
                raise ValueError("this signing attempt is no longer awaiting approvals")
            if self.signers[role] != "reviewing" or not self.review[role]:
                raise ValueError("this member has no verified review awaiting a decision")
            process = self.processes[role]
            if process.poll() is not None:
                raise ValueError("signing process ended; reset to retry")
            self.signers[role] = "signing" if action == "approve" else "declined"
            process.stdin.write(f"APPROVE {self.payment['id']}\n" if action == "approve" else "DECLINE\n")
            process.stdin.flush()

    def finish(self):
        with self.lock:
            if self.phase != "ready_to_send":
                raise ValueError("both members must approve before sending")
            self.phase = "sending"
            self.worker = threading.Thread(target=self._finish, daemon=True)
            self.worker.start()

    def _finish(self):
        try:
            owner = RUN / "source" / "member-3"
            base = [str(owner), str(owner / "pass.txt"), str(RUN / "source" / "roster.json"),
                    str(RUN / "payment")]
            out = self._command([str(binary("loki_member_payment")), "finish", *base], timeout=900)
            match = re.search(r"broadcast txid=([0-9a-f]{64}) payment=([0-9a-f]{64})", out)
            if not match or match.group(2) != self.payment["id"]:
                raise RuntimeError("finisher did not return the expected payment")
            txid = match.group(1)
            with self.lock:
                self.txid = txid
                self.phase = "broadcast"
            self.chain.mine(3)
            verified = self._command([str(binary("loki_member_payment")), "verify", *base, txid])
            recipient = RUN / "recipient" / "member-1"
            received = self._command([
                str(binary("loki_member_payment")), "receive", str(recipient),
                str(recipient / "pass.txt"), str(RUN / "recipient" / "roster.json"),
                str(RUN / "payment"), txid,
            ])
            if f"verified mined txid={txid}" not in verified or f"recipient independently decrypted txid={txid}" not in received:
                raise RuntimeError("mined transaction verification did not match")
            with self.lock:
                self.phase = "confirmed"
        except Exception as error:
            self._fail(error)

    def _fail(self, error: Exception):
        with self.lock:
            self.phase = "failed"
            self.error = str(error)

    def _stop_signers(self):
        for process in self.processes.values():
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        self.processes.clear()
        for reader in self.signer_threads:
            reader.join(timeout=5)
        self.signer_threads.clear()

    def reset(self):
        with self.lock:
            if self.worker and self.worker.is_alive():
                raise ValueError("wait for the current operation to finish before resetting")
        self._stop_signers()
        with self.lock:
            self.chain.stop()
            if ROOT.exists():
                shutil.rmtree(ROOT)
            self.cancel = threading.Event()
            self.chain = ManagedTHS(ROOT, lambda *_: None, self.cancel)
            self.phase = "idle"
            self.error = self.payment = self.txid = None
            self.review = {"alice": None, "bob": None}
            self.signers = {"alice": "waiting", "bob": "waiting"}

    def close(self):
        self.cancel.set()
        self._stop_signers()
        if self.worker and self.worker.is_alive():
            self.worker.join(timeout=30)
            if self.worker.is_alive():
                print("active operation did not settle; saved THS ownership for recovery", file=sys.stderr)
                return
        self.chain.stop()


FLOW = Flow()


class Handler(BaseHTTPRequestHandler):
    def send(self, code: int, data: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(data)

    def json(self, code: int, value: dict):
        self.send(code, json.dumps(value).encode(), "application/json")

    def role(self):
        return FLOW.role(self.headers.get("X-Loki-Token", ""))

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/api/state":
            role = self.role()
            if not role:
                return self.json(401, {"error": "open a member link from the coordinator"})
            origin = f"http://127.0.0.1:{self.server.server_port}"
            return self.json(200, FLOW.state(role, origin))
        assets = {"/": ("member.html", "text/html; charset=utf-8"),
                  "/member.js": ("member.js", "text/javascript; charset=utf-8"),
                  "/member.css": ("member.css", "text/css; charset=utf-8")}
        if path not in assets:
            return self.json(404, {"error": "not found"})
        file, ctype = assets[path]
        try:
            return self.send(200, (STATIC / file).read_bytes(), ctype)
        except OSError as error:
            return self.json(500, {"error": str(error)})

    def do_POST(self):
        if self.headers.get("Origin") != f"http://127.0.0.1:{self.server.server_port}":
            return self.json(403, {"error": "foreign or missing origin"})
        if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json":
            return self.json(415, {"error": "JSON required"})
        role = self.role()
        if not role:
            return self.json(401, {"error": "invalid session link"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 <= length <= 4096:
                raise ValueError("request body too large")
            body = json.loads(self.rfile.read(length) or b"{}")
            path = self.path.split("?", 1)[0]
            if path == "/api/start" and role == "admin":
                FLOW.start(body.get("amount_zat"), body.get("memo"))
            elif path == "/api/decide" and role in ("alice", "bob"):
                FLOW.decide(role, body.get("action"))
            elif path == "/api/finish" and role == "admin":
                FLOW.finish()
            elif path == "/api/reset" and role == "admin":
                FLOW.reset()
            else:
                return self.json(403, {"error": "this member cannot take that action"})
        except (ValueError, RuntimeError, json.JSONDecodeError) as error:
            return self.json(400, {"error": str(error)})
        return self.json(200, {"ok": True})

    def log_message(self, *_):
        pass  # URLs carry no token; keep the local demo quiet.


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8790)
    args = parser.parse_args()
    lock_file = (DEMO / ".member-sandbox.lock").open("a")
    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        parser.error("another member demo already owns this sandbox")
    FLOW.chain.recover()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"Coordinator: http://127.0.0.1:{args.port}/#{FLOW.tokens['admin']}", flush=True)
    print("Open signer links from the coordinator in two separate browser sessions.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        FLOW.close()
        server.server_close()
        lock_file.close()


if __name__ == "__main__":
    def interrupt(*_):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupt)
    main()
