#!/usr/bin/env python3
"""Loopback UI for a staged, disposable 2-of-3 regtest payment."""

from __future__ import annotations

import fcntl
import hmac
import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DEMO = Path(__file__).resolve().parent
POC = DEMO.parent
ROOT = Path(os.environ.get("LOKI_MEMBER_DEMO_ROOT", DEMO / ".member-sandbox")).resolve()
if ROOT.name != ".member-sandbox" and not ROOT.name.startswith("loki-member-demo-"):
    raise RuntimeError("demo state directory must be named .member-sandbox or loki-member-demo-*")
RUN = ROOT / "run"
STATIC = DEMO / "static"
sys.path.insert(0, str(POC))

from managed_ths import ManagedTHS, command  # noqa: E402
sys.path.insert(0, str(POC.parent / "communication" / "harness"))
import relay_payment  # noqa: E402
import run as relay_run  # noqa: E402
import three_members  # noqa: E402


def binary(name: str) -> Path:
    target = Path(os.environ.get("CARGO_TARGET_DIR", POC / "target"))
    if not target.is_absolute():
        target = POC / target
    path = target / "debug" / name
    if not path.is_file() or not os.access(path, os.X_OK):
        raise RuntimeError(f"build {name} with: cd poc && cargo build --locked --bins")
    return path


def free_relay_ports():
    sockets = [socket.socket(socket.AF_INET, socket.SOCK_STREAM) for _ in range(3)]
    try:
        for listener in sockets:
            listener.bind(("127.0.0.1", 0))
        return tuple(listener.getsockname()[1] for listener in sockets)
    finally:
        for listener in sockets:
            listener.close()


class Flow:
    def __init__(self):
        self.lock = threading.RLock()
        self.cancel = threading.Event()
        self.chain = ManagedTHS(ROOT, lambda *_: None, self.cancel)
        self.phase = "interrupted" if RUN.exists() else "idle"
        self.error = None
        self.vaults = None
        self.payment = None
        self.txid = None
        self.review = {"alice": None, "bob": None}
        self.signers = {"alice": "waiting", "bob": "waiting"}
        self.processes = {}
        self.signer_threads = []
        self.worker = None
        self.owner = self.context = self.relay_binary = self.pay_binary = None
        self.works = {}
        self.attempt = None
        self.sent = set()
        self.before_delivery = {}
        self.transport_lock = threading.Lock()
        self.tokens = {role: secrets.token_urlsafe(32) for role in ("admin", "alice", "bob")}

    def role(self, token: str) -> str | None:
        return next((role for role, secret in self.tokens.items()
                     if hmac.compare_digest(token, secret)), None)

    def state(self, role: str, origin: str) -> dict:
        with self.lock:
            out = {
                "role": role, "phase": self.phase, "error": self.error,
                "vaults": self.vaults, "payment": self.payment, "txid": self.txid,
                "approvals_count": sum(value == "approved" for value in self.signers.values()),
                "network": self.chain.snapshot(),
            }
            if role in self.review:
                out["review"] = self.review[role]
                out["own_status"] = self.signers[role]
            if role == "admin":
                out["signers"] = self.signers.copy()
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

    def _check_binaries(self):
        binary("loki_setup_member")
        self.pay_binary = binary("loki_member_payment")
        feature = subprocess.run([str(self.pay_binary), "features"], capture_output=True, timeout=5)
        if feature.returncode or feature.stdout != b"relay-backed-signing=1\n":
            raise ValueError("build loki_member_payment with --features relay-communication")
        binary("loki_relay_member")
        relay_run.find_binary("loki-relay-server", workspace=POC.parent / "communication")

    def create_vault(self):
        with self.lock:
            if self.phase != "idle":
                raise ValueError("reset this demo before creating another vault")
            self._check_binaries()
            self.phase = "creating_vault"
            self.error = None
            self.worker = threading.Thread(target=self._create_vault, daemon=True)
            self.worker.start()

    def _create_vault(self):
        try:
            self.chain.start()
            self._command([sys.executable, str(POC / "run-member-payment.py"),
                           "--name", self.chain.name, "--state", str(RUN), "--stage", "setup"], timeout=1200)
            vaults = json.loads((RUN / "vaults.json").read_text())
            if vaults["source"] == vaults["recipient"] or vaults["funded"]:
                raise RuntimeError("vault setup returned invalid addresses or funding state")
            with self.lock:
                self.vaults = vaults
                self.phase = "vault_ready"
        except Exception as error:
            self._fail(error)

    def fund(self):
        with self.lock:
            if self.phase != "vault_ready" or not self.vaults:
                raise ValueError("create the vault before funding it")
            self.phase = "funding"
            self.worker = threading.Thread(target=self._fund, daemon=True)
            self.worker.start()

    def _fund(self):
        try:
            self._command([sys.executable, str(POC / "run-member-payment.py"),
                           "--name", self.chain.name, "--state", str(RUN), "--stage", "fund"], timeout=300)
            vaults = json.loads((RUN / "vaults.json").read_text())
            if vaults != {**self.vaults, "funded": True}:
                raise RuntimeError("funding changed the vault addresses")
            with self.lock:
                self.vaults = vaults
                self.phase = "funded"
        except Exception as error:
            self._fail(error)

    def propose(self, amount: int, memo: str):
        if not isinstance(amount, int) or isinstance(amount, bool) or not 0 < amount < 100_000_000:
            raise ValueError("amount must be between 1 and 99,999,999 zat")
        if not isinstance(memo, str) or not 0 < len(memo.encode("utf-8")) <= 512:
            raise ValueError("memo must contain 1 to 512 UTF-8 bytes")
        with self.lock:
            if self.phase != "funded":
                raise ValueError("fund the vault before proposing a payment")
            self.phase = "preparing_payment"
            self.error = None
            self.worker = threading.Thread(target=self._prepare, args=(amount, memo), daemon=True)
            self.worker.start()

    def _prepare(self, amount: int, memo: str):
        try:
            self._command([
                sys.executable, str(POC / "run-member-payment.py"),
                "--name", self.chain.name, "--state", str(RUN), "--manual", "--stage", "prepare",
                "--amount-zat", str(amount), f"--memo={memo}",
            ], timeout=1200)
            manifest = json.loads((RUN / "payment" / "payment.json").read_text())
            if manifest["amount_zat"] != amount:
                raise RuntimeError("setup output differs from the payment manifest")
            payment = {
                "id": manifest["payment"], "source": self.vaults["source"],
                "recipient": self.vaults["recipient"], "amount_zat": manifest["amount_zat"],
                "memo": bytes.fromhex(manifest["memo"]).decode("utf-8"),
                "fee_zat": manifest["fee_zat"], "change_zat": manifest["change_zat"],
                "expiry_height": manifest["expiry_height"],
            }
            self.attempt = manifest["attempt"]
            self.owner = three_members.MemberEnvironments.create(RUN / "relay")
            deadline = time.monotonic() + 900
            self.context, _hashes, _isolation, _server, self.relay_binary = three_members.prepare_existing(
                self.owner, RUN / "source", free_relay_ports(), POC.parent / "communication", POC, deadline)
            for member in self.context.members:
                work = member.root / "payment" / manifest["attempt"]
                work.parent.mkdir(mode=0o700)
                work.mkdir(mode=0o700)
                relay_run._write_new(work / "payment.json", (RUN / "payment" / "payment.json").read_bytes(), 0o600)
                self.works[member.member_id] = work
            for member in self.context.members[:2]:
                if "commitments published" not in self._payment_command(member, "commit"):
                    raise RuntimeError("member did not publish commitments")
                self._pump()
            if "payment package published" not in self._payment_command(self.context.members[0], "package"):
                raise RuntimeError("proposer did not publish the checked payment package")
            self._pump()
            for name, member in (("alice", self.context.members[0]), ("bob", self.context.members[1])):
                self.before_delivery[name] = {item["id"] for item in
                    three_members.status(self.context, self.relay_binary, member, time.monotonic() + 120)["messages"]}
            with self.lock:
                self.payment = payment
                self.phase = "waiting_for_reviews"
            for name, member in (("alice", self.context.members[0]), ("bob", self.context.members[1])):
                args = self._payment_args(member, "approve")
                process = subprocess.Popen(args, cwd=member.root,
                                           stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT, text=True, bufsize=1)
                with self.lock:
                    self.processes[name] = process
                reader = threading.Thread(target=self._read_signer, args=(name, process), daemon=True)
                self.signer_threads.append(reader)
                reader.start()
        except Exception as error:
            self._fail(error)

    def _payment_args(self, member, action, *extra):
        return relay_payment.payment_command(
            self.owner, member, self.pay_binary, self.context.roster,
            self.works[member.member_id], self.chain.client.rpc_address, action, *extra)

    def _payment_command(self, member, action, *extra, timeout=300):
        result = command(self._payment_args(member, action, *extra), self.cancel,
                         timeout, cwd=str(member.root))
        if result.returncode:
            raise RuntimeError((result.stderr or result.stdout).strip()[-1000:]
                               or f"{action} exited {result.returncode}")
        return result.stdout

    def _pump(self):
        with self.transport_lock:
            relay_payment.pump(self.context, self.relay_binary, self.works,
                               self.attempt, self.sent, time.monotonic() + 120)

    def _deliver_approval(self, name):
        self._pump()
        member = self.context.members[0 if name == "alice" else 1]
        current = three_members.status(self.context, self.relay_binary, member, time.monotonic() + 120)
        delivered = [item for item in current["messages"]
                     if item["id"] not in self.before_delivery[name] and item["kind"] == "test"]
        return len(delivered) == 2 and all(item["stored_whole"] == "1" for item in delivered)

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
                if line == "signed locally; approval delivery pending relay storage":
                    lines.append(line)
            code = process.wait()
            locally_signed = code == 0 and lines[-1:] == [
                "signed locally; approval delivery pending relay storage"]
            delivered = False
            if locally_signed:
                try:
                    delivered = self._deliver_approval(name)
                except Exception as error:
                    with self.lock:
                        self.error = f"{name}'s share is saved locally; relay delivery needs retry: {error}"
            with self.lock:
                if locally_signed:
                    self.signers[name] = "approved" if delivered else "delivery_pending"
                    if delivered:
                        self.error = None
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
        if role not in self.review or action not in ("approve", "decline", "retry"):
            raise ValueError("a signer must approve or decline")
        with self.lock:
            if self.phase != "waiting_for_reviews":
                raise ValueError("this signing attempt is no longer awaiting approvals")
            if action == "retry":
                if self.signers[role] != "delivery_pending":
                    raise ValueError("this member has no saved approval to retry")
                self.signers[role] = "signing"
                reader = threading.Thread(target=self._retry_delivery, args=(role,), daemon=True)
                self.signer_threads.append(reader)
                reader.start()
                return
            if self.signers[role] != "reviewing" or not self.review[role]:
                raise ValueError("this member has no verified review awaiting a decision")
            process = self.processes[role]
            if process.poll() is not None:
                raise ValueError("signing process ended; reset to retry")
            self.signers[role] = "signing" if action == "approve" else "declined"
            process.stdin.write(f"APPROVE {self.payment['id']}\n" if action == "approve" else "DECLINE\n")
            process.stdin.flush()

    def _retry_delivery(self, role):
        try:
            member = self.context.members[0 if role == "alice" else 1]
            self._payment_command(member, "resend")
            delivered = self._deliver_approval(role)
            with self.lock:
                self.signers[role] = "approved" if delivered else "delivery_pending"
                if delivered:
                    self.error = None
                    if all(value == "approved" for value in self.signers.values()):
                        self.phase = "ready_to_send"
        except Exception as error:
            with self.lock:
                self.signers[role] = "delivery_pending"
                self.error = f"{role}'s relay delivery needs retry: {error}"

    def finish(self):
        with self.lock:
            if self.phase != "ready_to_send":
                raise ValueError("both members must approve before sending")
            self.phase = "sending"
            self.worker = threading.Thread(target=self._finish, daemon=True)
            self.worker.start()

    def _finish(self):
        try:
            member = self.context.members[2]
            process = subprocess.Popen(self._payment_args(member, "finish"), cwd=member.root,
                                       stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True)
            deadline = time.monotonic() + 900
            try:
                while process.poll() is None:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("finishing timed out")
                    self._pump()
                    time.sleep(0.1)
                out, err = process.communicate(timeout=2)
                if process.returncode:
                    raise RuntimeError((err or out).strip()[-1000:] or "finisher stopped")
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
            match = re.search(r"broadcast txid=([0-9a-f]{64}) payment=([0-9a-f]{64})", out)
            if not match or match.group(2) != self.payment["id"]:
                raise RuntimeError("finisher did not return the expected payment")
            txid = match.group(1)
            with self.lock:
                self.txid = txid
                self.phase = "broadcast"
            self.chain.mine(3)
            verified = self._payment_command(member, "verify", txid)
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
            if reader.is_alive():
                raise ValueError("wait for the current approval to finish before resetting")
        self.signer_threads.clear()

    def reset(self):
        with self.lock:
            if self.worker and self.worker.is_alive():
                raise ValueError("wait for the current operation to finish before resetting")
        self._stop_signers()
        with self.lock:
            self._close_owner()
            self.chain.stop()
            if ROOT.exists():
                shutil.rmtree(ROOT)
            self.cancel = threading.Event()
            self.chain = ManagedTHS(ROOT, lambda *_: None, self.cancel)
            self.phase = "idle"
            self.error = self.vaults = self.payment = self.txid = None
            self.review = {"alice": None, "bob": None}
            self.signers = {"alice": "waiting", "bob": "waiting"}
            self.context = self.relay_binary = self.pay_binary = None
            self.works = {}
            self.attempt = None
            self.sent = set()
            self.before_delivery = {}

    def _close_owner(self):
        if not self.owner and (RUN / "relay").exists():
            record = json.loads((RUN / "relay" / relay_run.OwnedRun.MARKER).read_text())
            self.owner = three_members.MemberEnvironments.reopen(
                RUN / "relay", expected_run_id=record["run_id"])
        if self.owner:
            self.owner.close(timeout=10)
            self.owner.delete(expected_run_id=self.owner.run_id)
            self.owner = None

    def close(self):
        self.cancel.set()
        self._stop_signers()
        if self.worker and self.worker.is_alive():
            self.worker.join(timeout=30)
            if self.worker.is_alive():
                print("active operation did not settle; saved THS ownership for recovery", file=sys.stderr)
                return
        self._close_owner()
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
                  "/member.css": ("member.css", "text/css; charset=utf-8"),
                  "/fonts/geist.woff2": ("fonts/geist.woff2", "font/woff2"),
                  "/fonts/geist-mono.woff2": ("fonts/geist-mono.woff2", "font/woff2"),
                  "/fonts/young-serif.woff2": ("fonts/young-serif.woff2", "font/woff2")}
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
            if path == "/api/create-vault" and role == "admin":
                FLOW.create_vault()
            elif path == "/api/fund" and role == "admin":
                FLOW.fund()
            elif path == "/api/propose" and role == "alice":
                FLOW.propose(body.get("amount_zat"), body.get("memo"))
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
    ROOT.parent.mkdir(parents=True, exist_ok=True)
    lock_file = ROOT.with_suffix(".lock").open("a")
    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        parser.error("another member demo already owns this sandbox")
    FLOW.chain.recover()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    for label, role in (("Carol", "admin"), ("Alice", "alice"), ("Bob", "bob")):
        print(f"{label}: http://127.0.0.1:{args.port}/#{FLOW.tokens[role]}", flush=True)
    print("Open each member URL in a separate browser profile.", flush=True)
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
