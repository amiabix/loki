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
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DEMO = Path(__file__).resolve().parent
POC = DEMO.parent
REPO = POC.parent
ROOT = DEMO / ".member-sandbox"
RUN = ROOT / "run"
STATIC = DEMO / "static"
sys.path.insert(0, str(POC))

from managed_ths import ManagedTHS, command  # noqa: E402
import relay_demo  # noqa: E402
import relay_observation  # noqa: E402
from relay_demo import RelayDemo  # noqa: E402
import run  # noqa: E402


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
        relay_demo.reap_recorded(ROOT / "relay")
        self.lock = threading.RLock()
        self.cancel = threading.Event()
        self.chain = ManagedTHS(ROOT, lambda *_: None, self.cancel)
        interrupted = RUN.exists()
        self.phase = "interrupted" if interrupted else "idle"
        self.error = "an unfinished attempt was interrupted; reset to retry" if interrupted else None
        self.payment = None
        self.txid = None
        self.delivery = "pending"
        self.review = {"alice": None, "bob": None}
        self.signers = {"alice": "waiting", "bob": "waiting"}
        self.processes = {}
        self.signer_threads = []
        self.worker = None
        self.substage = None
        self.relay = self._new_relay()
        self.leases = self.relay.leases
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
                "substage": self.substage,
                "delivery": self.delivery,
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
            self._preflight_relay()
            with self.lock:
                self.substage = "ths_starting"
            self.chain.start()
            with self.lock:
                self.substage = "vaults_preparing"
            self._prepare_fixture(amount, memo, transport="relay")
            with self.lock:
                self.substage = "relays_starting"
            self.relay.prepare(RUN / "source")
            with self.lock:
                self.substage = "signers_starting"
            self._start_signers(transport="relay")
        except Exception as error:
            try:
                self.relay.stop()
            except Exception:
                pass
            self._fail(error)

    def _preflight_relay(self) -> None:
        run.find_binary("loki-relay-server", workspace=REPO / "communication")
        run.find_binary("loki_relay_member", workspace=POC)
        run.find_binary("loki_member_payment", workspace=POC)
        binary("loki_setup_member")

    def _prepare_fixture(self, amount: int, memo: str, transport: str = "relay") -> None:
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
        if transport != "relay":
            raise RuntimeError("payment preparation uses the relay transport")
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

    def _new_relay(self) -> RelayDemo:
        return RelayDemo(
            ROOT, (ROOT / "loki-relay-server", ROOT / "loki_relay_member", ROOT / "loki_setup_member"),
            self.cancel, None)

    def _payment_env(self):
        return self.chain.client.env() if self.chain.client else None

    def _start_signers(self, transport: str = "relay") -> None:
        for name, number in (("alice", 1), ("bob", 2)):
            owner = RUN / "source" / f"member-{number}"
            args = [str(binary("loki_member_payment")), "sign", str(owner),
                    str(owner / "pass.txt"), str(RUN / "source" / "roster.json"),
                    str(RUN / "payment"), "--transport", transport]
            process = self.relay.start_payment(
                number, args, interactive=True, env=self._payment_env(), cwd=str(POC))
            with self.lock:
                self.processes[name] = process
            reader = threading.Thread(target=self._read_signer, args=(name, process, number), daemon=True)
            self.relay.workers[number].stdout_thread = reader
            self.signer_threads.append(reader)
            reader.start()

    def background_pass(self, member_id: int) -> None:
        """A poll or snapshot pass uses the same lease as a payment command."""
        if self.relay.paused.get(member_id):
            raise RuntimeError(f"member {member_id} is paused")
        self.leases.reserve(member_id, "poll")
        try:
            self._spawn_member_command(member_id)
        finally:
            self.leases.release(member_id)

    def _spawn_member_command(self, member_id: int) -> None:
        return None

    def _read_signer(self, name: str, process: subprocess.Popen, member_id: int | None = None):
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
            program = str(binary("loki_member_payment"))
            out = self.relay.run_payment(
                3, [program, "finish", *base, "--transport", "relay"],
                timeout=900, env=self._payment_env(), cwd=str(POC))
            match = re.search(r"broadcast txid=([0-9a-f]{64}) payment=([0-9a-f]{64})", out)
            if not match or match.group(2) != self.payment["id"]:
                raise RuntimeError("finisher did not return the expected payment")
            txid = match.group(1)
            with self.lock:
                self.txid = txid
                self.phase = "broadcast"
            self.chain.mine(3)
            verified = self.relay.run_payment(
                3, [program, "verify", *base, "--transport", "relay", txid],
                timeout=900, env=self._payment_env(), cwd=str(POC))
            recipient = RUN / "recipient" / "member-1"
            received = self._command([
                program, "receive", str(recipient), str(recipient / "pass.txt"),
                str(RUN / "recipient" / "roster.json"), str(RUN / "payment"),
                "--transport", "relay", txid,
            ])
            if f"verified mined txid={txid}" not in verified or f"recipient independently decrypted txid={txid}" not in received:
                raise RuntimeError("mined transaction verification did not match")
            with self.lock:
                self.phase = "confirmed"
        except Exception as error:
            self._fail(error)

    def resend_saved_share(self, member_id: int) -> str:
        """Resend a saved share through the relay. Approval does not mean the share was fetched."""
        if member_id not in (1, 2):
            raise ValueError("only a selected signer can resend")
        if self.delivery != "pending":
            raise ValueError("saved-share resend is only while delivery is pending")
        owner = RUN / "source" / f"member-{member_id}"
        return self.relay.run_payment(member_id, [
            str(binary("loki_member_payment")), "resend", str(owner), str(owner / "pass.txt"),
            str(RUN / "source" / "roster.json"), str(RUN / "payment"), "--transport", "relay",
        ], timeout=300, env=self._payment_env(), cwd=str(POC))

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
        self.cancel.set()
        self._stop_signers()
        try:
            self.relay.settle(timeout=5)
        except RuntimeError:
            pass
        self.relay.stop()
        with self.lock:
            self.chain.stop()
            if ROOT.exists():
                shutil.rmtree(ROOT)
            self.cancel = threading.Event()
            self.chain = ManagedTHS(ROOT, lambda *_: None, self.cancel)
            self.relay = self._new_relay()
            self.leases = self.relay.leases
            self.phase = "idle"
            self.error = self.payment = self.txid = None
            self.delivery = "pending"
            self.substage = None
            self.review = {"alice": None, "bob": None}
            self.signers = {"alice": "waiting", "bob": "waiting"}

    def note_browser_closed(self) -> None:
        """Closing a browser leaves this controller and its relays running."""
        return None

    def close(self):
        self.cancel.set()
        self._stop_signers()
        try:
            self.relay.settle(timeout=5)
        except RuntimeError:
            pass
        self.relay.stop()
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
        if path == "/api/relay/snapshot":
            role = self.role()
            if not role:
                return self.json(401, {"error": "open a member link from the coordinator"})
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            try:
                member = int(query.get("member", ["0"])[0])
            except ValueError:
                return self.json(400, {"error": "member must be 1, 2, or 3"})
            allowed = {"admin": {1, 2, 3}, "alice": {1}, "bob": {2}}.get(role, set())
            if member not in allowed:
                return self.json(403, {"error": "this member cannot view that relay member"})
            return self.json(200, FLOW.relay.cached_snapshot(member))
        if path == "/api/relay/state":
            role = self.role()
            if not role:
                return self.json(401, {"error": "open a member link from the coordinator"})
            return self.json(200, FLOW.relay.projection.state(role))
        if path == "/api/relay/events":
            role = self.role()
            if not role:
                return self.json(401, {"error": "open a member link from the coordinator"})
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            try:
                after = int(query.get("after", ["0"])[0])
                body = FLOW.relay.projection.events(role, after)
            except (ValueError, relay_observation.Rejected):
                return self.json(400, {"error": "cursor"})
            return self.json(200, body)
        marker = "/api/relay/messages/"
        if path.startswith(marker) and path.endswith("/objects"):
            role = self.role()
            if not role:
                return self.json(401, {"error": "open a member link from the coordinator"})
            message = path[len(marker):-len("/objects")]
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            try:
                after = int(query.get("after", ["0"])[0])
                limit = int(query.get("limit", ["100"])[0])
                body = FLOW.relay.projection.objects(role, message, after, limit)
            except relay_observation.Missing:
                return self.json(404, {"error": "message"})
            except relay_observation.Forbidden:
                return self.json(403, {"error": "this member cannot view that object"})
            except (ValueError, relay_observation.Rejected):
                return self.json(400, {"error": "object page"})
            return self.json(200, body)
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
            elif path == "/api/relay/restart" and role == "admin":
                FLOW.relay.restart_relay(body.get("relay"))
            elif path == "/api/relay/stop" and role == "admin":
                FLOW.relay.stop_relay(body.get("relay"))
            elif path == "/api/relay/member" and role == "admin":
                member = body.get("member")
                action = body.get("action")
                if action == "pause":
                    FLOW.relay.pause_member(member)
                elif action == "resume":
                    FLOW.relay.resume_member(member)
                else:
                    raise ValueError("action must be pause or resume")
            elif path == "/api/relay/resend" and role == "admin":
                FLOW.resend_saved_share(body.get("member"))
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
