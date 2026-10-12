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
import subprocess
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DEMO = Path(__file__).resolve().parent
POC = DEMO.parent
REPO = POC.parent
ROOT = Path(os.environ.get("LOKI_MEMBER_DEMO_ROOT", DEMO / ".member-sandbox")).resolve()
if ROOT.name != ".member-sandbox" and not ROOT.name.startswith("loki-member-demo-"):
    raise RuntimeError("demo state directory must be named .member-sandbox or loki-member-demo-*")
RUN = ROOT / "run"
STATIC = DEMO / "static"
# shortcut: one local process owns three fixed member stores; replace with member-owned setup before custody use.
MEMBERS = {"alice": 1, "bob": 2, "carol": 3}
PAIRS = {"AB": ("alice", "bob"), "AC": ("alice", "carol"), "BC": ("bob", "carol")}
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
        self.lock = threading.RLock()
        self.cancel = threading.Event()
        self.chain = ManagedTHS(ROOT, lambda *_: None, self.cancel)
        self.phase = "interrupted" if RUN.exists() else "idle"
        self.error = "an unfinished attempt was interrupted; reset to retry" if RUN.exists() else None
        self.vaults = None
        self.payment = None
        self.txid = None
        self.review = dict.fromkeys(MEMBERS)
        self.signers = dict.fromkeys(MEMBERS, "not_requested")
        self.processes = {}
        self.signer_threads = []
        self.worker = None
        self.pay_binary = None
        self.delivery = "pending"
        self.substage = None
        self.approver_stored = dict.fromkeys(MEMBERS, False)
        self.relay = self._new_relay()
        self.leases = self.relay.leases
        self.member_sandbox = {}
        self.tokens = {role: secrets.token_urlsafe(32) for role in MEMBERS}
        self.creator = None

    def recover(self):
        relay_demo.reap_recorded(ROOT / "relay")
        self.chain.recover()

    def role(self, token: str) -> str | None:
        return next((role for role, secret in self.tokens.items()
                     if hmac.compare_digest(token, secret)), None)

    def state(self, role: str) -> dict:
        with self.lock:
            out = {
                "role": role, "phase": self.phase, "error": self.error,
                "vaults": self.vaults, "payment": self.payment, "txid": self.txid,
                "creator": self.creator,
                "approver_stored": self.approver_stored.copy(),
                "substage": self.substage, "delivery": self.delivery,
                "approvals_count": sum(value == "approved" for value in self.signers.values()),
                "network": self.chain.snapshot(),
            }
            out["review"] = self.review[role]
            out["own_status"] = self.signers[role]
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
        self.relay.server = run.find_binary("loki-relay-server", workspace=REPO / "communication")

    def create_vault(self, role: str):
        with self.lock:
            if self.phase != "idle":
                raise ValueError("reset this demo before creating another vault")
            self._check_binaries()
            self.creator = role
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

    def propose(self, role: str, amount: int, memo: str, pair: str, recipient: str):
        if not isinstance(amount, int) or isinstance(amount, bool) or not 0 < amount < 100_000_000:
            raise ValueError("amount must be between 1 and 99,999,999 zat")
        if not isinstance(memo, str) or not 0 < len(memo.encode("utf-8")) <= 512:
            raise ValueError("memo must contain 1 to 512 UTF-8 bytes")
        if not isinstance(pair, str) or pair not in PAIRS:
            raise ValueError("choose two vault members to approve")
        if not isinstance(recipient, str) or not 10 <= len(recipient) <= 512 or any(c.isspace() for c in recipient):
            raise ValueError("enter a recipient unified address")
        with self.lock:
            if self.phase != "funded":
                raise ValueError("fund the vault before proposing a payment")
            self.phase = "preparing_payment"
            self.error = None
            self.worker = threading.Thread(target=self._prepare,
                                           args=(role, amount, memo, pair, recipient), daemon=True)
            self.worker.start()

    def _prepare(self, role: str, amount: int, memo: str, pair: str, recipient: str):
        try:
            self._command([
                sys.executable, str(POC / "run-member-payment.py"),
                "--name", self.chain.name, "--state", str(RUN), "--manual", "--stage", "prepare",
                "--amount-zat", str(amount), f"--memo={memo}",
                "--proposer", str(MEMBERS[role]), "--pair", pair, "--recipient", recipient,
                "--transport", "relay",
            ], timeout=1200)
            manifest = json.loads((RUN / "payment" / "payment.json").read_text())
            pair_roles = PAIRS[pair]
            if manifest["amount_zat"] != amount or manifest["pair"] != [MEMBERS[name] for name in pair_roles]:
                raise RuntimeError("setup output differs from the payment manifest")
            payment = {
                "id": manifest["payment"], "source": self.vaults["source"],
                "recipient": recipient, "amount_zat": manifest["amount_zat"],
                "memo": bytes.fromhex(manifest["memo"]).decode("utf-8"),
                "fee_zat": manifest["fee_zat"], "change_zat": manifest["change_zat"],
                "expiry_height": manifest["expiry_height"], "pair": pair_roles,
                "proposer": role, "recipient_verified": False,
            }
            with self.lock:
                self.payment = payment
                self.signers = {name: ("waiting" if name in pair_roles else "not_requested") for name in MEMBERS}
                self.substage = "relays_starting"
            self.relay.prepare(RUN / "source")
            with self.lock:
                self.phase = "waiting_for_reviews"
                self.substage = "signers_starting"
            self._start_signers()
            with self.lock:
                self.substage = None
        except Exception as error:
            self.relay.stop()
            self._fail(error)

    def _new_relay(self) -> RelayDemo:
        return RelayDemo(
            ROOT, (ROOT / "loki-relay-server", ROOT / "loki_relay_member", ROOT / "loki_setup_member"),
            self.cancel, None, snapshots=True)

    def _payment_env(self):
        return self.chain.client.env() if self.chain.client else None

    def _start_signers(self, transport: str = "relay") -> None:
        for name in self.payment["pair"]:
            number = MEMBERS[name]
            owner = RUN / "source" / f"member-{number}"
            args = self.wrap_member(number, [
                str(binary("loki_member_payment")), "sign", str(owner),
                str(owner / "pass.txt"), str(RUN / "source" / "roster.json"),
                str(RUN / "payment"), "--transport", transport])
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
                if line == "stored":
                    lines.append(line)
            code = process.wait()
            approved = f"approved payment {self.payment['id']} as member {MEMBERS[name]}"
            stored_after_approval = (
                code == 0
                and approved in lines
                and lines[-1:] == ["stored"]
                and lines.index(approved) < lines.index("stored")
            )
            with self.lock:
                if stored_after_approval:
                    self.signers[name] = "approved"
                    self.approver_stored[name] = True
                    if all(self.signers[role] == "approved" for role in self.payment["pair"]):
                        self.phase = "ready_to_send"
                elif approved in lines:
                    self.signers[name] = "delivery_pending"
                    self.error = f"{name}'s share is saved locally; relay delivery needs retry"
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
            if role not in self.payment["pair"]:
                raise ValueError("this member is not asked to approve this payment")
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
            worker = self.relay.workers.get(MEMBERS[role])
            if worker is not None and not worker.settled.wait(5):
                raise RuntimeError("payment worker did not settle")
            self.resend_saved_share(MEMBERS[role])
            with self.lock:
                self.signers[role] = "approved"
                self.approver_stored[role] = True
                self.error = None
                if all(self.signers[member] == "approved" for member in self.payment["pair"]):
                    self.phase = "ready_to_send"
        except Exception as error:
            with self.lock:
                self.signers[role] = "delivery_pending"
                self.error = f"{role}'s relay delivery needs retry: {error}"

    def finish(self, role: str):
        with self.lock:
            if self.phase != "ready_to_send":
                raise ValueError("both members must approve before sending")
            self.phase = "sending"
            self.worker = threading.Thread(target=self._finish, args=(role,), daemon=True)
            self.worker.start()

    def _finish(self, role: str):
        try:
            member_id = MEMBERS[role]
            self.relay.settle(timeout=5)
            owner = RUN / "source" / f"member-{member_id}"
            base = [str(owner), str(owner / "pass.txt"), str(RUN / "source" / "roster.json"),
                    str(RUN / "payment")]
            program = str(binary("loki_member_payment"))
            out = self.relay.run_payment(
                member_id, self.wrap_member(member_id, [program, "finish", *base, "--transport", "relay"]),
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
                member_id, self.wrap_member(member_id, [program, "verify", *base, "--transport", "relay", txid]),
                timeout=900, env=self._payment_env(), cwd=str(POC))
            if f"verified mined txid={txid}" not in verified:
                raise RuntimeError("mined transaction verification did not match")
            local_recipient = self.payment["recipient"] == self.vaults["recipient"]
            if local_recipient:
                recipient = RUN / "recipient" / "member-1"
                received = self._command(self.wrap_member("recipient", [
                    program, "receive", str(recipient), str(recipient / "pass.txt"),
                    str(RUN / "recipient" / "roster.json"), str(RUN / "payment"),
                    "--transport", "relay", txid,
                ]))
                if f"recipient independently decrypted txid={txid}" not in received:
                    raise RuntimeError("recipient vault did not verify the payment")
            with self.lock:
                self.payment["recipient_verified"] = local_recipient
                self.phase = "confirmed"
        except Exception as error:
            self._fail(error)

    def resend_saved_share(self, member_id: int) -> str:
        """Resend a saved share through the relay. Approval does not mean the share was fetched."""
        if not self.payment or member_id not in [MEMBERS[role] for role in self.payment["pair"]]:
            raise ValueError("only a selected signer can resend")
        if self.delivery != "pending":
            raise ValueError("saved-share resend is only while delivery is pending")
        owner = RUN / "source" / f"member-{member_id}"
        return self.relay.run_payment(member_id, self.wrap_member(member_id, [
            str(binary("loki_member_payment")), "resend", str(owner), str(owner / "pass.txt"),
            str(RUN / "source" / "roster.json"), str(RUN / "payment"), "--transport", "relay",
        ]), timeout=300, env=self._payment_env(), cwd=str(POC))

    def bind_member_sandbox(self) -> None:
        """Deny mailbox, other member roots, and relay stores for later payment children."""
        import relay_sandbox
        mailbox = RUN / "payment" / "mailbox"
        relay_root = ROOT / "relay"
        members = {member_id: RUN / "source" / f"member-{member_id}" for member_id in (1, 2, 3)}
        profiles = {}
        for member_id, root in members.items():
            denied = [members[other] for other in members if other != member_id]
            denied += [mailbox, relay_root]
            profiles[member_id] = relay_sandbox.write_member_profile(
                ROOT / "profiles" / f"member-{member_id}.sb", denied)
        profiles["recipient"] = relay_sandbox.write_member_profile(
            ROOT / "profiles" / "recipient.sb",
            [*members.values(), mailbox, relay_root])
        self.member_sandbox = profiles

    def wrap_member(self, member_id, argv: list[str]) -> list[str]:
        profile = self.member_sandbox.get(member_id)
        if profile is None:
            return list(argv)
        return ["/usr/bin/sandbox-exec", "-f", str(profile), *argv]

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

    def reset(self, role: str):
        with self.lock:
            if self.phase != "interrupted" and role != self.creator:
                raise ValueError("only the member who started this local test can reset it")
            if self.worker and self.worker.is_alive():
                raise ValueError("wait for the current operation to finish before resetting")
        sandboxed = bool(self.member_sandbox)
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
            self.error = self.vaults = self.payment = self.txid = None
            self.delivery = "pending"
            self.substage = None
            self.creator = None
            self.review = dict.fromkeys(MEMBERS)
            self.signers = dict.fromkeys(MEMBERS, "not_requested")
            self.approver_stored = dict.fromkeys(MEMBERS, False)
            self.member_sandbox = {}
            if sandboxed:
                self.bind_member_sandbox()

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
            return self.json(200, FLOW.state(role))
        if path == "/api/relay/snapshot":
            role = self.role()
            if not role:
                return self.json(401, {"error": "open a member link from the coordinator"})
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            try:
                member = int(query.get("member", ["0"])[0])
            except ValueError:
                return self.json(400, {"error": "member must be 1, 2, or 3"})
            allowed = {MEMBERS[role]}
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
                  "/member.css": ("member.css", "text/css; charset=utf-8"),
                  "/relay.js": ("relay.js", "text/javascript; charset=utf-8"),
                  "/relay.css": ("relay.css", "text/css; charset=utf-8")}
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
            if path == "/api/create-vault":
                FLOW.create_vault(role)
            elif path == "/api/fund":
                FLOW.fund()
            elif path == "/api/propose":
                FLOW.propose(role, body.get("amount_zat"), body.get("memo"),
                             body.get("pair"), body.get("recipient"))
            elif path == "/api/decide":
                FLOW.decide(role, body.get("action"))
            elif path == "/api/finish":
                FLOW.finish(role)
            elif path == "/api/reset":
                FLOW.reset(role)
            elif path == "/api/relay/restart" and role == FLOW.creator:
                FLOW.relay.restart_relay(body.get("relay"))
            elif path == "/api/relay/stop" and role == FLOW.creator:
                FLOW.relay.stop_relay(body.get("relay"))
            elif path == "/api/relay/member" and role == FLOW.creator:
                member = body.get("member")
                action = body.get("action")
                if action == "pause":
                    FLOW.relay.pause_member(member)
                elif action == "resume":
                    FLOW.relay.resume_member(member)
                else:
                    raise ValueError("action must be pause or resume")
            elif path == "/api/relay/resend" and role == FLOW.creator:
                FLOW.resend_saved_share(body.get("member"))
            else:
                return self.json(403, {"error": "this member cannot take that action"})
        except (ValueError, RuntimeError, json.JSONDecodeError) as error:
            return self.json(400, {"error": str(error)})
        return self.json(200, {"ok": True})

    def log_message(self, *_):
        pass  # URLs carry no token; keep the local demo quiet.


def use_sandbox(path: Path) -> Flow:
    """Point this process at a fresh sandbox before any chain recovery."""
    global ROOT, RUN, FLOW
    ROOT = Path(path).resolve()
    RUN = ROOT / "run"
    FLOW = Flow()
    return FLOW



def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8790)
    parser.add_argument("--sandbox", type=Path)
    args = parser.parse_args()
    if args.sandbox is not None:
        use_sandbox(args.sandbox)
    if os.environ.get("LOKI_MEMBER_SANDBOX") == "1":
        if sys.platform != "darwin" or not Path("/usr/bin/sandbox-exec").is_file():
            parser.error("macOS sandbox-exec is required for the relay payment gate")
        FLOW.bind_member_sandbox()
    lock_path = ROOT.with_suffix(".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_file = lock_path.open("a")
    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        parser.error("another member demo already owns this sandbox")
    FLOW.recover()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    for role, token in FLOW.tokens.items():
        print(f"{role.title()}: http://127.0.0.1:{args.port}/#{token}", flush=True)
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
