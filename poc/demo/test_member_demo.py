"""The UI may release a share only after that member's CLI review reaches its prompt."""

import subprocess
import sys
import tempfile
import threading
import time
import unittest
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import member_demo


class MemberDemoTest(unittest.TestCase):
    def flow(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        with patch.object(member_demo, "ROOT", root), patch.object(member_demo, "RUN", root / "run"):
            return member_demo.Flow()

    def test_member_tokens_are_distinct_and_amount_is_checked_before_start(self):
        flow = self.flow()
        for name, token in flow.tokens.items():
            self.assertEqual(flow.role(token), name)
        self.assertEqual(len(set(flow.tokens.values())), 3)
        self.assertIsNone(flow.role("wrong"))
        with self.assertRaisesRegex(ValueError, "amount"):
            flow.start(100_000_000, "memo")
        self.assertEqual(flow.phase, "idle")

    def test_member_state_returns_its_own_review(self):
        flow = self.flow()
        flow.review = {"alice": "Alice's checked payment", "bob": "Bob's checked payment"}
        alice = flow.state("alice", "http://127.0.0.1:8790")
        bob = flow.state("bob", "http://127.0.0.1:8790")
        carol = flow.state("admin", "http://127.0.0.1:8790")
        self.assertEqual(alice["review"], "Alice's checked payment")
        self.assertEqual(bob["review"], "Bob's checked payment")
        self.assertNotIn("links", alice)
        self.assertNotIn("links", bob)
        self.assertNotIn("review", carol)

    def test_review_prompt_then_exact_member_approval(self):
        flow = self.flow()
        payment = "a" * 64
        flow.payment = {"id": payment}
        flow.phase = "waiting_for_reviews"
        script = (
            "import sys\n"
            "print('Vault: ' + 'b'*64, flush=True)\n"
            "print('Recipient: uregtest1recipient', flush=True)\n"
            "print('Amount: 40000000 zat; memo: \\\"test\\\"', flush=True)\n"
            "print('Fee: 10000 zat; change to vault: 59990000 zat; expiry height: 1152', flush=True)\n"
            "print('Inputs: 1; candidate: ' + 'c'*64, flush=True)\n"
            f"print('Type APPROVE {payment} to sign:', flush=True)\n"
            f"if input() != 'APPROVE {payment}': sys.exit(1)\n"
            "print('signed locally; approval delivery pending relay storage', flush=True)\n"
        )
        process = subprocess.Popen([sys.executable, "-u", "-c", script],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True)
        self.addCleanup(lambda: process.kill() if process.poll() is None else None)
        self.addCleanup(process.stdout.close)
        self.addCleanup(process.stdin.close)
        flow.processes["alice"] = process
        with patch.object(flow, "_deliver_approval", return_value=True, create=True):
            reader = threading.Thread(target=flow._read_signer, args=("alice", process))
            reader.start()
            deadline = time.monotonic() + 3
            while flow.signers["alice"] != "reviewing" and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertEqual(flow.signers["alice"], "reviewing")
            self.assertIn("Recipient: uregtest1recipient", flow.review["alice"])
            with self.assertRaisesRegex(ValueError, "no verified review"):
                flow.decide("bob", "approve")
            flow.decide("alice", "approve")
            reader.join(timeout=3)
            self.assertFalse(reader.is_alive())
            self.assertEqual(flow.signers["alice"], "approved")

    def test_local_share_is_not_approved_without_relay_delivery(self):
        flow = self.flow()
        payment = "a" * 64
        flow.payment = {"id": payment}
        flow.phase = "waiting_for_reviews"
        script = (
            "import sys\n"
            "print('Vault: checked', flush=True)\n"
            "print('Recipient: checked', flush=True)\n"
            "print('Amount: checked', flush=True)\n"
            "print('Fee: checked', flush=True)\n"
            "print('Inputs: checked', flush=True)\n"
            f"print('Type APPROVE {payment} to sign:', flush=True)\n"
            f"if input() != 'APPROVE {payment}': sys.exit(1)\n"
            "print('signed locally; approval delivery pending relay storage', flush=True)\n"
        )
        process = subprocess.Popen([sys.executable, "-u", "-c", script],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True)
        self.addCleanup(lambda: process.kill() if process.poll() is None else None)
        self.addCleanup(process.stdout.close)
        self.addCleanup(process.stdin.close)
        flow.processes["alice"] = process
        with patch.object(flow, "_deliver_approval", return_value=False, create=True):
            reader = threading.Thread(target=flow._read_signer, args=("alice", process))
            reader.start()
            deadline = time.monotonic() + 3
            while flow.signers["alice"] != "reviewing" and time.monotonic() < deadline:
                time.sleep(.01)
            flow.decide("alice", "approve")
            reader.join(timeout=3)
        self.assertFalse(reader.is_alive())
        self.assertEqual(flow.signers["alice"], "delivery_pending")
        self.assertNotEqual(flow.phase, "ready_to_send")

    def test_delivery_retry_uses_saved_share_without_another_approval_prompt(self):
        flow = self.flow()
        flow.phase = "waiting_for_reviews"
        flow.signers = {"alice": "delivery_pending", "bob": "approved"}
        flow.context = SimpleNamespace(members=[SimpleNamespace(member_id=1)])
        with patch.object(flow, "_payment_command", return_value="resent exact saved approval") as command, \
             patch.object(flow, "_deliver_approval", return_value=True):
            flow.decide("alice", "retry")
            flow.signer_threads[-1].join(timeout=3)
        self.assertEqual(flow.signers["alice"], "approved")
        self.assertEqual(flow.phase, "ready_to_send")
        command.assert_called_once_with(flow.context.members[0], "resend")

    def test_relay_cleanup_uses_its_ownership_record(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            run = root / "run"
            run.mkdir()
            with patch.object(member_demo, "ROOT", root), patch.object(member_demo, "RUN", run):
                flow = member_demo.Flow()
                flow.owner = member_demo.three_members.MemberEnvironments.create(run / "relay")
                flow._close_owner()
                self.assertFalse((run / "relay").exists())
                owner = member_demo.three_members.MemberEnvironments.create(run / "relay")
                owner.close()
                del owner  # A restarted server no longer holds the old process lock.
                flow._close_owner()
                self.assertFalse((run / "relay").exists())

    def test_browser_action_needs_same_origin_and_the_right_member_link(self):
        flow = self.flow()
        handler = member_demo.Handler.__new__(member_demo.Handler)
        handler.path = "/api/decide"
        handler.server = SimpleNamespace(server_port=8790)
        handler.rfile = BytesIO(b'{"action":"approve"}')
        handler.json = Mock()
        with patch.object(member_demo, "FLOW", flow), patch.object(flow, "decide") as decide:
            handler.headers = {"Origin": "https://foreign.example", "Content-Type": "application/json",
                               "Content-Length": "20", "X-Loki-Token": flow.tokens["alice"]}
            handler.do_POST()
            self.assertEqual(handler.json.call_args.args[0], 403)
            handler.headers["Origin"] = "http://127.0.0.1:8790"
            handler.headers["X-Loki-Token"] = flow.tokens["admin"]
            handler.do_POST()
            self.assertEqual(handler.json.call_args.args[0], 403)
            handler.headers["X-Loki-Token"] = flow.tokens["alice"]
            handler.rfile = BytesIO(b'{"action":"approve"}')
            handler.do_POST()
            self.assertEqual(handler.json.call_args.args[0], 200)
            decide.assert_called_once_with("alice", "approve")


if __name__ == "__main__":
    unittest.main()
