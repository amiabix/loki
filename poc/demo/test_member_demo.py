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

    def test_member_tokens_are_distinct_and_payment_needs_a_funded_vault(self):
        flow = self.flow()
        for name, token in flow.tokens.items():
            self.assertEqual(flow.role(token), name)
        self.assertEqual(len(set(flow.tokens.values())), 3)
        self.assertIsNone(flow.role("wrong"))
        with self.assertRaisesRegex(ValueError, "amount"):
            flow.propose("bob", 100_000_000, "memo", "BC", "uregtest1recipient")
        self.assertEqual(flow.phase, "idle")
        with self.assertRaisesRegex(ValueError, "fund"):
            flow.propose("bob", 40_000_000, "memo", "BC", "uregtest1recipient")
        self.assertIsNone(flow.payment)

    def test_member_state_returns_its_own_review(self):
        flow = self.flow()
        flow.review = {"alice": "Alice's checked payment", "bob": "Bob's checked payment",
                       "carol": "Carol's checked payment"}
        alice = flow.state("alice")
        bob = flow.state("bob")
        carol = flow.state("carol")
        self.assertEqual(alice["review"], "Alice's checked payment")
        self.assertEqual(bob["review"], "Bob's checked payment")
        self.assertNotIn("links", alice)
        self.assertNotIn("links", bob)
        self.assertEqual(carol["review"], "Carol's checked payment")
        self.assertNotIn("signers", alice)
        self.assertNotIn("signers", bob)

    def test_unselected_member_cannot_approve(self):
        flow = self.flow()
        flow.payment = {"id": "a" * 64, "pair": ("bob", "carol")}
        flow.phase = "waiting_for_reviews"
        with self.assertRaisesRegex(ValueError, "not asked"):
            flow.decide("alice", "approve")
        self.assertEqual(flow.signers["alice"], "not_requested")

    def test_invalid_pair_does_not_start_preparing(self):
        flow = self.flow()
        flow.phase = "funded"
        with self.assertRaisesRegex(ValueError, "choose two"):
            flow.propose("bob", 12_000_000, "test", "AA", "uregtest1recipient")
        self.assertEqual(flow.phase, "funded")

    def test_actions_are_staged(self):
        flow = self.flow()
        with patch.object(member_demo, "binary", return_value=Path(sys.executable)), \
             patch.object(member_demo.relay_run, "find_binary", return_value=Path(sys.executable)), \
             patch.object(subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=b"relay-backed-signing=1\n")), \
             patch.object(flow, "_create_vault"):
            flow.create_vault("bob")
        self.assertEqual(flow.phase, "creating_vault")
        self.assertEqual(flow.creator, "bob")
        with self.assertRaisesRegex(ValueError, "vault"):
            flow.fund()
        flow.worker.join(timeout=3)

    def test_review_prompt_then_exact_member_approval(self):
        flow = self.flow()
        payment = "a" * 64
        flow.payment = {"id": payment, "pair": ("alice", "bob")}
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
        flow.payment = {"id": payment, "pair": ("alice", "bob")}
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
        flow.payment = {"pair": ("alice", "bob")}
        flow.signers = {"alice": "delivery_pending", "bob": "approved", "carol": "not_requested"}
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
            handler.headers["X-Loki-Token"] = "invalid"
            handler.do_POST()
            self.assertEqual(handler.json.call_args.args[0], 401)
            handler.headers["X-Loki-Token"] = flow.tokens["alice"]
            handler.rfile = BytesIO(b'{"action":"approve"}')
            handler.do_POST()
            self.assertEqual(handler.json.call_args.args[0], 200)
            decide.assert_called_once_with("alice", "approve")

    def test_any_member_can_create_and_propose_with_a_selected_pair(self):
        flow = self.flow()
        handler = member_demo.Handler.__new__(member_demo.Handler)
        handler.server = SimpleNamespace(server_port=8790)
        handler.json = Mock()
        payload = b'{"amount_zat":12000000,"memo":"test","pair":"BC","recipient":"uregtest1recipient"}'
        handler.headers = {"Origin": "http://127.0.0.1:8790", "Content-Type": "application/json",
                           "Content-Length": str(len(payload)), "X-Loki-Token": flow.tokens["bob"]}
        handler.path = "/api/propose"
        with patch.object(member_demo, "FLOW", flow), patch.object(flow, "propose") as propose, \
             patch.object(flow, "create_vault") as create:
            handler.rfile = BytesIO(payload)
            handler.do_POST()
            self.assertEqual(handler.json.call_args.args[0], 200)
            propose.assert_called_once_with("bob", 12_000_000, "test", "BC", "uregtest1recipient")
            handler.path = "/api/create-vault"
            handler.headers["X-Loki-Token"] = flow.tokens["carol"]
            handler.rfile = BytesIO(b'{}')
            handler.headers["Content-Length"] = "2"
            handler.do_POST()
            self.assertEqual(handler.json.call_args.args[0], 200)
            create.assert_called_once_with("carol")


if __name__ == "__main__":
    unittest.main()
