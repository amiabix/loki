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
            f"print('approved payment {payment} as member 1', flush=True)\n"
        )
        process = subprocess.Popen([sys.executable, "-u", "-c", script],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True)
        self.addCleanup(lambda: process.kill() if process.poll() is None else None)
        self.addCleanup(process.stdout.close)
        self.addCleanup(process.stdin.close)
        flow.processes["alice"] = process
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
