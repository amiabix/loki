"""The member seatbelt is proven before a payment, and the public report stays public."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

DEMO = Path(__file__).resolve().parent
sys.path.insert(0, str(DEMO))

import relay_sandbox  # noqa: E402
import verify_relay_payment as verify  # noqa: E402


class SandboxCanaryTest(unittest.TestCase):
    def test_canary_denies_mailbox_peer_root_and_relay_store(self):
        if sys.platform != "darwin":
            self.skipTest("macOS sandbox-exec")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            result = relay_sandbox.denial_canary(root)
            self.assertEqual(result["mailbox_denial"], True)
            self.assertEqual(result["peer_denial"], True)
            self.assertEqual(result["relay_denial"], True)
            self.assertEqual(result["own_read"], True)
            self.assertFalse((root / "run").exists())
            self.assertFalse((root / "relay").exists())


class PublicReportTest(unittest.TestCase):
    def test_report_keeps_public_fields_and_rejects_secrets(self):
        report = verify.build_report({
            "version": 1,
            "run_id": "demo",
            "source_revision": "abc",
            "binary_hashes": {"loki_member_payment": "ab" * 32},
            "vault": "vault",
            "roster_fingerprint": "finger",
            "relays": [{"run_id": "aa", "receipt_key": "bb"}],
            "carriers": [{"message_id": "cd" * 32, "envelope_hash": "ef" * 32}],
            "receipt_digests": ["12" * 32],
            "mailbox_denial": True,
            "txid": "34" * 32,
            "scenarios": [
                {"name": name, "label": "payment" if name.startswith("payment") else "transport",
                 "executed": True, "result": "passed"}
                for name in verify.SCENARIOS
            ],
            "token": "secret-token",
            "coordinator_url": "http://127.0.0.1:9/#secret-token",
        }, forbidden=("secret-token", "pass.txt", "passphrase"))
        encoded = json.dumps(report)
        self.assertNotIn("secret-token", encoded)
        self.assertNotIn("http://", encoded)
        self.assertEqual(report["mailbox_denial"], True)
        self.assertEqual(report["txid"], "34" * 32)
        self.assertEqual([item["name"] for item in report["scenarios"]], list(verify.SCENARIOS))
        with self.assertRaises(ValueError):
            verify.build_report({
                "version": 1, "run_id": "demo", "mailbox_denial": True, "txid": "34" * 32,
                "scenarios": report["scenarios"], "note": "secret-token",
            }, forbidden=("secret-token",))

    def test_payment_failure_keeps_the_reason_and_drops_paths(self):
        reason = verify.public_failure(
            "timed out waiting for member 1 Package /Users/megabyte/pass.txt "
            "http://127.0.0.1:9/#tok")
        self.assertIn("timed out waiting for member 1 Package", reason)
        self.assertNotIn("pass.txt", reason)
        self.assertNotIn("http", reason)
        self.assertNotIn("/Users", reason)
        self.assertEqual(verify.public_failure(""), "payment failed")

    def test_transport_scenarios_reads_a_fault_result(self):
        harness = DEMO.parent.parent / "communication" / "harness"
        sys.path.insert(0, str(harness))
        import run
        sentinel = {"scenarios": [{
            "scenario": "offline_delivery", "outcome": "passed", "simulation": False,
        }]}
        original = run.run_faults

        def fake(root, ports, **kwargs):
            return run.FaultResult(sentinel)

        run.run_faults = fake
        try:
            with tempfile.TemporaryDirectory() as temporary:
                mapped = verify.transport_scenarios(Path(temporary), 60)
        finally:
            run.run_faults = original
        self.assertEqual(mapped["offline_delivery"]["outcome"], "passed")

    def test_unexecuted_scenario_does_not_pass(self):
        scenarios = [
            {"name": name, "label": "transport", "executed": True, "result": "passed"}
            for name in verify.SCENARIOS
        ]
        scenarios[1]["executed"] = False
        with self.assertRaises(verify.GateError):
            verify.require_scenarios(scenarios)


if __name__ == "__main__":
    unittest.main()
