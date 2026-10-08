import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ths import THS, loopback_url
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "demo"))
import runner


class EndpointTests(unittest.TestCase):
    def test_rejects_remote_and_ambiguous_endpoints(self):
        for value in ("http://example.com:18232", "https://127.0.0.1:18232",
                      "http://user@127.0.0.1:18232", "http://127.0.0.1:18232/other",
                      "http://127.0.0.1:18232?next=remote", "http://127.0.0.1"):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                loopback_url(value)

    def test_node_error_is_propagated(self):
        chain = THS.__new__(THS)
        chain.rpc_url = "http://127.0.0.1:18242"
        with patch("ths.post", return_value={"error": {"message": "wrong chain"}}):
            with self.assertRaisesRegex(RuntimeError, "wrong chain"):
                chain.rpc("getblockcount")

    def test_future_branch_is_refused(self):
        chain = THS.__new__(THS)
        chain.rpc = Mock(return_value={"chain": "test", "upgrades": {
            "37a5165b": {"status": "active"}}, "consensus": {"nextblock": "future"}})
        with self.assertRaisesRegex(RuntimeError, "NU6.3"):
            chain.check()

    def test_funding_retries_use_same_key_and_pending_is_refused(self):
        chain = THS.__new__(THS)
        chain.app_url = "http://127.0.0.1:32815"
        with patch("ths.post", return_value={"status": "pending"}) as request:
            for _ in range(2):
                with self.assertRaisesRegex(RuntimeError, "funding not confirmed"):
                    chain.fund("test-vault")
            self.assertEqual(request.call_args_list[0], request.call_args_list[1])
            self.assertGreaterEqual(len(request.call_args.args[1]["idempotency_key"]), 8)


class RunnerTests(unittest.TestCase):
    def make_runner(self):
        with patch("runner.atexit.register"), patch("runner.signal.signal"):
            return runner.Runner()

    def test_unrelated_signer_failure_is_not_a_tamper_pass(self):
        instance = self.make_runner()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snap = root / "snapshot"
            snap.mkdir()
            (snap / "candidate_AC.pczt.hex").write_text("fixture")
            instance.restore_honest = Mock()
            instance.run_cli = Mock(side_effect=[True, False])
            with patch.object(runner, "STATE", root), patch.object(runner, "SNAP", snap):
                self.assertFalse(instance.step_tamper("memo"))
            self.assertIn("without the expected refusal", instance.events[-1]["text"])

    def test_rejected_candidate_with_ab_share_is_not_a_pass(self):
        instance = self.make_runner()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snap = root / "snapshot"
            snap.mkdir()
            (snap / "candidate_AC.pczt.hex").write_text("fixture")
            (root / "public").mkdir()
            (root / "public" / "share_AB_alice.hex").write_text("leaked")
            instance.restore_honest = Mock()
            def command(args, *other, **kwargs):
                if args[0] == "review-sign":
                    instance.emit("err", "REFUSED: MemoDiffers")
                    return False
                return True
            instance.run_cli = command
            with patch.object(runner, "STATE", root), patch.object(runner, "SNAP", snap):
                self.assertFalse(instance.step_tamper("memo"))

    def test_disconnect_never_stops_external_ths(self):
        instance = self.make_runner()
        chain = Mock()
        chain.name = "owned-by-developer"
        instance.ths = chain
        instance.stop_chain()
        self.assertIsNone(instance.ths)
        chain.mine.assert_not_called()
        self.assertEqual(chain.mock_calls, [])

    def test_snapshot_reports_unreachable_attached_node(self):
        instance = self.make_runner()
        instance.ths = Mock(name="chain")
        instance.ths.name = "loki"
        instance.ths.rpc_address = "127.0.0.1:18242"
        instance.ths.rpc.side_effect = RuntimeError("node unavailable")
        self.assertFalse(instance.snapshot()["chain_running"])

    def test_reset_removes_only_loki_sandbox(self):
        instance = self.make_runner()
        with tempfile.TemporaryDirectory() as temporary:
            demo = Path(temporary).resolve()
            sandbox = demo / ".sandbox"
            sandbox.mkdir()
            (sandbox / "account").write_text("disposable")
            outside = demo / "external-ths"
            outside.mkdir()
            instance.ths = Mock()
            instance.ths.name = "loki"
            with patch.object(runner, "DEMO", demo), patch.object(runner, "SANDBOX", sandbox), patch.object(runner, "POC", demo):
                self.assertTrue(instance.step_reset())
            self.assertFalse(sandbox.exists())
            self.assertTrue(outside.exists())


if __name__ == "__main__":
    unittest.main()
