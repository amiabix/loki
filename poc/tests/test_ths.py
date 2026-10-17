import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ths
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

    def test_funding_waits_for_confirmation_with_the_same_key(self):
        chain = THS.__new__(THS)
        chain.app_url = "http://127.0.0.1:32815"
        pending = {"status": "preparing"}
        prepared = {"status": "prepared", "txid": "transaction"}
        confirmed = {"status": "confirmed", "block_hash": "block"}
        with patch("ths.post", side_effect=[pending, prepared, confirmed]) as request, \
                patch.object(ths, "time", create=True) as clock:
            clock.monotonic.return_value = 0
            self.assertEqual(chain.fund("test-vault"), [confirmed])
            self.assertEqual(request.call_args_list[0], request.call_args_list[1])
            self.assertEqual(request.call_args_list[1], request.call_args_list[2])
            self.assertGreaterEqual(len(request.call_args.args[1]["idempotency_key"]), 8)
            self.assertEqual(clock.sleep.call_count, 2)

    def test_funding_pending_has_a_deadline(self):
        chain = THS.__new__(THS)
        chain.app_url = "http://127.0.0.1:32815"
        with patch("ths.post", return_value={"status": "pending"}), \
                patch.object(ths, "time", create=True) as clock:
            clock.monotonic.side_effect = [0, 121]
            with self.assertRaisesRegex(RuntimeError, "funding not confirmed"):
                chain.fund("test-vault")
            clock.sleep.assert_not_called()


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

    def test_stop_delegates_to_owned_network(self):
        instance = self.make_runner()
        instance.network = Mock()
        instance.done.add("start-chain")
        self.assertTrue(instance.stop_chain())
        instance.network.stop.assert_called_once_with()
        self.assertNotIn("start-chain", instance.done)

    def test_snapshot_does_not_treat_completion_as_a_live_network(self):
        instance = self.make_runner()
        instance.done.add("start-chain")
        instance.network = Mock()
        instance.network.snapshot.return_value = {
            "chain_running": False, "funding_state": "confirmed", "run_ended": False,
        }
        with patch.object(instance, "completed_on_disk", return_value=set()):
            snapshot = instance.snapshot()
        self.assertFalse(snapshot["chain_running"])
        self.assertNotIn("start-chain", snapshot["done"])

    def test_reset_removes_only_loki_sandbox(self):
        instance = self.make_runner()
        with tempfile.TemporaryDirectory() as temporary:
            demo = Path(temporary).resolve()
            sandbox = demo / ".sandbox"
            sandbox.mkdir()
            (sandbox / "account").write_text("disposable")
            outside = demo / "external-ths"
            outside.mkdir()
            network = instance.network = Mock()
            with patch.object(runner, "DEMO", demo), patch.object(runner, "SANDBOX", sandbox), patch.object(runner, "POC", demo):
                self.assertTrue(instance.step_reset())
            network.stop.assert_called_once_with()
            self.assertFalse(sandbox.exists())
            self.assertTrue(outside.exists())


if __name__ == "__main__":
    unittest.main()
