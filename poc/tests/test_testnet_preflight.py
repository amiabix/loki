import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location("loki_testnet", Path(__file__).parents[1] / "testnet.py")
testnet = importlib.util.module_from_spec(spec)
spec.loader.exec_module(testnet)


class TestnetPreflightTest(unittest.TestCase):
    def setUp(self):
        self.replies = {
            ("getblockhash", (0,)): testnet.GENESIS,
            ("getblockchaininfo", ()): {
                "chain": "test", "blocks": testnet.NU7_HEIGHT + 20,
                "headers": testnet.NU7_HEIGHT + 20,
                "consensus": {"nextblock": testnet.NU7_BRANCH},
            },
            ("z_gettreestate", (str(testnet.NU7_HEIGHT + 20),)): {
                "ironwood": {"commitments": {"finalRoot": "a" * 64}}},
        }

    def call(self, method, params):
        return self.replies[(method, tuple(params))]

    def test_accepts_public_testnet_nu7_with_ironwood_tree(self):
        self.assertEqual(testnet.preflight(self.call)["network"], "testnet")
        self.replies[("z_gettreestate", (str(testnet.NU7_HEIGHT + 20),))] = {
            "ironwood": {"commitments": {"finalState": "aabb"}}}
        self.assertTrue(testnet.preflight(self.call)["ironwood_tree_available"])

    def test_refuses_regtest_even_when_it_calls_itself_test(self):
        self.replies[("getblockhash", (0,))] = "b" * 64
        with self.assertRaisesRegex(ValueError, "genesis"):
            testnet.preflight(self.call)

    def test_refuses_stale_or_wrong_consensus_branch(self):
        info = self.replies[("getblockchaininfo", ())]
        info["blocks"] = testnet.NU7_HEIGHT - 1
        with self.assertRaisesRegex(ValueError, "NU7 activation"):
            testnet.preflight(self.call)
        info["blocks"] = testnet.NU7_HEIGHT + 20
        info["consensus"]["nextblock"] = "37a5165b"
        with self.assertRaisesRegex(ValueError, "NU7 branch"):
            testnet.preflight(self.call)

    def test_refuses_unsynced_or_missing_ironwood_tree(self):
        info = self.replies[("getblockchaininfo", ())]
        info["headers"] += 20
        with self.assertRaisesRegex(ValueError, "behind"):
            testnet.preflight(self.call)
        info["headers"] = info["blocks"]
        self.replies[("z_gettreestate", (str(info["blocks"]),))] = {}
        with self.assertRaisesRegex(ValueError, "Ironwood tree"):
            testnet.preflight(self.call)

    def test_rejects_nonlocal_rpc_urls(self):
        for url in ("http://example.com:8232", "https://127.0.0.1:8232",
                    "http://user:password@127.0.0.1:8232"):
            with self.subTest(url=url), self.assertRaisesRegex(ValueError, "loopback"):
                testnet.local_rpc(url)


if __name__ == "__main__":
    unittest.main()
