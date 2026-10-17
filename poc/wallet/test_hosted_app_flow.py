"""Opt-in hosted (relay) app journey: three relays, admission, three member apps.

Run with LOKI_HOSTED_FLOW=1. The payment part also needs LOKI_THS_INSTANCE set to a
running disposable THS regtest instance; without it only setup runs. Build first:

    cargo build --release --locked --bins --example hosted_ops --features relay-communication
    cargo build --release --locked --manifest-path ../communication/Cargo.toml \\
        -p loki-relay-server -p loki-setup-admission

LOKI_HOSTED_FLOW_PROFILE (release|debug) and LOKI_HOSTED_FLOW_RTT (ms) select the
binary profile and the added operator round-trip time. The run directory, with
`hosted-flow-report.json`, is kept when LOKI_HOSTED_FLOW_KEEP is set.
"""
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import hosted_flow  # noqa: E402


class HostedAppFlowTest(unittest.TestCase):
    def test_hosted_journey_without_external_fingerprint_injection(self):
        if os.environ.get("LOKI_HOSTED_FLOW") != "1":
            self.skipTest("set LOKI_HOSTED_FLOW=1 to run the hosted app journey")
        if shutil.which("unshare") is None:
            self.skipTest("needs util-linux unshare for the operator namespace")
        profile = os.environ.get("LOKI_HOSTED_FLOW_PROFILE", "release")
        temporary = tempfile.mkdtemp(prefix="loki-hosted-flow-")
        if not os.environ.get("LOKI_HOSTED_FLOW_KEEP"):
            self.addCleanup(shutil.rmtree, temporary, True)
        ths = os.environ.get("LOKI_THS_INSTANCE")
        args = SimpleNamespace(
            root=str(Path(temporary) / "run"), profile=profile, operator_profile=profile,
            rtt=float(os.environ.get("LOKI_HOSTED_FLOW_RTT", "0")), ths=ths, base=39100,
            skip_payment=not ths, isolation="unshare", isolation_name="lokins",
            joiner_wait=30, pump="driver", no_exchange=True, legacy_app=False)
        flow = hosted_flow.Flow(args)
        try:
            hosted_flow.journey(flow)
        finally:
            flow.stop()
        result = hosted_flow.report(flow.root)
        steps = [mark["step"] for mark in result["marks"]]
        # Joiners must show the roster fingerprint themselves (the finding-1 regression).
        self.assertIn("joiner_fingerprints_in_ui", steps)
        self.assertNotIn("joiner_fingerprint_missing", steps)
        self.assertIn("payment_activation_ready", steps)
        if ths:
            self.assertIn("confirmed_all", steps)
        self.assertGreater(result["http"]["requests"], 0)
        self.assertTrue(any(op.endswith("setup-step") or op.endswith("setup") for op in result["commands"]))
        print(f"\nhosted flow report: {flow.root / 'hosted-flow-report.json'}")
        hosted_flow.print_report(result)


if __name__ == "__main__":
    unittest.main()
