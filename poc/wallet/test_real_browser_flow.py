"""Opt-in real Chromium journey through three member apps and relay processes.

Run with LOKI_THS_INSTANCE set to an already running disposable THS regtest.
This exercises the local courier and operator-kit path on one host, not hosted
HTTPS setup or physical-device isolation.
"""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

import test_remote_join as join
from member_app import PAYMENT

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parents[1] / "communication" / "harness"))
import run  # noqa: E402
from ths import THS  # noqa: E402


class RealBrowserPaymentFlow(unittest.TestCase):
    def setUp(self):
        name = os.environ.get("LOKI_THS_INSTANCE")
        if not name:
            self.skipTest("set LOKI_THS_INSTANCE to a disposable THS instance")
        server = HERE.parents[1] / "communication" / "target" / "debug" / "loki-relay-server"
        if not server.is_file():
            self.skipTest("build communication's loki-relay-server first")
        if not PAYMENT.is_file():
            self.fail("Build poc binaries with --features relay-communication before this test")
        feature = subprocess.run([str(PAYMENT), "features"], text=True, capture_output=True)
        if feature.returncode or feature.stdout.strip() != "relay-backed-signing=1":
            self.fail("Build poc binaries with --features relay-communication before this test")
        self.server = server
        self.chain = THS(name)
        self.chain.check()
        self.root = Path(tempfile.mkdtemp(prefix="loki-browser-flow-", dir="/private/tmp"))
        self.completed = False
        self.addCleanup(lambda: shutil.rmtree(self.root) if self.completed else None)

    def browser(self, stage, **values):
        config = self.root / f"{stage}.private.json"
        raw = json.dumps({"urls": self.urls, "privateRoot": str(self.root), **values}).encode()
        descriptor = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(raw)
        result = subprocess.run(["node", str(HERE / "test-real-browser-flow.js"), stage,
                                 str(config)], cwd=HERE.parents[1], text=True,
                                capture_output=True, timeout=600)
        if result.returncode:
            diagnostic = self.root / f"{stage}-failure.private"
            diagnostic.write_text(result.stdout + result.stderr)
            diagnostic.chmod(0o600)
            self.fail(f"Real Chromium {stage} failed; private diagnostic: {diagnostic}")
        return json.loads(result.stdout)

    def wait_for(self, read, check, label, seconds=120):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            result = read()
            if check(result):
                return result
            time.sleep(0.5)
        self.fail(f"Timed out waiting for {label}")

    def test_create_pay_and_confirm_in_three_member_browsers(self):
        apps = [join.App(self.root / "member-1", invite_port=join.free_port(),
                         env={"LOKI_RPC": self.chain.rpc_address})]
        apps.extend(join.App(self.root / f"member-{slot}",
                             env={"LOKI_RPC": self.chain.rpc_address}) for slot in (2, 3))
        for app in apps:
            self.addCleanup(app.stop)
        self.urls = [f"http://127.0.0.1:{app.port}/#{app.token}" for app in apps]
        passphrases = [f"member {slot} browser test passphrase" for slot in (1, 2, 3)]
        setup = self.browser("setup", passphrases=passphrases)
        vault = apps[0].status()["vaults"][0]["vault"]
        self.assertEqual([app.status()["vaults"][0]["vault"] for app in apps], [vault] * 3)
        self.assertEqual([app.api("address", {"vault": vault})["address"] for app in apps],
                         [setup["address"]] * 3)

        owner = run.OwnedRun.create(self.root / "operator-run")
        self.addCleanup(owner.close)
        for folder in ("relays", "public-manifests", "capabilities", "capability-staging"):
            run._mkdir(owner.root / folder)
        deadline = time.monotonic() + 600
        relays = [run._init_relay(owner, index, join.free_port(), self.server, deadline,
                                  1048576, 8388608) for index in (1, 2, 3)]
        for relay in relays:
            relay.child = owner.start([str(self.server), "serve", "--root", str(relay.root),
                                       "--listen", run._listen(relay.endpoint)], cwd=relay.root)
            run._wait_listen(relay.child, run._listen(relay.endpoint), deadline)
        kits = []
        for app in apps:
            kit = app.root / "relay-kit"
            kit.mkdir(mode=0o700)
            shutil.copytree(owner.root / "public-manifests", kit / "manifests")
            shutil.copytree(owner.root / "capabilities", kit / "capabilities")
            kits.append(str(kit))
        self.assertEqual(self.browser("relay", kits=kits), {"relays": "connected"})
        for app in apps:
            status = app.api("relay-status", {"vault": vault})
            self.assertTrue(status["configured"] and status["reachable"], status)

        def funded():
            try:
                return self.chain.fund(setup["address"])
            except RuntimeError as error:
                if "funding not confirmed; retry the same vault" not in str(error):
                    raise
                return []

        self.wait_for(funded, bool, "faucet funding", seconds=300)
        self.wait_for(lambda: apps[0].api("balance", {"vault": vault}),
                      lambda balance: balance["balance_zat"] >= 100_000_000,
                      "source balance")
        def recipient_account():
            rows = json.loads(subprocess.check_output(["ths", "--name", self.chain.name,
                "wallet", "balances", "--json"], text=True))
            return next(row for row in rows if row["id"] == 2)

        recipient = recipient_account()
        self.assertEqual(self.browser("payment", recipient=recipient["unified_address"]),
                         {"broadcast": True})
        payments = apps[2].api(f"payments?vault={vault}")["payments"]
        self.assertEqual(len(payments), 1)
        self.assertEqual(payments[0]["phase"], "broadcast")
        txid = payments[0]["txid"]
        self.chain.mine(3)
        self.assertEqual(self.browser("confirmed"), {"membersConfirmed": 3})
        self.wait_for(recipient_account,
                      lambda row: row["ironwood_zatoshi"] >= recipient["ironwood_zatoshi"] + 40_000_000,
                      "recipient funds")
        for app in apps:
            self.assertEqual(app.api(f"payments?vault={vault}")["payments"][0]["phase"],
                             "confirmed")
        self.assertRegex(txid, r"^[0-9a-f]{64}$")
        self.completed = True


if __name__ == "__main__":
    unittest.main()
