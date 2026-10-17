"""Opt-in regtest journey through private member apps and three relays.

Run with LOKI_THS_INSTANCE set to an already running disposable THS instance.
The apps are separate processes on one host; this is not a physical-device test.
"""

import base64
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

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parents[1] / "communication" / "harness"))
import run  # noqa: E402
from ths import THS  # noqa: E402


class RelayPaymentFlowTest(unittest.TestCase):
    def setUp(self):
        name = os.environ.get("LOKI_THS_INSTANCE")
        if not name:
            self.skipTest("set LOKI_THS_INSTANCE to a disposable THS regtest instance")
        server = HERE.parents[1] / "communication" / "target" / "debug" / "loki-relay-server"
        if not server.is_file():
            self.skipTest("build communication's loki-relay-server first")
        self.server = server
        self.chain = THS(name)
        self.chain.check()
        self.temp = tempfile.TemporaryDirectory(prefix="loki-app-payment-", dir="/private/tmp")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def member(self, name, **options):
        app = join.App(self.root / name, env={"LOKI_RPC": self.chain.rpc_address}, **options)
        self.addCleanup(app.stop)
        app.api("profile-create", {"name": name, "passphrase": f"passphrase for {name} only"})
        return app

    def wait_for(self, read, check, what, seconds=120):
        deadline = time.monotonic() + seconds
        last = None
        while time.monotonic() < deadline:
            try:
                last = read()
                if check(last):
                    return last
            except join.Refused as error:
                last = str(error)
            time.sleep(0.5)
        self.fail(f"Timed out waiting for {what}: {last}")

    def test_vault_to_confirmed_payment_across_member_apps(self):
        self.payment_journey(2, 3)

    def test_three_of_four_payment_across_member_apps(self):
        self.payment_journey(3, 4)

    def payment_journey(self, threshold, count):
        creator = self.member("creator", invite_port=join.free_port())
        made = creator.api("create", {"name": "Relay payment", "members": count,
                                        "threshold": threshold})
        vault, invites = made["vault"], made["invites"]
        apps = (creator, *(self.member(f"member-{slot}") for slot in range(2, count + 1)))
        for app, invite in zip(apps[1:], invites):
            self.assertTrue(app.api("join", {"invite": invite})["joined"])
        join.RemoteJoinTest.finish_setup_members(self, apps, vault, invites)

        owner = run.OwnedRun.create(self.root / "operator-run")
        self.addCleanup(owner.close)
        for folder in ("relays", "public-manifests", "capabilities", "capability-staging"):
            run._mkdir(owner.root / folder)
        deadline = time.monotonic() + 600
        relays = [run._init_relay(owner, index, join.free_port(), self.server, deadline,
                                  1048576, 8388608, mailbox_count=count)
                  for index in (1, 2, 3)]
        for relay in relays:
            relay.child = owner.start([str(self.server), "serve", "--root", str(relay.root),
                                       "--listen", run._listen(relay.endpoint)], cwd=relay.root)
            run._wait_listen(relay.child, run._listen(relay.endpoint), deadline)

        for app in apps:
            kit = app.root / "relay-kit"
            kit.mkdir(mode=0o700)
            shutil.copytree(owner.root / "public-manifests", kit / "manifests")
            shutil.copytree(owner.root / "capabilities", kit / "capabilities")
            self.assertEqual(app.api("relay-provision", {"vault": vault, "bundle": str(kit)}),
                             {"provisioned": True})
        for sender in apps:
            for courier in sender.api("relay-export", {"vault": vault})["files"]:
                peer = apps[courier["peer"] - 1]
                self.assertNotEqual(peer, sender)
                self.assertEqual(peer.api("relay-import", {"vault": vault,
                                                            "name": courier["name"],
                                                            "data": courier["data"]}),
                                 {"imported_from": apps.index(sender) + 1})
                self.assertGreater(len(base64.b64decode(courier["data"])), 0)
        for app in apps:
            ready = app.api("relay-status", {"vault": vault})
            self.assertTrue(ready["configured"] and ready["reachable"], ready)

        source = creator.api("address", {"vault": vault})["address"]
        def funded():
            try:
                return self.chain.fund(source)
            except RuntimeError as error:
                if "'status': 'broadcast'" in str(error):
                    self.chain.mine(1)
                    return []
                if not any(f"'status': '{status}'" in str(error)
                           for status in ("preparing", "prepared")):
                    raise
                return []  # THS's idempotency key makes the next call a status retry.

        self.wait_for(funded, bool, "faucet funding", seconds=120)
        self.wait_for(lambda: creator.api("balance", {"vault": vault}),
                      lambda balance: balance["balance_zat"] >= 100_000_000,
                      "funded source balance")
        def recipient_account():
            balances = json.loads(subprocess.check_output(
                ["ths", "--name", self.chain.name, "wallet", "balances", "--json"], text=True))
            return next(item for item in balances if item["id"] == 2)

        receiver = recipient_account()
        recipient = receiver["unified_address"]
        received_before = receiver["ironwood_zatoshi"]
        amount = 40_000_000
        draft = creator.api("payment-draft", {"vault": vault, "recipient": recipient,
                                              "amount_zat": str(amount), "memo": "member app journey",
                                              "pair": "ABC" if threshold == 3 else "AB"})
        self.assertEqual(draft["status"], "draft_only")
        self.assertEqual(draft["signers"], list(range(1, threshold + 1)))
        attempt = draft["attempt"]
        self.assertEqual(creator.api("payment-publish", {"vault": vault, "attempt": attempt})["phase"],
                         "queued_for_delivery")

        def ready_to_review():
            for app in apps:
                app.api("payment-sync", {"vault": vault})
            for app in apps[:threshold]:
                app.api("payment-advance", {"vault": vault, "attempt": attempt})
            return [app.api("payment-review", {"vault": vault, "attempt": attempt})
                    for app in apps[:threshold]]

        reviews = self.wait_for(ready_to_review, lambda rows: len(rows) == threshold,
                                "independent transaction reviews", seconds=300)
        signer_attempt = (apps[1].data / "vaults" / vault / "signing" /
                          draft["payment"] / attempt)
        old_signer_attempt = self.root / "old-second-signing-attempt"
        self.assertTrue((signer_attempt / "nonces.sealed").is_file())
        shutil.copytree(signer_attempt, old_signer_attempt)
        self.assertEqual(reviews[0]["recipient"], reviews[1]["recipient"])
        for review in reviews:
            self.assertTrue(review["recipient"].startswith("uregtest1"))
            self.assertEqual(review["amount_zat"], amount)
            self.assertEqual(review["memo_utf8"], "member app journey")
            self.assertEqual(review["change_zat"], int(draft["change_zat"]))
            self.assertEqual(review["fee_zat"], int(draft["fee_zat"]))
        for app, review in zip(apps[:threshold], reviews):
            self.assertEqual(app.api("payment-approve", {"vault": vault, "attempt": attempt,
                                                          "review_token": review["review_token"]})["phase"],
                             "approval_pending_delivery")

        finisher = apps[threshold]

        def finish_from_non_signer():
            for app in apps:
                app.api("payment-sync", {"vault": vault})
            return finisher.api("payment-finish", {"vault": vault, "attempt": attempt})

        sent = self.wait_for(finish_from_non_signer, lambda result: result["phase"] == "broadcast",
                             "non-signer broadcast", seconds=180)
        self.chain.mine(3)
        verified = self.wait_for(lambda: finisher.api("payment-verify", {"vault": vault,
                                                                       "attempt": attempt,
                                                                       "txid": sent["txid"]}),
                                 lambda result: result["phase"] == "confirmed",
                                 "mined payment confirmation")
        self.assertGreaterEqual(verified["confirmations"], 1)
        self.assertEqual(finisher.api(f"payments?vault={vault}")["payments"][0]["phase"], "confirmed")
        self.wait_for(recipient_account,
                      lambda account: account["ironwood_zatoshi"] >= received_before + amount,
                      "independent recipient balance")
        for app in apps:
            self.wait_for(lambda app=app: app.api("balance", {"vault": vault}),
                          lambda balance: balance["balance_zat"] == int(draft["change_zat"]),
                          "each member's changed vault balance")

        # A restored old signer directory must not release a second share. These
        # are the same live relays that witnessed the mined approval above.
        shutil.rmtree(signer_attempt)
        shutil.copytree(old_signer_attempt, signer_attempt)
        with self.assertRaises(join.Refused) as refused:
            apps[1].api("payment-approve", {"vault": vault, "attempt": attempt,
                                           "review_token": reviews[1]["review_token"]})
        self.assertIn("nonce relay claim", str(refused.exception))
        self.assertFalse((signer_attempt / "decision").exists())
        self.assertFalse((signer_attempt / "share.sealed").exists())


if __name__ == "__main__":
    unittest.main()
