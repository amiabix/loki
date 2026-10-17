"""The background payment worker against fake native payment and relay binaries."""
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).parent))
import member_app  # noqa: E402
from member_app import Wallet  # noqa: E402
from payment_worker import STOP_SECONDS  # noqa: E402

PAYMENT = r'''#!/usr/bin/env python3
import json, os, sys, time
action = sys.argv[1]
if os.environ.get("FAKE_SLOW") == action:
    time.sleep(30)
replies = {"features": "relay-backed-signing=1", "tip": json.dumps({"height": 100}),
           "find-mined": "not mined"}
if action == "local-wires":
    replies["local-wires"] = json.dumps({"wires": sorted(os.listdir(os.path.join(sys.argv[5], "mailbox")))})
if action == "finish-check":
    sys.stderr.write("waiting for member 2 Share; sync relay inbox and retry\n")
    sys.exit(1)
print(replies.get(action, "ok"))
'''
RELAY = r'''#!/usr/bin/env python3
import json, sys
args = sys.argv[1:]
plan = json.load(open(args[args.index("--plan") + 1]))
signing = {}
for item in plan["signing"]:
    signing.setdefault(item["attempt"], []).append({"message": "d" * 64, "stored": True})
print(json.dumps({"proposals": {p.split("/")[-2]: {"message": "d" * 64, "stored": True} for p in plan["proposals"]},
                  "signing": signing, "imported": 0, "rejected": 0, "exported": {}}))
'''


class PaymentWorkerTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        bins = root / "bin"
        bins.mkdir()
        for name, source in (("loki_member_payment", PAYMENT), ("loki_relay_member", RELAY)):
            (bins / name).write_text(source)
            (bins / name).chmod(0o700)
        for name, path in (("PAYMENT", bins / "loki_member_payment"), ("RELAY", bins / "loki_relay_member")):
            patcher = patch.object(member_app, name, path)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.wallet = Wallet(root / "alice", root / "exchange")
        self.addCleanup(self.wallet.close)
        self.wallet.profile_data = {"id": "alice"}
        self.wallet.passphrase = "alice test passphrase"
        self.vault, self.attempt = "a" * 64, "b" * 64
        member = self.wallet.data / "vaults" / self.vault
        self.work = member / "payments" / self.attempt
        (self.work / "mailbox").mkdir(parents=True)
        (member / "membership.json").write_text(json.dumps({
            "vault": self.vault, "profile": "alice", "slot": 1, "threshold": 2, "members": 3}))
        (member / "roster.json").write_text("{}")
        (member / "final-backup-checked").write_text("checked")
        (member / "relay-setup.json").write_text(json.dumps({"phase": "ready"}))
        (self.work / "payment.json").write_text(json.dumps({
            "version": 1, "vault": self.vault, "attempt": self.attempt, "payment": "e" * 64,
            "pair": [1, 2], "expiry_height": 9216}))
        self.calls = []
        check = self.wallet.payment_worker.check

        def recording(binary_name, action):
            self.calls.append((self.wallet.payment_worker.on_worker(), binary_name, action))
            return check(binary_name, action)
        self.wallet.payment_worker.check = recording

    def wait_phase(self, phase, limit=20):
        end = time.monotonic() + limit
        while time.monotonic() < end:
            if self.wallet.payment_phase(self.work)["phase"] == phase:
                return
            time.sleep(0.05)
        self.fail(f"payment never reached {phase}: {self.wallet.payment_phase(self.work)}")

    def test_lock_reaps_a_child_started_during_shutdown(self):
        worker = self.wallet.payment_worker
        worker.local.worker = True
        worker.stop_event.set()
        process = Mock()
        process.poll.return_value = None
        with self.assertRaisesRegex(ValueError, "locked"):
            worker.track(process)
        process.kill.assert_called_once()
        process.communicate.assert_called_once()

    def test_worker_advances_without_a_page_and_never_decides(self):
        self.wallet.payment_status(self.work, "queued_for_delivery")
        self.wallet.payment_worker.start()
        self.wait_phase("package")
        # The member's own decision, as the signer window makes it.
        with self.wallet.payment_worker.user_action(self.vault):
            self.wallet.approve_payment(self.vault, self.attempt, "d" * 64)
            (self.work / "mailbox" / ("c" * 64)).write_bytes(b"own saved share")
        self.wait_phase("approved")
        end = time.monotonic() + 10
        while (True, "loki_member_payment", "finish-check") not in self.calls and time.monotonic() < end:
            time.sleep(0.05)
        self.wallet.lock_profile()
        worker_actions = {action for on_worker, _, action in self.calls if on_worker}
        self.assertTrue({"payment-sync", "commit", "package", "resend", "finish-check"} <= worker_actions,
                        worker_actions)
        self.assertFalse(worker_actions & {"review", "approve-reviewed", "finish"})
        self.assertIn((False, "loki_member_payment", "approve-reviewed"), self.calls)

    def test_worker_thread_cannot_review_approve_or_send(self):
        worker = self.wallet.payment_worker
        refused = []

        def attempt():
            worker.local.worker = True
            for action in ("review", "approve-reviewed", "finish", "approve", "sign"):
                try:
                    self.wallet.payment_command(action, self.vault, self.attempt)
                except PermissionError:
                    refused.append(action)
        thread = threading.Thread(target=attempt)
        thread.start()
        thread.join(10)
        self.assertEqual(refused, ["review", "approve-reviewed", "finish", "approve", "sign"])
        self.assertFalse([call for call in self.calls if call[0] and call[2] != "features" and call[2] not in refused])

    def test_lock_stops_a_running_native_step_within_five_seconds(self):
        os.environ["FAKE_SLOW"] = "commit"
        self.addCleanup(os.environ.pop, "FAKE_SLOW", None)
        self.wallet.payment_status(self.work, "published")
        self.wallet.payment_worker.start()
        end = time.monotonic() + 10
        while not self.wallet.payment_worker.processes and time.monotonic() < end:
            time.sleep(0.05)
        self.assertTrue(self.wallet.payment_worker.processes, "the slow commit never started")
        begun = time.monotonic()
        self.wallet.lock_profile()
        self.assertLess(time.monotonic() - begun, STOP_SECONDS)
        self.assertFalse(self.wallet.payment_worker.running())
        self.assertEqual(self.wallet.payment_phase(self.work)["phase"], "published")

    def test_check_for_updates_runs_one_pass_and_reports_errors(self):
        with self.assertRaisesRegex(ValueError, "Unlock"):
            self.wallet.sync_payments(self.vault)
        self.wallet.payment_status(self.work, "queued_for_delivery")
        self.wallet.payment_worker.start()
        self.assertEqual(self.wallet.sync_payments(self.vault)["payments"][0]["phase"] in
                         ("published", "commitments", "package"), True)
        (self.work.parent.parent / "roster.json").unlink()
        member_app.RELAY.write_text("#!/bin/sh\necho member_sealed >&2\nexit 1\n")
        with self.assertRaisesRegex(ValueError, "member_sealed"):
            self.wallet.sync_payments(self.vault)
        self.assertEqual(self.wallet.payments(self.vault)["updates"]["error"], "member_sealed")


if __name__ == "__main__":
    unittest.main()
