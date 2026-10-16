"""The setup app never creates or unlocks another member's share."""

import base64
import hashlib
import http.client
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
from member_app import SEED_WALLET, SETUP, Wallet, courier_name, encoded, make_signer_server
import member_app


class MemberWalletTest(unittest.TestCase):
    def test_lock_clears_profile_while_setup_worker_is_running(self):
        with tempfile.TemporaryDirectory(prefix="loki-lock-worker-") as temp:
            wallet = Wallet(Path(temp) / "member", Path(temp) / "exchange")
            self.addCleanup(wallet.close)
            wallet.profile_data = {"id": "profile"}
            wallet.passphrase = "example passphrase"
            started, release = threading.Event(), threading.Event()
            worker = threading.Thread(target=lambda: (started.set(), release.wait(2)), daemon=True)
            worker.start()
            started.wait(1)
            wallet.workers["a" * 64] = worker
            try:
                self.assertEqual(wallet.lock_profile(), {"locked": True})
                self.assertIsNone(wallet.profile_data)
                self.assertIsNone(wallet.passphrase)
            finally:
                release.set()
                worker.join(2)

    def test_lock_route_does_not_wait_for_payment_sync(self):
        with tempfile.TemporaryDirectory(prefix="loki-lock-sync-") as temp:
            wallet = Wallet(Path(temp) / "member", Path(temp) / "exchange")
            self.addCleanup(wallet.close)
            wallet.profile_data = {"id": "profile"}
            wallet.passphrase = "example passphrase"
            started, release = threading.Event(), threading.Event()
            server, token = make_signer_server(wallet, 0)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)

            def blocked_sync(_vault):
                started.set()
                release.wait(2)
                return {"payments": []}

            def request(path, body):
                connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=3)
                connection.request("POST", path, json.dumps(body), {"X-Loki-Token": token})
                response = connection.getresponse()
                result = response.status, json.loads(response.read())
                connection.close()
                return result

            with patch.object(wallet, "sync_payments", side_effect=blocked_sync):
                syncing = threading.Thread(target=lambda: request("/api/payment-sync", {"vault": "a" * 64}), daemon=True)
                syncing.start()
                self.assertTrue(started.wait(1))
                timer = threading.Timer(1, release.set)
                timer.start()
                try:
                    before = time.monotonic()
                    self.assertEqual(request("/api/lock", {})[0], 200)
                    self.assertLess(time.monotonic() - before, 0.6)
                    self.assertIsNone(wallet.passphrase)
                finally:
                    release.set()
                    timer.cancel()
                    syncing.join(2)

    def test_lock_terminates_running_native_command(self):
        with tempfile.TemporaryDirectory(prefix="loki-lock-command-") as temp:
            root = Path(temp)
            wallet = Wallet(root / "member", root / "exchange")
            self.addCleanup(wallet.close)
            wallet.profile_data = {"id": "profile"}
            wallet.passphrase = "example passphrase"
            executable = root / "slow-command"
            executable.write_text("#!/usr/bin/env python3\nimport pathlib, sys, time\npathlib.Path(sys.argv[2]).touch()\ntime.sleep(10)\n")
            executable.chmod(0o700)
            marker = root / "started"
            result = []

            def run():
                try:
                    wallet.command("run", marker, "@pass", binary=executable, timeout=12)
                    result.append("completed")
                except ValueError:
                    result.append("stopped")

            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            deadline = time.monotonic() + 10
            while not marker.exists() and worker.is_alive() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(marker.exists())
            wallet.lock_profile()
            worker.join(1)
            self.assertFalse(worker.is_alive())
            self.assertEqual(result, ["stopped"])
            self.assertEqual(list(wallet.data.glob(".unlock-*")), [])

    def test_lock_does_not_report_cancelled_setup_as_a_vault_failure(self):
        with tempfile.TemporaryDirectory(prefix="loki-lock-setup-state-") as temp:
            wallet = Wallet(Path(temp) / "member", Path(temp) / "exchange")
            self.addCleanup(wallet.close)
            wallet.profile_data = {"id": "profile"}
            wallet.passphrase = "example passphrase"
            vault = "a" * 64
            member = wallet.data / "vaults" / vault
            member.mkdir(parents=True)
            (wallet.exchange / vault).mkdir()
            identity = {"id": 1, "signing": "b" * 64, "encryption": "c" * 64}
            started, release = threading.Event(), threading.Event()

            def command(action, *_args, **_kwargs):
                if action == "identity-public":
                    return json.dumps(identity)
                if action == "run":
                    started.set()
                    release.wait(2)
                    raise ValueError("native command was cancelled")
                raise AssertionError(action)

            with patch.object(wallet, "vault_dir", return_value=(member, {"slot": 1})), \
                 patch.object(wallet, "roster", return_value={"fingerprint": "f", "members": [identity]}), \
                 patch.object(wallet, "command", side_effect=command):
                wallet.agree(vault, "f")
                self.assertTrue(started.wait(1))
                wallet.lock_profile()
                release.set()
                wallet.workers[vault].join(2)
            self.assertNotIn(vault, wallet.setup_errors)

    def test_lock_during_unlock_cannot_restore_profile_after_lock_returns(self):
        with tempfile.TemporaryDirectory(prefix="loki-lock-unlock-race-") as temp:
            wallet = Wallet(Path(temp) / "member", Path(temp) / "exchange")
            self.addCleanup(wallet.close)
            started, release = threading.Event(), threading.Event()
            result = []

            def opening(*_args, **_kwargs):
                started.set()
                release.wait(2)
                return json.dumps({"id": "profile"})

            def unlock():
                try:
                    wallet.unlock("example passphrase")
                    result.append("unlocked")
                except ValueError:
                    result.append("cancelled")

            with patch.object(wallet, "command", side_effect=opening):
                worker = threading.Thread(target=unlock, daemon=True)
                worker.start()
                self.assertTrue(started.wait(1))
                wallet.lock_profile()
                release.set()
                worker.join(2)
            self.assertEqual(result, ["cancelled"])
            self.assertIsNone(wallet.profile_data)
            self.assertIsNone(wallet.passphrase)

    def test_join_retries_after_identity_is_saved_before_membership(self):
        with tempfile.TemporaryDirectory(prefix="loki-join-retry-") as temp:
            root = Path(temp)
            wallet = Wallet(root / "member", root / "exchange")
            self.addCleanup(wallet.close)
            wallet.profile_data = {"id": "profile"}
            wallet.passphrase = "example passphrase"
            vault, secret = "a" * 64, "invite secret"
            exchange = wallet.exchange / vault
            exchange.mkdir()
            exchange.joinpath("draft.json").write_text(json.dumps({
                "vault": vault, "name": "Treasury", "members": 3, "threshold": 2,
                "expires_at": 9999999999,
                "invites": {"2": hashlib.sha256(secret.encode()).hexdigest(),
                            "3": "unused"}}))
            invite = encoded({"vault": vault, "slot": 2, "secret": secret})
            identity = {"id": 2, "signing": "b" * 64, "encryption": "c" * 64}

            def command(action, member, *_args, **_kwargs):
                if action == "identity":
                    secrets_dir = member / "secrets"
                    secrets_dir.mkdir(exist_ok=True)
                    (secrets_dir / "identity.sealed").write_bytes(b"saved sealed identity")
                    raise ValueError("response lost after identity was saved")
                if action == "identity-public":
                    return json.dumps(identity)
                raise AssertionError(action)

            with patch.object(wallet, "command", side_effect=command):
                with self.assertRaisesRegex(ValueError, "response lost"):
                    wallet.join(invite)
                (exchange / "join-2.json").write_bytes(b'{"id":')
                (wallet.data / "vaults" / vault / "membership.json").write_bytes(b'{"vault":')
                self.assertEqual(wallet.join(invite), {"vault": vault, "joined": True})
            self.assertEqual(json.loads((exchange / "join-2.json").read_text()), identity)
            self.assertEqual(wallet.vault_dir(vault)[1]["slot"], 2)

    def test_remote_join_keeps_membership_uncommitted_until_transport_is_saved(self):
        with tempfile.TemporaryDirectory(prefix="loki-remote-join-retry-") as temp:
            root = Path(temp)
            wallet = Wallet(root / "member", root / "exchange")
            self.addCleanup(wallet.close)
            wallet.profile_data = {"id": "profile"}
            wallet.passphrase = "example passphrase"
            vault, secret = "a" * 64, "invite secret"
            origin = "https://setup.example.invalid"
            exchange = wallet.exchange / vault
            draft = {"vault": vault, "name": "Treasury", "members": 3, "threshold": 2,
                     "expires_at": 9999999999,
                     "invites": {"2": hashlib.sha256(secret.encode()).hexdigest(), "3": "unused"}}
            invite = encoded({"vault": vault, "slot": 2, "secret": secret, "url": origin})
            identity = {"id": 2, "signing": "b" * 64, "encryption": "c" * 64}

            def command(action, member, *_args, **_kwargs):
                if action == "identity":
                    secrets_dir = member / "secrets"
                    secrets_dir.mkdir(exist_ok=True)
                    (secrets_dir / "identity.sealed").write_bytes(b"saved sealed identity")
                if action in ("identity", "identity-public"):
                    return json.dumps(identity)
                raise AssertionError(action)

            def claim(*_args):
                exchange.mkdir(exist_ok=True)
                (exchange / "draft.json").write_text(json.dumps(draft))

            original_write = member_app.write_new
            failed = False

            def fail_transport_once(path, value, mode=0o600):
                nonlocal failed
                if path.name == "transport.json" and not failed:
                    failed = True
                    raise OSError("transport write interrupted")
                return original_write(path, value, mode)

            with patch.object(wallet, "claim_remote", side_effect=claim), \
                 patch.object(wallet, "command", side_effect=command), \
                 patch.object(wallet, "ensure_sync"), \
                 patch("member_app.write_new", side_effect=fail_transport_once):
                with self.assertRaisesRegex(OSError, "transport write interrupted"):
                    wallet.join(invite)
                member = wallet.data / "vaults" / vault
                self.assertFalse((member / "membership.json").exists())
                self.assertEqual(wallet.join(invite), {"vault": vault, "joined": True})
                self.assertTrue((member / "transport.json").exists())

    def test_join_does_not_follow_a_partial_member_symlink(self):
        with tempfile.TemporaryDirectory(prefix="loki-join-symlink-") as temp:
            root = Path(temp)
            wallet = Wallet(root / "member", root / "exchange")
            self.addCleanup(wallet.close)
            wallet.profile_data = {"id": "profile"}
            wallet.passphrase = "example passphrase"
            vault, secret = "a" * 64, "invite secret"
            exchange = wallet.exchange / vault
            exchange.mkdir()
            (exchange / "draft.json").write_text(json.dumps({
                "vault": vault, "name": "Treasury", "members": 3, "threshold": 2,
                "expires_at": 9999999999,
                "invites": {"2": hashlib.sha256(secret.encode()).hexdigest(), "3": "unused"}}))
            (wallet.data / "vaults").mkdir()
            outside = root / "outside"
            outside.mkdir()
            (wallet.data / "vaults" / vault).symlink_to(outside)
            with patch.object(wallet, "command", side_effect=AssertionError("followed symlink")):
                with self.assertRaisesRegex(ValueError, "symbolic link"):
                    wallet.join(encoded({"vault": vault, "slot": 2, "secret": secret}))
            self.assertEqual(list(outside.iterdir()), [])

    def test_sync_stops_after_all_final_reports(self):
        with tempfile.TemporaryDirectory(prefix="loki-sync-done-") as temp:
            wallet = Wallet(Path(temp) / "member", Path(temp) / "exchange")
            self.addCleanup(wallet.close)
            vault = "a" * 64
            member = wallet.data / "vaults" / vault
            member.mkdir(parents=True)
            (member / "transport.json").write_text(json.dumps({
                "vault": vault, "origin": "http://127.0.0.1:1", "token": "test", "slot": 2}))
            (member / "final-backup-checked").write_text("checked\n")
            with patch.object(wallet, "sync_once") as sync, patch.object(
                    wallet, "backup_reports", return_value=[{"reported": True}] * 3):
                wallet.ensure_sync(vault)
                worker = wallet.syncs[vault]
                worker.join(timeout=2)
                self.assertFalse(worker.is_alive())
                self.assertEqual(sync.call_count, 1)
                wallet.ensure_sync(vault)
                self.assertIs(wallet.syncs[vault], worker)

    def test_final_status_receipt_is_owned_by_its_member(self):
        vault = "a" * 64
        self.assertTrue(courier_name(vault, f"{vault}-final-status-2.bin", "2"))
        self.assertFalse(courier_name(vault, f"{vault}-final-status-2.bin", "1"))

    def test_payment_sync_moves_only_own_wires_and_waits_for_relay_storage(self):
        with tempfile.TemporaryDirectory(prefix="loki-payment-sync-") as temp:
            wallet = Wallet(Path(temp) / "alice", Path(temp) / "exchange")
            self.addCleanup(wallet.close)
            vault, attempt, message, wire = ("a" * 64, "b" * 64, "c" * 64, "d" * 64)
            wallet.profile_data = {"id": "alice"}
            wallet.passphrase = "alice test passphrase"
            member = wallet.data / "vaults" / vault
            work = member / "payments" / attempt
            (work / "mailbox").mkdir(parents=True)
            (member / "membership.json").write_text(json.dumps({
                "vault": vault, "profile": "alice", "slot": 1, "threshold": 2, "members": 3}))
            (member / "roster.json").write_text("{}")
            (member / "final-backup-checked").write_text("checked")
            (work / "payment.json").write_text(json.dumps({
                "vault": vault, "attempt": attempt, "payment": "e" * 64, "pair": [1, 2]}))
            (work / "mailbox" / wire).write_bytes(b"own authenticated wire")
            wallet.payment_status(work, "queued_for_delivery")
            calls = []
            stored = False

            def command(action, *args, **_kwargs):
                calls.append((action, args))
                if action == "features": return "relay-backed-signing=1"
                if action == "send-proposal": return f"request message={message} digest={'f' * 64} needs_route=0"
                if action == "local-wires": return json.dumps({"wires": [wire]})
                if action == "status":
                    return f"message sender=1 id={message} stored_whole={int(stored)}"
                return "ok"

            with patch.object(wallet, "command", side_effect=command):
                self.assertEqual(wallet.sync_payments(vault)["payments"][0]["phase"], "queued_for_delivery")
                stored = True
                self.assertEqual(wallet.sync_payments(vault)["payments"][0]["phase"], "published")
            self.assertEqual([action for action, _ in calls].count("send-signing"), 2)
            self.assertEqual([action for action, _ in calls].count("export-signing"), 2)
            self.assertTrue(any(args[-2:] == ("--attempt", attempt) for action, args in calls
                                if action == "send-signing"))

    def test_saved_approval_waits_for_relay_storage(self):
        with tempfile.TemporaryDirectory(prefix="loki-approval-sync-") as temp:
            wallet = Wallet(Path(temp) / "alice", Path(temp) / "exchange")
            self.addCleanup(wallet.close)
            vault, attempt, wire, message = ("a" * 64, "b" * 64, "c" * 64, "d" * 64)
            wallet.profile_data = {"id": "alice"}
            wallet.passphrase = "alice test passphrase"
            member = wallet.data / "vaults" / vault
            work = member / "payments" / attempt
            (work / "mailbox").mkdir(parents=True)
            (member / "membership.json").write_text(json.dumps({
                "vault": vault, "profile": "alice", "slot": 1, "threshold": 2, "members": 3}))
            (member / "roster.json").write_text("{}")
            (member / "final-backup-checked").write_text("checked")
            (work / "payment.json").write_text(json.dumps({
                "vault": vault, "attempt": attempt, "payment": "e" * 64, "pair": [1, 2]}))
            wallet.payment_status(work, "approval_pending_delivery")
            stored = False

            def command(action, *args, **_kwargs):
                if action == "features": return "relay-backed-signing=1"
                if action == "local-wires": return json.dumps({"wires": [wire]})
                if action == "send-signing": return f"request message={message} digest={'f' * 64} needs_route=0"
                if action == "status":
                    return f"message sender=1 id={message} stored_whole={int(stored)}"
                if action == "finish-check":
                    raise ValueError("waiting for member 2 Share; sync relay inbox and retry")
                return "ok"

            with patch.object(wallet, "command", side_effect=command) as mocked:
                self.assertEqual(wallet.sync_payments(vault)["payments"][0]["phase"],
                                 "approval_pending_delivery")
                stored = True
                self.assertEqual(wallet.sync_payments(vault)["payments"][0]["phase"], "approved")
            self.assertEqual([call.args[0] for call in mocked.call_args_list].count("resend"), 2)

    def test_interrupted_approval_does_not_block_other_payment_sync(self):
        with tempfile.TemporaryDirectory(prefix="loki-interrupted-sync-") as temp:
            wallet = Wallet(Path(temp) / "alice", Path(temp) / "exchange")
            self.addCleanup(wallet.close)
            vault, bad, good = "a" * 64, "b" * 64, "c" * 64
            wallet.profile_data = {"id": "alice"}
            wallet.passphrase = "alice test passphrase"
            member = wallet.data / "vaults" / vault
            (member / "membership.json").parent.mkdir(parents=True)
            (member / "membership.json").write_text(json.dumps({
                "vault": vault, "profile": "alice", "slot": 1, "threshold": 2, "members": 3}))
            (member / "roster.json").write_text("{}")
            (member / "final-backup-checked").write_text("checked")
            for attempt, phase in ((bad, "approval_pending_delivery"), (good, "queued_for_delivery")):
                work = member / "payments" / attempt
                (work / "mailbox").mkdir(parents=True)
                (work / "payment.json").write_text(json.dumps({
                    "vault": vault, "attempt": attempt, "payment": "e" * 64, "pair": [1, 2]}))
                wallet.payment_status(work, phase)

            def command(action, *args, **_kwargs):
                if action == "features": return "relay-backed-signing=1"
                if action == "resend": raise ValueError("attempt was interrupted")
                if action == "local-wires": return json.dumps({"wires": []})
                if action == "send-proposal": return f"request message={'d' * 64} digest={'f' * 64} needs_route=0"
                if action == "status": return f"message sender=1 id={'d' * 64} stored_whole=1"
                return "ok"

            with patch.object(wallet, "command", side_effect=command):
                phases = {item["attempt"]: item["phase"] for item in wallet.sync_payments(vault)["payments"]}
            self.assertEqual(phases, {bad: "approval_interrupted", good: "published"})

    def test_payment_draft_uses_only_active_members_own_vault(self):
        with tempfile.TemporaryDirectory(prefix="loki-draft-") as temp:
            root = Path(temp)
            exchange = root / "exchange"
            alice = Wallet(root / "alice", exchange)
            bob = Wallet(root / "bob", exchange)
            self.addCleanup(alice.close)
            self.addCleanup(bob.close)
            vault = "a" * 64
            alice.profile_data = {"id": "alice"}
            bob.profile_data = {"id": "bob"}
            alice.passphrase = "alice test passphrase"
            bob.passphrase = "bob test passphrase"
            folder = alice.data / "vaults" / vault
            (folder / "secrets").mkdir(parents=True)
            (folder / "membership.json").write_text(json.dumps({
                "vault": vault, "profile": "alice", "slot": 1, "threshold": 2, "members": 3}))
            (folder / "roster.json").write_text("{}")
            with self.assertRaisesRegex(ValueError, "not active"):
                alice.prepare_payment(vault, "uregtest1recipient", "40000000", "test memo", "AB")
            (folder / "secrets" / "activation.sealed").write_bytes(b"active")
            (folder / "final-backup-checked").write_bytes(b"checked\n")

            def prepare(_action, member, _pass, roster, work, _recipient, amount, memo, pair, **kwargs):
                self.assertEqual(member, folder)
                self.assertEqual(roster, folder / "roster.json")
                self.assertEqual(work.parent, folder / "payments")
                self.assertEqual(work.stat().st_mode & 0o777, 0o700)
                self.assertEqual((amount, memo, pair), ("40000000", "test memo", "AB"))
                self.assertEqual(kwargs["binary"], Path(SETUP).with_name("loki_member_payment"))
                (work / "payment.json").write_text(json.dumps({
                    "vault": vault, "payment": "b" * 64, "attempt": "c" * 64, "amount_zat": 40000000,
                    "fee_zat": 10000, "change_zat": 59990000, "expiry_height": 9216,
                    "pair": [1, 2]}))
                return "payment created"

            with patch.object(alice, "command", side_effect=prepare) as command:
                draft = alice.prepare_payment(vault, "uregtest1recipient", "40000000", "test memo", "AB")
            self.assertEqual(command.call_count, 1)
            self.assertEqual(draft["payment"], "b" * 64)
            self.assertEqual(draft["attempt"], "c" * 64)
            self.assertEqual(draft["status"], "draft_only")
            self.assertEqual(len(list((folder / "payments").glob("*/payment.json"))), 1)
            self.assertTrue((folder / "payments" / ("c" * 64) / "payment.json").is_file())
            self.assertEqual(alice.payments(vault)["payments"][0]["phase"], "draft")
            with self.assertRaisesRegex(ValueError, "Choose two members"):
                alice.prepare_payment(vault, "uregtest1recipient", "40000000", "test memo", "AD")
            with self.assertRaisesRegex(ValueError, "positive amount"):
                alice.prepare_payment(vault, "uregtest1recipient", "0", "test memo", "AB")
            self.assertEqual(command.call_count, 1)
            with self.assertRaisesRegex(ValueError, "not a member"):
                bob.prepare_payment(vault, "uregtest1recipient", "40000000", "test memo", "AB")
            with self.assertRaisesRegex(ValueError, "not a member"):
                alice.prepare_payment("c" * 64, "uregtest1recipient", "40000000", "test memo", "AB")
            alice.profile_data = {"id": "another-profile"}
            with self.assertRaisesRegex(ValueError, "does not belong"):
                alice.prepare_payment(vault, "uregtest1recipient", "40000000", "test memo", "AB")

    def test_payment_stages_use_only_own_vault_and_verified_review(self):
        with tempfile.TemporaryDirectory(prefix="loki-payment-stages-") as temp:
            root = Path(temp)
            vault = "a" * 64
            attempt = "b" * 64
            payment = "c" * 64
            alice = Wallet(root / "alice", root / "exchange")
            bob = Wallet(root / "bob", root / "exchange")
            self.addCleanup(alice.close)
            self.addCleanup(bob.close)
            for wallet, name, slot in ((alice, "alice", 1), (bob, "bob", 2)):
                wallet.profile_data = {"id": name}
                wallet.passphrase = f"{name} long test passphrase"
                folder = wallet.data / "vaults" / vault
                (folder / "payments" / attempt).mkdir(parents=True)
                (folder / "final-backup-checked").write_text("checked")
                (folder / "membership.json").write_text(json.dumps({
                    "vault": vault, "profile": name, "slot": slot,
                    "threshold": 2, "members": 3}))
                (folder / "roster.json").write_text("{}")
            work = alice.data / "vaults" / vault / "payments" / attempt
            manifest = {"vault": vault, "attempt": attempt, "payment": payment,
                        "pair": [1, 2], "expiry_height": 9216}
            (work / "payment.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "not in this member"):
                bob.review_payment(vault, attempt)
            imported = bob.data / "vaults" / vault / "payments" / attempt
            (imported / "payment.json").write_text(json.dumps(manifest))
            self.assertEqual(bob.payments(vault)["payments"][0]["phase"], "received")
            with self.assertRaisesRegex(ValueError, "Invalid payment attempt"):
                alice.review_payment(vault, "../bob")
            review = {**manifest, "recipient": "uregtest1recipient", "amount_zat": 40000000,
                      "memo_utf8": "test memo", "fee_zat": 10000, "change_zat": 59990000,
                      "expiry_height": 9216, "review_token": "d" * 64,
                      "authorization_required": True}
            calls = []

            def command(action, *args, **_kwargs):
                calls.append(action)
                if action == "features": return "relay-backed-signing=1"
                if action == "balance": return json.dumps({"vault": vault, "height": 100})
                if action == "send-proposal": return f"proposal={payment} attempt={attempt}"
                if action == "review": return json.dumps(review)
                if action == "finish": return "broadcast txid=" + "e" * 64 + " payment=" + payment
                if action == "verify": return "verified mined txid=" + "e" * 64 + " confirmations=3 amount=40000000"
                return "ok"

            with patch.object(alice, "command", side_effect=command):
                self.assertEqual(alice.publish_payment(vault, attempt), {"phase": "queued_for_delivery"})
                with patch.object(alice, "balance", return_value={"height": 9216}):
                    with self.assertRaisesRegex(ValueError, "expired"):
                        alice.commit_payment(vault, attempt)
                self.assertEqual(alice.commit_payment(vault, attempt), {"phase": "commitments"})
                self.assertEqual(alice.package_payment(vault, attempt), {"phase": "package"})
                self.assertEqual(alice.review_payment(vault, attempt), review)
                with self.assertRaisesRegex(ValueError, "Review this exact"):
                    alice.approve_payment(vault, attempt, "wrong")
                self.assertNotIn("approve-reviewed", calls)
                self.assertEqual(alice.approve_payment(vault, attempt, "d" * 64)["phase"],
                                 "approval_pending_delivery")
                self.assertEqual(alice.resend_payment(vault, attempt)["phase"],
                                 "approval_pending_delivery")
                self.assertEqual(alice.finish_payment(vault, attempt)["phase"], "broadcast")
                self.assertEqual(alice.verify_payment(vault, attempt, "e" * 64)["phase"], "confirmed")
            self.assertEqual(calls.count("features"), 1)
            with patch.object(alice, "command", side_effect=command):
                self.assertEqual(alice.payments(vault)["payments"][0]["phase"], "confirmed")
            with patch.object(alice, "payment_command", side_effect=ValueError("transaction is not mined")):
                self.assertEqual(alice.payments(vault)["payments"][0]["phase"],
                                 "confirmation_needs_recheck")
                self.assertEqual(alice.payment_phase(work)["phase"], "confirmation_needs_recheck")
                self.assertEqual(alice.advance_payment(vault, attempt)["phase"],
                                 "confirmation_needs_recheck")
            with patch.object(alice, "command", side_effect=command):
                self.assertEqual(alice.advance_payment(vault, attempt)["phase"], "confirmed")
            review["vault"] = "f" * 64
            with patch.object(alice, "command", return_value=json.dumps(review)) as command:
                with self.assertRaisesRegex(ValueError, "differs from this payment"):
                    alice.review_payment(vault, attempt)
                self.assertEqual(command.call_count, 1)

    def payment_fixture(self, temp, slot=1, phase="published", pair=(1, 2), txid=None):
        vault, attempt = "a" * 64, "b" * 64
        wallet = Wallet(Path(temp) / f"member-{slot}", Path(temp) / "exchange")
        self.addCleanup(wallet.close)
        wallet.profile_data = {"id": f"member-{slot}"}
        wallet.passphrase = f"member {slot} long test passphrase"
        member = wallet.data / "vaults" / vault
        work = member / "payments" / attempt
        (work / "mailbox").mkdir(parents=True)
        (member / "membership.json").write_text(json.dumps({
            "vault": vault, "profile": f"member-{slot}", "slot": slot,
            "threshold": 2, "members": 3}))
        (member / "roster.json").write_text("{}")
        (member / "final-backup-checked").write_text("checked")
        (work / "payment.json").write_text(json.dumps({
            "vault": vault, "attempt": attempt, "payment": "e" * 64,
            "pair": list(pair), "expiry_height": 9216}))
        if phase:
            wallet.payment_status(work, phase, txid)
        return wallet, vault, attempt

    def test_relay_setup_keeps_operator_files_out_of_page_and_imports_only_sealed_peer_file(self):
        with tempfile.TemporaryDirectory(prefix="loki-relay-setup-") as temp:
            wallet, vault, _ = self.payment_fixture(temp, phase=None)
            bundle = Path(temp) / "operator-kit"
            manifests, capabilities = bundle / "manifests", bundle / "capabilities"
            manifests.mkdir(parents=True)
            capabilities.mkdir()
            own = wallet.data / "vaults" / vault
            peers = {2: b"sealed for member 2", 3: b"sealed for member 3"}
            imported = []

            def command(action, *args, **kwargs):
                self.assertEqual(kwargs["binary"].name, "loki_relay_member")
                self.assertEqual(args[:6], ("--member-root", own, "--passphrase-file", "@pass",
                                            "--roster", own / "roster.json"))
                if action == "provision":
                    self.assertEqual(args[6:], ("--relay-manifest", manifests,
                                                "--provision-capability-files", capabilities))
                    return "config revision=1 hash=" + "f" * 64
                if action == "export-config":
                    output = args[-1]
                    for peer, wire in peers.items():
                        (output / f"{vault}-relay-config-1-{peer}-1.bin").write_bytes(wire)
                    return "config revision=1 hash=" + "f" * 64
                if action == "import-config":
                    courier = args[-1]
                    self.assertEqual(courier.stat().st_mode & 0o777, 0o600)
                    imported.append(courier.read_bytes())
                    return "imported owner=2 revision=1 digest=" + "e" * 64
                raise AssertionError(action)

            with patch.object(wallet, "command", side_effect=command):
                self.assertEqual(wallet.relay_provision(vault, str(bundle)), {"provisioned": True})
                exported = wallet.relay_export(vault)["files"]
                self.assertEqual([item["peer"] for item in exported], [2, 3])
                self.assertEqual([base64.b64decode(item["data"]) for item in exported],
                                 [peers[2], peers[3]])
                self.assertEqual(wallet.relay_import(vault, base64.b64encode(b"sealed from peer 2").decode(),
                                                     f"{vault}-relay-config-2-1-1.bin"),
                                 {"imported_from": 2})
                self.assertEqual(imported, [b"sealed from peer 2"])
                with self.assertRaisesRegex(ValueError, "Invalid relay config file"):
                    wallet.relay_import(vault, "not base64", f"{vault}-relay-config-2-1-1.bin")
                with self.assertRaisesRegex(ValueError, "Invalid relay config file"):
                    wallet.relay_import(vault, base64.b64encode(b"other").decode(), "../courier.bin")
                with self.assertRaisesRegex(ValueError, "not a member"):
                    wallet.relay_provision("f" * 64, str(bundle))

    def test_relay_status_requires_peer_configs_and_two_reachable_relays(self):
        with tempfile.TemporaryDirectory(prefix="loki-relay-status-") as temp:
            wallet, vault, _ = self.payment_fixture(temp, phase=None)
            report = "inboxes=3 peers=2 live=2 routable=1"
            with patch.object(wallet, "command", return_value=report):
                self.assertEqual(wallet.relay_connection_status(vault),
                                 {"configured": True, "reachable": True, "inboxes": 3,
                                  "peers": 2, "live_relays": 2})
            with patch.object(wallet, "command", return_value=report.replace("peers=2", "peers=1")):
                self.assertFalse(wallet.relay_connection_status(vault)["configured"])
            with patch.object(wallet, "command", return_value=report.replace("routable=1", "routable=0")):
                self.assertFalse(wallet.relay_connection_status(vault)["reachable"])
            with patch.object(wallet, "command", return_value=report.replace(
                    "live=2", "live=1")):
                self.assertEqual(wallet.relay_connection_status(vault),
                                 {"configured": True, "reachable": False, "inboxes": 3,
                                  "peers": 2, "live_relays": 1})
            with patch.object(wallet, "command", side_effect=ValueError("member_sealed")):
                with self.assertRaisesRegex(ValueError, "member_sealed"):
                    wallet.relay_connection_status(vault)

    def test_four_member_operator_relays_keep_automatic_status_separate(self):
        with tempfile.TemporaryDirectory(prefix="loki-four-relay-status-") as temp:
            wallet, vault, _ = self.payment_fixture(temp, phase=None)
            member = wallet.data / "vaults" / vault
            membership = json.loads((member / "membership.json").read_text())
            membership["members"] = 4
            (member / "membership.json").write_text(json.dumps(membership))
            with patch.object(wallet, "command", return_value="inboxes=3 peers=3 live=2 routable=1"):
                self.assertEqual(wallet.relay_status(vault)["phase"], "not_configured")
                (member / "relay-setup.json").write_text(json.dumps({
                    "mode": "operator", "phase": "waiting", "detail": "Connecting operator relays."}))
                self.assertTrue(wallet.relay_connection_status(vault)["reachable"])
                self.assertEqual(wallet.relay_status(vault)["phase"], "ready")
                self.assertFalse(wallet.relay_status(vault)["available"])
                with self.assertRaisesRegex(ValueError, "operator relay connection controls"):
                    wallet.setup_relays(vault)
            with patch.object(wallet, "command", side_effect=AssertionError("cached status must not reprovision")):
                self.assertEqual(wallet.relay_status(vault)["phase"], "ready")
            with patch.object(wallet, "command", return_value="inboxes=3 peers=2 live=3 routable=1"):
                self.assertFalse(wallet.relay_connection_status(vault)["configured"])
            peers = {slot: f"sealed for {slot}".encode() for slot in (2, 3, 4)}
            def export(action, *args, **kwargs):
                self.assertEqual(action, "export-config")
                for peer, wire in peers.items():
                    (args[-1] / f"{vault}-relay-config-1-{peer}-1.bin").write_bytes(wire)
                return "exported"
            with patch.object(wallet, "command", side_effect=export):
                self.assertEqual([row["peer"] for row in wallet.relay_export(vault)["files"]], [2, 3, 4])
            with patch.object(wallet, "command", return_value="imported owner=4 revision=1 digest=" + "e" * 64):
                self.assertEqual(wallet.relay_import(vault, base64.b64encode(b"sealed from 4").decode(),
                                                     f"{vault}-relay-config-4-1-1.bin"), {"imported_from": 4})

    def test_readiness_check_preserves_automatic_relay_progress(self):
        with tempfile.TemporaryDirectory(prefix="loki-automatic-relay-status-") as temp:
            wallet, vault, _ = self.payment_fixture(temp, phase=None)
            state_path = wallet.data / "vaults" / vault / "relay-setup.json"
            saved = {"phase": "waiting", "detail": "Waiting for peer configs.",
                     "imported": [2], "network": "automatic-network"}
            state_path.write_text(json.dumps(saved))
            original = state_path.read_bytes()
            with patch.object(wallet, "command", return_value="inboxes=3 peers=2 live=2 routable=1"):
                self.assertTrue(wallet.relay_connection_status(vault)["reachable"])
            self.assertEqual(state_path.read_bytes(), original)
            state_path.unlink()
            with patch.object(wallet, "command", return_value="inboxes=3 peers=2 live=2 routable=1"):
                self.assertTrue(wallet.relay_connection_status(vault)["reachable"])
            self.assertFalse(state_path.exists())

    def test_operator_relay_routes_refuse_hosted_vaults(self):
        with tempfile.TemporaryDirectory(prefix="loki-hosted-relay-guard-") as temp:
            wallet, vault, _ = self.payment_fixture(temp, phase=None)
            member = wallet.data / "vaults" / vault
            membership = json.loads((member / "membership.json").read_text())
            membership["transport"] = "hosted"
            (member / "membership.json").write_text(json.dumps(membership))
            wallet.hosted = object()
            self.addCleanup(setattr, wallet, "hosted", None)
            with patch.object(wallet, "command") as command:
                for action in (lambda: wallet.relay_provision(vault, "/operator/kit"),
                               lambda: wallet.relay_export(vault),
                               lambda: wallet.relay_import(vault, "wire", "file"),
                               lambda: wallet.relay_connection_status(vault)):
                    with self.assertRaisesRegex(ValueError, "attach to relays automatically"):
                        action()
                command.assert_not_called()

    def test_relay_import_route_requires_private_token_and_refuses_invalid_file(self):
        with tempfile.TemporaryDirectory(prefix="loki-relay-route-") as temp:
            wallet, vault, _ = self.payment_fixture(temp, phase=None)
            server, token = make_signer_server(wallet, 0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            body = json.dumps({"vault": vault, "data": "not base64"})

            def request(key):
                conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1])
                conn.request("POST", "/api/relay-import", body,
                             {"X-Loki-Token": key, "Content-Type": "application/json"})
                response = conn.getresponse()
                result = response.status, json.loads(response.read())
                conn.close()
                return result

            self.assertEqual(request("wrong")[0], 403)
            code, result = request(token)
            self.assertEqual(code, 400)
            self.assertEqual(result["surface"], "relay-import")
            self.assertEqual(result["error"], "Invalid relay config file")

    def test_payment_advance_runs_mechanical_steps_once_and_never_approves(self):
        with tempfile.TemporaryDirectory(prefix="loki-advance-") as temp:
            wallet, vault, attempt = self.payment_fixture(temp, phase="published")
            calls = []

            def command(action, *_args, **_kwargs):
                calls.append(action)
                if action == "features": return "relay-backed-signing=1"
                if action == "balance": return json.dumps({"vault": vault, "height": 100})
                return "ok"

            with patch.object(wallet, "command", side_effect=command):
                self.assertEqual(wallet.advance_payment(vault, attempt),
                                 {"phase": "package", "did": ["commit", "package"]})
                self.assertEqual(wallet.advance_payment(vault, attempt),
                                 {"phase": "package", "did": []})
                report = wallet.payments(vault)
            self.assertEqual(report["payments"][0]["phase"], "package")
            self.assertEqual(report["readiness"], {
                "relay_ready": True,
                "relay_detail": "Payment build supports relay delivery. Check the relay connection above.",
                "scan_height": 100})
            self.assertEqual(calls.count("commit"), 1)
            self.assertEqual(calls.count("package"), 1)
            for decision in ("review", "approve", "approve-reviewed"):
                self.assertNotIn(decision, calls)

    def test_payment_advance_returns_while_waiting_and_raises_on_failure(self):
        with tempfile.TemporaryDirectory(prefix="loki-advance-wait-") as temp:
            wallet, vault, attempt = self.payment_fixture(temp, phase="commitments")

            def command(action, *_args, **_kwargs):
                if action == "features": return "relay-backed-signing=1"
                if action == "package":
                    raise ValueError("waiting for member 2 Commitment; sync relay inbox and retry")
                return "ok"

            with patch.object(wallet, "command", side_effect=command):
                self.assertEqual(wallet.advance_payment(vault, attempt),
                                 {"phase": "commitments", "did": []})
            self.assertTrue(wallet.relay_payment_ready)
            with patch.object(wallet, "command", side_effect=ValueError("package refused")):
                with self.assertRaisesRegex(ValueError, "package refused"):
                    wallet.advance_payment(vault, attempt)

    def test_payment_advance_does_nothing_without_a_possible_step(self):
        with tempfile.TemporaryDirectory(prefix="loki-advance-idle-") as temp:
            awaiting, vault, attempt = self.payment_fixture(temp, slot=1, phase="package")
            awaiting.relay_payment_ready = True
            with patch.object(awaiting, "command", return_value="not mined") as command:
                self.assertEqual(awaiting.advance_payment(vault, attempt),
                                 {"phase": "package", "did": []})
                self.assertEqual(command.call_args.args[0], "find-mined")
            outsider, vault, attempt = self.payment_fixture(temp, slot=3, phase=None)
            outsider.relay_payment_ready = True
            with patch.object(outsider, "command", return_value="not mined") as command:
                self.assertEqual(outsider.advance_payment(vault, attempt),
                                 {"phase": "received", "did": []})
                self.assertEqual(command.call_args.args[0], "find-mined")
            authorized, vault, attempt = self.payment_fixture(temp, slot=2, phase="approved")
            authorized.relay_payment_ready = True
            with patch.object(authorized, "command", return_value="not mined") as command:
                self.assertEqual(authorized.advance_payment(vault, attempt),
                                 {"phase": "approved", "did": []})
                self.assertEqual(command.call_args.args[0], "find-mined")

    def test_non_signer_sees_ready_only_after_verified_aggregate(self):
        with tempfile.TemporaryDirectory(prefix="loki-payment-ready-") as temp:
            wallet, vault, _ = self.payment_fixture(temp, slot=3, phase="received")

            def complete(action, *_args, **_kwargs):
                if action == "features":
                    return "relay-backed-signing=1"
                if action == "finish-check":
                    return "aggregate verified payment=" + "e" * 64 + " sighash=" + "f" * 64
                raise AssertionError(action)

            with patch.object(wallet, "command", side_effect=complete):
                self.assertTrue(wallet.payments(vault)["payments"][0]["ready_to_send"])

            def pending(action, *_args, **_kwargs):
                if action == "finish-check":
                    raise ValueError("waiting for member 2 Share; sync relay inbox and retry")
                raise AssertionError(action)

            with patch.object(wallet, "command", side_effect=pending):
                self.assertFalse(wallet.payments(vault)["payments"][0]["ready_to_send"])

            def before_package(action, *_args, **_kwargs):
                if action == "finish-check":
                    raise ValueError("error: No such file or directory (os error 2)")
                raise AssertionError(action)

            with patch.object(wallet, "command", side_effect=before_package):
                self.assertFalse(wallet.payments(vault)["payments"][0]["ready_to_send"])
            wallet.payment_status(wallet.payment(vault, "b" * 64)[2], "package")
            with patch.object(wallet, "command", side_effect=before_package):
                self.assertFalse(wallet.payments(vault)["payments"][0]["ready_to_send"])

    def test_non_finisher_finds_mined_spend_then_checks_exact_candidate(self):
        with tempfile.TemporaryDirectory(prefix="loki-chain-discovery-") as temp:
            wallet, vault, attempt = self.payment_fixture(temp, slot=1, phase="approved")
            txid = "d" * 64
            called = []

            def command(action, *args, **_kwargs):
                called.append(action)
                if action == "features": return "relay-backed-signing=1"
                if action == "find-mined": return f"mined txid={txid}"
                if action == "verify":
                    self.assertEqual(args[-1], txid)
                    return f"verified mined txid={txid} confirmations=2 amount=40000000"
                raise AssertionError(action)

            with patch.object(wallet, "command", side_effect=command):
                self.assertEqual(wallet.advance_payment(vault, attempt)["phase"], "confirmed")
            self.assertIn("find-mined", called)
            self.assertIn("verify", called)

    def test_payment_advance_verifies_with_the_recorded_txid(self):
        with tempfile.TemporaryDirectory(prefix="loki-advance-verify-") as temp:
            txid = "e" * 64
            wallet, vault, attempt = self.payment_fixture(temp, phase="broadcast", txid=txid)
            seen = []

            def command(action, *args, **_kwargs):
                if action == "features": return "relay-backed-signing=1"
                if action == "verify":
                    seen.append(args[-1])
                    return f"verified mined txid={txid} confirmations=3 amount=40000000"
                return "ok"

            with patch.object(wallet, "command", side_effect=command):
                self.assertEqual(wallet.advance_payment(vault, attempt),
                                 {"phase": "confirmed", "did": ["verify"]})
                self.assertEqual(wallet.verify_payment(vault, attempt)["txid"], txid)
                self.assertEqual(wallet.verify_payment(vault, attempt, txid)["txid"], txid)
            self.assertEqual(seen, [txid, txid, txid])

    def test_payment_advance_rechecks_saved_confirmation_after_reorg(self):
        with tempfile.TemporaryDirectory(prefix="loki-advance-reorg-") as temp:
            wallet, vault, attempt = self.payment_fixture(
                temp, phase="confirmed", txid="e" * 64)
            missing = 'getrawtransaction: {"code":-5,"message":"Transaction not found in mempool or best chain"}'
            with patch.object(wallet, "payment_command", side_effect=ValueError(missing)):
                self.assertEqual(wallet.advance_payment(vault, attempt)["phase"],
                                 "confirmation_needs_recheck")
            work = wallet.data / "vaults" / vault / "payments" / attempt
            self.assertEqual(wallet.payment_phase(work)["phase"],
                             "confirmation_needs_recheck")

    def test_payment_get_holds_wallet_lock_while_rolling_back_confirmation(self):
        with tempfile.TemporaryDirectory(prefix="loki-payment-get-reorg-") as temp:
            wallet, vault, attempt = self.payment_fixture(temp, phase="confirmed", txid="e" * 64)
            server, token = make_signer_server(wallet, 0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            payments = wallet.payments

            def checked(vault):
                self.assertTrue(wallet.lock.locked())
                return payments(vault)

            with patch.object(wallet, "payments", side_effect=checked), \
                 patch.object(wallet, "payment_command", side_effect=ValueError("transaction is not mined")):
                conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1])
                conn.request("GET", f"/api/payments?vault={vault}", headers={"X-Loki-Token": token})
                response = conn.getresponse()
                result = json.loads(response.read())
                conn.close()
            self.assertEqual(response.status, 200, result)
            self.assertEqual(result["payments"][0]["phase"], "confirmation_needs_recheck")
            work = wallet.data / "vaults" / vault / "payments" / attempt
            self.assertEqual(wallet.payment_phase(work)["phase"], "confirmation_needs_recheck")

    def test_payment_pair_defaults_to_one_holding_this_member(self):
        with tempfile.TemporaryDirectory(prefix="loki-default-pair-") as temp:
            for slot, expected in ((1, "AB"), (2, "AB"), (3, "AC")):
                wallet, vault, _ = self.payment_fixture(temp, slot=slot, phase=None)
                chosen = []

                def prepare(_action, _member, _pass, _roster, work, _recipient, amount, memo, pair,
                            **_kwargs):
                    (work / "payment.json").write_text(json.dumps({
                        "vault": vault, "payment": "b" * 64, "attempt": format(len(chosen), "064x"),
                        "amount_zat": int(amount), "fee_zat": 10000, "change_zat": 59990000,
                        "expiry_height": 9216,
                        "pair": [ord(letter) - ord("A") + 1 for letter in pair]}))
                    chosen.append(pair)
                    return "payment created"

                with patch.object(wallet, "command", side_effect=prepare):
                    draft = wallet.prepare_payment(vault, "uregtest1recipient", "40000000", "memo")
                    self.assertEqual(chosen, [expected])
                    self.assertIn(slot, draft["pair"])
                    wallet.prepare_payment(vault, "uregtest1recipient", "40000000", "memo", "BC")
                self.assertEqual(chosen, [expected, "BC"])

    def test_four_member_vault_reaches_one_address_after_every_backup(self):
        if not SETUP.is_file():
            self.skipTest("build setup binary first")
        with tempfile.TemporaryDirectory(prefix="loki-four-member-") as temp:
            root = Path(temp)
            exchange = root / "exchange"
            wallets = [Wallet(root / f"member-{slot}", exchange) for slot in range(1, 5)]
            for wallet in wallets:
                self.addCleanup(wallet.close)
            for slot, wallet in enumerate(wallets, 1):
                wallet.create_profile(f"Member {slot}", f"distinct passphrase for member {slot}")
            created = wallets[0].create("Four person treasury", members=4)
            vault = created["vault"]
            self.assertEqual(len(created["invites"]), 3)
            for wallet, invite in zip(wallets[1:], created["invites"]):
                wallet.join(invite)
            fingerprints = [wallet.roster(vault)["fingerprint"] for wallet in wallets]
            self.assertEqual(len(set(fingerprints)), 1)
            self.assertTrue(all(wallet.status(vault)["total_members"] == 4 for wallet in wallets))
            self.assertTrue(all(not wallet.status(vault)["account_linked"] for wallet in wallets))
            for wallet in wallets:
                wallet.agree(vault, fingerprints[0])
            for wallet in wallets:
                wallet.workers[vault].join(timeout=90)
                self.assertFalse(wallet.workers[vault].is_alive())
                self.assertIsNone(wallet.setup_errors.get(vault))
            saved_words = []
            for wallet in wallets:
                words = wallet.backup(vault)["words"]
                saved_words.append(words)
                card = (wallet.data / "vaults" / vault / "card" / "vault.card").read_bytes()
                wallet.verify(vault, words, base64.b64encode(card).decode())
            for wallet in wallets:
                wallet.activate(vault)
                self.assertEqual(wallet.status(vault)["phase"], "final_backup")
                with self.assertRaisesRegex(ValueError, "final backup"):
                    wallet.address(vault)
            for index, (wallet, words) in enumerate(zip(wallets, saved_words)):
                wallet.finalize_backup(vault, words)
                final_card = (wallet.data / "vaults" / vault / "final-card" / "vault.card").read_bytes()
                if index == 0:
                    member = wallet.data / "vaults" / vault
                    with self.assertRaisesRegex(ValueError, "Check your final backup card"):
                        wallet.command("backup-report", member, "@pass", member / "roster.json")
                    damaged = bytearray(final_card)
                    damaged[-1] ^= 1
                    with self.assertRaises(ValueError):
                        wallet.verify_final_backup(vault, words, base64.b64encode(damaged).decode())
                    self.assertEqual(wallet.status(vault)["phase"], "final_backup")
                    self.assertFalse((exchange / vault / f"{vault}-final-status-1.bin").exists())
                wallet.verify_final_backup(vault, words, base64.b64encode(final_card).decode())
                if index == 0:
                    card_path = member / "final-card" / "vault.card"
                    card_path.rename(member / "final-card" / "held.card")
                    try:
                        with self.assertRaisesRegex(ValueError, "Check your final backup card"):
                            wallet.command("backup-report", member, "@pass", member / "roster.json")
                    finally:
                        (member / "final-card" / "held.card").rename(card_path)
            for wallet in wallets:
                self.assertTrue(wallet.address(vault).startswith("uregtest1"))
            for pair in ("AB", "AC", "AD", "BC", "BD", "CD"):
                with patch.object(wallets[0], "command", side_effect=ValueError("native preparation reached")) as native:
                    with self.assertRaisesRegex(ValueError, "native preparation reached"):
                        wallets[0].prepare_payment(vault, "uregtest1recipient", "40000000", "memo", pair)
                    self.assertEqual(native.call_args.args[0], "prepare")
                    self.assertEqual(native.call_args.args[-1], pair)
            addresses = [wallet.command("address", wallet.data / "vaults" / vault, "@pass")
                         for wallet in wallets]
            self.assertEqual(len(set(addresses)), 1)
            self.assertTrue(addresses[0].startswith("uregtest1"))
            restored = Wallet(root / "restored", exchange)
            self.addCleanup(restored.close)
            restored.create_profile("Restored member", "restored member passphrase")
            card = (wallets[0].data / "vaults" / vault / "final-card" / "vault.card").read_bytes()
            result = restored.restore_vault("Four person treasury", saved_words[0],
                                            base64.b64encode(card).decode())
            self.assertEqual(result["address"], addresses[0])
            self.assertEqual(restored.address(vault), addresses[0])

    def test_create_join_certify_and_check_backups_in_three_roots(self):
        if not SETUP.is_file():
            self.skipTest("build loki_setup_member first")
        with tempfile.TemporaryDirectory(prefix="loki-wallet-test-") as temp:
            root = Path(temp)
            exchange = root / "exchange"
            wallets = [Wallet(root / f"member-{slot}", exchange) for slot in (1, 2, 3)]
            for wallet in wallets:
                self.addCleanup(wallet.close)
            passwords = [f"distinct passphrase for member {slot}" for slot in (1, 2, 3)]
            profiles = [wallet.create_profile(f"Member {slot}", passwords[slot - 1])["profile"]
                        for slot, wallet in enumerate(wallets, 1)]
            self.assertEqual(len({profile["id"] for profile in profiles}), 3)
            created = wallets[0].create("Group treasury")
            vault = created["vault"]
            invites = created["invites"]
            draft_path = exchange / vault / "draft.json"
            draft = json.loads(draft_path.read_text())
            draft_path.write_text(json.dumps({**draft, "threshold": 3}))
            with self.assertRaisesRegex(ValueError, "Unsupported vault draft"):
                wallets[1].join(invites[0])
            draft_path.write_text(json.dumps(draft))
            self.assertEqual(wallets[1].join(invites[0]), {"vault": vault, "joined": True})
            self.assertEqual(wallets[2].join(invites[1]), {"vault": vault, "joined": True})
            with self.assertRaisesRegex(ValueError, "already been claimed"):
                attacker = Wallet(root / "attacker", exchange)
                self.addCleanup(attacker.close)
                attacker.create_profile("Attacker", "attacker passphrase for test")
                attacker.join(invites[0])

            fingerprints = [wallet.roster(vault)["fingerprint"] for wallet in wallets]
            self.assertEqual(len(set(fingerprints)), 1)
            with self.assertRaisesRegex(ValueError, "does not match"):
                wallets[0].agree(vault, "0" * 64)
            wallets[0].lock_profile()
            self.assertEqual(wallets[0].status()["phase"], "locked")
            # the wording is part of the interface now: it is what the unlock
            # form shows, so assert on that rather than on the binary's stderr
            with self.assertRaisesRegex(ValueError, "Could not open your profile"):
                wallets[0].unlock("wrong passphrase for this vault")
            self.assertEqual(wallets[0].unlock(passwords[0])["profile"], profiles[0])
            self.assertEqual(wallets[0].status(vault)["phase"], "compare_roster")
            self.assertTrue(all(not wallet.status(vault)["account_linked"] for wallet in wallets))
            for wallet in wallets:
                self.assertEqual(wallet.agree(vault, fingerprints[0]), {"started": True})
            for wallet in wallets:
                wallet.workers[vault].join(timeout=90)
                self.assertFalse(wallet.workers[vault].is_alive())
                self.assertIsNone(wallet.setup_errors.get(vault))
                self.assertEqual(wallet.status(vault)["phase"], "back_up")

            saved_words = []
            for index, wallet in enumerate(wallets):
                words = wallet.backup(vault)["words"]
                saved_words.append(words)
                card = (wallet.data / "vaults" / vault / "card" / "vault.card").read_bytes()
                if index == 0:
                    with self.assertRaises(ValueError):
                        wallet.verify(vault, "wrong words")
                    self.assertEqual(wallet.verify(vault, words), {"verified": True})
                else:
                    self.assertEqual(wallet.verify(vault, words, base64.b64encode(card).decode()),
                                     {"verified": True})
                if index == 0:
                    self.assertEqual(wallet.status(vault)["backup_checks_received"], 1)
            self.assertEqual(wallets[0].status(vault)["backup_checks_received"], 3)
            for wallet in wallets:
                wallet.activate(vault)
                self.assertEqual(wallet.status(vault)["phase"], "final_backup")
                self.assertEqual([r["reported"] for r in wallet.status(vault)["backups"]],
                                 [False, False, False])
            for index, (wallet, words) in enumerate(zip(wallets, saved_words)):
                sealed_words = wallet.data / "vaults" / vault / "secrets" / "backup-words.sealed"
                if index == 0:
                    self.assertTrue(sealed_words.is_file())
                    self.assertFalse(wallet.status(vault)["final_card_needs_words"])
                    wallet.finalize_backup(vault)
                    self.assertFalse(sealed_words.exists())
                    self.assertTrue(wallet.status(vault)["final_card_created"])
                else:
                    if index == 1:
                        sealed_words.unlink()  # an older setup with no temporary copy
                        self.assertTrue(wallet.status(vault)["final_card_needs_words"])
                    wallet.finalize_backup(vault, words)
                final_card = (wallet.data / "vaults" / vault / "final-card" / "vault.card").read_bytes()
                self.assertEqual(wallet.verify_final_backup(vault, words, base64.b64encode(final_card).decode()),
                                 {"verified": True})
                self.assertEqual([r["reported"] for r in wallet.status(vault)["backups"]],
                                 [True] * (index + 1) + [False] * (2 - index))
            reports = wallets[0].status(vault)["backups"]
            self.assertEqual([r["reported"] for r in reports], [True, True, True])
            second = exchange / vault / f"{vault}-final-status-2.bin"
            third = exchange / vault / f"{vault}-final-status-3.bin"
            original = second.read_bytes()
            second.write_bytes(third.read_bytes())
            self.assertEqual(wallets[0].status(vault)["backups"][1],
                             {"slot": 2, "reported": False, "invalid": True})
            forged = bytearray(original)
            forged[-1] ^= 1
            second.write_bytes(forged)
            self.assertEqual(wallets[0].status(vault)["backups"][1],
                             {"slot": 2, "reported": False, "invalid": True})
            second.write_bytes(b"unreadable receipt")
            self.assertEqual(wallets[0].status(vault)["backups"][1],
                             {"slot": 2, "reported": False, "invalid": True})
            second.unlink()
            second.mkdir()
            self.assertEqual(wallets[0].status(vault)["backups"][1],
                             {"slot": 2, "reported": False, "invalid": True})
            second.rmdir()
            second.write_bytes(original)
            third.unlink()
            self.assertEqual(wallets[0].status(vault)["backups"][2],
                             {"slot": 3, "reported": False, "invalid": False})
            receipts = list((exchange / vault).glob(f"{vault}-backup-*.bin"))
            self.assertEqual(len(receipts), 3)
            for receipt in receipts:
                receipt.unlink()
            saved_final = (wallets[0].data / "vaults" / vault / "final-card" / "vault.card").read_bytes()
            self.assertEqual(wallets[0].verify_final_backup(
                vault, saved_words[0], base64.b64encode(saved_final).decode()), {"verified": True})
            addresses = [wallet.address(vault) for wallet in wallets]
            self.assertEqual(len(set(addresses)), 1)
            self.assertTrue(addresses[0].startswith("uregtest1"))
            saved_final = (wallets[0].data / "vaults" / vault / "final-card" / "vault.card").read_bytes()
            recovered = Wallet(root / "recovered-member", root / "empty-exchange")
            self.addCleanup(recovered.close)
            recovered.create_profile("Recovered member", "new device passphrase for test")
            with self.assertRaises(ValueError):
                recovered.restore_vault("Recovered treasury", saved_words[0],
                                        base64.b64encode((wallets[0].data / "vaults" / vault /
                                                          "card" / "vault.card").read_bytes()).decode())
            self.assertEqual(recovered.vaults(), [])
            damaged = bytearray(saved_final)
            damaged[-1] ^= 1
            with self.assertRaises(ValueError):
                recovered.restore_vault("Recovered treasury", saved_words[0],
                                        base64.b64encode(damaged).decode())
            self.assertEqual(recovered.vaults(), [])
            result = recovered.restore_vault("Recovered treasury", saved_words[0],
                                             base64.b64encode(saved_final).decode())
            self.assertEqual(result, {"vault": vault, "slot": 1, "address": addresses[0]})
            self.assertEqual(recovered.status(vault)["phase"], "active")
            self.assertEqual(recovered.address(vault), addresses[0])
            self.assertEqual((recovered.data / "vaults" / vault / "final-card" / "vault.card").read_bytes(),
                             saved_final)
            with self.assertRaisesRegex(ValueError, "already has a membership"):
                recovered.restore_vault("Duplicate", saved_words[0], base64.b64encode(saved_final).decode())
            self.assertEqual(len(recovered.vaults()), 1)
            sealed = (wallets[0].data / "vaults" / vault / "secrets" / "vault.sealed").read_bytes()
            seed = root / "wallet-seed.txt"
            seed.write_text("abandon " * 23 + "art")
            os.chmod(seed, 0o600)
            challenge = root / "challenge.json"
            challenge.write_text(json.dumps(wallets[0].begin_link(vault)))
            proof = json.loads(subprocess.run(
                [SEED_WALLET, "prove", seed, challenge], capture_output=True,
                text=True, check=True).stdout)
            wallets[0].link(vault, proof)
            self.assertTrue(wallets[0].status(vault)["account_linked"])
            self.assertEqual((wallets[0].data / "vaults" / vault / "secrets" / "vault.sealed").read_bytes(), sealed)
            self.assertEqual(wallets[0].address(vault), addresses[0])
            for index, wallet in enumerate(wallets):
                self.assertEqual(wallet.status(vault)["phase"], "active")
                self.assertEqual(len(list(wallet.data.glob("vaults/*/secrets/vault.sealed"))), 1)
                for other in wallets[:index] + wallets[index + 1:]:
                    self.assertFalse((wallet.data / other.data.name / "secrets").exists())
            second = wallets[0].create("Second vault")["vault"]
            self.assertNotEqual(second, vault)
            self.assertEqual(len(wallets[0].status()["vaults"]), 2)
            self.assertEqual(wallets[0].status(second)["phase"], "waiting_for_members")
            with self.assertRaisesRegex(ValueError, "not a member"):
                wallets[1].status(second)
            first_key = json.loads((exchange / vault / "join-1.json").read_text())
            second_key = json.loads((exchange / second / "join-1.json").read_text())
            self.assertNotEqual(first_key["signing"], second_key["signing"])
            self.assertNotEqual(first_key["encryption"], second_key["encryption"])
            self.assertEqual(wallets[0].status()["vaults"][0]["profile"], profiles[0]["id"])
            self.assertEqual(wallets[0].status()["vaults"][1]["profile"], profiles[0]["id"])
            with patch.object(wallets[0], "command", return_value=json.dumps(
                    {"vault": vault, "height": 42, "balance_zat": 5000, "unspent_notes": 1})) as call:
                self.assertEqual(wallets[0].balance(vault)["balance_zat"], 5000)
                self.assertEqual(call.call_args.args[1], wallets[0].data / "vaults" / vault)
            with patch.object(wallets[0], "command", return_value=json.dumps({"vault": second})):
                with self.assertRaisesRegex(ValueError, "another vault"):
                    wallets[0].balance(vault)
            link_record = wallets[0].data / "vaults" / vault / "secrets" / "account-link.sealed"
            damaged = bytearray(link_record.read_bytes())
            damaged[-1] ^= 1
            link_record.write_bytes(damaged)
            status = wallets[0].status(vault)
            self.assertEqual(status["phase"], "active")
            self.assertIn("account_link_error", status)
            self.assertEqual(wallets[0].address(vault), addresses[0])

            (exchange / vault).rename(root / "retired-courier")
            for wallet in wallets:
                self.assertEqual(wallet.status(vault)["phase"], "active")
                self.assertEqual(wallet.status(vault)["fingerprint"], fingerprints[0])
                self.assertIn(vault, [item["vault"] for item in wallet.status()["vaults"]])
                self.assertEqual(wallet.address(vault), addresses[0])
            roster_path = wallets[1].data / "vaults" / vault / "roster.json"
            saved_roster = json.loads(roster_path.read_text())
            for changed in ({**saved_roster, "vault": "0" * 64},
                            {**saved_roster, "members": [{**saved_roster["members"][0],
                                                          "signing": "0" * 64},
                                                         *saved_roster["members"][1:]]},
                            {**saved_roster, "members": [saved_roster["members"][0],
                                                          {**saved_roster["members"][1], "signing": "0" * 64},
                                                          *saved_roster["members"][2:]]},
                            {**saved_roster, "threshold": 3}):
                roster_path.write_text(json.dumps(changed))
                with self.assertRaises(ValueError):
                    wallets[1].status(vault)
            roster_path.write_text(json.dumps(saved_roster))

    def test_roster_confirmations_are_published_and_compared(self):
        """Each app publishes the fingerprint it confirmed, and reads the others.

        The courier is untrusted, so a matching entry is only a coordination
        signal; the test that matters is that a DIFFERING entry is reported as
        a mismatch rather than quietly passing as agreement."""
        with tempfile.TemporaryDirectory(prefix="loki-confirm-") as temp:
            root = Path(temp)
            exchange = root / "exchange"
            wallet = Wallet(root / "member", exchange)
            self.addCleanup(wallet.close)
            vault = "a" * 64
            folder = exchange / vault
            folder.mkdir(mode=0o700, parents=True)
            (folder / "draft.json").write_text(json.dumps({"vault": vault, "members": 3}))

            mine = "8f3a 21c7 d490 be65"
            self.assertEqual(
                [entry["confirmed"] for entry in wallet.confirmations(vault, mine)],
                [False, False, False])

            for slot, published in ((1, mine), (2, mine), (3, "0000 1111 2222 3333")):
                (folder / f"confirm-{slot}.json").write_text(
                    json.dumps({"slot": slot, "fingerprint": published, "at": 0}))

            seen = wallet.confirmations(vault, mine)
            self.assertEqual([entry["confirmed"] for entry in seen], [True, True, True])
            self.assertEqual([entry["matches"] for entry in seen], [True, True, False])

            # an unreadable claim is a mismatch, never a silent pass
            (folder / "confirm-2.json").write_text("not json")
            self.assertEqual(wallet.confirmations(vault, mine)[1],
                             {"slot": 2, "confirmed": False, "matches": False, "at": None})

    def test_rejects_exchange_inside_private_root(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaisesRegex(ValueError, "separate"):
                Wallet(root / "member", root / "member" / "exchange")

    def test_private_root_cannot_be_opened_twice(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first = Wallet(root / "member", root / "exchange")
            self.addCleanup(first.close)
            with self.assertRaisesRegex(ValueError, "already open"):
                Wallet(root / "member", root / "exchange")
            self.assertIsNotNone(first.process_lock)

    def test_legacy_single_vault_root_is_not_modified(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            old = root / "member"
            old.mkdir()
            (old / "membership.json").write_text('{"vault":"old"}')
            with self.assertRaisesRegex(ValueError, "single-vault"):
                Wallet(old, root / "exchange")
            self.assertEqual((old / "membership.json").read_text(), '{"vault":"old"}')

    def test_profile_name_is_required(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            wallet = Wallet(root / "member", root / "exchange")
            self.addCleanup(wallet.close)
            with self.assertRaisesRegex(ValueError, "profile name"):
                wallet.create_profile(None, "a passphrase that is long enough")
            self.assertEqual(wallet.status()["phase"], "new_profile")


if __name__ == "__main__":
    unittest.main()
