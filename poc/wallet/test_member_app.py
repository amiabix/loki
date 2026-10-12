"""The setup app never creates or unlocks another member's share."""

import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
from member_app import SEED_WALLET, SETUP, Wallet


class MemberWalletTest(unittest.TestCase):
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

            def prepare(_action, member, _pass, roster, work, _recipient, amount, memo, pair, **kwargs):
                self.assertEqual(member, folder)
                self.assertEqual(roster, folder / "roster.json")
                self.assertEqual(work.parent, folder / "payments")
                self.assertEqual(work.stat().st_mode & 0o777, 0o700)
                self.assertEqual((amount, memo, pair), ("40000000", "test memo", "AB"))
                self.assertEqual(kwargs["binary"], Path(SETUP).with_name("loki_member_payment"))
                (work / "payment.json").write_text(json.dumps({
                    "vault": vault, "payment": "b" * 64, "amount_zat": 40000000,
                    "fee_zat": 10000, "change_zat": 59990000, "expiry_height": 9216,
                    "pair": [1, 2]}))
                return "payment created"

            with patch.object(alice, "command", side_effect=prepare) as command:
                draft = alice.prepare_payment(vault, "uregtest1recipient", "40000000", "test memo", "AB")
            self.assertEqual(command.call_count, 1)
            self.assertEqual(draft["payment"], "b" * 64)
            self.assertEqual(draft["status"], "draft_only")
            self.assertEqual(len(list((folder / "payments").glob("*/payment.json"))), 1)
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
            for wallet in wallets:
                words = wallet.backup(vault)["words"]
                card = (wallet.data / "vaults" / vault / "card" / "vault.card").read_bytes()
                wallet.verify(vault, words, base64.b64encode(card).decode())
            addresses = [wallet.address(vault) for wallet in wallets]
            self.assertEqual(len(set(addresses)), 1)
            self.assertTrue(addresses[0].startswith("uregtest1"))

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
            with self.assertRaisesRegex(ValueError, "failed authentication"):
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

            for wallet in wallets:
                words = wallet.backup(vault)["words"]
                card = (wallet.data / "vaults" / vault / "card" / "vault.card").read_bytes()
                self.assertEqual(wallet.verify(vault, words, base64.b64encode(card).decode()),
                                 {"verified": True})
            addresses = [wallet.address(vault) for wallet in wallets]
            self.assertEqual(len(set(addresses)), 1)
            self.assertTrue(addresses[0].startswith("uregtest1"))
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
