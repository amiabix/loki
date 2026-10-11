"""The setup app never creates or unlocks another member's share."""

import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from member_app import SETUP, Wallet


class MemberWalletTest(unittest.TestCase):
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
