"""The setup app never creates or unlocks another member's share."""

import base64
import sys
import tempfile
import time
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
            passphrase = "a distinct passphrase for this regtest member"
            invites = wallets[0].create("Group treasury", passphrase)["invites"]
            self.assertEqual(wallets[1].join(invites[0], passphrase), {"joined": True})
            self.assertEqual(wallets[2].join(invites[1], passphrase), {"joined": True})
            with self.assertRaisesRegex(ValueError, "already been claimed"):
                attacker = Wallet(root / "attacker", exchange)
                self.addCleanup(attacker.close)
                attacker.join(invites[0], passphrase)

            fingerprints = [wallet.roster()["fingerprint"] for wallet in wallets]
            self.assertEqual(len(set(fingerprints)), 1)
            with self.assertRaisesRegex(ValueError, "does not match"):
                wallets[0].agree("0" * 64, passphrase)
            with self.assertRaisesRegex(ValueError, "failed authentication"):
                wallets[0].agree(fingerprints[0], "wrong passphrase for this vault")
            self.assertIsNone(wallets[0].worker)
            for wallet in wallets:
                self.assertEqual(wallet.agree(fingerprints[0], passphrase), {"started": True})
            for wallet in wallets:
                wallet.worker.join(timeout=90)
                self.assertFalse(wallet.worker.is_alive())
                self.assertIsNone(wallet.setup_error)
                self.assertEqual(wallet.status()["phase"], "back_up")

            for wallet in wallets:
                words = wallet.backup(passphrase)["words"]
                card = (wallet.data / "card" / "vault.card").read_bytes()
                self.assertEqual(wallet.verify(passphrase, words, base64.b64encode(card).decode()),
                                 {"verified": True})
            addresses = [wallet.address(passphrase) for wallet in wallets]
            self.assertEqual(len(set(addresses)), 1)
            self.assertTrue(addresses[0].startswith("uregtest1"))
            for index, wallet in enumerate(wallets):
                self.assertEqual(wallet.status()["phase"], "active")
                self.assertEqual(len(list(wallet.data.glob("secrets/vault.sealed"))), 1)
                for other in wallets[:index] + wallets[index + 1:]:
                    self.assertFalse((wallet.data / other.data.name / "secrets").exists())

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

    def test_restart_during_key_creation_is_reported_not_reoffered(self):
        """A round dies with its process; the next app must say so, not restart it."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first = Wallet(root / "member", root / "exchange")
            (first.data / "keygen.running").write_text("8f3a 21c7")
            first.close()

            second = Wallet(root / "member", root / "exchange")
            self.addCleanup(second.close)
            self.assertIn("interrupted", second.setup_error)
            self.assertFalse((second.data / "keygen.running").exists())

            # and the marker is cleared, so confirming the roster again can proceed
            second.close()
            third = Wallet(root / "member", root / "exchange")
            self.addCleanup(third.close)
            self.assertIsNone(third.setup_error)


if __name__ == "__main__":
    unittest.main()
