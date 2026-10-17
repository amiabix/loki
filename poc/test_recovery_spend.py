"""Offline checks for the two exported artifacts used by recovery spending."""

import importlib.util
import pathlib
import tempfile
import unittest
from unittest import mock


SCRIPT = pathlib.Path(__file__).with_name("run-member-payment.py")
spec = importlib.util.spec_from_file_location("member_payment", SCRIPT)
payment = importlib.util.module_from_spec(spec)
spec.loader.exec_module(payment)


class RecoverySpendTest(unittest.TestCase):
    def test_restores_both_signers_without_original_member_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for number in (2, 3):
                card = root / "source" / f"final-card-{number}"
                card.mkdir(parents=True)
                (card / "vault.card").write_bytes(f"card-{number}".encode())
                (root / "source" / f"words-{number}.txt").write_text(f"words-{number}\n")
            with mock.patch.object(payment, "run", return_value="same vault") as restored:
                signers, roster = payment.restore_pair(root, "setup", {}, (2, 3), "same vault")
            self.assertEqual([member[0].name for member in signers], ["member", "member"])
            self.assertEqual(roster, root / "recovered-member-2" / "member" / "roster.json")
            self.assertEqual(restored.call_count, 2)
            for number in (2, 3):
                recovered = root / f"recovered-member-{number}"
                self.assertFalse((recovered / "card").exists())
                self.assertFalse((recovered / "words.txt").exists())
                self.assertEqual(restored.call_args_list[number - 2].args[0], [
                    "setup", "restore", recovered / "member", recovered / "pass.txt",
                    root / "source" / f"final-card-{number}", root / "source" / f"words-{number}.txt",
                ])

    def test_rejects_restored_address_that_differs_from_funded_vault(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            card = root / "source" / "final-card-1"
            card.mkdir(parents=True)
            (card / "vault.card").write_bytes(b"card")
            (root / "source" / "words-1.txt").write_text("words\n")
            with mock.patch.object(payment, "run", return_value="different vault"):
                with self.assertRaisesRegex(RuntimeError, "recovered signer derived another vault address"):
                    payment.restore_pair(root, "setup", {}, (1,), "funded vault")


if __name__ == "__main__":
    unittest.main()
