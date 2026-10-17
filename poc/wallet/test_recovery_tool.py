"""Member recovery flows with a fake regtest command boundary."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from recovery_tool import RecoveryTool


FAKE = '''#!/usr/bin/env python3
import json, pathlib, sys
action, *args = sys.argv[1:]
if action == "restore":
    owner, password, card, words = map(pathlib.Path, args)
    data = json.loads((card / "vault.card").read_text())
    if words.read_text().strip() != data["words"]:
        sys.exit("wrong words")
    owner.mkdir()
    (owner / "roster.json").write_text(json.dumps({"vault": data["vault"],
        "threshold": 2, "members": [{"id": i} for i in (1, 2, 3)]}))
    if not data.get("legacy"):
        (owner / "secrets").mkdir()
        (owner / "secrets" / "activation.sealed").write_text("active")
    (owner / "slot").write_text(str(data["slot"]))
    print(data["address"])
elif action == "identity-public":
    print(json.dumps({"id": int((pathlib.Path(args[0]) / "slot").read_text())}))
elif action == "prepare-sweep":
    owner, password, roster, work, recipient, memo, pair = args
    work = pathlib.Path(work)
    work.mkdir()
    (work / "payment.json").write_text(json.dumps({"vault": json.loads(pathlib.Path(roster).read_text())["vault"],
        "payment": "a" * 64, "pair": [ord(c) - 64 for c in pair], "recipient": recipient,
        "amount_zat": 99000000, "fee_zat": 1000000, "change_zat": 0}))
    print("prepared")
elif action == "sign":
    print("Vault: " + json.loads(pathlib.Path(args[2]).read_text())["vault"])
    print("Recipient: " + json.loads((pathlib.Path(args[3]) / "payment.json").read_text())["recipient"])
    print("Amount: 99000000 zat; memo: \\"sweep\\"")
    print("Type APPROVE " + "a" * 64 + " to sign:", flush=True)
    if sys.stdin.readline().strip() != "APPROVE " + "a" * 64:
        sys.exit("approval declined")
    print("approved")
elif action == "finish":
    print("broadcast txid=" + "b" * 64 + " payment=" + "a" * 64)
elif action == "verify":
    if json.loads((pathlib.Path(args[3]) / "payment.json").read_text())["recipient"] == "uregtest-verification-error":
        sys.exit("regtest RPC unavailable after broadcast")
    print("verified mined txid=" + args[-1] + " confirmations=3 amount=99000000")
else:
    sys.exit("unexpected action " + action)
'''


class RecoveryToolTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binary = self.root / "fake-member"
        self.binary.write_text(FAKE)
        self.binary.chmod(0o700)
        self.vault = "c" * 64

    def artifacts(self, slots=(1, 2), address="uregtest-source"):
        result = []
        for slot in slots:
            card = self.root / f"member-{slot}.card"
            words = " ".join([f"word{slot}"] * 24)
            card.write_text(json.dumps({"vault": self.vault, "address": address,
                                        "slot": slot, "words": words}))
            result.append((card, words, f"new passphrase for {slot}"))
        return result

    def test_lost_device_uses_only_saved_cards_and_words(self):
        with RecoveryTool(self.binary, self.binary) as tool:
            result = tool.sweep(self.artifacts(), "uregtest-new-vault", lambda *_: True)
            self.assertEqual(result["txid"], "b" * 64)
            self.assertTrue(result["verified"])
            self.assertEqual(result["pair"], "AB")
            self.assertTrue(all("Recipient: uregtest-new-vault" in review
                                for review in result["reviews"]))
            work = tool.root
        self.assertFalse(work.exists())

    def test_lost_passphrase_needs_only_new_passphrases(self):
        with RecoveryTool(self.binary, self.binary) as tool:
            result = tool.sweep(self.artifacts((2, 3)), "uregtest-new-vault", lambda *_: True)
            self.assertEqual(result["pair"], "BC")
            self.assertTrue(result["verified"])

    def test_relay_outage_uses_no_relay_command(self):
        with RecoveryTool(self.binary, self.binary, env={"LOKI_RPC": "127.0.0.1:18232"}) as tool:
            result = tool.sweep(self.artifacts((1, 3)), "uregtest-new-vault", lambda *_: True)
            self.assertEqual(result["pair"], "AC")
            self.assertTrue(result["verified"])

    def test_departure_sweeps_to_distinct_new_vault(self):
        with RecoveryTool(self.binary, self.binary) as tool:
            with self.assertRaisesRegex(ValueError, "different vault"):
                tool.sweep(self.artifacts(), "uregtest-source", lambda *_: True)
            result = tool.sweep(self.artifacts(), "uregtest-new-vault", lambda *_: True)
            self.assertTrue(result["verified"])

    def test_two_distinct_members_and_explicit_approvals_required(self):
        with RecoveryTool(self.binary, self.binary) as tool:
            with self.assertRaisesRegex(ValueError, "distinct members"):
                tool.sweep(self.artifacts((1, 1)), "uregtest-new-vault", lambda *_: True)
        with RecoveryTool(self.binary, self.binary) as tool:
            with self.assertRaisesRegex(ValueError, "declined"):
                tool.sweep(self.artifacts(), "uregtest-new-vault", lambda *_: False)

    def test_provisional_card_cannot_start_a_spend(self):
        artifacts = self.artifacts()
        card = artifacts[0][0]
        data = json.loads(card.read_text())
        card.write_text(json.dumps({**data, "legacy": True}))
        with RecoveryTool(self.binary, self.binary) as tool:
            with self.assertRaisesRegex(ValueError, "final spend recovery card"):
                tool.sweep(artifacts, "uregtest-new-vault", lambda *_: True)

    def test_broadcast_txid_survives_a_later_verification_failure(self):
        with RecoveryTool(self.binary, self.binary) as tool:
            result = tool.sweep(self.artifacts(), "uregtest-verification-error", lambda *_: True)
            self.assertEqual(result["txid"], "b" * 64)
            self.assertFalse(result["verified"])
            self.assertIn("RPC unavailable", result["verification_error"])


if __name__ == "__main__":
    unittest.main()
