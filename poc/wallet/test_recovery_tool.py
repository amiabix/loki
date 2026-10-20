"""Black-box CLI protocol checks; fake children do not prove a funded sweep."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


FAKE = '''#!/usr/bin/env python3
import json, os, pathlib, sys
def identity(slot):
    return {"id": slot, "signing": "58" + "66" * 31, "encryption": "01" * 32}
action, *args = sys.argv[1:]
if os.environ.get("LOKI_TEST_NATIVE_RECOVERY"):
    secret_positions = {"restore": (1, 3), "identity-public": (1,),
        "prepare-sweep": (1,), "sign": (1,), "finish": (1,), "verify": (1,)}
    for position in secret_positions.get(action, ()):
        if not args[position].startswith("/dev/fd/"):
            sys.exit("secret supplied through a named file")
if action == "restore":
    owner, password, card, words = map(pathlib.Path, args)
    data = json.loads((card / "vault.card").read_text())
    if words.read_text().strip() != data["words"]:
        sys.exit("wrong words")
    owner.mkdir()
    (owner / "roster.json").write_text(json.dumps({"vault": data["vault"],
        "threshold": 2, "members": [identity(i) for i in (1, 2, 3)]}))
    if not data.get("legacy"):
        (owner / "secrets").mkdir()
        (owner / "secrets" / "activation.sealed").write_text("active")
    (owner / "slot").write_text(str(data["slot"]))
    print(data["address"])
elif action == "identity-public":
    print(json.dumps(identity(int((pathlib.Path(args[0]) / "slot").read_text()))))
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
    recipient = json.loads((pathlib.Path(args[3]) / "payment.json").read_text())["recipient"]
    if recipient == "uregtest-long-review":
        print("x" * 20000)
    print("Recipient: " + recipient)
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


class NativeRecoveryCliTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.vault = "c" * 64
        binary = Path(os.environ.get("LOKI_RECOVERY_BIN", Path(__file__).parents[1] / "target" / "debug" / "loki_recover"))
        shutil.copy2(binary, self.root / "loki_recover")
        for name in ("loki_setup_member", "loki_member_payment"):
            child = self.root / name
            child.write_text(FAKE)
            child.chmod(0o700)

    def artifacts(self, slots=(1, 2), address="uregtest-source"):
        result = []
        for slot in slots:
            card = self.root / f"member-{slot}.card"
            words = " ".join([f"word{slot}"] * 24)
            card.write_text(json.dumps({"vault": self.vault, "address": address,
                                        "slot": slot, "words": words}))
            result.append((card, words, f"new passphrase for {slot}"))
        return result

    def run_recovery(self, artifacts=None, recipient="uregtest-new-vault", approvals=None, rpc=False):
        if artifacts is None:
            artifacts = self.artifacts()
        if approvals is None:
            approvals = ("a" * 64, "a" * 64)
        answers = [value for card, words, passphrase in artifacts
                   for value in (str(card), words, passphrase)]
        answers += [recipient, *approvals]
        args = [str(self.root / "loki_recover")]
        if rpc:
            args += ["--rpc", "127.0.0.1:18232"]
        result = subprocess.run(args, input="\n".join(answers) + "\n", text=True,
                                capture_output=True, timeout=30,
                                env={**os.environ, "LOKI_TEST_NATIVE_RECOVERY": "1", "TMPDIR": str(self.root)})
        for _, words, passphrase in artifacts:
            self.assertNotIn(words, result.stdout + result.stderr)
            self.assertNotIn(passphrase, result.stdout + result.stderr)
        self.assertFalse(list(self.root.glob("loki-recovery-*")), "temporary recovery stores remained")
        return result

    def test_cli_protocol_requires_two_reviewed_approvals(self):
        result = self.run_recovery()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Recipient: uregtest-new-vault", result.stdout)
        self.assertEqual(result.stdout.count("type payment ID"), 2)
        self.assertIn("b" * 64, result.stdout)
        self.assertIn("Mined sweep verified", result.stdout)

    def test_cli_accepts_bc_pair_and_rpc_option(self):
        result = self.run_recovery(self.artifacts((2, 3)), rpc=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Mined sweep verified", result.stdout)

    def test_same_vault_destination_is_refused(self):
        result = self.run_recovery(recipient="uregtest-source")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("different vault", result.stderr)

    def test_two_distinct_members_required(self):
        result = self.run_recovery(self.artifacts((1, 1)))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("distinct members", result.stderr)

    def test_each_member_must_explicitly_approve(self):
        for approvals in (("no",), ("a" * 64, "no")):
            with self.subTest(approvals=approvals):
                result = self.run_recovery(approvals=approvals)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("declined", result.stderr)

    def test_provisional_card_cannot_start_a_spend(self):
        artifacts = self.artifacts()
        card = artifacts[0][0]
        data = json.loads(card.read_text())
        card.write_text(json.dumps({**data, "legacy": True}))
        result = self.run_recovery(artifacts)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("final spend recovery card", result.stderr)

    def test_broadcast_txid_survives_later_verification_failure(self):
        result = self.run_recovery(recipient="uregtest-verification-error")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Broadcast transaction: " + "b" * 64, result.stdout)
        self.assertIn("Verification incomplete", result.stdout)
        self.assertIn("RPC unavailable", result.stdout)

    def test_oversized_signer_review_is_rejected(self):
        result = self.run_recovery(recipient="uregtest-long-review")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("review exceeded", result.stderr)


if __name__ == "__main__":
    unittest.main()
