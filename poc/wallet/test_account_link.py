"""Optional reference-wallet account proof remains bound to one vault identity."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from member_app import SEED_WALLET, Wallet


WORDS = "abandon " * 23 + "art"


class AccountLinkTest(unittest.TestCase):
    def test_seed_wallet_proof_binds_one_profile_to_its_vault_identity(self):
        with tempfile.TemporaryDirectory(prefix="loki-account-link-") as temp:
            root = Path(temp)
            app = Wallet(root / "member", root / "exchange")
            self.addCleanup(app.close)
            app.create_profile("Owner", "a long local passphrase")
            vault = app.create("Treasury")["vault"]
            challenge = app.begin_link(vault)
            seed_file = root / "seed.txt"
            seed_file.write_text(WORDS)
            os.chmod(seed_file, 0o600)
            challenge_file = root / "challenge.json"
            challenge_file.write_text(json.dumps(challenge))
            proof = json.loads(subprocess.run(
                [SEED_WALLET, "prove", seed_file, challenge_file],
                text=True, capture_output=True, check=True,
            ).stdout)
            altered = {**proof, "signature": proof["signature"][:-1] +
                       ("0" if proof["signature"][-1] != "0" else "1")}
            with self.assertRaisesRegex(ValueError, "signature"):
                app.link(vault, altered)
            linked = app.link(vault, proof)
            self.assertEqual(linked["account_ak"], proof["account_ak"])
            self.assertEqual(app.status(vault)["account_ak"], proof["account_ak"])

            another = app.create("Another treasury")["vault"]
            app.begin_link(another)
            with self.assertRaisesRegex(ValueError, "challenge|signature"):
                app.link(another, proof)

            other_seed = root / "other-seed.txt"
            other_seed.write_text("zoo " * 23 + "vote")
            os.chmod(other_seed, 0o600)
            other_challenge = root / "other-challenge.json"
            other_challenge.write_text(json.dumps(app.begin_link(another)))
            other_proof = json.loads(subprocess.run(
                [SEED_WALLET, "prove", other_seed, other_challenge],
                text=True, capture_output=True, check=True,
            ).stdout)
            with self.assertRaisesRegex(ValueError, "different account"):
                app.link(another, other_proof)


if __name__ == "__main__":
    unittest.main()
