from pathlib import Path
import re
import subprocess
import unittest


class DependencyGraphTests(unittest.TestCase):
    def test_production_transaction_signing_and_proving_use_one_zakura_family(self):
        poc = Path(__file__).resolve().parents[1]
        tree = subprocess.run(
            ["cargo", "tree", "--offline", "--locked", "--edges", "normal,build", "--prefix", "none"],
            cwd=poc, check=True, capture_output=True, text=True,
        ).stdout
        packages = set(re.findall(r"^([\w-]+) v([^\s]+)", tree, re.MULTILINE))
        old = {"orchard", "reddsa", "pasta_curves", "pczt", "zcash_primitives", "sapling-crypto",
               "halo2_proofs", "halo2_gadgets", "halo2_poseidon", "jubjub", "redjubjub",
               "bellman", "bls12_381", "pairing", "sinsemilla", "equihash",
               "zcash_address", "zcash_protocol", "zcash_transparent"}
        self.assertFalse({name for name, _ in packages} & old)
        family = {name: version for name, version in packages if name.startswith("zakura-")}
        self.assertEqual(len(family), 20)
        self.assertEqual(family.pop("zakura-pczt"), "0.1.0-rc4")
        self.assertEqual(set(family.values()), {"2.2.0"})
        for name in ("frost-core", "frost-rerandomized"):
            self.assertEqual({version for package, version in packages if package == name}, {"3.0.0"})
