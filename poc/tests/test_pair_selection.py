import importlib.util
from pathlib import Path
import unittest
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


spec = importlib.util.spec_from_file_location("run_ths", Path(__file__).resolve().parents[1] / "run-ths.py")
run_ths = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run_ths)


class PairSelectionTests(unittest.TestCase):
    def test_default_pair_is_ab(self):
        self.assertEqual(run_ths.parse_args(["--name", "test-instance"]).pair, "AB")

    def test_only_the_selected_pair_has_two_signers(self):
        for pair, expected in {"AB": ("alice", "bob"), "AC": ("alice", "carol"), "BC": ("bob", "carol")}.items():
            with self.subTest(pair=pair):
                args = run_ths.parse_args(["--name", "test-instance", "--pair", pair])
                signers = run_ths.PAIR_MEMBERS[args.pair]
                self.assertEqual(signers, expected)
                complete = [name for name, members in run_ths.PAIR_MEMBERS.items() if set(members) <= set(signers)]
                self.assertEqual(complete, [pair])

    def test_unknown_pair_is_refused(self):
        with self.assertRaises(SystemExit):
            run_ths.parse_args(["--name", "test-instance", "--pair", "CA"])

class WithholdingTests(unittest.TestCase):
    def state(self, root):
        state = root / "state"
        for member in ("alice", "bob", "carol"):
            (state / member).mkdir(parents=True)
            (state / member / "synthetic-secret").write_text(member)
        return state

    def test_move_failure_restores_every_moved_member(self):
        import shutil
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self.state(root)
            withheld = root / "withheld"
            withheld.mkdir()
            real_move = shutil.move
            def move(source, destination):
                if Path(source) == state / "bob":
                    raise OSError("injected move failure")
                return real_move(source, destination)
            with patch.object(run_ths.tempfile, "mkdtemp", return_value=str(withheld)), patch.object(run_ths.shutil, "move", side_effect=move):
                with self.assertRaisesRegex(OSError, "injected move failure"):
                    run_ths.finish_without_approvers(lambda *args: self.fail("must not finish after a failed move"), state, root / "replica", root / "work")
            for member in ("alice", "bob", "carol"):
                self.assertEqual((state / member / "synthetic-secret").read_text(), member)

    def test_restore_failure_retains_keys_and_restores_other_members(self):
        import shutil
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self.state(root)
            withheld = root / "withheld"
            withheld.mkdir()
            real_move = shutil.move
            def move(source, destination):
                if Path(source) == withheld / "bob":
                    raise OSError("injected restore failure")
                return real_move(source, destination)
            def finish(*args):
                self.assertFalse(any((state / member).exists() for member in ("alice", "bob", "carol")))
            with patch.object(run_ths.tempfile, "mkdtemp", return_value=str(withheld)), patch.object(run_ths.shutil, "move", side_effect=move):
                with self.assertRaisesRegex(RuntimeError, str(withheld)):
                    run_ths.finish_without_approvers(finish, state, root / "replica", root / "work")
            self.assertEqual((withheld / "bob" / "synthetic-secret").read_text(), "bob")
            for member in ("alice", "carol"):
                self.assertEqual((state / member / "synthetic-secret").read_text(), member)

class HarnessBehaviorTests(unittest.TestCase):
    def test_selected_pair_reaches_every_finisher_and_verifies_its_artifacts(self):
        import contextlib
        import io
        import json
        import subprocess
        import tempfile
        from unittest.mock import Mock, patch
        for mode in ("local", "replica", "posted"):
            for pair in ("AB", "AC", "BC"):
                with self.subTest(mode=mode, pair=pair), tempfile.TemporaryDirectory() as temporary:
                    state = Path(temporary) / "state"
                    commands = []
                    chain = Mock(endpoints={})
                    chain.fund.return_value = [{"txid": "synthetic-public-funding"}]
                    chain.rpc.return_value = {"height": 123, "confirmations": 3}
                    def run(argv, **kwargs):
                        if argv[0] == "cargo":
                            return subprocess.CompletedProcess(argv, 0, stdout=json.dumps({"reason": "compiler-artifact", "executable": "loki", "target": {"name": "loki"}}))
                        commands.append(argv)
                        stage = argv[1]
                        if stage == "setup":
                            (state / "public").mkdir()
                            for member in ("alice", "bob", "carol"):
                                (state / member).mkdir()
                        elif stage == "review-sign":
                            member = argv[3]
                            for signed_pair, members in run_ths.PAIR_MEMBERS.items():
                                if member in members:
                                    (state / "public" / f"share_{signed_pair}_{member}.hex").write_text("public share")
                        elif stage in ("finish", "post-final", "replicate"):
                            self.assertEqual(argv[-2:], ["--pair", pair] if stage != "replicate" or mode != "posted" else [pair, "--with-final"])
                            if stage == "finish":
                                (state / "public" / "mined.txt").write_text(f"pair={pair}\ntxid=synthetic-public-txid\n")
                            elif stage == "replicate":
                                (state / "replica").mkdir()
                        elif stage == "finish-second":
                            self.assertFalse(any((state / member).exists() for member in ("alice", "bob", "carol")))
                            (state / "finisher" / "self").mkdir(parents=True)
                            (state / "finisher" / "self" / "finished.txt").write_text(f"pair={pair}\ntxid=synthetic-public-txid\n")
                        return subprocess.CompletedProcess(argv, 0, stdout="synthetic-address\n")
                    with patch.object(run_ths, "THS", return_value=chain), patch.object(run_ths, "run", side_effect=run), patch.object(sys, "argv", ["run-ths.py", "--name", "test", "--pair", pair, "--finish-mode", mode, "--state", str(state)]), contextlib.redirect_stdout(io.StringIO()):
                        run_ths.main()
                    reviewers = [argv[3] for argv in commands if argv[1] == "review-sign"]
                    self.assertEqual(reviewers, list(run_ths.PAIR_MEMBERS[pair]))
                    verified = next(argv for argv in commands if argv[1] == "verify-effects")
                    self.assertEqual(Path(verified[2]).resolve(), (state / ("public" if mode == "local" else "replica")).resolve())
                    self.assertEqual(json.loads((state / "ths-result.json").read_text())["pair"], pair)
