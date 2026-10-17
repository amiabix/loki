"""The member service client against a fake child that speaks the same protocol."""
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).parent))
import member_service  # noqa: E402
from member_app import Wallet  # noqa: E402

FAKE = r'''#!/usr/bin/env python3
import json, os, sys, time
log = open(os.environ["FAKE_LOG"], "a")
first = json.loads(sys.stdin.readline())
log.write(json.dumps({"argv": sys.argv, "env_has_pass": first["passphrase"] in "".join(os.environ.values())}) + "\n")
log.flush()
if first.get("op") != "unlock" or first.get("passphrase") != "right pass":
    print(json.dumps({"unlocked": False, "error": "service_unlock"}), flush=True)
    sys.exit(1)
print(json.dumps({"unlocked": True}), flush=True)
for line in sys.stdin:
    frame = json.loads(line)
    if frame.get("op") == "lock":
        if os.environ.get("FAKE_IGNORE_LOCK"):
            time.sleep(30)
        sys.exit(0)
    log.write(json.dumps({k: frame.get(k) for k in ("op", "args", "words", "private_hex")}) + "\n")
    log.flush()
    root = frame["args"][0]
    if root.endswith("hang"):
        continue
    if root.endswith("die"):
        sys.exit(3)
    if root.endswith("refuse"):
        print(json.dumps({"id": frame["id"], "ok": False, "error": "setup_worker_locked"}), flush=True)
        continue
    result = {"words": "abandon art"} if frame["op"] == "setup-backup-create" else {"phase": "round1_saved", "pid": os.getpid()}
    print(json.dumps({"id": frame["id"], "ok": True, "result": result}), flush=True)
'''


class MemberServiceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.binary = self.root / "loki_member_service"
        self.binary.write_text(FAKE)
        self.binary.chmod(0o700)
        self.log = self.root / "log.jsonl"
        os.environ["FAKE_LOG"] = str(self.log)
        self.addCleanup(os.environ.pop, "FAKE_LOG", None)
        self.service = member_service.MemberService(self.binary, self.root)
        self.addCleanup(self.service.stop)

    def entries(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_passphrase_goes_only_through_the_pipe_and_wrong_one_is_refused(self):
        with self.assertRaisesRegex(member_service.ServiceError, "refused"):
            self.service.start("wrong pass")
        self.assertFalse(self.service.running())
        self.service.start("right pass")
        self.assertEqual(self.service.call("setup-step", [self.root / "vault", "@session"]),
                         {"phase": "round1_saved", "pid": self.service.process.pid})
        started = [entry for entry in self.entries() if "argv" in entry]
        self.assertTrue(all(not entry["env_has_pass"] and "right pass" not in " ".join(entry["argv"])
                            for entry in started))
        with self.assertRaisesRegex(member_service.ServiceError, "Not a member service command"):
            self.service.call("profile-open", [self.root])
        with self.assertRaisesRegex(ValueError, "setup_worker_locked"):
            self.service.call("setup-step", [self.root / "refuse", "@session"])

    def test_timeout_kills_the_child_and_a_death_fails_the_waiting_call(self):
        self.service.start("right pass")
        first = self.service.process
        begun = time.monotonic()
        with self.assertRaisesRegex(member_service.ServiceError, "timed out"):
            self.service.call("setup-step", [self.root / "hang", "@session"], timeout=0.5)
        self.assertLess(time.monotonic() - begun, 3)
        self.assertFalse(self.service.running())
        self.assertIsNotNone(first.poll())
        self.service.start("right pass")
        with self.assertRaisesRegex(member_service.ServiceError, "stopped"):
            self.service.call("setup-step", [self.root / "die", "@session"], timeout=10)

    def test_lock_stops_a_child_that_ignores_it_within_five_seconds(self):
        os.environ["FAKE_IGNORE_LOCK"] = "1"
        self.addCleanup(os.environ.pop, "FAKE_IGNORE_LOCK", None)
        self.service.start("right pass")
        process = self.service.process
        waiter = threading.Thread(target=lambda: self.assertRaises(
            member_service.ServiceError, self.service.call, "setup-step", [self.root / "hang", "@session"]))
        waiter.start()
        time.sleep(0.2)
        begun = time.monotonic()
        self.service.stop()
        waiter.join(1)
        self.assertFalse(waiter.is_alive(), "Lock releases callers waiting on the child")
        self.assertLess(time.monotonic() - begun, member_service.STOP_SECONDS + 0.5)
        self.assertIsNotNone(process.poll())

    def test_hosted_setup_routes_setup_commands_and_restarts_with_the_held_passphrase(self):
        bundle = self.root / "operators"
        bundle.write_bytes(b"public bundle")
        wallet = Wallet(self.root / "member", self.root / "exchange", transport="hosted",
                        operator_bundle=bundle, operator_key="a" * 64, enrollment_grant=bundle)
        self.addCleanup(wallet.close)
        wallet.profile_data = {"id": "alice", "name": "Alice"}
        wallet.passphrase = "right pass"
        hosted = wallet.hosted
        hosted.service = member_service.MemberService(self.binary, wallet.data)
        self.addCleanup(hosted.service.stop)
        vault = self.root / "vault"
        first = json.loads(hosted.native("setup-step", vault))
        self.assertEqual(first["phase"], "round1_saved")
        hosted.service.process.kill()
        hosted.service.process.wait()
        second = json.loads(hosted.native("setup-step", vault))
        self.assertNotEqual(first["pid"], second["pid"], "a dead service is restarted")
        self.assertEqual(hosted.native("setup-backup-create", vault, vault / "card"), "abandon art")
        hosted.native("setup-backup-verify", vault, vault / "card", "@words", words="abandon art")
        calls = [entry for entry in self.entries() if "op" in entry]
        self.assertEqual(calls[-1], {"op": "setup-backup-verify", "args": [str(vault), "@session", str(vault / "card"), "@words"],
                                     "words": "abandon art", "private_hex": None})
        self.assertFalse(any(path.name.startswith(".hosted-command-") for path in wallet.data.iterdir()),
                         "service calls write no passphrase files")
        hosted.stop()
        self.assertFalse(hosted.service.running())


if __name__ == "__main__":
    unittest.main()
