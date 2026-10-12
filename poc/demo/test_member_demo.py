"""The UI may release a share only after that member's CLI review reaches its prompt."""

import fcntl
import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import member_demo


class MemberDemoTest(unittest.TestCase):
    def flow(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        with patch.object(member_demo, "ROOT", root), patch.object(member_demo, "RUN", root / "run"):
            return member_demo.Flow()

    def test_member_tokens_are_distinct_and_payment_needs_a_funded_vault(self):
        flow = self.flow()
        for name, token in flow.tokens.items():
            self.assertEqual(flow.role(token), name)
        self.assertEqual(len(set(flow.tokens.values())), 3)
        self.assertIsNone(flow.role("wrong"))
        with self.assertRaisesRegex(ValueError, "amount"):
            flow.propose("bob", 100_000_000, "memo", "BC", "uregtest1recipient")
        self.assertEqual(flow.phase, "idle")
        with self.assertRaisesRegex(ValueError, "fund"):
            flow.propose("bob", 40_000_000, "memo", "BC", "uregtest1recipient")
        self.assertIsNone(flow.payment)

    def test_member_state_returns_its_own_review(self):
        flow = self.flow()
        flow.review = {"alice": "Alice's checked payment", "bob": "Bob's checked payment",
                       "carol": "Carol's checked payment"}
        alice = flow.state("alice")
        bob = flow.state("bob")
        carol = flow.state("carol")
        self.assertEqual(alice["review"], "Alice's checked payment")
        self.assertEqual(bob["review"], "Bob's checked payment")
        self.assertNotIn("links", alice)
        self.assertNotIn("links", bob)
        self.assertEqual(carol["review"], "Carol's checked payment")
        self.assertNotIn("signers", alice)
        self.assertNotIn("signers", bob)

    def test_unselected_member_cannot_approve(self):
        flow = self.flow()
        flow.payment = {"id": "a" * 64, "pair": ("bob", "carol")}
        flow.phase = "waiting_for_reviews"
        with self.assertRaisesRegex(ValueError, "not asked"):
            flow.decide("alice", "approve")
        self.assertEqual(flow.signers["alice"], "not_requested")

    def test_invalid_pair_does_not_start_preparing(self):
        flow = self.flow()
        flow.phase = "funded"
        with self.assertRaisesRegex(ValueError, "choose two"):
            flow.propose("bob", 12_000_000, "test", "AA", "uregtest1recipient")
        self.assertEqual(flow.phase, "funded")

    def test_actions_are_staged(self):
        flow = self.flow()
        with patch.object(member_demo, "binary", return_value=Path(sys.executable)), \
             patch.object(member_demo.run, "find_binary", return_value=Path(sys.executable)), \
             patch.object(subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=b"relay-backed-signing=1\n")), \
             patch.object(flow, "_create_vault"):
            flow.create_vault("bob")
        self.assertEqual(flow.phase, "creating_vault")
        self.assertEqual(flow.creator, "bob")
        with self.assertRaisesRegex(ValueError, "vault"):
            flow.fund()
        flow.worker.join(timeout=3)

    def test_review_prompt_then_exact_member_approval(self):
        flow = self.flow()
        payment = "a" * 64
        flow.payment = {"id": payment, "pair": ("alice", "bob")}
        flow.phase = "waiting_for_reviews"
        script = (
            "import sys\n"
            "print('Vault: ' + 'b'*64, flush=True)\n"
            "print('Recipient: uregtest1recipient', flush=True)\n"
            "print('Amount: 40000000 zat; memo: \\\"test\\\"', flush=True)\n"
            "print('Fee: 10000 zat; change to vault: 59990000 zat; expiry height: 1152', flush=True)\n"
            "print('Inputs: 1; candidate: ' + 'c'*64, flush=True)\n"
            f"print('Type APPROVE {payment} to sign:', flush=True)\n"
            f"if input() != 'APPROVE {payment}': sys.exit(1)\n"
            f"print('approved payment {payment} as member 1', flush=True)\n"
            "print('stored', flush=True)\n"
        )
        process = subprocess.Popen([sys.executable, "-u", "-c", script],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True)
        self.addCleanup(lambda: process.kill() if process.poll() is None else None)
        self.addCleanup(process.stdout.close)
        self.addCleanup(process.stdin.close)
        flow.processes["alice"] = process
        with patch.object(flow, "_payment_env", return_value=None):
            reader = threading.Thread(target=flow._read_signer, args=("alice", process))
            reader.start()
            deadline = time.monotonic() + 3
            while flow.signers["alice"] != "reviewing" and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertEqual(flow.signers["alice"], "reviewing")
            self.assertIn("Recipient: uregtest1recipient", flow.review["alice"])
            with self.assertRaisesRegex(ValueError, "no verified review"):
                flow.decide("bob", "approve")
            flow.decide("alice", "approve")
            reader.join(timeout=3)
            self.assertFalse(reader.is_alive())
            self.assertEqual(flow.signers["alice"], "approved")

    def test_local_share_is_not_approved_without_relay_delivery(self):
        flow = self.flow()
        payment = "a" * 64
        flow.payment = {"id": payment, "pair": ("alice", "bob")}
        flow.phase = "waiting_for_reviews"
        script = (
            "import sys\n"
            "print('Vault: checked', flush=True)\n"
            "print('Recipient: checked', flush=True)\n"
            "print('Amount: checked', flush=True)\n"
            "print('Fee: checked', flush=True)\n"
            "print('Inputs: checked', flush=True)\n"
            f"print('Type APPROVE {payment} to sign:', flush=True)\n"
            f"if input() != 'APPROVE {payment}': sys.exit(1)\n"
            f"print('approved payment {payment} as member 1', flush=True)\n"
        )
        process = subprocess.Popen([sys.executable, "-u", "-c", script],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True)
        self.addCleanup(lambda: process.kill() if process.poll() is None else None)
        self.addCleanup(process.stdout.close)
        self.addCleanup(process.stdin.close)
        flow.processes["alice"] = process
        with patch.object(flow, "_payment_env", return_value=None):
            reader = threading.Thread(target=flow._read_signer, args=("alice", process))
            reader.start()
            deadline = time.monotonic() + 3
            while flow.signers["alice"] != "reviewing" and time.monotonic() < deadline:
                time.sleep(.01)
            flow.decide("alice", "approve")
            reader.join(timeout=3)
        self.assertFalse(reader.is_alive())
        self.assertEqual(flow.signers["alice"], "delivery_pending")
        self.assertNotEqual(flow.phase, "ready_to_send")

    def test_delivery_retry_uses_saved_share_without_another_approval_prompt(self):
        flow = self.flow()
        flow.phase = "waiting_for_reviews"
        flow.payment = {"pair": ("alice", "bob")}
        flow.signers = {"alice": "delivery_pending", "bob": "approved", "carol": "not_requested"}
        with patch.object(flow, "resend_saved_share", return_value="resent exact saved approval") as command:
            flow.decide("alice", "retry")
            flow.signer_threads[-1].join(timeout=3)
        self.assertEqual(flow.signers["alice"], "approved")
        self.assertIs(flow.approver_stored["alice"], True)
        self.assertEqual(flow.phase, "ready_to_send")
        command.assert_called_once_with(1)

    def test_browser_action_needs_same_origin_and_the_right_member_link(self):
        flow = self.flow()
        handler = member_demo.Handler.__new__(member_demo.Handler)
        handler.path = "/api/decide"
        handler.server = SimpleNamespace(server_port=8790)
        handler.rfile = BytesIO(b'{"action":"approve"}')
        handler.json = Mock()
        with patch.object(member_demo, "FLOW", flow), patch.object(flow, "decide") as decide:
            handler.headers = {"Origin": "https://foreign.example", "Content-Type": "application/json",
                               "Content-Length": "20", "X-Loki-Token": flow.tokens["alice"]}
            handler.do_POST()
            self.assertEqual(handler.json.call_args.args[0], 403)
            handler.headers["Origin"] = "http://127.0.0.1:8790"
            handler.headers["X-Loki-Token"] = "invalid"
            handler.do_POST()
            self.assertEqual(handler.json.call_args.args[0], 401)
            handler.headers["X-Loki-Token"] = flow.tokens["alice"]
            handler.rfile = BytesIO(b'{"action":"approve"}')
            handler.do_POST()
            self.assertEqual(handler.json.call_args.args[0], 200)
            decide.assert_called_once_with("alice", "approve")

    def test_any_member_can_create_and_propose_with_a_selected_pair(self):
        flow = self.flow()
        handler = member_demo.Handler.__new__(member_demo.Handler)
        handler.server = SimpleNamespace(server_port=8790)
        handler.json = Mock()
        payload = b'{"amount_zat":12000000,"memo":"test","pair":"BC","recipient":"uregtest1recipient"}'
        handler.headers = {"Origin": "http://127.0.0.1:8790", "Content-Type": "application/json",
                           "Content-Length": str(len(payload)), "X-Loki-Token": flow.tokens["bob"]}
        handler.path = "/api/propose"
        with patch.object(member_demo, "FLOW", flow), patch.object(flow, "propose") as propose, \
             patch.object(flow, "create_vault") as create:
            handler.rfile = BytesIO(payload)
            handler.do_POST()
            self.assertEqual(handler.json.call_args.args[0], 200)
            propose.assert_called_once_with("bob", 12_000_000, "test", "BC", "uregtest1recipient")
            handler.path = "/api/create-vault"
            handler.headers["X-Loki-Token"] = flow.tokens["carol"]
            handler.rfile = BytesIO(b'{}')
            handler.headers["Content-Length"] = "2"
            handler.do_POST()
            self.assertEqual(handler.json.call_args.args[0], 200)
            create.assert_called_once_with("carol")


    def test_signer_lease_blocks_a_second_store_open(self):
        flow = self.flow()
        spawned = []
        flow._spawn_member_command = lambda member_id: spawned.append(member_id)
        flow.leases.reserve(1, "sign")
        with self.assertRaisesRegex(RuntimeError, "busy"):
            flow.background_pass(1)
        self.assertEqual(spawned, [])
        flow.leases.release(1)
        flow.background_pass(1)
        self.assertEqual(spawned, [1])

    def test_interrupted_attempt_requires_reset(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "run").mkdir()
        with patch.object(member_demo, "ROOT", root), patch.object(member_demo, "RUN", root / "run"):
            flow = member_demo.Flow()
        self.assertEqual(flow.phase, "interrupted")
        self.assertIn("reset", flow.error)
        with self.assertRaisesRegex(ValueError, "reset"):
            flow.create_vault("alice")

    def test_reset_stops_owned_relays_and_only_the_sandbox(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        outside = root.parent / f"outside-{root.name}"
        outside.write_text("keep")
        self.addCleanup(lambda: outside.unlink(missing_ok=True))
        foreign = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        foreign.bind(("127.0.0.1", 0))
        foreign.listen()
        self.addCleanup(foreign.close)
        with patch.object(member_demo, "ROOT", root), patch.object(member_demo, "RUN", root / "run"):
            flow = member_demo.Flow()
            flow.leases.reserve(1, "sign")
            owner = member_demo.run.OwnedRun.create(root / "relay")
            child = owner.start(
                [sys.executable, "-c", "import time; time.sleep(60)"], cwd=owner.root)
            flow.relay.owner = owner
            lock_path = root.with_suffix(".lock")
            self.addCleanup(lambda: lock_path.unlink(missing_ok=True))
            with lock_path.open("a") as held:
                fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
                flow.creator = "carol"
                flow.reset("carol")
                self.assertTrue(lock_path.exists())
                with lock_path.open("a") as contender:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertIsNotNone(child.poll())
            self.assertFalse(root.exists())
            self.assertEqual(outside.read_text(), "keep")
            self.assertIsNone(flow.leases.holder[1])
            flow.background_pass(1)
        port = foreign.getsockname()[1]
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            accepted, _ = foreign.accept()
            accepted.close()

    def test_close_stops_relays_and_a_browser_close_does_not(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        with patch.object(member_demo, "ROOT", root), patch.object(member_demo, "RUN", root / "run"):
            flow = member_demo.Flow()
            flow.phase = "waiting_for_reviews"
            owner = member_demo.run.OwnedRun.create(root / "relay")
            child = owner.start(
                [sys.executable, "-c", "import time; time.sleep(60)"], cwd=owner.root)
            flow.relay.owner = owner
            flow.note_browser_closed()
            self.assertEqual(flow.phase, "waiting_for_reviews")
            self.assertIsNone(child.poll())
            flow.chain.stop = lambda: None
            flow.close()
            self.assertIsNotNone(child.poll())
            self.assertTrue(root.exists())

    def test_finish_and_verify_hold_member_three_on_the_relay(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        payment = "ab" * 32
        txid = "cd" * 32
        ready = root / "finish-ready"
        release = root / "finish-go"
        args_path = root / "finish-args"
        program = root / "payment-cli"
        program.write_text(
            "#!/bin/sh\n"
            f"printf '%s\\n' \"$@\" > '{args_path}.'\"$1\"\n"
            "case \"$1\" in\n"
            "  finish)\n"
            f"    touch '{ready}'\n"
            "    ticks=0\n"
            f"    while [ ! -f '{release}' ] && [ \"$ticks\" -lt 40 ]; do sleep 0.05; ticks=$((ticks+1)); done\n"
            f"    echo 'broadcast txid={txid} payment={payment}'\n"
            "    ;;\n"
            "  verify)\n"
            f"    echo 'verified mined txid={txid}'\n"
            "    ;;\n"
            "  receive)\n"
            f"    echo 'recipient independently decrypted txid={txid}'\n"
            "    ;;\n"
            "esac\n"
        )
        program.chmod(0o755)
        mined = []
        self.addCleanup(lambda: release.write_text("go"))
        with patch.object(member_demo, "ROOT", root), patch.object(member_demo, "RUN", root / "run"):
            flow = member_demo.Flow()
            flow.phase = "ready_to_send"
            flow.payment = {"id": payment, "pair": ("alice", "bob"), "recipient": "uregtest1recipient"}
            flow.vaults = {"recipient": "uregtest1recipient"}
            flow.chain.mine = lambda count: mined.append(count)
            flow.chain.client = SimpleNamespace(env=lambda: None)
            with patch.object(member_demo, "binary", lambda name: program):
                worker = threading.Thread(target=flow._finish, args=("carol",))
                worker.start()
                deadline = time.monotonic() + 3
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(ready.exists())
                self.assertEqual(flow.leases.holder[3], "finish")
                with self.assertRaisesRegex(RuntimeError, "busy"):
                    flow.background_pass(3)
                release.write_text("go")
                worker.join(timeout=5)
            self.assertFalse(worker.is_alive())
            self.assertEqual(flow.phase, "confirmed")
            self.assertEqual(mined, [3])
            recorded = (args_path.with_name(args_path.name + ".finish")).read_text().splitlines()
            self.assertEqual(recorded[0], "finish")
            self.assertIn("--transport", recorded)
            self.assertEqual(recorded[recorded.index("--transport") + 1], "relay")
            verify_args = (args_path.with_name(args_path.name + ".verify")).read_text().splitlines()
            self.assertEqual(verify_args[0], "verify")
            self.assertEqual(verify_args[verify_args.index("--transport") + 1], "relay")
            self.assertEqual(flow.state("carol")["delivery"], "pending")
            self.assertIsNone(flow.leases.holder[3])

    def test_pending_delivery_stays_distinct_from_approval(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        args_path = root / "resend-args"
        program = root / "resend-cli"
        program.write_text(
            "#!/bin/sh\n"
            f"printf '%s\\n' \"$@\" > '{args_path}'\n"
            "echo resent\n"
        )
        program.chmod(0o755)
        with patch.object(member_demo, "ROOT", root), patch.object(member_demo, "RUN", root / "run"):
            flow = member_demo.Flow()
            flow.signers = {"alice": "approved", "bob": "approved", "carol": "not_requested"}
            flow.phase = "ready_to_send"
            flow.payment = {"id": "ab" * 32, "pair": ("alice", "bob")}
            state = flow.state("carol")
            self.assertEqual(state["approvals_count"], 2)
            self.assertEqual(state["delivery"], "pending")
            self.assertNotIn("fetched", json.dumps(state))
            flow.chain.client = SimpleNamespace(env=lambda: None)
            with patch.object(member_demo, "binary", lambda name: program):
                flow.resend_saved_share(1)
            recorded = args_path.read_text().splitlines()
            self.assertIn("resend", recorded)
            self.assertIn("--transport", recorded)
            self.assertEqual(recorded[recorded.index("--transport") + 1], "relay")
            self.assertNotIn("file", recorded)
            self.assertEqual(flow.state("carol")["delivery"], "pending")

    def test_startup_reaps_only_a_matching_recorded_relay(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        relay = root / "relay"
        relay.mkdir()
        owned = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        stranger = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])

        def stop(process):
            if process.poll() is None:
                process.kill()
            process.wait(timeout=3)

        self.addCleanup(lambda: stop(owned))
        self.addCleanup(lambda: stop(stranger))
        identity = member_demo.relay_demo.process_identity(owned.pid)
        (relay / "owned-children.json").write_text(json.dumps({
            "version": 1,
            "children": [
                {"pid": owned.pid, "identity": identity},
                {"pid": stranger.pid, "identity": "not-this-process"},
            ],
        }))
        with patch.object(member_demo, "ROOT", root), patch.object(member_demo, "RUN", root / "run"):
            flow = member_demo.Flow()
            self.assertIsNone(owned.poll())
            with patch.object(flow.chain, "recover"):
                flow.recover()
        self.assertIsNotNone(owned.wait(timeout=3))
        self.assertIsNone(stranger.poll())

    def snapshot_get(self, flow, path, token):
        handler = member_demo.Handler.__new__(member_demo.Handler)
        handler.path = path
        handler.headers = {"X-Loki-Token": token}
        handler.server = SimpleNamespace(server_port=8790)
        captured = {}

        def send(code, data, ctype):
            del ctype
            captured["code"] = code
            captured["body"] = json.loads(data)

        handler.send = send
        with patch.object(member_demo, "FLOW", flow):
            handler.do_GET()
        return captured

    def test_simultaneous_snapshot_gets_read_the_cache_only(self):
        flow = self.flow()
        page = {"version": 1, "section": "logical", "rows": [], "member": 1}
        flow.relay.remember_snapshot(1, page)
        flow.relay.service_snapshot = Mock(side_effect=AssertionError("GET opened a worker"))
        spawned = []
        barrier = threading.Barrier(2)
        results = []

        def one_get():
            barrier.wait(timeout=3)
            with patch("subprocess.Popen", side_effect=lambda *args, **kwargs: spawned.append(args)):
                results.append(self.snapshot_get(
                    flow, "/api/relay/snapshot?member=1", flow.tokens["alice"]))

        threads = [threading.Thread(target=one_get) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=3)
        self.assertEqual(spawned, [])
        self.assertEqual([item["code"] for item in results], [200, 200])
        self.assertEqual(results[0]["body"]["page"], page)
        self.assertEqual(results[0]["body"]["stale"], False)
        foreign = self.snapshot_get(flow, "/api/relay/snapshot?member=2", flow.tokens["alice"])
        self.assertEqual(foreign["code"], 403)
        flow.relay.service_snapshot.assert_not_called()

    def test_an_unbound_member_is_not_sandboxed(self):
        flow = self.flow()
        self.assertEqual(flow.wrap_member(1, ["sign"]), ["sign"])
        flow.member_sandbox[1] = flow.relay.root / "member-1.sb"
        wrapped = flow.wrap_member(1, ["sign"])
        self.assertEqual(wrapped[0], "/usr/bin/sandbox-exec")
        self.assertEqual(wrapped[-1], "sign")

    def test_isolated_sandbox_recover_leaves_the_default_instance(self):
        original_root = member_demo.ROOT
        original_run = member_demo.RUN
        original_flow = member_demo.FLOW
        manifest = original_root / "ths-instance.json"
        before = manifest.read_bytes() if manifest.exists() else None
        touched = []
        original_flow.chain.recover = lambda: touched.append("default")
        try:
            with tempfile.TemporaryDirectory() as temporary:
                sandbox = Path(temporary).resolve()
                flow = member_demo.use_sandbox(sandbox)
                self.assertIsNot(flow, original_flow)
                self.assertEqual(member_demo.ROOT, sandbox)
                self.assertEqual(member_demo.RUN, sandbox / "run")
                flow.chain.recover()
                self.assertEqual(touched, [])
                self.assertFalse((sandbox / "ths-instance.json").exists())
            if before is not None:
                self.assertEqual(manifest.read_bytes(), before)
        finally:
            member_demo.ROOT = original_root
            member_demo.RUN = original_run
            member_demo.FLOW = original_flow

    def test_preparing_a_dynamic_pair_uses_the_direct_carrier(self):
        flow = self.flow()
        flow.vaults = {"source": "uregtest1source", "recipient": "uregtest1recipient"}
        manifest = {"amount_zat": 12_000_000, "pair": [2, 3], "payment": "a" * 64,
                    "memo": "74657374", "fee_zat": 10000, "change_zat": 87990000,
                    "expiry_height": 1152}
        with patch.object(flow, "_command") as command, \
             patch.object(Path, "read_text", return_value=json.dumps(manifest)), \
             patch.object(flow.relay, "prepare") as prepare, \
             patch.object(flow, "_start_signers") as start:
            flow._prepare("carol", 12_000_000, "test", "BC", "uregtest1recipient")
        self.assertEqual(flow.phase, "waiting_for_reviews")
        self.assertEqual(flow.payment["pair"], ("bob", "carol"))
        self.assertEqual(flow.payment["proposer"], "carol")
        self.assertEqual(flow.signers["alice"], "not_requested")
        self.assertIn("--transport", command.call_args.args[0])
        prepare.assert_called_once()
        start.assert_called_once_with()

    def test_external_recipient_confirms_without_local_receive_claim(self):
        flow = self.flow()
        flow.payment = {"id": "a" * 64, "pair": ("bob", "carol"),
                        "recipient": "uregtest1external", "recipient_verified": False}
        flow.vaults = {"recipient": "uregtest1local"}
        txid = "b" * 64
        with patch.object(member_demo, "binary", return_value=Path(sys.executable)), \
             patch.object(flow.relay, "run_payment", side_effect=[
                 f"broadcast txid={txid} payment={'a' * 64}", f"verified mined txid={txid}"]) as pay, \
             patch.object(flow.chain, "mine") as mine, patch.object(flow, "_command") as receive:
            flow._finish("bob")
        self.assertEqual(flow.phase, "confirmed")
        self.assertIs(flow.payment["recipient_verified"], False)
        self.assertEqual([call.args[0] for call in pay.call_args_list], [2, 2])
        self.assertEqual([call.args[1][1] for call in pay.call_args_list], ["finish", "verify"])
        mine.assert_called_once_with(3)
        receive.assert_not_called()

    def test_binary_preflight_saves_the_real_relay_server_for_restart(self):
        flow = self.flow()
        server = Path("/private/tmp/actual-relay-server")
        with patch.object(member_demo, "binary", return_value=Path(sys.executable)), \
             patch.object(member_demo.run, "find_binary", return_value=server), \
             patch.object(subprocess, "run", return_value=SimpleNamespace(
                 returncode=0, stdout=b"relay-backed-signing=1\n")):
            flow._check_binaries()
        self.assertEqual(flow.relay.server, server)

    def test_controller_initialization_does_not_reap_before_the_lock(self):
        with patch.object(member_demo.relay_demo, "reap_recorded") as reap:
            flow = self.flow()
            reap.assert_not_called()
            with patch.object(flow.chain, "recover") as recover:
                flow.recover()
            reap.assert_called_once()
            recover.assert_called_once()


if __name__ == "__main__":
    unittest.main()
