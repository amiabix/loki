"""Relay preparation owns only the relays it starts."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

DEMO = Path(__file__).resolve().parent
sys.path.insert(0, str(DEMO))

import relay_demo  # noqa: E402


class RelayPreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir()
        self.chain_start_calls = 0
        self.foreign = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.foreign.bind(("127.0.0.1", 0))
        self.foreign.listen()
        self.addCleanup(self.foreign.close)

    def foreign_listener_is_running(self) -> bool:
        port = self.foreign.getsockname()[1]
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                accepted, _ = self.foreign.accept()
                accepted.close()
            return True
        except OSError:
            return False

    def demo_with_failure_on_third_relay(self):
        def lifecycle(owner, source, ports, **_kwargs):
            del source, ports
            sleep = [sys.executable, "-c", "import time; time.sleep(30)"]
            owner.start(sleep, cwd=owner.root)
            owner.start(sleep, cwd=owner.root)
            raise RuntimeError("third relay failed")

        return relay_demo.RelayDemo(
            self.root, (self.root / "server", self.root / "member", self.root / "setup"),
            threading.Event(), None, lifecycle=lifecycle)

    def test_partial_start_stops_only_owned_children(self):
        demo = self.demo_with_failure_on_third_relay()
        with self.assertRaises(RuntimeError):
            demo.prepare(self.source)
        self.assertEqual(demo.owned_live_children(), [])
        self.assertTrue(self.foreign_listener_is_running())
        self.assertEqual(self.chain_start_calls, 0)
        self.assertEqual(demo.chain_start_calls, 0)

    def test_provision_failure_after_init_stops_owned_children(self):
        def lifecycle(owner, source, ports, **_kwargs):
            del source, ports
            owner.start([sys.executable, "-c", "import time; time.sleep(30)"], cwd=owner.root)
            raise RuntimeError("provision failed")

        demo = relay_demo.RelayDemo(
            self.root / "second",
            (self.root / "server", self.root / "member", self.root / "setup"),
            threading.Event(), None, lifecycle=lifecycle)
        (self.root / "second").mkdir()
        with self.assertRaises(RuntimeError):
            demo.prepare(self.source)
        self.assertEqual(demo.owned_live_children(), [])

    def test_cancelled_preparation_does_not_create_a_run(self):
        cancel = threading.Event()
        cancel.set()
        demo = relay_demo.RelayDemo(
            self.root / "third",
            (self.root / "server", self.root / "member", self.root / "setup"),
            cancel, None, lifecycle=lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("started")))
        (self.root / "third").mkdir()
        with self.assertRaises(RuntimeError):
            demo.prepare(self.source)
        self.assertFalse((self.root / "third" / "relay").exists())

    def test_prepare_records_owned_children_for_a_later_reap(self):
        def lifecycle(owner, source, ports, **_kwargs):
            del source, ports
            owner.start([sys.executable, "-c", "import time; time.sleep(30)"], cwd=owner.root)
            return SimpleNamespace(relays=[], public_report=lambda: {"relays": []})

        demo = relay_demo.RelayDemo(
            self.root / "recorded",
            (self.root / "server", self.root / "member", self.root / "setup"),
            threading.Event(), None, lifecycle=lifecycle)
        (self.root / "recorded").mkdir()
        self.addCleanup(demo.stop)
        demo.prepare(self.source)
        record = json.loads((demo.owner.root / "owned-children.json").read_text())
        self.assertEqual(record["version"], 1)
        self.assertEqual(len(record["children"]), 1)
        child = record["children"][0]
        self.assertEqual(child["pid"], demo.owned_live_children()[0].pid)
        self.assertEqual(child["identity"], relay_demo.process_identity(child["pid"]))


class RelaySchedulingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.demo = relay_demo.RelayDemo(
            self.root, (self.root / "server", self.root / "member", self.root / "setup"),
            threading.Event(), None)
        self.addCleanup(self.demo.close)

    def test_payment_blocks_only_that_member_until_readers_settle(self):
        ready = self.root / "ready"
        script = (
            "import pathlib, sys, time\n"
            f"pathlib.Path({str(ready)!r}).write_text('up')\n"
            "sys.stdin.readline()\n"
        )
        process = self.demo.start_payment(
            1, [sys.executable, "-u", "-c", script, "sign"], interactive=True)
        self.addCleanup(lambda: process.kill() if process.poll() is None else None)
        deadline = time.monotonic() + 3
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(self.demo.leases.holder[1], "sign")
        self.demo.leases.reserve(2, "poll")
        self.demo.leases.release(2)
        with self.assertRaisesRegex(RuntimeError, "busy"):
            self.demo.leases.reserve(1, "poll")
        process.stdin.write("\n")
        process.stdin.flush()
        self.demo.settle(timeout=3)
        self.assertEqual(process.wait(timeout=3), 0)
        self.assertIsNone(self.demo.leases.holder[1])
        self.demo.leases.reserve(1, "poll")
        self.demo.leases.release(1)

    def test_snapshot_at_the_prompt_uses_the_owning_worker(self):
        payment = "ab" * 32
        script = (
            "import json, os, sys\n"
            "args = sys.argv[1:]\n"
            "fds = {}\n"
            "index = 0\n"
            "while index < len(args):\n"
            "    if args[index] in ('--observe-fd', '--control-fd', '--response-fd'):\n"
            "        fds[args[index]] = int(args[index + 1])\n"
            "        index += 2\n"
            "    else:\n"
            "        index += 1\n"
            f"print('Type APPROVE {payment} to sign:', flush=True)\n"
            "buffer = b''\n"
            "while b'\\n' not in buffer:\n"
            "    chunk = os.read(fds['--control-fd'], 4096)\n"
            "    if not chunk:\n"
            "        raise SystemExit(2)\n"
            "    buffer += chunk\n"
            "request = json.loads(buffer.decode())\n"
            "if request['type'] != 'snapshot_page' or request['version'] != 1:\n"
            "    raise SystemExit(3)\n"
            "page = {'version': 1, 'snapshot_id': request['snapshot_id'], 'member': 1,\n"
            "        'section': request['section'], 'after': request['after'],\n"
            "        'next': request['after'], 'complete': True, 'rows': []}\n"
            "os.write(fds['--response-fd'], (json.dumps(page) + '\\n').encode())\n"
            "sys.stdin.readline()\n"
        )
        spawned = []
        real_popen = subprocess.Popen

        def tracking(*args, **kwargs):
            spawned.append(args[0] if args else kwargs.get("args"))
            return real_popen(*args, **kwargs)

        with mock.patch("subprocess.Popen", tracking):
            process = self.demo.start_payment(
                1, [sys.executable, "-u", "-c", script, "sign"], interactive=True)
            self.addCleanup(lambda: process.kill() if process.poll() is None else None)
            line = process.stdout.readline()
            self.assertIn("Type APPROVE", line)
            page = self.demo.service_snapshot(1)
            again = self.demo.cached_snapshot(1)
        self.assertEqual(page["section"], "logical")
        self.assertEqual(page["rows"], [])
        self.assertEqual(again["stale"], False)
        self.assertEqual(again["page"]["section"], "logical")
        self.assertTrue(spawned)
        self.assertFalse(any("status" in part or "loki_relay_member" in part
                             for argv in spawned for part in argv))
        process.stdin.write("\n")
        process.stdin.flush()
        self.demo.settle(timeout=3)

    def test_observe_pipe_reaches_the_public_projection(self):
        script = (
            "import json, os, sys\n"
            "fds = {}\n"
            "args = sys.argv[1:]\n"
            "index = 0\n"
            "while index < len(args):\n"
            "    if args[index] in ('--observe-fd', '--control-fd', '--response-fd'):\n"
            "        fds[args[index]] = int(args[index + 1])\n"
            "        index += 2\n"
            "    else:\n"
            "        index += 1\n"
            "event = {'version': 1, 'run_id': 'abc123', 'producer_id': 'member-1',\n"
            "         'producer_sequence': 1, 'observed_at': '2026-10-11T00:00:00Z',\n"
            "         'event_type': 'original_authenticated', 'actor_member': 1}\n"
            "os.write(fds['--observe-fd'], (json.dumps(event) + '\\n').encode())\n"
            "sys.stdin.readline()\n"
        )
        process = self.demo.start_payment(
            1, [sys.executable, "-u", "-c", script, "sign"], interactive=True)
        self.addCleanup(lambda: process.kill() if process.poll() is None else None)
        deadline = time.monotonic() + 2
        saved = 0
        while time.monotonic() < deadline:
            saved = self.demo.projection.state("admin")["saved"]
            if saved:
                break
            time.sleep(0.02)
        self.assertEqual(saved, 1)
        self.assertEqual(self.demo.projection.run_id, "abc123")
        process.stdin.write("\n")
        process.stdin.flush()
        self.demo.settle(timeout=3)

    def test_snapshot_read_failure_is_stale_and_starts_no_status_command(self):
        script = (
            "import sys\n"
            "print('Type APPROVE " + ("ab" * 32) + " to sign:', flush=True)\n"
            "sys.stdin.readline()\n"
        )
        spawned = []
        real_popen = subprocess.Popen

        def tracking(*args, **kwargs):
            spawned.append(args[0] if args else kwargs.get("args"))
            return real_popen(*args, **kwargs)

        with mock.patch("subprocess.Popen", tracking):
            process = self.demo.start_payment(
                1, [sys.executable, "-u", "-c", script, "sign"], interactive=True)
            self.addCleanup(lambda: process.kill() if process.poll() is None else None)
            self.assertIn("Type APPROVE", process.stdout.readline())
            with self.assertRaisesRegex(RuntimeError, "snapshot"):
                self.demo.service_snapshot(1)
            cached = self.demo.cached_snapshot(1)
        self.assertEqual(cached["stale"], True)
        self.assertIsNone(cached["page"])
        self.assertFalse(any("status" in part or "loki_relay_member" in part
                             for argv in spawned for part in argv))
        process.stdin.write("\n")
        process.stdin.flush()
        self.demo.settle(timeout=3)

    def test_failed_member_process_releases_the_lease(self):
        process = self.demo.start_payment(
            2, [sys.executable, "-c", "import sys; sys.exit(7)", "verify"], interactive=False)
        self.demo.settle(timeout=3)
        self.assertEqual(process.returncode, 7)
        self.assertIsNone(self.demo.leases.holder[2])
        self.demo.leases.reserve(2, "poll")
        self.demo.leases.release(2)

    def test_cancel_settles_the_worker_without_another_open(self):
        spawned = []
        real_popen = subprocess.Popen

        def tracking(*args, **kwargs):
            spawned.append(args[0] if args else kwargs.get("args"))
            return real_popen(*args, **kwargs)

        with mock.patch("subprocess.Popen", tracking):
            process = self.demo.start_payment(
                2, [sys.executable, "-c", "import time; time.sleep(60)", "finish"],
                interactive=True)
            self.demo.cancel.set()
            self.demo.settle(timeout=3)
        self.assertIsNotNone(process.poll())
        self.assertIsNone(self.demo.leases.holder[2])
        self.assertFalse(any("status" in part or "loki_relay_member" in part
                             for argv in spawned for part in argv))

    def test_pause_is_busy_during_payment_and_resume_allows_the_next_pass(self):
        process = self.demo.start_payment(
            1, [sys.executable, "-c", "import sys; sys.stdin.readline()", "sign"],
            interactive=True)
        self.addCleanup(lambda: process.kill() if process.poll() is None else None)
        with self.assertRaisesRegex(RuntimeError, "busy"):
            self.demo.pause_member(1)
        process.stdin.write("\n")
        process.stdin.flush()
        self.demo.settle(timeout=3)
        self.demo.pause_member(1)
        with self.assertRaisesRegex(RuntimeError, "paused"):
            self.demo.run_payment(
                1, [sys.executable, "-c", "print('nope')", "resend"], timeout=3)
        self.demo.resume_member(1)
        output = self.demo.run_payment(
            1, [sys.executable, "-c", "print('resent')", "resend"], timeout=3)
        self.assertEqual(output, "resent\n")
        self.assertIsNone(self.demo.leases.holder[1])

    def test_restart_relay_reuses_the_store_and_does_not_start_a_chain(self):
        relays = []
        for index in (1, 2, 3):
            relays.append(SimpleNamespace(
                endpoint=f"http://127.0.0.1:{19000 + index}", run_id=f"run-{index}",
                root=self.root / str(index), child=None))
        self.demo.owner = SimpleNamespace(root=self.root / "relay", _children=[])
        self.demo.context = SimpleNamespace(relays=relays, public_report=lambda: {"relays": []})
        restarted = []

        def restart(owner, relay, server, deadline):
            del owner, deadline
            restarted.append((relay.run_id, server))

        with mock.patch.object(relay_demo.run, "restart_relay", restart):
            self.demo.restart_relay(2)
        self.assertEqual(restarted, [("run-2", self.root / "server")])
        self.assertEqual(self.demo.chain_start_calls, 0)
        with self.assertRaisesRegex(ValueError, "relay"):
            self.demo.restart_relay(4)


if __name__ == "__main__":
    unittest.main()
