"""Relay preparation owns only the relays it starts."""

from __future__ import annotations

import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
