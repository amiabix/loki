"""Owned relay lifecycle for one payment source. The browser does not choose paths or ports."""

from __future__ import annotations

import json
import socket
import sys
from pathlib import Path

DEMO = Path(__file__).resolve().parent
REPO = DEMO.parent.parent
HARNESS = REPO / "communication" / "harness"
if str(HARNESS) not in sys.path:
    sys.path.insert(0, str(HARNESS))

import run  # noqa: E402


def free_ports() -> tuple[int, int, int]:
    listeners = []
    try:
        for _ in range(3):
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(("127.0.0.1", 0))
            listeners.append(listener)
        return tuple(listener.getsockname()[1] for listener in listeners)
    finally:
        for listener in listeners:
            listener.close()


class RelayDemo:
    """Three relays owned by this controller. A partial start stops only those children."""

    def __init__(self, root, binaries, cancel, consumer, *, timeout=120,
                 communication_workspace=None, poc_workspace=None, lifecycle=None):
        self.root = Path(root)
        self.server, self.member_bin, self.setup_bin = binaries
        self.cancel = cancel
        self.consumer = consumer
        self.timeout = timeout
        self.communication_workspace = Path(
            communication_workspace or REPO / "communication")
        self.poc_workspace = Path(poc_workspace or DEMO.parent)
        self.mailbox_bytes = 67_108_864
        self.total_bytes = 268_435_456
        self.lifecycle = lifecycle or run.start_existing_members
        self.owner = None
        self.context = None
        self.chain_start_calls = 0

    def prepare(self, source) -> None:
        if self.cancel.is_set():
            raise RuntimeError("preparation cancelled")
        if self.owner is not None:
            raise RuntimeError("relay preparation already started")
        ports = free_ports()
        relay_root = self.root / "relay"
        self.owner = run.OwnedRun.create(relay_root)
        try:
            self.context = self.lifecycle(
                self.owner, source, ports,
                communication_workspace=self.communication_workspace,
                poc_workspace=self.poc_workspace,
                timeout=self.timeout,
                mailbox_bytes=self.mailbox_bytes,
                total_bytes=self.total_bytes,
            )
        except BaseException:
            self._stop_owned()
            raise
        self._write_manifest()
        if self.consumer is not None:
            self.consumer(self.public_manifest())

    def owned_live_children(self):
        if self.owner is None:
            return []
        return [child for child in self.owner._children if child.poll() is None]

    def public_manifest(self) -> dict:
        if self.context is None or self.owner is None:
            return {}
        report = self.context.public_report()
        report["version"] = 1
        report["processes"] = [child.pid for child in self.owned_live_children()]
        return report

    def _write_manifest(self) -> None:
        path = self.owner.root / "relay-demo.json"
        path.write_text(json.dumps(self.public_manifest(), sort_keys=True) + "\n")
        path.chmod(0o644)

    def stop(self) -> None:
        """Stop serve processes this controller started. A foreign listener is left alone."""
        self._stop_owned()

    def _stop_owned(self) -> None:
        owner = self.owner
        if owner is None:
            return
        try:
            owner.close()
        finally:
            self.context = None
