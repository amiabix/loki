"""Owned relay lifecycle for one payment source. The browser does not choose paths or ports."""

from __future__ import annotations

import json
import os
import queue
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

DEMO = Path(__file__).resolve().parent
REPO = DEMO.parent.parent
HARNESS = REPO / "communication" / "harness"
if str(HARNESS) not in sys.path:
    sys.path.insert(0, str(HARNESS))

import run  # noqa: E402

PAYMENT_KINDS = {"sign", "finish", "verify", "resend", "receive"}


class MemberLease:
    """One store owner at a time. A payment command and a background pass share the lease."""

    def __init__(self):
        self._locks = {member_id: threading.Lock() for member_id in (1, 2, 3)}
        self.holder = {member_id: None for member_id in (1, 2, 3)}

    def reserve(self, member_id: int, kind: str) -> None:
        if member_id not in self._locks:
            raise ValueError("member must be 1, 2, or 3")
        if not self._locks[member_id].acquire(blocking=False):
            raise RuntimeError(f"member {member_id} store is busy")
        self.holder[member_id] = kind

    def release(self, member_id: int) -> None:
        if self.holder.get(member_id) is None:
            return
        self.holder[member_id] = None
        self._locks[member_id].release()


def process_identity(pid: int) -> str | None:
    """Return start time plus arguments.

    macOS rewrites a Python argv0 from the symlink to the real executable after
    exec. The arguments and start time stay put, and a recycled pid has a new
    start time, so this identity still refuses a stranger at the same pid.
    """
    previous = None
    last = None
    for _ in range(25):
        result = subprocess.run(
            ["ps", "-ww", "-p", str(pid), "-o", "lstart=", "-o", "command="],
            capture_output=True, text=True, timeout=5, check=False)
        if result.returncode == 1 and not result.stdout.strip():
            return None
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or "could not inspect the process")
        parts = result.stdout.split()
        # Drop the executable. Its path changes once during exec; the arguments do not.
        last = " ".join(parts[:5] + parts[6:]) if len(parts) >= 6 else " ".join(parts)
        if len(parts) >= 7 and last == previous:
            return last
        previous = last
        time.sleep(0.05)
    return last


def reap_recorded(root) -> None:
    """Stop relay children recorded by a previous controller, and only those children."""
    path = Path(root) / "owned-children.json"
    if not path.is_file():
        return
    try:
        record = json.loads(path.read_text())
    except (OSError, ValueError):
        return
    if record.get("version") != 1 or not isinstance(record.get("children"), list):
        return
    for item in record["children"]:
        if not isinstance(item, dict):
            continue
        pid = item.get("pid")
        identity = item.get("identity")
        if type(pid) is not int or not isinstance(identity, str) or identity == "":
            continue
        current = process_identity(pid)
        if current != identity:
            continue
        os.kill(pid, signal.SIGTERM)
        deadline = time.monotonic() + 2
        while process_identity(pid) == identity and time.monotonic() < deadline:
            time.sleep(0.05)
        if process_identity(pid) == identity:
            os.kill(pid, signal.SIGKILL)


def _payment_kind(argv: list[str]) -> str:
    for arg in argv:
        if arg in PAYMENT_KINDS:
            return arg
    raise ValueError("payment command is missing")


class _Worker:
    def __init__(self, member_id, kind, process, observe_r, control_w, response_r):
        self.member_id = member_id
        self.kind = kind
        self.process = process
        self.observe_r = observe_r
        self.control_w = control_w
        self.response_r = response_r
        self.responses = queue.Queue()
        self.stdout_thread = None
        self.response_thread = None
        self.observe_thread = None
        self.owns_stdio = False
        self.settled = threading.Event()


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
        self.leases = MemberLease()
        self.paused = {member_id: False for member_id in (1, 2, 3)}
        self.workers = {}
        self.cache = {}
        self.stale = {member_id: True for member_id in (1, 2, 3)}
        self.cache_lock = threading.Lock()

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
        self._write_children()
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

    def close(self) -> None:
        """Cancel payment workers, then stop relays this controller started."""
        self.cancel.set()
        try:
            self.settle(timeout=3)
        except RuntimeError:
            for worker in list(self.workers.values()):
                if worker.process.poll() is None:
                    worker.process.kill()
            self.settle(timeout=3)
        for worker in self.workers.values():
            for stream in (worker.process.stdin, worker.process.stdout, worker.process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
        self.stop()

    def start_payment(self, member_id: int, argv: list[str], *, interactive: bool,
                      env=None, cwd=None) -> subprocess.Popen:
        """Lease one member store and spawn its payment process with export pipes."""
        if member_id not in (1, 2, 3):
            raise ValueError("member must be 1, 2, or 3")
        if self.paused.get(member_id):
            raise RuntimeError(f"member {member_id} is paused")
        if self.cancel.is_set():
            raise RuntimeError("preparation cancelled")
        kind = _payment_kind(argv)
        self.leases.reserve(member_id, kind)
        observe_r, observe_w = os.pipe()
        control_r, control_w = os.pipe()
        response_r, response_w = os.pipe()
        command = [
            *argv, "--observe-fd", str(observe_w), "--control-fd", str(control_r),
            "--response-fd", str(response_w),
        ]
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE if interactive else subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                cwd=cwd, env=env, text=True, bufsize=1,
                pass_fds=(observe_w, control_r, response_w))
        except Exception:
            self.leases.release(member_id)
            for fd in (observe_r, observe_w, control_r, control_w, response_r, response_w):
                os.close(fd)
            raise
        for fd in (observe_w, control_r, response_w):
            os.close(fd)
        worker = _Worker(member_id, kind, process, observe_r, control_w, response_r)
        worker.response_thread = threading.Thread(
            target=self._read_responses, args=(worker,), daemon=True)
        worker.observe_thread = threading.Thread(
            target=self._drain, args=(observe_r,), daemon=True)
        worker.owns_stdio = interactive
        worker.response_thread.start()
        worker.observe_thread.start()
        self.workers[member_id] = worker
        threading.Thread(target=self._watch, args=(worker,), daemon=True).start()
        return process

    def run_payment(self, member_id: int, argv: list[str], *, timeout: int,
                    env=None, cwd=None) -> str:
        """Run one non-interactive payment command and return its stdout."""
        process = self.start_payment(member_id, argv, interactive=False, env=env, cwd=cwd)
        try:
            stdout, _ = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            self.settle(timeout=3)
            raise RuntimeError(f"{Path(argv[0]).name} timed out after {timeout}s")
        self.settle(timeout=max(timeout, 1))
        if process.returncode:
            raise RuntimeError(stdout.strip()[-1000:] or f"{Path(argv[0]).name} exited {process.returncode}")
        return stdout

    def pause_member(self, member_id: int) -> None:
        if member_id not in (1, 2, 3):
            raise ValueError("member must be 1, 2, or 3")
        if self.leases.holder.get(member_id) in PAYMENT_KINDS:
            raise RuntimeError(f"member {member_id} store is busy")
        self.paused[member_id] = True

    def resume_member(self, member_id: int) -> None:
        if member_id not in (1, 2, 3):
            raise ValueError("member must be 1, 2, or 3")
        self.paused[member_id] = False

    def restart_relay(self, index: int) -> None:
        """Restart one owned relay on its saved store. This does not start or mine a chain."""
        if type(index) is not int or index not in (1, 2, 3):
            raise ValueError("relay index must be 1, 2, or 3")
        if self.context is None or self.owner is None:
            raise RuntimeError("relays are not running")
        relay = self.context.relays[index - 1]
        run.restart_relay(self.owner, relay, self.server, time.monotonic() + self.timeout)
        self._write_children()

    def service_snapshot(self, member_id: int, section: str = "logical") -> dict:
        """Ask the owning payment worker for one public page. Never spawn a status command."""
        worker = self.workers.get(member_id)
        if worker is None or worker.process.poll() is not None:
            self._mark_stale(member_id)
            raise RuntimeError("snapshot read failed")
        request = {
            "version": 1, "type": "snapshot_page", "snapshot_id": "generation-1",
            "section": section, "after": "0", "limit": 100,
        }
        try:
            os.write(worker.control_w, (json.dumps(request) + "\n").encode())
            line = worker.responses.get(timeout=1)
            page = json.loads(line.decode())
        except (OSError, ValueError, queue.Empty, TypeError):
            self._mark_stale(member_id)
            raise RuntimeError("snapshot read failed")
        if not isinstance(page, dict) or page.get("error") or page.get("section") != section:
            self._mark_stale(member_id)
            raise RuntimeError("snapshot read failed")
        self.remember_snapshot(member_id, page)
        return page

    def remember_snapshot(self, member_id: int, page: dict) -> None:
        with self.cache_lock:
            self.cache[member_id] = page
            self.stale[member_id] = False

    def cached_snapshot(self, member_id: int) -> dict:
        """Return the last page read by the controller loop. This opens no store."""
        with self.cache_lock:
            return {"stale": bool(self.stale.get(member_id, True)),
                    "page": self.cache.get(member_id)}

    def settle(self, timeout: float = 5) -> None:
        deadline = time.monotonic() + timeout
        for worker in list(self.workers.values()):
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not worker.settled.wait(remaining):
                raise RuntimeError("payment worker did not settle")

    def _watch(self, worker: _Worker) -> None:
        try:
            while worker.process.poll() is None:
                if self.cancel.is_set():
                    worker.process.terminate()
                    try:
                        worker.process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        worker.process.kill()
                        worker.process.wait(timeout=2)
                    break
                time.sleep(0.05)
            if worker.stdout_thread is not None:
                worker.stdout_thread.join(timeout=5)
            if worker.response_thread is not None:
                worker.response_thread.join(timeout=1)
        finally:
            for fd in (worker.control_w, worker.response_r, worker.observe_r):
                try:
                    os.close(fd)
                except OSError:
                    pass
            if worker.owns_stdio:
                for stream in (worker.process.stdin, worker.process.stdout, worker.process.stderr):
                    if stream is not None and not stream.closed:
                        stream.close()
            self.leases.release(worker.member_id)
            worker.settled.set()

    def _read_responses(self, worker: _Worker) -> None:
        buffer = b""
        while True:
            try:
                chunk = os.read(worker.response_r, 4096)
            except OSError:
                break
            if not chunk:
                break
            buffer += chunk
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                worker.responses.put(line)

    def _drain(self, fd: int) -> None:
        while True:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break

    def _mark_stale(self, member_id: int) -> None:
        with self.cache_lock:
            self.cache[member_id] = None
            self.stale[member_id] = True

    def _write_children(self) -> None:
        if self.owner is None:
            return
        children = []
        for child in self.owned_live_children():
            identity = process_identity(child.pid)
            if identity:
                children.append({"pid": child.pid, "identity": identity})
        path = Path(self.owner.root) / "owned-children.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"version": 1, "children": children}, sort_keys=True) + "\n")
        path.chmod(0o600)

    def _stop_owned(self) -> None:
        owner = self.owner
        if owner is None:
            return
        try:
            close = getattr(owner, "close", None)
            if close is not None:
                close()
        finally:
            self.context = None
