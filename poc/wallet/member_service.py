"""Client for `loki_member_service`: hosted setup commands in one native child.

The child gets the passphrase once, in its first stdin frame, and keeps it only in its
memory; nothing secret is written to a file, argv or the environment. Each call is one
JSON line on stdin and one reply line on stdout. The app keeps its own copy of the
passphrase so it can restart a service that died or timed out.
"""
import json
import os
import subprocess
import threading
import time

import timing

# Kept in step with `loki_poc::member_service::ALLOWED`.
ALLOWED = frozenset((
    "setup-config-check", "setup-status", "setup-info", "setup-evidence", "setup-create",
    "setup-join", "setup-invite", "setup-fingerprint", "setup-agree", "setup-step",
    "setup-abort", "setup-backup-create", "setup-backup-verify", "setup-backup-finalize",
))
STOP_SECONDS = 5


def enabled():
    return os.environ.get("LOKI_MEMBER_SERVICE", "1") != "0"


class ServiceError(ValueError):
    pass


class MemberService:
    def __init__(self, binary, data):
        self.binary = binary
        self.data = data
        self.lock = threading.Lock()
        self.process = None
        # Per child: callers waiting for a reply id, and replies not yet collected.
        self.waiting = {}
        self.replies = {}
        self.next_id = 0

    def available(self):
        return self.binary.is_file() and os.access(self.binary, os.X_OK)

    def running(self):
        return self.process is not None and self.process.poll() is None

    def start(self, passphrase, timeout=60):
        """Start (or restart) the child and unlock it. Raises if the passphrase is refused."""
        with self.lock:
            self._kill()
            process = subprocess.Popen([str(self.binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL)
            self.process = process
            self.waiting, self.replies = {}, {}
            ready = threading.Event()
            unlocked = {}
            reader = threading.Thread(target=self._read, args=(process, self.waiting, self.replies, ready, unlocked),
                                      daemon=True)
            reader.start()
            frame = json.dumps({"op": "unlock", "data": str(self.data), "passphrase": passphrase}) + "\n"
            try:
                process.stdin.write(frame.encode())
                process.stdin.flush()
            except OSError as error:
                self._kill()
                raise ServiceError("The member service could not start") from error
            finally:
                del frame
        if not ready.wait(timeout) or not unlocked.get("unlocked"):
            with self.lock:
                if self.process is process:
                    self._kill()
            raise ServiceError("The member service refused to unlock")

    def _read(self, process, waiting, replies, ready, unlocked):
        try:
            for line in process.stdout:
                try:
                    reply = json.loads(line)
                except ValueError:
                    continue
                if "unlocked" in reply:
                    unlocked.update(reply)
                    ready.set()
                    continue
                with self.lock:
                    event = waiting.pop(reply.get("id"), None)
                    if event is not None:
                        replies[reply.get("id")] = reply
                        event.set()
        except (OSError, ValueError):
            pass  # The pipe was closed by stop or a restart.
        ready.set()
        # This child is gone: wake every caller still waiting on it.
        with self.lock:
            for event in waiting.values():
                event.set()
            waiting.clear()

    def call(self, op, args, private=None, words=None, timeout=120):
        if op not in ALLOWED:
            raise ServiceError("Not a member service command")
        with self.lock:
            if not self.running():
                raise ServiceError("The member service is not running")
            self.next_id += 1
            ident = self.next_id
            event = threading.Event()
            waiting, replies = self.waiting, self.replies
            waiting[ident] = event
            frame = {"id": ident, "op": op, "args": [str(arg) for arg in args]}
            if private is not None:
                frame["private_hex"] = bytes(private).hex()
            if words is not None:
                frame["words"] = words
            try:
                self.process.stdin.write((json.dumps(frame) + "\n").encode())
                self.process.stdin.flush()
            except OSError as error:
                waiting.pop(ident, None)
                raise ServiceError("The member service stopped") from error
            finally:
                frame.clear()
        started = time.monotonic()
        if not event.wait(timeout):
            timing.record(f"service {op}", started, "timeout", *args[:1])
            with self.lock:
                waiting.pop(ident, None)
                if self.waiting is waiting:
                    self._kill()
            raise ServiceError("Hosted setup timed out; its saved state can be retried")
        with self.lock:
            reply = replies.pop(ident, None)
        if reply is None:
            timing.record(f"service {op}", started, "died", *args[:1])
            raise ServiceError("The member service stopped; its saved state can be retried")
        timing.record(f"service {op}", started, 0 if reply.get("ok") else 1, *args[:1])
        if not reply.get("ok"):
            raise ServiceError(f"error: {reply.get('error') or 'Hosted setup could not advance'}")
        return reply.get("result")

    def stop(self):
        """Lock: ask the child to stop, then kill it after STOP_SECONDS at the latest."""
        with self.lock:
            process, self.process = self.process, None
            for event in self.waiting.values():
                event.set()
            self.waiting.clear()
        if process is None:
            return
        try:
            process.stdin.write(b'{"op":"lock"}\n')
            process.stdin.close()
        except OSError:
            pass
        try:
            process.wait(STOP_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        self._close(process)

    def _kill(self):
        process, self.process = self.process, None
        if process is not None:
            if process.poll() is None:
                process.kill()
                process.wait()
            self._close(process)

    @staticmethod
    def _close(process):
        for stream in (process.stdin, process.stdout):
            try:
                stream.close()
            except (OSError, ValueError):
                pass
