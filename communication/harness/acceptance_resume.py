"""Resume owned acceptance without replaying irreversible actions."""

import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import tempfile

TERMINAL = {'aborted', 'admission_rejected', 'expired', 'checkpoint_conflict',
            'terminal_pending', 'activation_unverified'}
BACKUPS = {'awaiting_backups', 'certified', 'payment_handoff', 'active'}
CERTIFIED = {'certified', 'payment_handoff', 'active'}


def agreement_needed(status, fingerprint):
    if status['phase'] in TERMINAL:
        raise RuntimeError('Ceremony stopped; preserve saved state')
    agreed = status.get('agreed_fingerprint')
    if agreed is not None and agreed != fingerprint:
        raise RuntimeError('Saved signer consent differs from fingerprint')
    if status['phase'] in BACKUPS and agreed is None:
        raise RuntimeError('Late ceremony has no saved signer consent')
    return agreed is None


def backup_actions(status, *, words, final_card):
    if status['phase'] in TERMINAL:
        raise RuntimeError('Ceremony stopped; preserve saved state')
    if status['phase'] not in BACKUPS:
        raise RuntimeError('Ceremony has not reached backup phase')
    if final_card:
        if status['phase'] not in CERTIFIED:
            raise RuntimeError('Final card conflicts with saved ceremony phase')
        return ()
    if not words:
        if status['phase'] in CERTIFIED:
            raise RuntimeError('Certified backup words missing; reconcile preserved card')
        return ('create', 'verify')
    return ('verify',) if status['phase'] == 'awaiting_backups' else ('finalize',)


def write_new(path, data):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix='.acceptance-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.unlink(temporary)


def ensure_manifest(path, original):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != original:
            raise RuntimeError('Saved payment manifest differs from original attempt')
    else:
        write_new(path, original)


@contextlib.contextmanager
def controller_lock(root):
    fd = os.open(Path(root) / '.acceptance-controller.lock', os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


class Actions:
    """Record intent before execution; uncertain writes require reconciliation."""

    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(mode=0o700, exist_ok=True)

    def paths(self, name, identity):
        digest = hashlib.sha256(json.dumps([name, identity], sort_keys=True).encode()).hexdigest()
        return self.root / (digest + '.intent'), self.root / (digest + '.done')

    def run(self, name, identity, action, *, idempotent=False):
        intent, done = self.paths(name, identity)
        if done.exists():
            return done.read_bytes()
        if intent.exists() and not idempotent:
            raise RuntimeError('Uncertain ' + name + '; reconcile original operation before retry')
        if not intent.exists():
            write_new(intent, json.dumps({'action': name, 'identity': identity}).encode())
        result = action()
        if not isinstance(result, bytes):
            raise TypeError('Durable action result must be bytes')
        write_new(done, result)
        return result

    def reconcile(self, name, identity, result):
        intent, done = self.paths(name, identity)
        if not intent.exists():
            raise RuntimeError('Cannot reconcile an action without saved intent')
        if done.exists():
            if done.read_bytes() != result:
                raise RuntimeError('Reconciled action differs from saved result')
        else:
            write_new(done, result)


def ssh_argv(host, command=None):
    argv = ['tailscale', 'ssh', host, '-o', 'ConnectTimeout=10', '-o', 'ConnectionAttempts=1',
            '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3',
            '-o', 'ExitOnForwardFailure=yes']
    if command is not None:
        argv.append(command)
    return argv


class RpcTunnel:
    """Supervise only this controller's reverse forward and verify remote RPC."""

    def __init__(self, host, readiness, diagnostics, *, attempts=3):
        self.host, self.readiness, self.diagnostics = host, readiness, diagnostics
        self.attempts = attempts
        self.process = None
        self.log = None
        self.verified_at = 0

    def stop(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5)
            self.process = None
        if self.log is not None:
            self.log.close()
            self.log = None

    def ensure(self):
        if self.process is not None and self.process.poll() is None:
            if time.monotonic() - self.verified_at < 15:
                return
            if self.readiness():
                self.verified_at = time.monotonic()
                return
        self.stop()
        for attempt in range(self.attempts):
            path = Path(self.diagnostics) / ('rpc-tunnel-' + str(time.time_ns()) + '.private')
            self.log = os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb')
            self.process = subprocess.Popen(ssh_argv(self.host) +
                ['-N', '-R', '127.0.0.1:47052:127.0.0.1:18452'],
                stdin=subprocess.DEVNULL, stdout=self.log, stderr=self.log)
            deadline = time.monotonic() + 25
            while self.process.poll() is None and time.monotonic() < deadline:
                if self.readiness():
                    self.verified_at = time.monotonic()
                    return
                time.sleep(1)
            self.stop()
            if attempt + 1 < self.attempts:
                time.sleep(2)
        raise RuntimeError('Owned RPC forward unavailable; diagnostics retained')

    def __enter__(self):
        self.ensure()
        return self

    def __exit__(self, *_):
        self.stop()
