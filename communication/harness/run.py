"""Ownership helpers, offline acceptance, and fault-scenario dispatch.

The acceptance and fault commands print and save public ids, hashes, lengths,
and counts. Passphrases, capabilities, payload bytes, and request bodies stay
in their files and out of argv logging.
"""

import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import select
import shutil
import socket
import stat
import subprocess
import sys
import time
import uuid


class OwnershipError(RuntimeError):
    pass


class CapturedOutput:
    """Bounded stdout from one owned command. Stderr is not retained."""

    def __init__(self, returncode, stdout):
        self.returncode = returncode
        self.stdout = stdout


def preflight_ports(ports):
    ports = tuple(ports)
    if any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
        raise OwnershipError('Invalid loopback port')
    if len(set(ports)) != len(ports):
        raise OwnershipError('Duplicate loopback ports')
    held = []
    try:
        for port in ports:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            held.append(listener)
            listener.bind(('127.0.0.1', port))
    except OSError as error:
        raise OwnershipError('Selected loopback port is unavailable') from error
    finally:
        for listener in held:
            listener.close()


def find_binary(name, *, workspace, target_dir=None, profile='debug', env=None):
    if any(not isinstance(part, str) or not part or part in ('.', '..') or
           Path(part).name != part for part in (name, profile)):
        raise OwnershipError('Binary and profile must be single path components')
    workspace = Path(workspace).resolve()
    env = os.environ if env is None else env
    target = Path(target_dir if target_dir is not None else
                  env.get('CARGO_TARGET_DIR', 'target'))
    if not target.is_absolute():
        target = workspace / target
    binary = target.resolve() / profile / name
    if binary.resolve().parent != target.resolve() / profile:
        raise OwnershipError('Binary is outside the selected build')
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise OwnershipError('Selected build binary is missing or not executable')
    return binary


class OwnedRun:
    MARKER = '.harness-owner.json'

    LIFECYCLE = '.harness-lifecycle.json'
    LOCK = '.harness-owner.lock'
    NESTED = 'fault-children.json'

    def __init__(self, root, run_id):
        self.root = Path(root).absolute()
        self.run_id = run_id
        self._children = []
        self._nested_owners = {}
        self._lock_fd = None
        self._reopened = False
        self._deleted = False
        info = self.root.stat()
        self._root_identity = (info.st_dev, info.st_ino)

    @classmethod
    def create(cls, root):
        root = Path(root).absolute()
        if any(path.is_symlink() for path in (root, *root.parents)):
            raise OwnershipError('Run root has a symlink component')
        try:
            root.mkdir(mode=0o700)
        except OSError as error:
            raise OwnershipError('Run root must be a new selected directory') from error
        owner = cls(root, uuid.uuid4().hex)
        with (root / cls.MARKER).open('x') as marker:
            json.dump({'run_id': owner.run_id, 'root': str(root)}, marker)
        owner._write_lifecycle('open')
        owner._acquire_lock(create=True)
        return owner

    @classmethod
    def reopen(cls, root, *, expected_run_id):
        """Return the retained owner for one exact stopped root.

        The lock is the only liveness signal. A name or process id is not
        ownership, and this path does not signal or stop any process.
        """
        root = Path(root).absolute()
        if any(path.is_symlink() for path in (root, *root.parents)):
            raise OwnershipError('Run root is a symlink')
        if isinstance(expected_run_id, str) is False or expected_run_id == '':
            raise OwnershipError('Run ID does not match')
        try:
            info = root.lstat()
        except OSError as error:
            raise OwnershipError('Selected run root is unavailable') from error
        if not stat.S_ISDIR(info.st_mode):
            raise OwnershipError('Selected run root is unavailable')
        owner = cls(root, expected_run_id)
        owner._lifecycle_record()
        owner._acquire_lock(create=False)
        try:
            record = owner._lifecycle_record()
        except BaseException:
            owner._release_lock()
            raise
        if record['state'] != 'stopped':
            owner._release_lock()
            raise OwnershipError('Retained run is incomplete')
        owner._reopened = True
        return owner

    def _command(self, argv, cwd):
        if not isinstance(argv, (list, tuple)) or not argv:
            raise OwnershipError('An explicit argv list is required')
        if not all(isinstance(arg, str) for arg in argv):
            raise OwnershipError('Arguments must be strings')
        binary = Path(argv[0])
        if not binary.is_absolute() or not binary.is_file() or not os.access(binary, os.X_OK):
            raise OwnershipError('An absolute executable path is required')
        return list(argv), str(Path(cwd).resolve())

    def start(self, argv, *, cwd):
        argv, cwd = self._command(argv, cwd)
        self._authorize_spawn()
        child = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 shell=False)
        self._children.append(child)
        return child

    def capture(self, argv, *, cwd, timeout, output_limit=16384):
        """Run one owned command and return its bounded stdout."""
        return self.capture_group([(argv, cwd)], timeout=timeout,
                                  output_limit=output_limit)[0]

    def capture_group(self, jobs, *, timeout, output_limit=16384):
        """Run at most three owned commands together and return bounded stdout.

        Stderr is counted and discarded. It is not returned or logged, because
        setup and member commands can write local failures there.
        """
        if not math.isfinite(timeout) or timeout < 0:
            raise OwnershipError('Command deadline must be finite and nonnegative')
        if type(output_limit) is not int or not 1 <= output_limit <= 65536:
            raise OwnershipError('Captured output bound is invalid')
        if not isinstance(jobs, (list, tuple)) or not 1 <= len(jobs) <= 3:
            raise OwnershipError('Command group exceeds the capture bound')
        deadline = time.monotonic() + timeout
        prepared = []
        for job in jobs:
            if not isinstance(job, (list, tuple)) or len(job) != 2:
                raise OwnershipError('An explicit argv list is required')
            prepared.append(self._command(job[0], job[1]))
        self._authorize_spawn()
        items = []
        try:
            for argv, cwd in prepared:
                child = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.DEVNULL,
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         shell=False, bufsize=0)
                self._children.append(child)
                items.append({'child': child, 'stdout': bytearray(), 'stderr_len': 0})
            pending = list(items)
            while pending:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise OwnershipError('Owned command exceeded its deadline')
                readers = []
                owners = {}
                for item in pending:
                    for stream, kind in ((item['child'].stdout, 'stdout'),
                                         (item['child'].stderr, 'stderr')):
                        if stream is not None and not stream.closed:
                            readers.append(stream)
                            owners[stream] = (item, kind)
                if not readers:
                    pending = self._reap_captured(pending, deadline)
                    continue
                ready, _, _ = select.select(readers, [], [], remaining)
                if not ready:
                    raise OwnershipError('Owned command exceeded its deadline')
                for stream in ready:
                    item, kind = owners[stream]
                    chunk = os.read(stream.fileno(), 4096)
                    if not chunk:
                        stream.close()
                        continue
                    if kind == 'stdout':
                        if len(item['stdout']) + len(chunk) > output_limit:
                            raise OwnershipError(
                                'Owned command output exceeded the capture bound')
                        item['stdout'].extend(chunk)
                    else:
                        item['stderr_len'] += len(chunk)
                        if item['stderr_len'] > output_limit:
                            raise OwnershipError(
                                'Owned command output exceeded the capture bound')
                pending = self._reap_captured(pending, deadline)
            return [CapturedOutput(item['code'], bytes(item['stdout'])) for item in items]
        except BaseException as original:
            incomplete = False
            for item in items:
                try:
                    self._settle_child(item['child'])
                except (OSError, subprocess.TimeoutExpired, OwnershipError):
                    incomplete = True
            if incomplete:
                raise OwnershipError(
                    'Owned child shutdown did not complete before deadline') from original
            raise

    def _reap_captured(self, pending, deadline):
        still = []
        for item in pending:
            child = item['child']
            if child.stdout is not None and not child.stdout.closed:
                still.append(item)
                continue
            if child.stderr is not None and not child.stderr.closed:
                still.append(item)
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise OwnershipError('Owned command exceeded its deadline')
            item['code'] = child.wait(timeout=remaining)
        return still

    def _settle_child(self, child):
        try:
            if child.poll() is None:
                self.stop(child, timeout=2.0)
        finally:
            for stream in (child.stdout, child.stderr):
                if stream is not None and not stream.closed:
                    stream.close()

    def stop(self, child, *, timeout=2.0):
        if not any(child is owned for owned in self._children):
            raise OwnershipError('Process handle is not owned by this controller')
        if not math.isfinite(timeout) or timeout < 0:
            raise OwnershipError('Shutdown timeout must be finite and nonnegative')
        if child.poll() is not None:
            return
        deadline = time.monotonic() + timeout
        child.terminate()
        try:
            child.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=max(0.0, deadline - time.monotonic()))

    def close(self, *, timeout=2.0):
        if not math.isfinite(timeout) or timeout < 0:
            raise OwnershipError('Shutdown timeout must be finite and nonnegative')
        # A later close is harmless only after this same handle's authorized
        # delete. A missing root or a released lock remains incomplete.
        if self._deleted:
            return
        deadline = time.monotonic() + timeout
        failed = False
        for child in self._children:
            try:
                self.stop(child, timeout=max(0.0, deadline - time.monotonic()))
            except (OSError, subprocess.TimeoutExpired):
                failed = True
        if failed:
            raise OwnershipError('Owned child shutdown did not complete before deadline')
        # A nested scenario keeps its own processes. An empty direct list is not stopped.
        self._require_nested_settled(require_unlocked=False)
        self._mark_stopped()

    def delete(self, *, expected_run_id, root=None):
        if any(child.poll() is None for child in self._children):
            raise OwnershipError('Owned processes must be stopped before deletion')
        selected = self.root if root is None else Path(root).absolute()
        if any(path.is_symlink() for path in (selected, *selected.parents)):
            raise OwnershipError('Run root is a symlink')
        if selected != self.root:
            raise OwnershipError('Root is outside the selected run')
        if expected_run_id != self.run_id:
            raise OwnershipError('Run ID does not match')
        try:
            info = selected.stat()
        except OSError as error:
            raise OwnershipError('Selected run root is unavailable') from error
        if (info.st_dev, info.st_ino) != self._root_identity:
            raise OwnershipError('Selected run root was replaced')
        if (selected / self.MARKER).is_symlink():
            raise OwnershipError('Ownership marker is a symlink')
        if not (selected / self.MARKER).is_file():
            raise OwnershipError('Run has no ownership marker')
        try:
            marker = json.loads((selected / self.MARKER).read_text())
        except (OSError, ValueError) as error:
            raise OwnershipError('Unreadable ownership marker') from error
        if marker != {'run_id': self.run_id, 'root': str(self.root)}:
            raise OwnershipError('Ownership marker does not match')
        record = self._lifecycle_record()
        if record['state'] != 'stopped':
            raise OwnershipError('Retained run is incomplete')
        self._require_nested_settled(require_unlocked=True)
        shutil.rmtree(selected)
        self._deleted = True
        self._release_lock()

    def _authorize_spawn(self):
        """Make the persisted lifecycle agree with a new child before it exists.

        A handle reopened for deletion cannot spawn. Any other stopped owner
        must durably return to open while it still holds the lock. A missing
        or foreign lock or lifecycle record cannot authorize a process.
        """
        if self._reopened:
            raise OwnershipError('Closed run cannot start a process')
        if self._lock_fd is None:
            raise OwnershipError('Retained run is incomplete')
        record = self._lifecycle_record()
        if record['state'] == 'open':
            return
        if record['state'] != 'stopped':
            raise OwnershipError('Retained run is incomplete')
        self._write_lifecycle('open')
        if self._lifecycle_record()['state'] != 'open':
            raise OwnershipError('Retained run is incomplete')

    def _mark_stopped(self):
        """Record a stopped run only after every owned handle has settled."""
        if self._lock_fd is None:
            raise OwnershipError('Retained run is incomplete')
        if any(child.poll() is None for child in self._children):
            raise OwnershipError('Owned processes must be stopped before the run is retained')
        self._write_lifecycle('stopped')

    def bind_nested_run(self, *, scenario, child):
        """Record one child root before that child can serve.

        The binding is the child run id and the directory device and inode.
        A later stop or delete uses that record, not a process name or id.
        """
        if self._reopened or self._lock_fd is None:
            raise OwnershipError('Retained run is incomplete')
        if _SCENARIO_NAME.fullmatch(scenario) is None:
            raise OwnershipError('harness_arguments')
        if child.root.parent.name != 'scenarios' or child.root.parent.parent != self.root:
            raise OwnershipError('Root is outside the selected run')
        if child.root.name != scenario:
            raise OwnershipError('Root is outside the selected run')
        if any(path.is_symlink() for path in (child.root, *child.root.parents)):
            raise OwnershipError('Run root is a symlink')
        info = child.root.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise OwnershipError('Selected run root is unavailable')
        if (info.st_dev, info.st_ino) != child._root_identity:
            raise OwnershipError('Selected run root was replaced')
        records = self._read_nested_index()
        if any(item['run_id'] == child.run_id or item['scenario'] == scenario for item in records):
            raise OwnershipError('Nested scenario is active')
        records.append({
            'dev': info.st_dev,
            'ino': info.st_ino,
            'root': str(child.root),
            'run_id': child.run_id,
            'scenario': scenario,
        })
        self._write_nested_index(records)
        self._nested_owners[child.run_id] = child

    def _require_nested_settled(self, *, require_unlocked):
        for record in self._read_nested_index():
            self._check_nested_binding(record)
            child = self._nested_owners.get(record['run_id'])
            if child is not None:
                if any(process.poll() is None for process in child._children):
                    raise OwnershipError(
                        'Owned processes must be stopped before the run is retained')
                if child._lifecycle_record()['state'] != 'stopped':
                    raise OwnershipError('Nested scenario is active')
            else:
                if _directory_lock_held(record['root']):
                    raise OwnershipError('Nested scenario is active')
                if _nested_lifecycle_state(record) != 'stopped':
                    raise OwnershipError('Nested scenario is active')
            if require_unlocked and _directory_lock_held(record['root']):
                raise OwnershipError('Nested scenario is active')

    def _check_nested_binding(self, record):
        root = Path(record['root'])
        if any(path.is_symlink() for path in (root, *root.parents)):
            raise OwnershipError('Run root is a symlink')
        if self.root not in root.parents or root.name != record['scenario']:
            raise OwnershipError('Root is outside the selected run')
        info = root.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise OwnershipError('Selected run root is unavailable')
        if (info.st_dev, info.st_ino) != (record['dev'], record['ino']):
            raise OwnershipError('Selected run root was replaced')
        marker_path = root / self.MARKER
        try:
            marker = json.loads(marker_path.read_text(encoding='ascii'))
        except (OSError, UnicodeError, ValueError) as error:
            raise OwnershipError('Unreadable ownership marker') from error
        if marker != {'run_id': record['run_id'], 'root': str(root)}:
            raise OwnershipError('Ownership marker does not match')

    def _read_nested_index(self):
        path = self.root / self.NESTED
        try:
            info = path.lstat()
        except FileNotFoundError:
            return []
        except OSError as error:
            raise OwnershipError('Retained run is incomplete') from error
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 65536:
            raise OwnershipError('Retained run is incomplete')
        try:
            loaded = json.loads(path.read_text(encoding='ascii'))
        except (OSError, UnicodeError, ValueError) as error:
            raise OwnershipError('Retained run is incomplete') from error
        if not isinstance(loaded, dict) or set(loaded) != {'children'}:
            raise OwnershipError('Retained run is incomplete')
        children = loaded['children']
        if not isinstance(children, list):
            raise OwnershipError('Retained run is incomplete')
        records = []
        seen = set()
        for item in children:
            if not isinstance(item, dict) or set(item) != {
                    'dev', 'ino', 'root', 'run_id', 'scenario'}:
                raise OwnershipError('Retained run is incomplete')
            if type(item['dev']) is not int or type(item['ino']) is not int:
                raise OwnershipError('Retained run is incomplete')
            if item['run_id'] in seen or _SCENARIO_NAME.fullmatch(item['scenario']) is None:
                raise OwnershipError('Retained run is incomplete')
            if re.fullmatch(r'[0-9a-f]{32}', item['run_id']) is None:
                raise OwnershipError('Run ID does not match')
            if item['root'] != str(self.root / 'scenarios' / item['scenario']):
                raise OwnershipError('Root is outside the selected run')
            seen.add(item['run_id'])
            records.append(item)
        return records

    def _write_nested_index(self, records):
        path = self.root / self.NESTED
        if path.is_symlink():
            raise OwnershipError('Retained run is incomplete')
        payload = {'children': records}
        temporary = self.root / f'.nested-{secrets.token_hex(8)}.tmp'
        _write_new(temporary, json.dumps(payload, sort_keys=True,
                                         separators=(',', ':')).encode('ascii') + b'\n', 0o600)
        os.replace(temporary, path)
        os.chmod(path, 0o600)

    def _lifecycle_payload(self, state):
        marker_path = self.root / self.MARKER
        try:
            marker_info = marker_path.lstat()
            root_info = self.root.lstat()
        except OSError as error:
            raise OwnershipError('Retained run is incomplete') from error
        if not stat.S_ISREG(marker_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
            raise OwnershipError('Retained run is incomplete')
        if (root_info.st_dev, root_info.st_ino) != self._root_identity:
            raise OwnershipError('Selected run root was replaced')
        return {
            'device': root_info.st_dev,
            'inode': root_info.st_ino,
            'marker': hashlib.sha256(marker_path.read_bytes()).hexdigest(),
            'root': str(self.root),
            'run_id': self.run_id,
            'state': state,
        }

    def _write_lifecycle(self, state):
        if state not in ('open', 'stopped'):
            raise OwnershipError('Retained run is incomplete')
        data = json.dumps(self._lifecycle_payload(state), sort_keys=True,
                          separators=(',', ':')).encode('ascii') + b'\n'
        path = self.root / self.LIFECYCLE
        if path.is_symlink():
            raise OwnershipError('Retained run is incomplete')
        temporary = self.root / f'.lifecycle-{secrets.token_hex(8)}.tmp'
        _write_new(temporary, data, 0o600)
        os.replace(temporary, path)
        os.chmod(path, 0o600)

    def _lifecycle_record(self):
        path = self.root / self.LIFECYCLE
        try:
            info = path.lstat()
        except FileNotFoundError as error:
            raise OwnershipError('Retained run has no lifecycle record') from error
        except OSError as error:
            raise OwnershipError('Retained run is incomplete') from error
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 8192:
            raise OwnershipError('Retained run is incomplete')
        marker_path = self.root / self.MARKER
        try:
            marker_info = marker_path.lstat()
        except OSError as error:
            raise OwnershipError('Run has no ownership marker') from error
        if not stat.S_ISREG(marker_info.st_mode):
            raise OwnershipError('Ownership marker is a symlink')
        try:
            record = json.loads(path.read_text(encoding='ascii'))
            marker = marker_path.read_bytes()
            root_info = self.root.lstat()
        except (OSError, UnicodeError, ValueError) as error:
            raise OwnershipError('Retained run is incomplete') from error
        if not isinstance(record, dict) or set(record) != {
                'device', 'inode', 'marker', 'root', 'run_id', 'state'}:
            raise OwnershipError('Retained run is incomplete')
        if type(record['device']) is not int or type(record['inode']) is not int:
            raise OwnershipError('Retained run is incomplete')
        if record['state'] not in ('open', 'stopped'):
            raise OwnershipError('Retained run is incomplete')
        if record['run_id'] != self.run_id:
            raise OwnershipError('Run ID does not match')
        if record['root'] != str(self.root):
            raise OwnershipError('Root is outside the selected run')
        if (record['device'], record['inode']) != (root_info.st_dev, root_info.st_ino):
            raise OwnershipError('Selected run root was replaced')
        if (root_info.st_dev, root_info.st_ino) != self._root_identity:
            raise OwnershipError('Selected run root was replaced')
        if record['marker'] != hashlib.sha256(marker).hexdigest():
            raise OwnershipError('Retained run is incomplete')
        try:
            loaded = json.loads(marker.decode('ascii'))
        except (UnicodeError, ValueError) as error:
            raise OwnershipError('Unreadable ownership marker') from error
        if loaded != {'run_id': self.run_id, 'root': str(self.root)}:
            raise OwnershipError('Ownership marker does not match')
        return record

    def _acquire_lock(self, *, create):
        """Hold one exclusive advisory lock until delete or process exit.

        Lock failure means another live owner still exists. It is not a reason
        to inspect or terminate that process. Reopening never creates the lock.
        """
        if self._lock_fd is not None:
            raise OwnershipError('Run root has an active harness owner')
        path = self.root / self.LOCK
        try:
            info = path.lstat()
        except FileNotFoundError:
            info = None
        except OSError as error:
            raise OwnershipError('Retained run is incomplete') from error
        flags = os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0)
        if info is None:
            if not create:
                raise OwnershipError('Retained run is incomplete')
            flags |= os.O_CREAT | os.O_EXCL
        elif not stat.S_ISREG(info.st_mode):
            raise OwnershipError('Retained run is incomplete')
        try:
            descriptor = os.open(path, flags, 0o600)
        except OSError as error:
            raise OwnershipError('Retained run is incomplete') from error
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            os.close(descriptor)
            raise OwnershipError('Run root has an active harness owner') from error
        self._lock_fd = descriptor
        os.chmod(path, 0o600)

    def _release_lock(self):
        descriptor = self._lock_fd
        self._lock_fd = None
        if descriptor is not None:
            os.close(descriptor)

    def __del__(self):
        try:
            self._release_lock()
        except OSError:
            pass


_HEX64 = re.compile(r'[0-9a-f]{64}\Z')
_PUBLIC_INT = re.compile(r'[1-9][0-9]*\Z')
_CONFIG_LINE = re.compile(r'config revision=([1-9][0-9]*) hash=([0-9a-f]{64})\Z')
_INBOX_LINE = re.compile(
    r'inbox member=([123]) pin=([0-9a-f]{64}) run=([0-9a-f]{64}) '
    r'mailbox=([0-9a-f]{64}) append_revision=([1-9][0-9]*) endpoint=(\S+)\Z')
_COURIER_LINE = re.compile(
    r'courier=([0-9a-f]{64})-relay-config-([123])-([123])-([1-9][0-9]*)\.bin\Z')
_IMPORT_LINE = re.compile(
    r'imported owner=([123]) revision=([1-9][0-9]*) digest=([0-9a-f]{64})\Z')
_TEMP_LINK = re.compile(r'\.[0-9a-f]{32}\.tmp\Z')
_I64_MAX = 2**63 - 1


class RelayBinding:
    def __init__(self, endpoint, run_id, receipt_key, root, child):
        self.endpoint = endpoint
        self.run_id = run_id
        self.receipt_key = receipt_key
        self.root = root
        self.child = child


class CertifiedMember:
    def __init__(self, member_id, root, passphrase_file, signing, encryption):
        self.member_id = member_id
        self.root = root
        self.passphrase_file = passphrase_file
        self.signing = signing
        self.encryption = encryption
        self.config_revision = None
        self.config_hash = None


class PeerCourier:
    def __init__(self, name, owner, peer, revision, path):
        self.name = name
        self.owner = owner
        self.peer = peer
        self.revision = revision
        self.path = path
        self.digest = None


class SetupContext:
    """Reusable certified setup. Paths to secrets stay on this object, not in the public report."""

    def __init__(self, owner, vault, fingerprint, mailbox_bytes, total_bytes, relays,
                 members, roster, inboxes, couriers):
        self.owner = owner
        self.vault = vault
        self.fingerprint = fingerprint
        self.mailbox_bytes = mailbox_bytes
        self.total_bytes = total_bytes
        self.relays = relays
        self.members = members
        self.roster = roster
        self.inboxes = inboxes
        self.couriers = couriers

    def public_report(self):
        return {
            'harness_run_id': self.owner.run_id,
            'vault': self.vault,
            'roster_fingerprint': self.fingerprint,
            'mailbox_bytes': self.mailbox_bytes,
            'total_bytes': self.total_bytes,
            'mailbox_count': 3,
            'relays': [{
                'endpoint': relay.endpoint,
                'run_id': relay.run_id,
                'receipt_key': relay.receipt_key,
            } for relay in self.relays],
            'members': [{
                'id': member.member_id,
                'signing': member.signing,
                'encryption': member.encryption,
                'config_revision': member.config_revision,
                'config_hash': member.config_hash,
            } for member in self.members],
            'inboxes': [dict(inbox) for inbox in self.inboxes],
            'couriers': [{
                'name': courier.name,
                'owner': courier.owner,
                'peer': courier.peer,
                'revision': courier.revision,
                'digest': courier.digest,
            } for courier in self.couriers],
        }


def _ambient_target_dir(target_dir):
    """Return one target directory for every lookup in this controller call.

    An explicit ``target_dir`` is unchanged, so ``find_binary`` still joins a
    relative directory to the workspace. When it is omitted and
    ``CARGO_TARGET_DIR`` is set, Cargo's directory is made absolute from the
    controller cwd and reused for both workspaces. An unset variable stays
    omitted, leaving each workspace its default ``target``.
    """
    if target_dir is not None:
        return target_dir
    selected = os.environ.get('CARGO_TARGET_DIR')
    if not selected:
        return None
    path = Path(selected)
    if not path.is_absolute():
        path = Path.cwd() / path
    return str(path.absolute())


def prepare_certified_setup(root, ports, *, communication_workspace, poc_workspace, timeout,
                            target_dir=None, profile='debug', mailbox_bytes=1048576,
                            total_bytes=8388608, owner=None):
    """Certify three members and provision nine inboxes under a new owned run.

    Relay serve processes keep running on the returned context. This does not
    send, acknowledge, rotate, or call address, backup, funding, scan, sign, or
    chain commands. Failure stops owned children and leaves the directory in place.
    """
    target_dir = _ambient_target_dir(target_dir)
    if not math.isfinite(timeout) or timeout <= 0:
        raise OwnershipError('Setup deadline must be finite and positive')
    if type(mailbox_bytes) is not int or not 1 <= mailbox_bytes <= _I64_MAX:
        raise OwnershipError('Mailbox quota is outside the public bound')
    if type(total_bytes) is not int or not mailbox_bytes <= total_bytes <= _I64_MAX:
        raise OwnershipError('Relay quota is outside the public bound')
    ports = tuple(ports)
    if len(ports) != 3:
        raise OwnershipError('Three loopback ports are required')
    server = find_binary('loki-relay-server', workspace=communication_workspace,
                         target_dir=target_dir, profile=profile)
    setup_bin = find_binary('loki_setup_member', workspace=poc_workspace,
                            target_dir=target_dir, profile=profile)
    member_bin = find_binary('loki_relay_member', workspace=poc_workspace,
                             target_dir=target_dir, profile=profile)
    preflight_ports(ports)
    if owner is None:
        owner = OwnedRun.create(root)
    else:
        root = Path(root).absolute()
        if owner.root != root or owner._reopened or owner._lock_fd is None:
            raise OwnershipError('Retained run is incomplete')
    try:
        return _certified_setup(owner, ports, server, setup_bin, member_bin, timeout,
                                mailbox_bytes, total_bytes)
    except BaseException:
        try:
            owner.close()
        except (OSError, subprocess.TimeoutExpired, OwnershipError) as error:
            raise OwnershipError(
                'Owned child shutdown did not complete before deadline') from error
        raise


def _certified_setup(owner, ports, server, setup_bin, member_bin, timeout, mailbox_bytes,
                     total_bytes):
    deadline = time.monotonic() + timeout
    for name in ('relays', 'public-manifests', 'capabilities', 'capability-staging',
                 'members', 'exchange', 'courier-export', 'descriptors'):
        _mkdir(owner.root / name)
    relays = tuple(
        _init_relay(owner, index, port, server, deadline, mailbox_bytes, total_bytes)
        for index, port in enumerate(ports, start=1))
    if len({relay.run_id for relay in relays}) != 3 or len({
            relay.receipt_key for relay in relays}) != 3:
        raise OwnershipError('Relay identities are not distinct')
    _rmdir(owner.root / 'capability-staging', 'Capability staging was not retired')
    _expect_names(owner.root / 'public-manifests', ['1', '2', '3'])
    _expect_names(owner.root / 'capabilities', sorted(relay.receipt_key for relay in relays))
    for relay in relays:
        child = owner.start([
            str(server), 'serve', '--root', str(relay.root), '--listen',
            _listen(relay.endpoint),
        ], cwd=relay.root)
        relay.child = child
        _wait_listen(relay.child, _listen(relay.endpoint), deadline)
    created = []
    for member_id in (1, 2, 3):
        created.append(_create_member(owner, setup_bin, member_id, created, relays, deadline))
    members = tuple(created)
    if len({member.signing for member in members}) != 3 or len({
            member.encryption for member in members}) != 3:
        raise OwnershipError('Member identities are not distinct')
    vault = secrets.token_hex(32)
    if _HEX64.fullmatch(vault) is None:
        raise OwnershipError('Roster vault is not public hex')
    roster = owner.root / 'roster.json'
    _write_new(roster, json.dumps({
        'vault': vault,
        'members': [{
            'id': member.member_id,
            'signing': member.signing,
            'encryption': member.encryption,
        } for member in members],
    }, separators=(',', ':')).encode('ascii') + b'\n', 0o644)
    fingerprint = _fingerprint_text(_command_text(owner, [
        str(setup_bin), 'fingerprint', str(roster),
    ], owner.root, deadline))
    jobs = []
    for member in members:
        argv = [str(setup_bin), 'run', str(member.root), str(member.passphrase_file),
                str(roster), str(owner.root / 'exchange'), fingerprint]
        _reject_foreign(argv, _foreign(member, members, relays))
        jobs.append((argv, member.root))
    for result in owner.capture_group(jobs, timeout=_remaining(deadline)):
        if result.returncode != 0:
            raise OwnershipError('Owned command exited unsuccessfully')
        if result.stdout != b'':
            raise OwnershipError('Setup run returned unexpected output')
    inboxes = []
    for member in members:
        config, lines = _member_command(owner, member_bin, member, members, relays, roster,
                                        deadline, 'provision', [
                                            '--relay-manifest',
                                            str(owner.root / 'public-manifests'),
                                            '--provision-capability-files',
                                            str(owner.root / 'capabilities'),
                                        ])
        member.config_revision, member.config_hash = config
        inboxes.extend(_parse_inboxes(lines, member, relays))
    if len(inboxes) != 9 or len({inbox['mailbox'] for inbox in inboxes}) != 9:
        raise OwnershipError('Provision did not publish nine inbox ids')
    couriers = []
    for member in members:
        _mkdir(owner.root / 'courier-export' / str(member.member_id))
        _, lines = _member_command(
            owner, member_bin, member, members, relays, roster, deadline, 'export-config',
            ['--courier-directory', str(owner.root / 'courier-export' / str(member.member_id))])
        export_dir = owner.root / 'courier-export' / str(member.member_id)
        for name, owner_id, peer_id, revision in _parse_couriers(lines, vault, member.member_id):
            _release_single_link(export_dir, name)
            destination_dir = owner.root / 'descriptors' / str(peer_id)
            _mkdir(destination_dir)
            target = destination_dir / name
            (export_dir / name).rename(target)
            couriers.append(PeerCourier(name, owner_id, peer_id, revision, target))
        _rmdir(export_dir, 'Courier directory has an unexpected file')
    _rmdir(owner.root / 'courier-export', 'Courier directory has an unexpected file')
    expected_pairs = {(left, right) for left in (1, 2, 3) for right in (1, 2, 3) if left != right}
    if {(courier.owner, courier.peer) for courier in couriers} != expected_pairs or len({
            courier.name for courier in couriers}) != 6:
        raise OwnershipError('Export did not publish six peer descriptors')
    for courier in couriers:
        recipient = members[courier.peer - 1]
        config, lines = _member_command(
            owner, member_bin, recipient, members, relays, roster, deadline, 'import-config',
            ['--courier-file', str(courier.path)])
        recipient.config_revision, recipient.config_hash = config
        courier.digest = _parse_import(lines, courier)
    context = SetupContext(owner, vault, fingerprint, mailbox_bytes, total_bytes, relays,
                           members, roster, tuple(inboxes), tuple(couriers))
    _write_new(owner.root / 'setup-report.json',
               json.dumps(context.public_report(), sort_keys=True).encode('ascii') + b'\n',
               0o644)
    return context


def _init_relay(owner, index, port, server, deadline, mailbox_bytes, total_bytes):
    endpoint = f'http://127.0.0.1:{port}'
    relay_root = owner.root / 'relays' / str(index)
    projection = owner.root / 'public-manifests' / str(index)
    if projection.resolve() in relay_root.resolve().parents or relay_root.resolve(
    ) in projection.resolve().parents:
        raise OwnershipError('Public relay projection overlaps a relay root')
    staging = owner.root / 'capability-staging' / str(index)
    secret = bytearray(secrets.token_bytes(32))
    try:
        _write_new(staging, secret, 0o600)
        text = _command_text(owner, [
            str(server), 'init', '--root', str(relay_root), '--provision-capability-file',
            str(staging), '--total-bytes', str(total_bytes), '--mailbox-bytes',
            str(mailbox_bytes), '--mailbox-count', '3', '--listen', _listen(endpoint),
        ], owner.root, deadline)
        if text != '':
            raise OwnershipError('Relay init returned unexpected output')
        manifest, run_id, receipt_key = _public_manifest(relay_root / 'manifest', endpoint)
        named = owner.root / 'capabilities' / receipt_key
        try:
            _write_new(named, secret, 0o600)
        except FileExistsError as error:
            raise OwnershipError('Relay identities are not distinct') from error
        recorded = bytearray(named.read_bytes())
        try:
            info = named.lstat()
            if recorded != secret or not stat.S_ISREG(
                    info.st_mode) or info.st_nlink != 1 or info.st_size != 32:
                raise OwnershipError('Provision capability file does not match the relay')
        finally:
            recorded[:] = b'\x00' * len(recorded)
    finally:
        secret[:] = b'\x00' * len(secret)
        try:
            staging.unlink()
        except FileNotFoundError:
            pass
    _mkdir(projection)
    _write_new(projection / 'manifest', manifest, 0o644)
    _write_new(projection / 'mailbox-bytes', f'{mailbox_bytes}\n'.encode('ascii'), 0o644)
    _expect_names(projection, ['mailbox-bytes', 'manifest'])
    if (projection / 'manifest').read_bytes() != manifest:
        raise OwnershipError('Public relay projection is not the manifest directory')
    if (projection / 'mailbox-bytes').read_text(encoding='ascii') != f'{mailbox_bytes}\n':
        raise OwnershipError('Public relay projection is not the manifest directory')
    return RelayBinding(endpoint, run_id, receipt_key, relay_root, None)


def _create_member(owner, setup_bin, member_id, others, relays, deadline):
    root = owner.root / 'members' / str(member_id)
    _mkdir(root)
    passphrase = root / 'passphrase'
    _write_new(passphrase, secrets.token_hex(32).encode('ascii') + b'\n', 0o600)
    member = CertifiedMember(member_id, root, passphrase, '', '')
    argv = [str(setup_bin), 'identity', str(root), str(member_id), str(passphrase)]
    _reject_foreign(argv, _foreign(member, others, relays))
    try:
        identity = json.loads(_command_text(owner, argv, root, deadline))
    except json.JSONDecodeError as error:
        raise OwnershipError('Identity status is not the public member record') from error
    if not isinstance(identity, dict) or set(identity) != {'encryption', 'id', 'signing'}:
        raise OwnershipError('Identity status is not the public member record')
    if identity['id'] != member_id or _HEX64.fullmatch(identity['signing']) is None or _HEX64.fullmatch(
            identity['encryption']) is None:
        raise OwnershipError('Identity status is not the public member record')
    member.signing = identity['signing']
    member.encryption = identity['encryption']
    return member


def _member_command(owner, binary, member, members, relays, roster, deadline, command, extra):
    argv = [str(binary), command, '--member-root', str(member.root), '--passphrase-file',
            str(member.passphrase_file), '--roster', str(roster), *extra]
    _reject_foreign(argv, _foreign(member, members, relays))
    return _status_lines(_command_text(owner, argv, member.root, deadline))


def _foreign(member, members, relays):
    foreign = [relay.root for relay in relays]
    for other in members:
        if other.member_id != member.member_id:
            foreign.append(other.root)
            foreign.append(other.passphrase_file)
    return foreign


def _reject_foreign(argv, foreign):
    forbidden = [path.resolve() for path in foreign]
    for arg in argv:
        if not arg.startswith(os.sep):
            continue
        path = Path(arg).resolve()
        if any(path == root or root in path.parents for root in forbidden):
            raise OwnershipError('Member command includes another member or relay root')


def _command_text(owner, argv, cwd, deadline):
    result = owner.capture(argv, cwd=cwd, timeout=_remaining(deadline))
    if result.returncode != 0:
        raise OwnershipError('Owned command exited unsuccessfully')
    if b'\0' in result.stdout:
        raise OwnershipError('Owned command returned an invalid status')
    try:
        text = result.stdout.decode('ascii')
    except UnicodeError as error:
        raise OwnershipError('Owned command returned an invalid status') from error
    if 'route_error' in text or 'retrieval_error' in text:
        raise OwnershipError('Remote relay failure is not setup success')
    return text


def _status_lines(text):
    if text == '' or not text.endswith('\n') or '\r' in text:
        raise OwnershipError('Owned command returned an invalid status')
    lines = text[:-1].split('\n')
    if any(line == '' for line in lines):
        raise OwnershipError('Owned command returned an invalid status')
    config = None
    body = []
    for line in lines:
        matched = _CONFIG_LINE.fullmatch(line)
        if matched:
            if config is not None:
                raise OwnershipError('Owned command returned an invalid status')
            revision = _public_int(matched.group(1))
            config = (revision, matched.group(2))
        else:
            body.append(line)
    if config is None:
        raise OwnershipError('Member status omitted the public config reference')
    return config, body


def _parse_inboxes(lines, member, relays):
    if len(lines) != 3:
        raise OwnershipError('Provision did not publish three inboxes')
    found = []
    pins = set()
    relays_by_key = {relay.receipt_key: relay for relay in relays}
    for line in lines:
        matched = _INBOX_LINE.fullmatch(line)
        if matched is None:
            raise OwnershipError('Provision did not publish three inboxes')
        member_id, pin, run_id, mailbox, revision, endpoint = matched.groups()
        relay = relays_by_key.get(pin)
        if int(member_id) != member.member_id or _public_int(revision) != 1 or relay is None:
            raise OwnershipError('Provision did not publish three inboxes')
        if relay.run_id != run_id or relay.endpoint != endpoint or pin in pins:
            raise OwnershipError('Provision did not match the pinned relays')
        pins.add(pin)
        found.append({
            'member': member.member_id,
            'pin': pin,
            'run': run_id,
            'mailbox': mailbox,
            'append_revision': 1,
            'endpoint': endpoint,
        })
    if pins != set(relays_by_key):
        raise OwnershipError('Provision did not match the pinned relays')
    return found


def _parse_couriers(lines, vault, owner_id):
    if len(lines) != 2:
        raise OwnershipError('Export did not publish two peer descriptors')
    found = []
    peers = set()
    for line in lines:
        matched = _COURIER_LINE.fullmatch(line)
        if matched is None:
            raise OwnershipError('Export did not publish two peer descriptors')
        file_vault, owner, peer, revision = matched.groups()
        peer_id = int(peer)
        if file_vault != vault or int(owner) != owner_id or peer_id == owner_id or peer_id in peers:
            raise OwnershipError('Export did not publish two peer descriptors')
        peers.add(peer_id)
        found.append((
            f'{file_vault}-relay-config-{owner}-{peer}-{revision}.bin',
            owner_id, peer_id, _public_int(revision)))
    if peers != {1, 2, 3} - {owner_id}:
        raise OwnershipError('Export did not publish two peer descriptors')
    return found


def _parse_import(lines, courier):
    if len(lines) != 1:
        raise OwnershipError('Import did not return the recipient result')
    matched = _IMPORT_LINE.fullmatch(lines[0])
    if matched is None:
        raise OwnershipError('Import did not return the recipient result')
    owner, revision, digest = matched.groups()
    if int(owner) != courier.owner or _public_int(revision) != courier.revision:
        raise OwnershipError('Import did not return the recipient result')
    return digest


def _fingerprint_text(text):
    if not text.endswith('\n') or text[:-1].find('\n') != -1:
        raise OwnershipError('Roster fingerprint is not public hex')
    if _HEX64.fullmatch(text[:-1]) is None:
        raise OwnershipError('Roster fingerprint is not public hex')
    return text[:-1]


def _public_manifest(path, endpoint):
    try:
        info = path.lstat()
    except OSError as error:
        raise OwnershipError('Relay manifest is not the public line format') from error
    if not stat.S_ISREG(info.st_mode) or info.st_size > 8192:
        raise OwnershipError('Relay manifest is not the public line format')
    data = path.read_bytes()
    if data.count(b'\n') != 3 or not data.endswith(b'\n') or b'\0' in data or b'\r' in data:
        raise OwnershipError('Relay manifest is not the public line format')
    lines = data[:-1].split(b'\n')
    if len(lines) != 3 or any(
            line == b'' or any(byte < 33 or byte > 126 for byte in line) for line in lines):
        raise OwnershipError('Relay manifest is not the public line format')
    try:
        text = [line.decode('ascii') for line in lines]
    except UnicodeError as error:
        raise OwnershipError('Relay manifest is not the public line format') from error
    if text[0] != endpoint or _HEX64.fullmatch(text[1]) is None or _HEX64.fullmatch(text[2]) is None:
        raise OwnershipError('Relay manifest is not the public line format')
    return data, text[1], text[2]


def _release_single_link(directory, name):
    """Drop the publisher's hidden extra hard link without reading descriptor bytes.

    Recipient import accepts a private file with one link. The export command
    leaves a same-inode temporary name beside the public courier basename.
    """
    path = directory / name
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise OwnershipError('Courier file is not a regular descriptor')
    prefix = f'.{name}.'
    for child in directory.iterdir():
        if child.name == name:
            continue
        child_info = child.lstat()
        same = child_info.st_dev == info.st_dev and child_info.st_ino == info.st_ino
        if not same:
            continue
        temporary = child.name.startswith(prefix) and _TEMP_LINK.search(child.name) is not None
        if not temporary or not stat.S_ISREG(child_info.st_mode):
            raise OwnershipError('Courier directory has an unexpected file')
        child.unlink()
    if path.lstat().st_nlink != 1:
        raise OwnershipError('Courier file is not a regular descriptor')


def _wait_listen(child, listen, deadline):
    host, port = listen.rsplit(':', 1)
    while True:
        if child.poll() is not None:
            raise OwnershipError('Relay serve exited before accepting')
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise OwnershipError('Relay serve did not accept before the deadline')
        try:
            stream = socket.create_connection((host, int(port)), min(0.2, remaining))
        except OSError:
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
            continue
        stream.close()
        return


def _listen(endpoint):
    if not endpoint.startswith('http://127.0.0.1:'):
        raise OwnershipError('Relay endpoint is not a selected loopback URL')
    return endpoint.removeprefix('http://')


def _public_int(text):
    if _PUBLIC_INT.fullmatch(text) is None:
        raise OwnershipError('Owned command returned an invalid status')
    value = int(text)
    if value > _I64_MAX:
        raise OwnershipError('Owned command returned an invalid status')
    return value


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if not math.isfinite(remaining) or remaining <= 0:
        raise OwnershipError('Owned command exceeded its deadline')
    return remaining


def _rmdir(path, message):
    try:
        path.rmdir()
    except OSError as error:
        raise OwnershipError(message) from error


def _mkdir(path):
    if path.is_symlink():
        raise OwnershipError('Run root has a symlink component')
    path.mkdir(mode=0o700, exist_ok=True)
    if path.is_symlink() or not path.is_dir():
        raise OwnershipError('Run root has a symlink component')
    os.chmod(path, 0o700)


def _expect_names(path, names):
    if sorted(child.name for child in path.iterdir()) != list(names):
        raise OwnershipError('Selected directory does not have the expected public names')


def _write_new(path, data, mode):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, mode)


# Status for two messages, every recipient object, and remote retrieval lines
# can exceed the setup capture default. The helper maximum still rejects overflow.
_ACCEPTANCE_DEADLINE = 300.0
_ACCEPTANCE_OUTPUT_LIMIT = 65536
_ACCEPTANCE_ATTEMPTS = 12
_ORDINARY_PAYLOAD_BYTES = 64
_CHUNKED_PAYLOAD_BYTES = 65537
_ALICE = 1
_BOB = 2
_CAROL = 3
_WIRE_MULTIPLE = 1024
_WIRE_MAX = 65536
_CHUNK_MAX = 274
_OBJECT_MAX = _CHUNK_MAX + 1
_AUDIENCE = 3

_MESSAGE_LINE = re.compile(
    r'message sender=([123]) id=([0-9a-f]{64}) digest=([0-9a-f]{64}) kind=([a-z0-9]+) '
    r'session=(-|[0-9a-f]{64}) readiness=(ready|pending) stored_whole=(unavailable|[01]) '
    r'received_whole=([01]) received_author=([01]) needs_route=([0-9]+)\Z')
_RECEIVED_MEMBER_LINE = re.compile(r'received_member id=([123]) value=([01])\Z')
_STORED_MEMBER_LINE = re.compile(r'stored_member id=([123]) value=([01])\Z')
_STORED_PIN_LINE = re.compile(
    r'stored_pin scope=(member|whole) member=([123]|-) pin=([0-9a-f]{64}) run=([0-9a-f]{64})\Z')
_RECIPIENT_LINE = re.compile(r'recipient id=([123]) root=([0-9a-f]{64}) needs_route=([01])\Z')
_OBJECT_LINE = re.compile(
    r'object recipient=([123]) ordinal=([0-9]+) hash=([0-9a-f]{64}) length=([0-9]+)\Z')
_UPLOAD_LINE = re.compile(
    r'upload recipient=([123]) hash=([0-9a-f]{64}) pin=([0-9a-f]{64}) run=([0-9a-f]{64}) '
    r'acknowledged=([01]) receipt_digest=(-|[0-9a-f]{64})\Z')
_INCOMING_LINE = re.compile(
    r'incoming sender=([123]) id=([0-9a-f]{64}) digest=([0-9a-f]{64}) kind=([a-z0-9]+) '
    r'session=(-|[0-9a-f]{64}) readiness=(ready|pending) received_whole=([01]) '
    r'received_author=([01]) root=([0-9a-f]{64})\Z')
_INCOMING_MEMBER_LINE = re.compile(
    r'incoming_received_member sender=([123]) id=([0-9a-f]{64}) digest=([0-9a-f]{64}) '
    r'member=([123]) value=([01])\Z')
_ACK_LINE = re.compile(
    r'ack sender=([123]) id=([0-9a-f]{64}) digest=([0-9a-f]{64}) author=([123]) '
    r'ack_message=([0-9a-f]{64}) request=([0-9a-f]{64})\Z')
_ENTRY_LINE = re.compile(
    r'entry pin=([0-9a-f]{64}) run=([0-9a-f]{64}) mailbox=([0-9a-f]{64}) sequence=([0-9]+) '
    r'hash=([0-9a-f]{64}) length=([0-9]+) receipt_digest=([0-9a-f]{64}) '
    r'retrieved_hash=([0-9a-f]{64}) retrieved_length=([0-9]+)\Z')
_REMOTE_INBOX_LINE = re.compile(
    r'remote_inbox member=([123]) pin=([0-9a-f]{64}) run=([0-9a-f]{64}) mailbox=([0-9a-f]{64}) '
    r'entries=([0-9]+) failures=([0-9]+) result=(ok|partial)\Z')
_SEND_ID_LINE = re.compile(r'request_id=([0-9a-f]{64})\Z')
_SEND_LINE = re.compile(
    r'request message=([0-9a-f]{64}) digest=([0-9a-f]{64}) needs_route=([0-9]+)\Z')
_UPLOAD_PROGRESS_LINE = re.compile(
    r'upload message=([0-9a-f]{64}) digest=([0-9a-f]{64}) needs_route=(-|[123](?:,[123])*) '
    r'stopped_third=([01])\Z')
_COUNT_LINE = re.compile(r'([0-9]+)\Z')
_ROUTE_ERROR_LINE = re.compile(
    r'route_error pin=([0-9a-f]{64}) run=([0-9a-f]{64}) mailbox=([0-9a-f]{64}) '
    r'result=error code=([a-z][a-z0-9_]*)\Z')
_SCENARIO_NAME = re.compile(r'[a-z][a-z0-9_]{0,40}\Z')
_DIAG_REASON = re.compile(r'[a-z][a-z0-9_]{0,63}\Z')
_ZERO_INT = re.compile(r'0|[1-9][0-9]*\Z')


class _StatusCursor:
    def __init__(self, lines):
        self.lines = lines
        self.index = 0

    def next(self):
        if self.index >= len(self.lines):
            raise OwnershipError('Owned command returned an invalid status')
        line = self.lines[self.index]
        self.index += 1
        return line

    def peek(self):
        if self.index >= len(self.lines):
            return None
        return self.lines[self.index]


class AcceptanceResult:
    """Public acceptance evidence plus the retained setup context.

    Passphrase paths remain on the context. ``public_report`` omits them.
    """

    def __init__(self, context, report):
        self.context = context
        self.report = report

    def public_report(self):
        return self.report


def run_acceptance(root, ports, *, communication_workspace, poc_workspace, timeout,
                   target_dir=None, profile='debug'):
    """Run the offline whole-vault scenario and retain the root.

    Ordinary return and failure both stop owned handles and leave the directory
    in place. Only ``delete_retained_run`` removes a stopped owned root.
    """
    if not math.isfinite(timeout) or timeout <= 0:
        raise OwnershipError('Acceptance deadline must be finite and positive')
    target_dir = _ambient_target_dir(target_dir)
    deadline = time.monotonic() + timeout
    phase = {'name': 'setup'}
    context = prepare_certified_setup(
        root, ports, communication_workspace=communication_workspace,
        poc_workspace=poc_workspace, timeout=_remaining(deadline), target_dir=target_dir,
        profile=profile)
    try:
        report = _acceptance_report(context, communication_workspace, poc_workspace, deadline,
                                    target_dir, profile, phase)
    except BaseException as original:
        _write_acceptance_failure(context.owner.root, phase['name'], original)
        _retain_owned(context.owner, original)
        raise
    _retain_owned(context.owner, None)
    _write_new(context.owner.root / 'acceptance-report.json',
               _json_bytes(report), 0o644)
    return AcceptanceResult(context, report)


def delete_retained_run(root, expected_run_id):
    """Delete one explicitly selected stopped run after its owner is gone."""
    owner = OwnedRun.reopen(root, expected_run_id=expected_run_id)
    owner.delete(expected_run_id=expected_run_id)


def _retain_owned(owner, original):
    try:
        owner.close()
    except (OSError, subprocess.TimeoutExpired, OwnershipError) as error:
        if original is None:
            raise OwnershipError(
                'Owned child shutdown did not complete before deadline') from error
        raise OwnershipError(
            'Owned child shutdown did not complete before deadline') from original


def _acceptance_report(context, communication_workspace, poc_workspace, deadline, target_dir,
                       profile, phase):
    server = find_binary('loki-relay-server', workspace=communication_workspace,
                         target_dir=target_dir, profile=profile)
    member_bin = find_binary('loki_relay_member', workspace=poc_workspace,
                             target_dir=target_dir, profile=profile)
    members = context.members
    if [member.member_id for member in members] != [_ALICE, _BOB, _CAROL]:
        raise OwnershipError('Certified roster is not the three-member audience')
    alice, bob, carol = members
    phase['name'] = 'publish'
    originals, pair = _publish_messages(context, member_bin, alice, deadline)
    phase['name'] = 'recipients'
    acknowledgements = _receive_offline(
        context, member_bin, (bob, carol), originals, pair, deadline)
    phase['name'] = 'reconcile'
    alice_status = _reconcile_author(
        context, member_bin, alice, originals, acknowledgements, deadline)
    phase['name'] = 'remote_before'
    before = _remote_snapshot(
        context, member_bin, members, originals, acknowledgements, pair, deadline)
    phase['name'] = 'restart'
    _restart_relays(context, server, deadline)
    phase['name'] = 'remote_after'
    after = _remote_snapshot(
        context, member_bin, members, originals, acknowledgements, pair, deadline)
    _compare_remote(before, after)
    phase['name'] = 'report'
    return _public_acceptance(
        context, originals, acknowledgements, pair, alice_status, before, after)


def _publish_messages(context, member_bin, alice, deadline):
    payload_dir = context.owner.root / 'payloads'
    _mkdir(payload_dir)
    sent = []
    for name, size in (('ordinary', _ORDINARY_PAYLOAD_BYTES),
                       ('chunked', _CHUNKED_PAYLOAD_BYTES)):
        blob = bytearray(secrets.token_bytes(size))
        path = payload_dir / name
        try:
            _write_new(path, blob, 0o600)
        finally:
            blob[:] = b'\x00' * len(blob)
        request_id = secrets.token_hex(32)
        text = _member_text(context, member_bin, alice, deadline, 'send', [
            '--payload-file', str(path), '--request-id', request_id,
        ])
        message_id, digest = _parse_send(text, request_id)
        sent.append({
            'name': name,
            'request_id': request_id,
            'payload_length': size,
            'id': message_id,
            'digest': digest,
        })
    if len({item['id'] for item in sent}) != len(sent):
        raise OwnershipError('Owned command returned an invalid status')
    for _ in range(_ACCEPTANCE_ATTEMPTS):
        _parse_upload_progress(_member_text(
            context, member_bin, alice, deadline, 'upload', [], allow_empty=True))
        status = _member_status(context, member_bin, alice, deadline, verify=False)
        if _originals_stored(status, sent):
            originals = _bind_originals(status, sent)
            pair = _shared_pair(context, originals)
            return originals, pair
    raise OwnershipError('Acceptance observation was not reached before the attempt bound')


def _receive_offline(context, member_bin, recipients, originals, pair, deadline):
    """Poll and upload from each recipient root while the author stays idle.

    Acknowledgement links stay on the member who created them. This captures
    those rows and does not copy them onto Alice.
    """
    captured = []
    for member in recipients:
        if member.member_id == _ALICE:
            raise OwnershipError('Author process is not offline')
        found = None
        for _ in range(_ACCEPTANCE_ATTEMPTS):
            text = _member_text(context, member_bin, member, deadline, 'poll', ['--once'])
            if text != 'poll=ok\n':
                raise OwnershipError('Owned command returned an invalid status')
            status = _member_status(context, member_bin, member, deadline, verify=False)
            if not _incoming_bound(status, originals):
                continue
            _parse_upload_progress(_member_text(
                context, member_bin, member, deadline, 'upload', [], allow_empty=True))
            status = _member_status(context, member_bin, member, deadline, verify=False)
            found = _received_stored(status, member.member_id, originals, pair)
            if _incoming_bound(status, originals) and found is not None:
                break
            found = None
        if found is None:
            raise OwnershipError(
                'Acceptance observation was not reached before the attempt bound')
        captured.extend(found)
    return captured


def _reconcile_author(context, member_bin, alice, originals, acknowledgements, deadline):
    for _ in range(_ACCEPTANCE_ATTEMPTS):
        text = _member_text(context, member_bin, alice, deadline, 'poll', ['--once'])
        if text != 'poll=ok\n':
            raise OwnershipError('Owned command returned an invalid status')
        status = _member_status(context, member_bin, alice, deadline, verify=False)
        if _author_reconciled(status, originals, acknowledgements):
            return status
    raise OwnershipError('Acceptance observation was not reached before the attempt bound')


def _remote_snapshot(context, member_bin, members, originals, acknowledgements, pair, deadline):
    snapshot = {}
    for member in members:
        status = _member_status(context, member_bin, member, deadline, verify=True)
        _require_remote_retrieval(status, member.member_id)
        _require_replica_ciphertext(
            status, originals, acknowledgements, pair, member.member_id)
        snapshot[member.member_id] = status
    _require_distinct_ciphertext(snapshot)
    return snapshot


def _restart_relays(context, server, deadline):
    owner = context.owner
    for relay in context.relays:
        if not any(relay.child is child for child in owner._children):
            raise OwnershipError('Process handle is not owned by this controller')
        owner.stop(relay.child, timeout=min(2.0, _remaining(deadline)))
        if relay.child.poll() is None:
            raise OwnershipError('Owned processes must be stopped before the run is retained')
    for relay in context.relays:
        relay.child = owner.start([
            str(server), 'serve', '--root', str(relay.root), '--listen', _listen(relay.endpoint),
        ], cwd=relay.root)
        _wait_listen(relay.child, _listen(relay.endpoint), deadline)


def _compare_remote(before, after):
    for member_id in (_ALICE, _BOB, _CAROL):
        if _remote_signature(before[member_id]) != _remote_signature(after[member_id]):
            raise OwnershipError('Remote relay evidence changed across the owned restart')
        if not _remote_signature(before[member_id])[0]:
            raise OwnershipError('Remote relay evidence was not an exact retrieval')


def _member_text(context, binary, member, deadline, command, extra, allow_empty=False):
    argv = [str(binary), command, '--member-root', str(member.root), '--passphrase-file',
            str(member.passphrase_file), '--roster', str(context.roster), *extra]
    _reject_foreign(argv, _foreign(member, context.members, context.relays))
    result = context.owner.capture(
        argv, cwd=member.root, timeout=_remaining(deadline),
        output_limit=_ACCEPTANCE_OUTPUT_LIMIT)
    if result.returncode != 0:
        raise OwnershipError('Owned command exited unsuccessfully')
    if b'\0' in result.stdout or b'\r' in result.stdout:
        raise OwnershipError('Owned command returned an invalid status')
    try:
        text = result.stdout.decode('ascii')
    except UnicodeError as error:
        raise OwnershipError('Owned command returned an invalid status') from error
    if text == '':
        if allow_empty:
            return ''
        raise OwnershipError('Owned command returned an invalid status')
    if not text.endswith('\n') or '\n\n' in text:
        raise OwnershipError('Owned command returned an invalid status')
    return text


def _member_status(context, binary, member, deadline, *, verify):
    extra = ['--verify-relays'] if verify else []
    parsed = _parse_status(_member_text(
        context, binary, member, deadline, 'status', extra), member.member_id, verify)
    expected = {
        (item['pin'], item['run'], item['mailbox'], item['endpoint'], item['append_revision'])
        for item in context.inboxes if item['member'] == member.member_id}
    found = {
        (item['pin'], item['run'], item['mailbox'], item['endpoint'], item['append_revision'])
        for item in parsed['inboxes']}
    if found != expected:
        raise OwnershipError('Owned command returned an invalid status')
    return parsed


def _originals_stored(status, sent):
    by_id = {item['id']: item for item in sent}
    if len(by_id) != len(sent):
        return False
    found = [message for message in status['messages'] if message['id'] in by_id]
    if len(found) != len(sent) or len(status['messages']) != len(sent):
        return False
    for message in found:
        sent_item = by_id[message['id']]
        if message['sender'] != _ALICE or message['digest'] != sent_item['digest']:
            return False
        if message['kind'] != 'test' or message['readiness'] != 'ready':
            return False
        if message['stored_whole'] != '1' or message['needs_route'] != 0:
            return False
        if set(message['stored_members']) != {_ALICE, _BOB, _CAROL}:
            return False
        if any(value != 1 for value in message['stored_members'].values()):
            return False
        if set(message['recipients']) != {_ALICE, _BOB, _CAROL}:
            return False
    return True


def _bind_originals(status, sent):
    by_id = {message['id']: message for message in status['messages']}
    originals = []
    for item in sent:
        message = by_id[item['id']]
        objects = {recipient: [] for recipient in (_ALICE, _BOB, _CAROL)}
        for obj in message['objects']:
            objects[obj['recipient']].append(obj)
        if any(not rows for rows in objects.values()):
            raise OwnershipError('Chunked transfer is missing a signed object')
        originals.append({
            'name': item['name'],
            'request_id': item['request_id'],
            'payload_length': item['payload_length'],
            'sender': message['sender'],
            'id': message['id'],
            'digest': message['digest'],
            'session': message['session'],
            'kind': message['kind'],
            'readiness': message['readiness'],
            'objects': objects,
            'recipients': {
                recipient: {'root': info['root'], 'needs_route': info['needs_route']}
                for recipient, info in message['recipients'].items()},
            'uploads': message['uploads'],
            'whole_pins': list(message['whole_pins']),
            'member_pins': {key: list(value) for key, value in message['member_pins'].items()},
        })
    ordinary = next(item for item in originals if item['payload_length'] == _ORDINARY_PAYLOAD_BYTES)
    chunked = next(item for item in originals if item['payload_length'] == _CHUNKED_PAYLOAD_BYTES)
    if ordinary['payload_length'] >= _CHUNKED_PAYLOAD_BYTES:
        raise OwnershipError('Chunked transfer is missing a signed object')
    for recipient in (_ALICE, _BOB, _CAROL):
        if not len(chunked['objects'][recipient]) > len(ordinary['objects'][recipient]):
            raise OwnershipError('Chunked transfer is missing a signed object')
    return originals


def _bind_single_original(context, status, sent):
    """Bind one stored ordinary message and its saved receipts.

    Acceptance binding still requires a name plus both the ordinary and
    chunked messages. One fault message has neither, and still needs three
    recipient copies on one shared pair with an acknowledged receipt digest
    for every object.
    """
    if sent['payload_length'] != _ORDINARY_PAYLOAD_BYTES:
        raise OwnershipError('Chunked transfer is missing a signed object')
    message = _only_message(status, sent['id'])
    if _one_stored(message, sent) is False:
        raise OwnershipError('Chunked transfer is missing a signed object')
    objects = {recipient: [] for recipient in (_ALICE, _BOB, _CAROL)}
    for obj in message['objects']:
        if obj['recipient'] not in objects:
            raise OwnershipError('Chunked transfer is missing a signed object')
        objects[obj['recipient']].append(obj)
    if any(not rows for rows in objects.values()):
        raise OwnershipError('Chunked transfer is missing a signed object')
    if set(message['recipients']) != {_ALICE, _BOB, _CAROL}:
        raise OwnershipError('Chunked transfer is missing a signed object')
    original = {
        'request_id': sent['request_id'],
        'payload_length': sent['payload_length'],
        'sender': message['sender'],
        'id': message['id'],
        'digest': message['digest'],
        'session': message['session'],
        'kind': message['kind'],
        'readiness': message['readiness'],
        'objects': objects,
        'recipients': {
            recipient: {'root': info['root'], 'needs_route': info['needs_route']}
            for recipient, info in message['recipients'].items()},
        'uploads': message['uploads'],
        'whole_pins': list(message['whole_pins']),
        'member_pins': {key: list(value) for key, value in message['member_pins'].items()},
    }
    return original, _shared_pair(context, (original,))


def _shared_pair(context, originals):
    """Require one relay pair on every object, chunk, root, and author copy."""
    whole = None
    for original in originals:
        if original['kind'] != 'test' or original['readiness'] != 'ready':
            raise OwnershipError('Owned command returned an invalid status')
        pins = {(item['pin'], item['run']) for item in original['whole_pins']}
        if _pins_are_pair(pins) is False:
            raise OwnershipError('Whole-vault replicas are not one shared pair')
        if whole is None:
            whole = pins
        elif pins != whole:
            raise OwnershipError('Whole-vault replicas are not one shared pair')
        if _copies_on_pair(original, whole) is None:
            raise OwnershipError('Whole-vault replicas are not one shared pair')
    if whole is None:
        raise OwnershipError('Whole-vault replicas are not one shared pair')
    setup = {(relay.receipt_key, relay.run_id) for relay in context.relays}
    if not whole <= setup or len(setup) != 3:
        raise OwnershipError('Whole-vault replicas are not one shared pair')
    return whole


def _pins_are_pair(pins):
    return len(pins) == 2 and len({pin for pin, _run in pins}) == 2 and len({
        run for _pin, run in pins}) == 2


def _copies_on_pair(message, pair):
    """Return three recipient object lists stored on one exact pair.

    A complete transfer may contain one root object plus 274 chunks.
    """
    if {(item['pin'], item['run']) for item in message['whole_pins']} != pair:
        return None
    objects = {recipient: [] for recipient in (_ALICE, _BOB, _CAROL)}
    flat = message['objects']
    if isinstance(flat, dict):
        flat = [obj for recipient in (_ALICE, _BOB, _CAROL) for obj in flat.get(recipient, ())]
    for obj in flat:
        if obj['recipient'] not in objects:
            return None
        objects[obj['recipient']].append(obj)
    for recipient in (_ALICE, _BOB, _CAROL):
        member_pins = {(item['pin'], item['run'])
                       for item in message['member_pins'].get(recipient, ())}
        if member_pins != pair:
            return None
        rows = objects[recipient]
        ordinals = sorted(obj['ordinal'] for obj in rows)
        if not rows or ordinals != list(range(len(rows))):
            return None
        if not 1 <= len(rows) <= _OBJECT_MAX:
            return None
        root = message.get('recipients', {}).get(recipient, {}).get('root')
        last = next(obj for obj in rows if obj['ordinal'] == len(rows) - 1)
        if root is None or last['hash'] != root:
            return None
        for obj in rows:
            if obj['length'] % _WIRE_MULTIPLE or not _WIRE_MULTIPLE <= obj['length'] <= _WIRE_MAX:
                return None
            for pin, run in pair:
                digests = [
                    upload['receipt_digest'] for upload in message['uploads']
                    if upload['recipient'] == recipient and upload['hash'] == obj['hash']
                    and upload['pin'] == pin and upload['run'] == run and upload['acknowledged'] == 1]
                if len(digests) != 1 or _HEX64.fullmatch(digests[0]) is None:
                    return None
    return objects


def _incoming_bound(status, originals):
    for original in originals:
        rows = [row for row in status['incoming']
                if row['sender'] == original['sender'] and row['id'] == original['id']
                and row['digest'] == original['digest'] and row['session'] == original['session']
                and row['kind'] == 'test']
        if len(rows) != 1:
            return False
    return True


def _received_stored(status, member_id, originals, pair):
    """Bind this member's ack links to that member's stored Received outboxes."""
    if any(ack['author'] != member_id for ack in status['acks']):
        return None
    if len(status['acks']) != len(originals):
        return None
    received = [message for message in status['messages']
                if message['kind'] == 'received' and message['sender'] == member_id]
    if len(received) != len(originals):
        return None
    bound = []
    used = set()
    for original in originals:
        rows = [ack for ack in status['acks']
                if ack['sender'] == original['sender'] and ack['id'] == original['id']
                and ack['digest'] == original['digest'] and ack['author'] == member_id]
        if len(rows) != 1 or rows[0]['ack_message'] in used:
            return None
        ack = rows[0]
        matches = [message for message in received if message['id'] == ack['ack_message']]
        if len(matches) != 1 or matches[0]['stored_whole'] != '1' or matches[0]['needs_route'] != 0:
            return None
        copies = _copies_on_pair(matches[0], pair)
        if copies is None:
            return None
        used.add(ack['ack_message'])
        bound.append({
            'author': member_id,
            'ack_message': ack['ack_message'],
            'original_id': original['id'],
            'original_digest': original['digest'],
            'received_digest': matches[0]['digest'],
            'received_session': matches[0]['session'],
            'objects': copies,
            'uploads': list(matches[0]['uploads']),
        })
    if len(used) != len(originals):
        return None
    return bound


def _author_reconciled(status, originals, acknowledgements):
    """Reconcile Alice's existing logical rows with Bob and Carol's Received ids.

    Her self-copy does not insert an incoming test original or an ack link.
    """
    if status['logical_count'] != len(originals) or len(status['messages']) != len(originals):
        return False
    if status['acks'] or len(acknowledgements) != len(originals) * 2:
        return False
    if any(row['kind'] == 'test' for row in status['incoming']):
        return False
    if len(status['incoming']) != len(acknowledgements):
        return False
    by_id = {message['id']: message for message in status['messages']}
    if set(by_id) != {item['id'] for item in originals}:
        return False
    for original in originals:
        message = by_id[original['id']]
        if message['sender'] != _ALICE or message['kind'] != 'test':
            return False
        if message['digest'] != original['digest'] or message['session'] != original['session']:
            return False
        if message['readiness'] != 'ready':
            return False
        if message['received_whole'] != 1 or message['received_author'] != 1:
            return False
        members = message['received_members']
        if set(members) != {_ALICE, _BOB, _CAROL}:
            return False
        if members[_ALICE] != 0 or members[_BOB] != 1 or members[_CAROL] != 1:
            return False
    for ack in acknowledgements:
        rows = [row for row in status['incoming']
                if row['kind'] == 'received' and row['sender'] == ack['author']
                and row['id'] == ack['ack_message'] and row['digest'] == ack['received_digest']
                and row['session'] == ack['received_session']]
        if len(rows) != 1:
            return False
    return True


def _require_remote_retrieval(status, member_id):
    local = {(item['pin'], item['run'], item['mailbox']) for item in status['inboxes']}
    remote = {(item['pin'], item['run'], item['mailbox']) for item in status['remote_inboxes']}
    if local != remote or len(remote) != 3:
        raise OwnershipError('Remote relay evidence was not an exact retrieval')
    if any(item['member'] != member_id or item['failures'] != 0 or item['result'] != 'ok'
           for item in status['remote_inboxes']):
        raise OwnershipError('Remote relay evidence was not an exact retrieval')
    for item in status['remote_entries']:
        if item['retrieved_hash'] != item['hash'] or item['retrieved_length'] != item['length']:
            raise OwnershipError('Remote relay evidence was not an exact retrieval')
        if item['length'] % _WIRE_MULTIPLE or not _WIRE_MULTIPLE <= item['length'] <= _WIRE_MAX:
            raise OwnershipError('Remote relay evidence was not an exact retrieval')


def _require_replica_ciphertext(status, originals, acknowledgements, pair, member_id):
    """Match each relay object to the receipt saved when that upload was acknowledged.

    The same check runs before and after restart, so a new receipt that is merely
    stable across the restart does not replace the original digest.
    """
    expected = _saved_receipts(originals, acknowledgements, member_id, pair)
    lengths = []
    for pin, run in sorted(pair):
        inbox = next((item for item in status['remote_inboxes']
                      if item['pin'] == pin and item['run'] == run), None)
        if inbox is None:
            raise OwnershipError('Recipient ciphertext is not identical across relays')
        seen = {}
        for entry in status['remote_entries']:
            if (entry['pin'], entry['run'], entry['mailbox']) != (pin, run, inbox['mailbox']):
                continue
            item = (entry['length'], entry['receipt_digest'])
            if seen.get(entry['hash'], item) != item:
                raise OwnershipError('Recipient ciphertext is not identical across relays')
            if expected.get((pin, run, entry['hash'])) != item:
                raise OwnershipError('Remote relay evidence was not an exact retrieval')
            if entry['retrieved_hash'] != entry['hash'] or entry['retrieved_length'] != entry['length']:
                raise OwnershipError('Remote relay evidence was not an exact retrieval')
            seen[entry['hash']] = item
        relay_expected = {
            obj_hash: item for (entry_pin, entry_run, obj_hash), item in expected.items()
            if (entry_pin, entry_run) == (pin, run)}
        if seen != relay_expected:
            raise OwnershipError('Remote relay evidence was not an exact retrieval')
        lengths.append({obj_hash: length for obj_hash, (length, _digest) in seen.items()})
    if lengths[0] != lengths[1]:
        raise OwnershipError('Recipient ciphertext is not identical across relays')
    return lengths[0]


def _saved_receipts(originals, acknowledgements, member_id, pair):
    expected = {}

    def add(message):
        for obj in message['objects'][member_id]:
            for pin, run in pair:
                matched = [upload for upload in message['uploads']
                           if upload['recipient'] == member_id and upload['hash'] == obj['hash']
                           and upload['pin'] == pin and upload['run'] == run
                           and upload['acknowledged'] == 1]
                if len(matched) != 1 or _HEX64.fullmatch(matched[0]['receipt_digest']) is None:
                    raise OwnershipError('Remote relay evidence was not an exact retrieval')
                key = (pin, run, obj['hash'])
                item = (obj['length'], matched[0]['receipt_digest'])
                if expected.get(key, item) != item:
                    raise OwnershipError('Remote relay evidence was not an exact retrieval')
                expected[key] = item

    for original in originals:
        add(original)
    for ack in acknowledgements:
        add(ack)
    return expected


def _require_distinct_ciphertext(snapshot):
    seen = {}
    for member_id, status in snapshot.items():
        hashes = {entry['hash'] for entry in status['remote_entries']}
        for digest in hashes:
            if digest in seen and seen[digest] != member_id:
                raise OwnershipError('Recipient ciphertext is not distinct')
            seen[digest] = member_id
    if not seen:
        raise OwnershipError('Remote relay evidence was not an exact retrieval')


def _remote_signature(status):
    entries = tuple(sorted(
        (item['pin'], item['run'], item['mailbox'], item['sequence'], item['hash'],
         item['length'], item['receipt_digest'], item['retrieved_hash'], item['retrieved_length'])
        for item in status['remote_entries']))
    inboxes = tuple(sorted(
        (item['pin'], item['run'], item['mailbox'], item['entries'], item['failures'],
         item['result'])
        for item in status['remote_inboxes']))
    return entries, inboxes


def _public_acceptance(context, originals, acknowledgements, pair, alice_status, before, after):
    def view(snapshot):
        rows = []
        for member_id in (_ALICE, _BOB, _CAROL):
            status = snapshot[member_id]
            rows.append({
                'member': member_id,
                'entries': [{
                    'hash': item['hash'],
                    'length': item['length'],
                    'mailbox': item['mailbox'],
                    'pin': item['pin'],
                    'receipt_digest': item['receipt_digest'],
                    'retrieved_hash': item['retrieved_hash'],
                    'retrieved_length': item['retrieved_length'],
                    'run': item['run'],
                    'sequence': item['sequence'],
                } for item in status['remote_entries']],
                'inboxes': [{
                    'entries': item['entries'],
                    'failures': item['failures'],
                    'mailbox': item['mailbox'],
                    'pin': item['pin'],
                    'result': item['result'],
                    'run': item['run'],
                } for item in status['remote_inboxes']],
            })
        return rows

    alice_by_id = {message['id']: message for message in alice_status['messages']}
    messages = []
    for original in originals:
        author = alice_by_id[original['id']]
        objects = []
        for recipient in (_ALICE, _BOB, _CAROL):
            for obj in original['objects'][recipient]:
                objects.append({
                    'hash': obj['hash'],
                    'length': obj['length'],
                    'ordinal': obj['ordinal'],
                    'recipient': recipient,
                })
        messages.append({
            'digest': original['digest'],
            'id': original['id'],
            'kind': original['kind'],
            'objects': objects,
            'payload_length': original['payload_length'],
            'readiness': author['readiness'],
            'received_author': author['received_author'],
            'received_members': [{
                'member': member,
                'value': author['received_members'][member],
            } for member in (_ALICE, _BOB, _CAROL)],
            'received_whole': author['received_whole'],
            'request_id': original['request_id'],
            'sender': original['sender'],
            'session': original['session'],
        })
    acknowledgements = [{
        'ack_message': ack['ack_message'],
        'author': ack['author'],
        'objects': [{
            'hash': obj['hash'],
            'length': obj['length'],
            'ordinal': obj['ordinal'],
            'recipient': recipient,
        } for recipient in (_ALICE, _BOB, _CAROL) for obj in ack['objects'][recipient]],
        'original_digest': ack['original_digest'],
        'original_id': ack['original_id'],
        'received_digest': ack['received_digest'],
        'received_session': ack['received_session'],
    } for ack in acknowledgements]
    return {
        'acknowledgements': acknowledgements,
        'checks': [
            'same_pair',
            'complete_objects',
            'identical_ciphertext',
            'distinct_recipient_ciphertext',
            'offline_recipients',
            'self_copy',
            'both_acknowledgements',
            'remote_restart',
        ],
        'messages': messages,
        'pair': [{'pin': pin, 'run': run} for pin, run in sorted(pair)],
        'remote_after': view(after),
        'remote_before': view(before),
        'result': 'accepted',
        'self_effect': {
            'logical_count': alice_status['logical_count'],
            'logical_ids': [item['id'] for item in originals],
            'self_acknowledgements': len(alice_status['acks']),
        },
        'setup': context.public_report(),
    }


def _parse_send(text, request_id):
    lines = text[:-1].split('\n')
    if len(lines) != 2:
        raise OwnershipError('Owned command returned an invalid status')
    request = _SEND_ID_LINE.fullmatch(lines[0])
    body = _SEND_LINE.fullmatch(lines[1])
    if request is None or body is None or request.group(1) != request_id:
        raise OwnershipError('Owned command returned an invalid status')
    # Commit records all three recipients as needing a route. Upload binds later.
    if _bounded_int(body.group(3), 0, _AUDIENCE) != _AUDIENCE:
        raise OwnershipError('Member send did not commit every recipient')
    return body.group(1), body.group(2)


def _parse_upload_progress(text):
    if text == '':
        return []
    rows = []
    for line in text[:-1].split('\n'):
        matched = _UPLOAD_PROGRESS_LINE.fullmatch(line)
        if matched is None:
            raise OwnershipError('Owned command returned an invalid status')
        rows.append(matched.group(1))
    return rows


def _parse_status(text, member_id, verify, *, expected_route_failures=()):
    """Parse member status. An empty failure set still rejects every route error.

    Fault observations pass the pins that are expected to fail. Every other
    route must still parse as an exact retrieval.
    """
    expected = tuple(expected_route_failures)
    if any(_HEX64.fullmatch(pin) is None for pin in expected) or len(set(expected)) != len(expected):
        raise OwnershipError('Owned command returned an invalid status')
    if expected and not verify:
        raise OwnershipError('Owned command returned an invalid status')
    cursor = _StatusCursor(text[:-1].split('\n'))
    if cursor.next() != 'section=local' or cursor.next() != 'receipt_digest_alg=blake3':
        raise OwnershipError('Owned command returned an invalid status')
    if cursor.next() != f'member={member_id}':
        raise OwnershipError('Owned command returned an invalid status')
    config = _CONFIG_LINE.fullmatch(cursor.next())
    if config is None:
        raise OwnershipError('Owned command returned an invalid status')
    inboxes = []
    for _ in range(3):
        matched = _INBOX_LINE.fullmatch(cursor.next())
        if matched is None or int(matched.group(1)) != member_id:
            raise OwnershipError('Owned command returned an invalid status')
        inboxes.append({
            'member': member_id,
            'pin': matched.group(2),
            'run': matched.group(3),
            'mailbox': matched.group(4),
            'append_revision': _public_int(matched.group(5)),
            'endpoint': matched.group(6),
        })
    counts = {}
    for name in ('logical_count', 'incoming_count', 'ack_count', 'pending_transfers'):
        line = cursor.next()
        prefix = name + '='
        if not line.startswith(prefix) or _COUNT_LINE.fullmatch(line[len(prefix):]) is None:
            raise OwnershipError('Owned command returned an invalid status')
        counts[name] = _bounded_int(line[len(prefix):], 0, _I64_MAX)
    messages = []
    while cursor.peek() is not None and cursor.peek().startswith('message '):
        messages.append(_parse_message(cursor))
    incoming = []
    while cursor.peek() is not None and cursor.peek().startswith('incoming '):
        incoming.append(_parse_incoming(cursor))
    acks = []
    while cursor.peek() is not None and cursor.peek().startswith('ack '):
        acks.append(_parse_ack(cursor.next()))
    remote_entries = []
    remote_inboxes = []
    if verify:
        if cursor.next() != 'section=remote' or cursor.next() != 'receipt_digest_alg=blake3':
            raise OwnershipError('Owned command returned an invalid status')
        seen_failures = []
        pending = []
        while cursor.peek() is not None:
            line = cursor.next()
            if line.startswith('retrieval_error ') or (
                    line.startswith('route_error ') and not expected):
                raise OwnershipError('Remote relay evidence was not an exact retrieval')
            if line.startswith('route_error '):
                matched = _ROUTE_ERROR_LINE.fullmatch(line)
                if matched is None or pending or matched.group(1) not in expected:
                    raise OwnershipError('Remote relay evidence was not an exact retrieval')
                if any(item['pin'] == matched.group(1) for item in seen_failures):
                    raise OwnershipError('Remote relay evidence was not an exact retrieval')
                seen_failures.append({
                    'code': matched.group(4),
                    'mailbox': matched.group(3),
                    'pin': matched.group(1),
                    'run': matched.group(2),
                })
                continue
            entry = _ENTRY_LINE.fullmatch(line)
            if entry is not None:
                pending.append(_entry_record(entry))
                continue
            inbox = _REMOTE_INBOX_LINE.fullmatch(line)
            if inbox is None:
                raise OwnershipError('Owned command returned an invalid status')
            record = _remote_inbox_record(inbox)
            if record['member'] != member_id or len(pending) != record['entries']:
                raise OwnershipError('Remote relay evidence was not an exact retrieval')
            if any((item['pin'], item['run'], item['mailbox']) != (
                    record['pin'], record['run'], record['mailbox']) for item in pending):
                raise OwnershipError('Remote relay evidence was not an exact retrieval')
            if record['failures'] != 0 or record['result'] != 'ok':
                raise OwnershipError('Remote relay evidence was not an exact retrieval')
            remote_entries.extend(pending)
            remote_inboxes.append(record)
            pending = []
        if pending:
            raise OwnershipError('Owned command returned an invalid status')
        if expected and {item['pin'] for item in seen_failures} != set(expected):
            raise OwnershipError('Fault route did not fail closed')
        remote_pins = {item['pin'] for item in remote_inboxes}
        if expected and (remote_pins & set(expected) or remote_pins | set(expected) != {
                item['pin'] for item in inboxes}):
            raise OwnershipError('Remote relay evidence was not an exact retrieval')
    elif cursor.peek() is not None:
        raise OwnershipError('Owned command returned an invalid status')
    if counts['logical_count'] != len(messages) or counts['incoming_count'] != len(incoming):
        raise OwnershipError('Owned command returned an invalid status')
    if counts['ack_count'] != len(acks):
        raise OwnershipError('Owned command returned an invalid status')
    parsed = {
        'acks': acks,
        'config_hash': config.group(2),
        'config_revision': _public_int(config.group(1)),
        'inboxes': inboxes,
        'incoming': incoming,
        'messages': messages,
        'remote_entries': remote_entries,
        'remote_inboxes': remote_inboxes,
        **counts,
    }
    if expected:
        parsed['route_errors'] = seen_failures
    return parsed


def _parse_message(cursor):
    matched = _MESSAGE_LINE.fullmatch(cursor.next())
    if matched is None:
        raise OwnershipError('Owned command returned an invalid status')
    message = {
        'sender': int(matched.group(1)),
        'id': matched.group(2),
        'digest': matched.group(3),
        'kind': matched.group(4),
        'session': matched.group(5),
        'readiness': matched.group(6),
        'stored_whole': matched.group(7),
        'received_whole': int(matched.group(8)),
        'received_author': int(matched.group(9)),
        'needs_route': _bounded_int(matched.group(10), 0, _I64_MAX),
        'received_members': {},
        'stored_members': {},
        'whole_pins': [],
        'member_pins': {},
        'recipients': {},
        'objects': [],
        'uploads': [],
    }
    while cursor.peek() is not None and not cursor.peek().startswith((
            'message ', 'incoming ', 'ack ', 'section=')):
        line = cursor.next()
        if _attach_message_line(message, line) is False:
            raise OwnershipError('Owned command returned an invalid status')
    return message


def _attach_message_line(message, line):
    received = _RECEIVED_MEMBER_LINE.fullmatch(line)
    if received is not None:
        message['received_members'][int(received.group(1))] = int(received.group(2))
        return True
    stored = _STORED_MEMBER_LINE.fullmatch(line)
    if stored is not None:
        message['stored_members'][int(stored.group(1))] = int(stored.group(2))
        return True
    pin = _STORED_PIN_LINE.fullmatch(line)
    if pin is not None:
        item = {'pin': pin.group(3), 'run': pin.group(4)}
        if pin.group(1) == 'whole':
            if pin.group(2) != '-':
                return False
            message['whole_pins'].append(item)
            return True
        member = int(pin.group(2))
        message['member_pins'].setdefault(member, []).append(item)
        return True
    recipient = _RECIPIENT_LINE.fullmatch(line)
    if recipient is not None:
        message['recipients'][int(recipient.group(1))] = {
            'root': recipient.group(2),
            'needs_route': int(recipient.group(3)),
        }
        return True
    obj = _OBJECT_LINE.fullmatch(line)
    if obj is not None:
        message['objects'].append({
            'recipient': int(obj.group(1)),
            'ordinal': _bounded_int(obj.group(2), 0, _CHUNK_MAX),
            'hash': obj.group(3),
            'length': _bounded_int(obj.group(4), _WIRE_MULTIPLE, _WIRE_MAX),
        })
        return True
    upload = _UPLOAD_LINE.fullmatch(line)
    if upload is not None:
        message['uploads'].append({
            'recipient': int(upload.group(1)),
            'hash': upload.group(2),
            'pin': upload.group(3),
            'run': upload.group(4),
            'acknowledged': int(upload.group(5)),
            'receipt_digest': upload.group(6),
        })
        return True
    return False


def _parse_incoming(cursor):
    matched = _INCOMING_LINE.fullmatch(cursor.next())
    if matched is None:
        raise OwnershipError('Owned command returned an invalid status')
    record = {
        'sender': int(matched.group(1)),
        'id': matched.group(2),
        'digest': matched.group(3),
        'kind': matched.group(4),
        'session': matched.group(5),
        'readiness': matched.group(6),
        'received_whole': int(matched.group(7)),
        'received_author': int(matched.group(8)),
        'root': matched.group(9),
        'members': [],
    }
    for _ in range(3):
        member = _INCOMING_MEMBER_LINE.fullmatch(cursor.next())
        if member is None or int(member.group(1)) != record['sender'] or (
                member.group(2) != record['id'] or member.group(3) != record['digest']):
            raise OwnershipError('Owned command returned an invalid status')
        record['members'].append({
            'member': int(member.group(4)),
            'value': int(member.group(5)),
        })
    return record


def _parse_ack(line):
    matched = _ACK_LINE.fullmatch(line)
    if matched is None:
        raise OwnershipError('Owned command returned an invalid status')
    return {
        'sender': int(matched.group(1)),
        'id': matched.group(2),
        'digest': matched.group(3),
        'author': int(matched.group(4)),
        'ack_message': matched.group(5),
        'request': matched.group(6),
    }


def _entry_record(matched):
    length = _bounded_int(matched.group(6), 0, _I64_MAX)
    retrieved = _bounded_int(matched.group(9), 0, _I64_MAX)
    return {
        'pin': matched.group(1),
        'run': matched.group(2),
        'mailbox': matched.group(3),
        'sequence': _bounded_int(matched.group(4), 0, _I64_MAX),
        'hash': matched.group(5),
        'length': length,
        'receipt_digest': matched.group(7),
        'retrieved_hash': matched.group(8),
        'retrieved_length': retrieved,
    }


def _remote_inbox_record(matched):
    return {
        'member': int(matched.group(1)),
        'pin': matched.group(2),
        'run': matched.group(3),
        'mailbox': matched.group(4),
        'entries': _bounded_int(matched.group(5), 0, _I64_MAX),
        'failures': _bounded_int(matched.group(6), 0, _I64_MAX),
        'result': matched.group(7),
    }


def _bounded_int(text, low, high):
    if _COUNT_LINE.fullmatch(text) is None or (len(text) > 1 and text.startswith('0')):
        raise OwnershipError('Owned command returned an invalid status')
    value = int(text)
    if value > _I64_MAX or not low <= value <= high:
        raise OwnershipError('Owned command returned an invalid status')
    return value


def _json_bytes(payload):
    return json.dumps(payload, sort_keys=True).encode('ascii') + b'\n'


def _write_acceptance_failure(root, phase, error):
    detail = str(error) if isinstance(error, OwnershipError) else type(error).__name__
    path = root / 'acceptance-report.json'
    if path.exists():
        return
    try:
        _write_new(path, _json_bytes({
            'error': detail,
            'phase': phase,
            'result': 'failed',
        }), 0o644)
    except OSError:
        return


def _directory_lock_held(root):
    path = Path(root) / OwnedRun.LOCK
    flags = os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise OwnershipError('Retained run is incomplete') from error
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return True
        return False
    finally:
        os.close(descriptor)


def _nested_lifecycle_state(record):
    root = Path(record['root'])
    path = root / OwnedRun.LIFECYCLE
    try:
        info = path.lstat()
        text = path.read_text(encoding='ascii')
        marker = (root / OwnedRun.MARKER).read_bytes()
        root_info = root.lstat()
    except (OSError, UnicodeError) as error:
        raise OwnershipError('Retained run is incomplete') from error
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 8192:
        raise OwnershipError('Retained run is incomplete')
    try:
        loaded = json.loads(text)
        marker_loaded = json.loads(marker.decode('ascii'))
    except (UnicodeError, ValueError) as error:
        raise OwnershipError('Retained run is incomplete') from error
    if not isinstance(loaded, dict) or loaded.get('run_id') != record['run_id']:
        raise OwnershipError('Run ID does not match')
    if loaded.get('root') != str(root) or loaded.get('state') not in ('open', 'stopped'):
        raise OwnershipError('Retained run is incomplete')
    if (loaded.get('device'), loaded.get('inode')) != (record['dev'], record['ino']):
        raise OwnershipError('Selected run root was replaced')
    if (root_info.st_dev, root_info.st_ino) != (record['dev'], record['ino']):
        raise OwnershipError('Selected run root was replaced')
    if loaded.get('marker') != hashlib.sha256(marker).hexdigest():
        raise OwnershipError('Retained run is incomplete')
    if marker_loaded != {'run_id': record['run_id'], 'root': str(root)}:
        raise OwnershipError('Ownership marker does not match')
    return loaded['state']


_FAULT_DEADLINE = 1200.0
_QUOTA_MAILBOX_BYTES = 2048
_QUOTA_TOTAL_BYTES = 6144
_FAULT_SCENARIOS = (
    'outage', 'quota', 'retained_restart', 'missing_chunk', 'forged_inner_sender',
    'invalid_receipt', 'missing_download', 'append_rotation', 'offline_delivery',
    'crash_recovery', 'binding', 'ordering_conflict', 'provisioning_retry',
    'canonical_vectors', 'orphan_flood', 'sealed_config', 'capacity',
)
_SCENARIO_META = {
    'outage': ('owned_handle_stop', 'process_stop'),
    'quota': ('quota_init', 'authenticated_cli'),
    'retained_restart': ('owned_handle_stop', 'process_stop'),
    'append_rotation': ('rotate_append', 'authenticated_cli'),
}
_FIXTURE_EXPECTED = {'missing_chunk': 'Missing recipient copy/chunk/manifest — Whole-vault Stored is withheld without the same two complete replicas; incomplete transfers generate no Received', 'forged_inner_sender': 'Valid shared append credential, forged inner sender — Storage can succeed, but client authentication refuses the message', 'invalid_receipt': 'Forged/mismatched receipt; duplicate relay key URLs — Receipt refused or key counted once', 'missing_download': 'Malformed entries / temporarily missing object — Quarantine or durable pending task; later valid entries progress; restart retains outstanding retrieval work'}

# These are native test processes using the production library boundaries.
# Scripted peers and injected storage faults are identified in each report.
_TEST_FAULTS = {
    'missing_chunk': (
        ('client', 'inbox', 'staged_auth'),
        ('client', 'outbox', 'stored_pair'),
        ('client', 'transfer', 'transfer_complete_missing_restore'),
        ('client', 'received', 'incoming_crash_partial_and_quarantine'),
    ),
    'forged_inner_sender': (('client', 'relay_faults', 'forged_inner_sender'),),
    'invalid_receipt': (
        ('client', 'outbox', 'receipt_binding'),
        ('client', 'outbox', 'stored_pair'),
    ),
    'missing_download': (
        ('client', 'inbox', 'capture_atomic'),
        ('client', 'inbox', 'download_recovery'),
    ),
    'crash_recovery': (
        ('server', 'crash', 'relay_commit_fault'),
        ('client', 'outbox', 'outbox_crash'),
        ('client', 'received', 'incoming_crash'),
    ),
    'binding': (('client', 'crypto', 'hpke_binding'),
                ('client', 'crypto', 'inner_signature'),
                ('client', 'transfer', 'transfer_complete')),
    'ordering_conflict': (('client', 'received', 'received_reference'),
                         ('client', 'received', 'received_atomic_conflict'),
                         ('client', 'received', 'incoming_crash_reordered_relays')),
    'provisioning_retry': (('server', 'provisioning', 'rotation_monotonic'),
                           ('poc', 'relay_member', 'partial_rotation')),
    'canonical_vectors': (('protocol', 'canonical', 'canonical_subset'),
                           ('protocol', 'envelope', 'wire_boundary'),
                           ('client', 'crypto_vectors', 'selected_suite_vectors'),
                           ('client', 'transfer', 'transfer_complete_maximum274')),
    'orphan_flood': (('client', None,
                     'store::incoming_crash_tests::orphan_chunk_flood_budget_preserves_downloads_after_reopen'),),
    'sealed_config': (('poc', 'relay_member',
                      'communication_cli_missing_referenced_sealed_config_fails_closed'),),
    'capacity': (('server', 'store', 'capacity_preserves'),),
}
_SCENARIO_META.update({name: ('native_test_fixture', 'scripted_peer_and_library')
                       for name in _TEST_FAULTS})
_SCENARIO_META['offline_delivery'] = ('offline_member_processes', 'process_stop')

_TEST_EXPECTED = dict(_FIXTURE_EXPECTED)
_TEST_EXPECTED.update({
    'crash_recovery': 'Exact retry, relay/client commit boundaries, SIGKILL recovery and real SQLite FULL',
    'binding': 'Ciphertext, context, canonical, signed sender and complete transfer checks refuse invalid input',
    'ordering_conflict': 'Deduplication, early Received validation and encrypted conflict preservation after reopen',
    'provisioning_retry': 'Exact creation/rotation retry preserves current revisions and saved ciphertext',
    'canonical_vectors': 'Canonical rejection, selected-suite RFC vectors and exact envelope/chunk bounds',
    'orphan_flood': 'Orphan chunk flood reaches local admission limit without losing pending download or ciphertext',
    'sealed_config': 'Missing sealed configuration fails closed across member command restart',
    'capacity': 'Capacity preserves duplicate receipts, reads and accepted objects after reopen',
    'offline_delivery': 'Offline recipients authenticate their copies, author reconciles once, and Received returns without loops',
})


def _test_fault_evidence(owner, name, communication, poc, deadline, target_dir):
    cargo = shutil.which('cargo')
    if cargo is None:
        raise OwnershipError('Selected test runner is unavailable')
    checks = []
    for package, suite, selector in _TEST_FAULTS[name]:
        workspace = poc if package == 'poc' else communication
        # rustup selects Cargo from argv[0]; resolving its symlink changes that name.
        argv = [str(Path(cargo).absolute()), 'test', '--manifest-path',
                str(Path(workspace).resolve() / 'Cargo.toml'), '--locked', '--offline']
        if package == 'poc':
            argv.extend(['--features', 'relay-communication'])
        else:
            argv.extend(['-p', 'loki-relay-' + package])
        argv.extend(['--lib'] if suite is None else ['--test', suite])
        if target_dir is not None:
            argv.extend(['--target-dir', str(target_dir)])
        argv.extend([selector, '--', '--nocapture'])
        result = owner.capture(argv, cwd=workspace, timeout=_remaining(deadline),
                               output_limit=65536)
        # Only counts and test identifiers are public. Panic output may contain
        # fixture bodies and is deliberately excluded even on failure.
        summaries = re.findall(rb'test result: ok\. (\d+) passed; 0 failed;', result.stdout)
        names = re.findall(rb'^test ([A-Za-z0-9_:]+) \.\.\. ok$', result.stdout, re.MULTILINE)
        if (result.returncode != 0 or not summaries or int(summaries[-1]) == 0 or
                not any(selector in item.decode('ascii') for item in names)):
            raise OwnershipError('Native fault check failed or executed no cases')
        checks.append({'package': package, 'suite': suite, 'selector': selector,
                       'passed': int(summaries[-1]),
                       'tests': [item.decode('ascii') for item in names],
                       'output_digest': hashlib.sha256(result.stdout).hexdigest(),
                       'exit_code': result.returncode})
        observations = re.findall(rb'^fault-observation=(\{[^\n]+\})$', result.stdout, re.MULTILINE)
        if observations:
            observed = json.loads(observations[-1])
            public = {}
            for key in ('hash', 'relay_key', 'run'):
                value = observed.get(key)
                if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
                    raise OwnershipError('Native fault observation is invalid')
                public[key] = value
            for key in ('length', 'sequence', 'originals', 'acknowledgements'):
                value = observed.get(key)
                if type(value) is not int or not 0 <= value <= _I64_MAX:
                    raise OwnershipError('Native fault observation is invalid')
                public[key] = value
            if observed.get('rejection') != 'signature':
                raise OwnershipError('Native fault observation is invalid')
            public['rejection'] = 'signature'
            checks[-1]['observed'] = public
        flood = re.search(rb'^orphan-flood accepted=(\d+) pending=(\d+) cursor=(\d+) '
                          rb'refused_hash=([0-9a-f]{64})$', result.stdout, re.MULTILINE)
        if flood:
            checks[-1]['observed'] = {
                'accepted': int(flood.group(1)), 'pending_downloads': int(flood.group(2)),
                'cursor': int(flood.group(3)), 'refused_hash': flood.group(4).decode('ascii')}
    kind = ('process_kill_sqlite_full_and_scripted_peer' if name == 'crash_recovery'
            else 'scripted_peer_and_library')
    return {'expected': _TEST_EXPECTED[name], 'outcome': 'passed',
            'observation': {'checks': checks}, 'simulation': True,
            'injection': 'native_test_fixture', 'injection_kind': kind,
            'reason': None}


class FaultResult:
    """Sanitized fault campaign. Secret paths stay on the owned roots."""

    def __init__(self, report):
        self.report = report

    def public_report(self):
        return self.report


def run_faults(root, ports, *, communication_workspace, poc_workspace, timeout, scenarios=None,
               target_dir=None, profile='debug'):
    """Run selected fault scenarios and retain every root.

    Outcomes are passed, failed, or skipped only after this call performs the
    scenario. A source listing is not a result of this function until it runs.
    """
    if not math.isfinite(timeout) or timeout <= 0:
        raise OwnershipError('Acceptance deadline must be finite and positive')
    selected = _FAULT_SCENARIOS if scenarios is None else tuple(scenarios)
    if not selected or any(name not in _FAULT_SCENARIOS for name in selected):
        raise OwnershipError('harness_arguments')
    if len(set(selected)) != len(selected):
        raise OwnershipError('harness_arguments')
    target_dir = _ambient_target_dir(target_dir)
    parent = OwnedRun.create(root)
    reports = []
    phase = {'name': 'select'}
    try:
        _mkdir(parent.root / 'scenarios')
        deadline = time.monotonic() + timeout
        for name in selected:
            phase['name'] = name
            reports.append(_run_fault_scenario(
                parent, name, ports, min(deadline, time.monotonic() + 300), target_dir, profile, communication_workspace,
                poc_workspace))
        report = {
            'harness_run_id': parent.run_id,
            'inventory': _fault_inventory(reports),
            'limits': {
                'deadline_seconds': timeout,
                'output_limit': _ACCEPTANCE_OUTPUT_LIMIT,
                'power_loss': False,
            },
            'result': 'failed' if any(item['outcome'] == 'failed' for item in reports) else 'completed',
            'scenarios': reports,
        }
        _write_new(parent.root / 'fault-report.json', _json_bytes(report), 0o644)
    except BaseException as original:
        _write_fault_failure(parent.root, phase['name'], original, reports)
        _retain_owned(parent, original)
        raise
    _retain_owned(parent, None)
    return FaultResult(report)


def _run_fault_scenario(parent, name, ports, deadline, target_dir, profile, communication, poc):
    child = OwnedRun.create(parent.root / 'scenarios' / name)
    try:
        parent.bind_nested_run(scenario=name, child=child)
        if name in _TEST_FAULTS:
            try:
                evidence = _test_fault_evidence(child, name, communication, poc, deadline, target_dir)
            except OwnershipError as error:
                evidence = _failed_evidence(name, error)
                evidence['simulation'] = True
        else:
            try:
                mailbox = _QUOTA_MAILBOX_BYTES if name == 'quota' else 1048576
                total = _QUOTA_TOTAL_BYTES if name == 'quota' else 8388608
                context = prepare_certified_setup(
                    child.root, ports, communication_workspace=communication, poc_workspace=poc,
                    timeout=_remaining(deadline), target_dir=target_dir, profile=profile,
                    mailbox_bytes=mailbox, total_bytes=total, owner=child)
                server = find_binary('loki-relay-server', workspace=communication,
                                     target_dir=target_dir, profile=profile)
                member_bin = find_binary('loki_relay_member', workspace=poc, target_dir=target_dir,
                                         profile=profile)
                if name == 'offline_delivery':
                    observation = _acceptance_report(context, communication, poc, deadline,
                                                     target_dir, profile, {'name': 'setup'})
                    evidence = {'expected': _TEST_EXPECTED[name], 'outcome': 'passed',
                                'observation': observation, 'reason': None}
                else:
                    evidence = _FAULT_BODIES[name](context, server, member_bin, deadline)
            except OwnershipError as error:
                evidence = _failed_evidence(name, error)
        report = _scenario_report(child, name, evidence)
        if not (child.root / 'scenario-report.json').exists():
            _write_new(child.root / 'scenario-report.json', _json_bytes(report), 0o644)
        return report
    finally:
        child.close()


def _scenario_report(child, name, evidence):
    injection, kind = _SCENARIO_META[name]
    return {
        'expected': evidence['expected'],
        'injection': evidence.get('injection', injection),
        'injection_kind': evidence.get('injection_kind', kind),
        'needs_context': evidence.get('needs_context'),
        'observation': evidence.get('observation'),
        'outcome': evidence['outcome'],
        'power_loss': False,
        'reason': evidence.get('reason'),
        'scenario': name,
        'scenario_run_id': child.run_id,
        'simulation': evidence.get('simulation', False),
    }


def _failed_evidence(name, error):
    expected = _TEST_EXPECTED.get(name)
    if expected is None:
        expected = _IMPLEMENTED_EXPECTED[name]
    return {
        'expected': expected,
        'observation': None,
        'outcome': 'failed',
        'reason': str(error),
    }


def _write_fault_failure(root, phase, error, reports):
    path = root / 'fault-report.json'
    if path.exists():
        return
    detail = str(error) if isinstance(error, OwnershipError) else type(error).__name__
    try:
        _write_new(path, _json_bytes({
            'error': detail,
            'inventory': _fault_inventory(reports),
            'phase': phase,
            'result': 'failed',
            'scenarios': reports,
        }), 0o644)
    except OSError:
        return


_IMPLEMENTED_EXPECTED = {
    'outage': (
        'One honest relay unavailable — Two remaining instances can hold the complete set; an '
        'already complete set retains at least one acknowledged copy per object'),
    'quota': (
        'A new object stays unstored and unacknowledged while accepted objects, receipt '
        'digests, and a verify-relays read remain, and Received is not evicted'),
    'retained_restart': (
        'Committed objects, key, run, and receipt digests survive an owned relay restart on the '
        'same roots'),
    'append_rotation': (
        'Append rotation advances the authenticated append revision and leaves the stored hash, '
        'length, sequence, and receipt digest unchanged'),
}
_FAULT_CASES = (
    {'case_id': 'spec10-01', 'scenarios': ['offline_delivery'], 'observation': "Bob/Carol offline; Alice sends and stops — Both later retrieve and authenticate the same message through their own copies, without Alice's running process or secret directory"},
    {'case_id': 'spec10-02', 'scenarios': ['offline_delivery'], 'observation': 'Sender self-copy — Alice retrieves/reconciles her copy after intact-store restart without a second application effect or acknowledgement'},
    {'case_id': 'spec10-03', 'scenarios': ['offline_delivery', 'ordering_conflict'], 'observation': 'Received return path — Bob/Carol save before acknowledging; Alice retrieves their acknowledgements later; acknowledgement delivery creates no loop'},
    {'case_id': 'spec10-04', 'scenarios': ['crash_recovery'], 'observation': 'Lost PUT response and duplicated uploads — Original bytes, position and receipt returned; no extra entry or quota charge'},
    {'case_id': 'spec10-05', 'scenarios': ['retained_restart', 'crash_recovery'], 'observation': 'Relay restart / write failures — Committed objects/key/run/receipts survive; pre-commit failure yields no valid Stored receipt; uncertain outcomes recover through retry'},
    {'case_id': 'spec10-06', 'scenarios': ['crash_recovery', 'missing_download'], 'observation': 'Client crashes around outgoing/incoming/ack commits — No send before outbox commit; no Received before saved authenticated state; pending downloads and exact retries recover'},
    {'case_id': 'spec10-07', 'scenarios': ['outage'], 'observation': 'One honest relay unavailable — Two remaining instances can hold the complete set; an already complete set retains at least one acknowledged copy per object'},
    {'case_id': 'spec10-08', 'scenarios': ['missing_chunk'], 'observation': 'Missing recipient copy/chunk/manifest — Whole-vault Stored is withheld without the same two complete replicas; incomplete transfers generate no Received'},
    {'case_id': 'spec10-09', 'scenarios': ['binding'], 'observation': 'Altered ciphertext, wrong recipient/vault/roster/sender — Refusal or quarantine; no application effect or Received'},
    {'case_id': 'spec10-10', 'scenarios': ['forged_inner_sender'], 'observation': 'Valid shared append credential, forged inner sender — Storage can succeed, but client authentication refuses the message'},
    {'case_id': 'spec10-11', 'scenarios': ['ordering_conflict'], 'observation': 'Duplicate/reordered objects, early Received/prerequisite — One local logical effect; dependencies remain pending and reconcile without a global relay ordering assumption'},
    {'case_id': 'spec10-12', 'scenarios': ['ordering_conflict'], 'observation': 'Conflicting body under authenticated logical ID — Preserve conflict; no silent replacement or second effect'},
    {'case_id': 'spec10-13', 'scenarios': ['invalid_receipt'], 'observation': 'Forged/mismatched receipt; duplicate relay key URLs — Receipt refused or key counted once'},
    {'case_id': 'spec10-14', 'scenarios': ['quota', 'capacity'], 'observation': 'Capacity reached — Reject new objects, retain accepted ones, allow duplicate retry/read; no eviction after Received'},
    {'case_id': 'spec10-15', 'scenarios': ['missing_download'], 'observation': 'Malformed entries / temporarily missing object — Quarantine or durable pending task; later valid entries progress; restart retains outstanding retrieval work'},
    {'case_id': 'spec10-16', 'scenarios': ['provisioning_retry'], 'observation': 'Invalid provisioning revision / creation retry — Refuse conflicts/stale replacement; identical creation does not undo a later append-capability update'},
    {'case_id': 'spec10-17', 'scenarios': ['canonical_vectors', 'binding'], 'observation': 'Canonical encoding / HPKE vectors / boundaries — Refuse noncanonical/unknown versions and malformed lengths; selected suite vectors and exact 64 KiB/chunk boundaries pass'},
    {'case_id': 'plan-duplicate-download-order', 'scenarios': ['ordering_conflict'], 'observation': 'duplicate downloads through three relays in different orders'},
    {'case_id': 'plan-omitted-intermediate-sequence', 'scenarios': ['missing_download'], 'observation': 'response metadata omitting an intermediate sequence'},
    {'case_id': 'plan-sqlite-full', 'scenarios': ['crash_recovery'], 'observation': 'genuine SQLite-full fixture with reads after reopen'},
    {'case_id': 'plan-client-disk-full', 'scenarios': ['missing_download', 'crash_recovery'], 'observation': 'client disk-full during journal capture and during original+ack commit'},
    {'case_id': 'plan-orphan-chunk-flood', 'scenarios': ['orphan_flood'], 'observation': 'orphan chunk flood hitting local staging admission limit without task eviction'},
    {'case_id': 'plan-early-received-wrong-target', 'scenarios': ['ordering_conflict'], 'observation': 'valid Received before original, wrong target type/session/body digest, signer==original author'},
    {'case_id': 'plan-authenticated-conflict', 'scenarios': ['ordering_conflict'], 'observation': 'authenticated same-ID different-body preserving both encrypted sources'},
    {'case_id': 'plan-restart-after-receipt', 'scenarios': ['retained_restart'], 'observation': 'relay restart after receipt commit'},
    {'case_id': 'plan-missing-sealed-config', 'scenarios': ['sealed_config'], 'observation': 'client restart with missing sealed referenced config failing closed rather than sending on stale config'},
)


def _fault_inventory(reports):
    by_name = {item['scenario']: item for item in reports}
    rows = []
    for case in _FAULT_CASES:
        selected = [by_name[name] for name in case['scenarios'] if name in by_name]
        failed = [item for item in selected if item['outcome'] == 'failed']
        complete = len(selected) == len(case['scenarios'])
        outcome = ('failed' if failed else
                   'passed' if complete and all(item['outcome'] == 'passed' for item in selected)
                   else None)
        rows.append({'case_id': case['case_id'], 'observation': case['observation'],
                     'scenarios': case['scenarios'], 'outcome': outcome,
                     'disposition': 'executed' if complete else 'not_selected',
                     'simulation': any(item.get('simulation', False) for item in selected),
                     'reason': failed[0]['reason'] if failed else
                               None if outcome == 'passed' else 'Required scenario was not executed.'})
    return rows


def _authenticated_relay_order(context, member_bin, deadline):
    """Return owned relays in canonical receipt-key order.

    Member provision sorts targets by pin key before it builds each
    descriptor. The first two keys are the preferred upload pair. The
    greatest key is the relay StopAfterStored skips. context.relays is
    only the init and port handle list, used here as a pin lookup.
    """
    by_pin = {}
    for relay in context.relays:
        if relay.receipt_key in by_pin:
            raise OwnershipError('Relay identities are not distinct')
        by_pin[relay.receipt_key] = relay
    if len(by_pin) != 3:
        raise OwnershipError('Relay identities are not distinct')
    order = None
    for member in context.members:
        status = _member_status(context, member_bin, member, deadline, verify=False)
        printed = status['inboxes']
        recorded = [item for item in context.inboxes if item['member'] == member.member_id]
        if len(printed) != 3 or len(recorded) != 3:
            raise OwnershipError('Relay identities are not distinct')
        identity = [
            (item['pin'], item['run'], item['mailbox'], item['endpoint']) for item in printed]
        if identity != [
                (item['pin'], item['run'], item['mailbox'], item['endpoint']) for item in recorded]:
            raise OwnershipError('Relay identities are not distinct')
        pins = []
        for item in printed:
            relay = by_pin.get(item['pin'])
            if relay is None or relay.run_id != item['run'] or relay.endpoint != item['endpoint']:
                raise OwnershipError('Relay identities are not distinct')
            pins.append(item['pin'])
        if pins != sorted(pins):
            raise OwnershipError('Relay identities are not distinct')
        if order is None:
            order = pins
        elif pins != order:
            raise OwnershipError('Relay identities are not distinct')
    ordered = tuple(by_pin[pin] for pin in order)
    if len({relay.receipt_key for relay in ordered}) != 3 or [relay.receipt_key for relay in ordered] != sorted(order):
        raise OwnershipError('Relay identities are not distinct')
    return ordered


def _fault_outage(context, server, member_bin, deadline):
    del server
    ordered = _authenticated_relay_order(context, member_bin, deadline)
    preferred = ordered[:2]
    held_out = ordered[2]
    _stop_owned_relay(context, held_out, deadline)
    originals, pair = _publish_messages(
        context, member_bin, context.members[0], deadline)
    live = {pin for pin, _run in pair}
    preferred_pair = {(relay.receipt_key, relay.run_id) for relay in preferred}
    if held_out.receipt_key in live or pair != preferred_pair:
        raise OwnershipError('Whole-vault replicas are not one shared pair')
    before = _fault_member_views(
        context, member_bin, deadline, expected=(held_out.receipt_key,), diagnostics=True)
    for member_id, status in before.items():
        if [item['code'] for item in status['route_errors']] != ['transport']:
            raise OwnershipError('Fault route did not fail closed')
        if any(item['pin'] == held_out.receipt_key for item in status['remote_entries']):
            raise OwnershipError('Remote relay evidence was not an exact retrieval')
        _require_replica_ciphertext(status, originals, (), pair, member_id)
    alice = before[_ALICE]
    for message in alice['messages']:
        if message['kind'] == 'test' and _copies_on_pair(message, pair) is None:
            raise OwnershipError('Whole-vault replicas are not one shared pair')
    retained = next(relay for relay in preferred if relay.receipt_key == sorted(live)[1])
    stopped = next(relay for relay in preferred if relay.receipt_key == sorted(live)[0])
    acked_before = {
        member_id: _acked_retries(status['diagnostics'], {retained.receipt_key})
        for member_id, status in before.items()}
    retained_before = {
        member_id: _pin_entries(status, retained.receipt_key) for member_id, status in before.items()}
    if any(not rows for rows in retained_before.values()):
        raise OwnershipError('Remote relay evidence was not an exact retrieval')
    cursors_before = {
        member_id: _known_cursors(status['diagnostics'], context, member_id)
        for member_id, status in before.items()}
    _stop_owned_relay(context, stopped, deadline)
    during = _fault_member_views(
        context, member_bin, deadline,
        expected=(held_out.receipt_key, stopped.receipt_key), diagnostics=False)
    for member_id, status in during.items():
        if sorted(item['code'] for item in status['route_errors']) != ['transport', 'transport']:
            raise OwnershipError('Fault route did not fail closed')
        if _pin_entries(status, retained.receipt_key) != retained_before[member_id]:
            raise OwnershipError('Accepted ciphertext identity changed')
        if _local_receipts(status) != _local_receipts(before[member_id]):
            raise OwnershipError('Accepted ciphertext identity changed')
    bob = context.members[_BOB - 1]
    text = _member_text(context, member_bin, bob, deadline, 'poll', ['--once'])
    if text != 'poll=ok\n':
        raise OwnershipError('Owned command returned an invalid status')
    after = _member_fault_status(
        context, member_bin, bob, deadline, verify=True, diagnostics=True,
        expected_route_failures=(held_out.receipt_key, stopped.receipt_key))
    # poll_once publishes Received automatically, so new entries are expected.
    # Every original receipt and retrieved ciphertext must still be present.
    _require_retained_entries(retained_before[_BOB], _pin_entries(after, retained.receipt_key))
    _require_retained_entries(acked_before[_BOB],
                              _acked_retries(after['diagnostics'], {retained.receipt_key}))
    if not _incoming_bound(after, originals):
        raise OwnershipError('Remaining acknowledged replica did not authenticate both messages')
    after_cursors = _known_cursors(after['diagnostics'], context, _BOB)
    if _cursor_at(after_cursors, retained.receipt_key) < _cursor_at(cursors_before[_BOB], retained.receipt_key):
        raise OwnershipError('Remote relay evidence was not an exact retrieval')
    return _passed('outage', {
        'diagnostics_authority': 'transport',
        'held_out_pin': held_out.receipt_key,
        'pair': [{'pin': pin, 'run': run} for pin, run in sorted(pair)],
        'pending_download_count': after['diagnostics']['pending_download_count'],
        'poll': 'ok',
        'retained_entries': _public_pin_entries(after, retained.receipt_key),
        'retained_pin': retained.receipt_key,
        'route_error_codes': ['transport', 'transport'],
        'stopped_pin': stopped.receipt_key,
    })


def _fault_quota(context, server, member_bin, deadline):
    del server
    ordered = _authenticated_relay_order(context, member_bin, deadline)
    alice = context.members[0]
    bob = context.members[1]
    sent = _send_one(context, member_bin, alice, _ORDINARY_PAYLOAD_BYTES, deadline)
    shape = _member_status(context, member_bin, alice, deadline, verify=False)
    _require_quota_shape(shape, sent)
    stored = _upload_until(context, member_bin, alice, sent, deadline, require_stored=True)
    original, pair = _bind_single_original(context, stored, sent)
    preferred = {(relay.receipt_key, relay.run_id) for relay in ordered[:2]}
    if pair != preferred:
        raise OwnershipError('Whole-vault replicas are not one shared pair')
    acknowledgements = _receive_offline(
        context, member_bin, (bob,), (original,), pair, deadline)
    if len(acknowledgements) != 1 or acknowledgements[0]['author'] != _BOB:
        raise OwnershipError('Received objects were evicted')
    before = {
        member.member_id: _member_fault_status(
            context, member_bin, member, deadline, verify=True, diagnostics=True)
        for member in context.members}
    for member_id, status in before.items():
        _require_remote_retrieval(status, member_id)
        _require_replica_ciphertext(status, (original,), acknowledgements, pair, member_id)
    before_alice = before[_ALICE]
    before_bob = before[_BOB]
    second = _send_one(context, member_bin, alice, _ORDINARY_PAYLOAD_BYTES, deadline)
    _upload_until(context, member_bin, alice, second, deadline, require_stored=False, attempts=2)
    after = {
        member.member_id: _member_fault_status(
            context, member_bin, member, deadline, verify=True, diagnostics=True)
        for member in context.members}
    for member_id, status in after.items():
        _require_remote_retrieval(status, member_id)
        _require_replica_ciphertext(status, (original,), acknowledgements, pair, member_id)
    after_alice = after[_ALICE]
    after_bob = after[_BOB]
    _reject_quota_message(after_alice, second, pair)
    if _message_wire(before_alice, sent['id']) != _message_wire(after_alice, sent['id']):
        raise OwnershipError('Accepted ciphertext identity changed')
    if _remote_for_hashes(before_alice, _message_hashes(before_alice, sent['id'])) != (
            _remote_for_hashes(after_alice, _message_hashes(before_alice, sent['id']))):
        raise OwnershipError('Accepted ciphertext identity changed')
    if _message_wire(before_bob, acknowledgements[0]['ack_message']) != _message_wire(
            after_bob, acknowledgements[0]['ack_message']):
        raise OwnershipError('Received objects were evicted')
    if _received_stored(after_bob, _BOB, (original,), pair) is None:
        raise OwnershipError('Received objects were evicted')
    attempted, unattempted = _quota_upload_bindings(
        after_alice, second, pair, ordered[2], context)
    if after_alice['diagnostics']['sample_count'] != before_alice['diagnostics']['sample_count']:
        raise OwnershipError('Accepted ciphertext identity changed')
    return _passed('quota', {
        'accepted_entries': _public_entries(after_alice),
        'attempted_pair': attempted,
        'diagnostics_authority': 'transport',
        'duplicate_acknowledged_put': 'skipped',
        'pair': [{'pin': pin, 'run': run} for pin, run in sorted(pair)],
        'read': 'verify-relays',
        'received_message': acknowledgements[0]['ack_message'],
        'sample_count': after_alice['diagnostics']['sample_count'],
        'fallback_third': unattempted,
    }, needs_context=(
        'NEEDS_CONTEXT: upload_pending skips acknowledged rows, so member upload after Stored '
        'does not send a duplicate PUT. No allowed CLI forces that retry. Unchanged snapshots '
        'after a no-op upload are not that observation.'))


def _fault_retained_restart(context, server, member_bin, deadline):
    originals, pair = _publish_messages(context, member_bin, context.members[0], deadline)
    before = _remote_snapshot(
        context, member_bin, context.members, originals, (), pair, deadline)
    cursors = {}
    for member in context.members:
        status = _member_fault_status(
            context, member_bin, member, deadline, verify=False, diagnostics=True)
        cursors[member.member_id] = _known_cursors(status['diagnostics'], context, member.member_id)
    _restart_relays(context, server, deadline)
    after = _remote_snapshot(
        context, member_bin, context.members, originals, (), pair, deadline)
    _compare_remote(before, after)
    for member in context.members:
        status = _member_fault_status(
            context, member_bin, member, deadline, verify=False, diagnostics=True)
        if _known_cursors(status['diagnostics'], context, member.member_id) != cursors[member.member_id]:
            raise OwnershipError('Remote relay evidence changed across the owned restart')
    alice = after[_ALICE]
    return _passed('retained_restart', {
        'entries': _public_entries(alice),
        'pair': [{'pin': pin, 'run': run} for pin, run in sorted(pair)],
        'receipts_bound': True,
    })


def _fault_append_rotation(context, server, member_bin, deadline):
    del server
    alice = context.members[0]
    sent = _send_one(context, member_bin, alice, _ORDINARY_PAYLOAD_BYTES, deadline)
    stored = _upload_until(context, member_bin, alice, sent, deadline, require_stored=True)
    original, pair = _bind_single_original(context, stored, sent)
    before = _member_fault_status(
        context, member_bin, alice, deadline, verify=True, diagnostics=True)
    _require_remote_retrieval(before, _ALICE)
    _require_replica_ciphertext(before, (original,), (), pair, _ALICE)
    prior_append = {
        (item['pin'], item['run'], item['mailbox'], item['endpoint']): item['append_revision']
        for item in before['inboxes']}
    if any(revision >= _I64_MAX for revision in prior_append.values()):
        raise OwnershipError('Append revision did not advance')
    expected_append = {key: revision + 1 for key, revision in prior_append.items()}
    text = _member_text(context, member_bin, alice, deadline, 'rotate-append', [])
    config = _CONFIG_LINE.fullmatch(text[:-1])
    if config is None or _public_int(config.group(1)) <= before['config_revision']:
        raise OwnershipError('Append revision did not advance')
    reference = (_public_int(config.group(1)), config.group(2))
    after = _member_fault_status(
        context, member_bin, alice, deadline, verify=True, diagnostics=True,
        expected_append=expected_append, config_reference=reference)
    captured_append = {
        (item['pin'], item['run'], item['mailbox'], item['endpoint']): item['append_revision']
        for item in after['inboxes']}
    captured_reference = (after['config_revision'], after['config_hash'])
    if captured_append != expected_append or captured_reference != reference:
        raise OwnershipError('Append revision did not advance')
    _require_replica_ciphertext(after, (original,), (), pair, _ALICE)
    if _remote_identity(after) != _remote_identity(before):
        raise OwnershipError('Accepted ciphertext identity changed')
    if _acked_retries(after['diagnostics']) != _acked_retries(before['diagnostics']):
        raise OwnershipError('Accepted ciphertext identity changed')
    second = _send_one(context, member_bin, alice, _ORDINARY_PAYLOAD_BYTES, deadline)
    if second['id'] == sent['id']:
        raise OwnershipError('Owned command returned an invalid status')
    final = _member_fault_status(
        context, member_bin, alice, deadline, verify=True, diagnostics=False,
        expected_append=captured_append, config_reference=captured_reference)
    _require_replica_ciphertext(final, (original,), (), pair, _ALICE)
    if _remote_identity(final) != _remote_identity(before):
        raise OwnershipError('Accepted ciphertext identity changed')
    if not _one_stored(_only_message(final, sent['id']), sent):
        raise OwnershipError('Accepted ciphertext identity changed')
    fresh = _only_message(final, second['id'])
    if fresh['needs_route'] != _AUDIENCE or fresh['stored_whole'] == '1':
        raise OwnershipError('Member send did not commit every recipient')
    return _passed('append_rotation', {
        'append_revisions': [{
            'mailbox': item['mailbox'],
            'pin': item['pin'],
            'revision': item['append_revision'],
            'run': item['run'],
        } for item in after['inboxes']],
        'config_hash': reference[1],
        'config_revision': reference[0],
        'entries': _public_entries(after),
        'exact_http_retry': 'skipped',
        'stored_message': sent['id'],
    }, needs_context=(
        'NEEDS_CONTEXT: upload_pending skips acknowledged rows, so member upload after Stored '
        'does not resend the original bytes. Append revision advance and unchanged stored '
        'identity are observed. Exact HTTP retry is not claimed.'))


def _passed(name, observation, *, needs_context=None):
    evidence = {
        'expected': _IMPLEMENTED_EXPECTED[name],
        'injection': _SCENARIO_META[name][0],
        'injection_kind': _SCENARIO_META[name][1],
        'observation': observation,
        'outcome': 'passed',
        'reason': None,
    }
    if needs_context is not None:
        evidence['needs_context'] = needs_context
    return evidence


_FAULT_BODIES = {
    'outage': _fault_outage,
    'quota': _fault_quota,
    'retained_restart': _fault_retained_restart,
    'append_rotation': _fault_append_rotation,
}


def _fault_member_views(context, member_bin, deadline, *, expected, diagnostics):
    found = {}
    for member in context.members:
        found[member.member_id] = _member_fault_status(
            context, member_bin, member, deadline, verify=True, diagnostics=diagnostics,
            expected_route_failures=expected)
    return found


def _member_fault_status(context, binary, member, deadline, *, verify, diagnostics,
                         expected_route_failures=(), expected_append=None,
                         config_reference=None):
    extra = []
    if verify:
        extra.append('--verify-relays')
    if diagnostics:
        extra.append('--diagnostics')
    text = _member_text(context, binary, member, deadline, 'status', extra)
    body, diagnostic = _split_diagnostics(text)
    if diagnostics == (diagnostic is None):
        raise OwnershipError('Owned command returned an invalid status')
    parsed = _parse_status(
        body, member.member_id, verify, expected_route_failures=expected_route_failures)
    _bind_member_inboxes(context, member, parsed, expected_append=expected_append)
    if config_reference is not None:
        revision, digest = config_reference
        if parsed['config_revision'] != revision or parsed['config_hash'] != digest:
            raise OwnershipError('Append revision did not advance')
    if diagnostics:
        parsed['diagnostics'] = _parse_diagnostics(diagnostic)
    return parsed


def _bind_member_inboxes(context, member, parsed, *, expected_append=None):
    """Require the member's own pin, run, mailbox, and endpoint from setup.

    The default append revision is the setup value. One rotate command
    passes the exact revisions it captured instead of any later value.
    """
    setup = {
        (item['pin'], item['run'], item['mailbox'], item['endpoint']): item['append_revision']
        for item in context.inboxes if item['member'] == member.member_id}
    if expected_append is None:
        expected = setup
        mismatch = 'Owned command returned an invalid status'
    else:
        if set(expected_append) != set(setup):
            raise OwnershipError('Append revision did not advance')
        expected = expected_append
        mismatch = 'Append revision did not advance'
    found = {}
    for item in parsed['inboxes']:
        key = (item['pin'], item['run'], item['mailbox'], item['endpoint'])
        if key not in expected or key in found or item['append_revision'] != expected[key]:
            raise OwnershipError(mismatch)
        found[key] = item['append_revision']
    if set(found) != set(expected):
        raise OwnershipError(mismatch)


def _split_diagnostics(text):
    marker = '\nsection=diagnostics\n'
    if marker not in text:
        if 'section=diagnostics' in text:
            raise OwnershipError('Owned command returned an invalid status')
        return text, None
    head, tail = text.split(marker, 1)
    if 'section=diagnostics' in head or 'section=diagnostics' in tail:
        raise OwnershipError('Owned command returned an invalid status')
    return head + '\n', tail


def _parse_diagnostics(text):
    if not text.endswith('\n') or '\n\n' in text or '\r' in text:
        raise OwnershipError('Owned command returned an invalid status')
    lines = text[:-1].split('\n')
    if not lines or lines[0] != 'diagnostics_authority=transport':
        raise OwnershipError('Owned command returned an invalid status')
    names = (
        'route_cursor_count', 'pending_download_count', 'download_rejection_count',
        'source_rejection_count', 'upload_work_count', 'upload_pending_count', 'sample_count',
        'sample_bytes')
    if len(lines) < 1 + len(names):
        raise OwnershipError('Owned command returned an invalid status')
    counts = {}
    for offset, name in enumerate(names, start=1):
        prefix = name + '='
        if not lines[offset].startswith(prefix):
            raise OwnershipError('Owned command returned an invalid status')
        counts[name] = _bounded_int(lines[offset][len(prefix):], 0, _I64_MAX)
    rows = lines[1 + len(names):]
    expected = (
        counts['route_cursor_count'] + counts['pending_download_count']
        + counts['download_rejection_count'] + counts['source_rejection_count']
        + counts['upload_work_count'] + counts['sample_count'])
    if len(rows) != expected:
        raise OwnershipError('Owned command returned an invalid status')
    cursor = _StatusCursor(rows)
    route_cursors = [_take_rows(cursor, counts['route_cursor_count'], _parse_route_cursor)]
    pending = [_take_rows(cursor, counts['pending_download_count'], _parse_pending_download)]
    download_rejections = [
        _take_rows(cursor, counts['download_rejection_count'], _parse_download_rejection)]
    source_rejections = [
        _take_rows(cursor, counts['source_rejection_count'], _parse_source_rejection)]
    upload_retries = [_take_rows(cursor, counts['upload_work_count'], _parse_upload_retry)]
    samples = [_take_rows(cursor, counts['sample_count'], _parse_sample)]
    route_cursors = route_cursors[0]
    pending = pending[0]
    download_rejections = download_rejections[0]
    source_rejections = source_rejections[0]
    upload_retries = upload_retries[0]
    samples = samples[0]
    if cursor.peek() is not None:
        raise OwnershipError('Owned command returned an invalid status')
    if sum(item['length'] for item in samples) != counts['sample_bytes']:
        raise OwnershipError('Owned command returned an invalid status')
    pending_uploads = sum(item['acknowledged'] == 0 for item in upload_retries)
    if pending_uploads != counts['upload_pending_count']:
        raise OwnershipError('Owned command returned an invalid status')
    return {
        'download_rejections': download_rejections,
        'pending_downloads': pending,
        'route_cursors': route_cursors,
        'samples': samples,
        'source_rejections': source_rejections,
        'upload_retries': upload_retries,
        **counts,
    }


def _take_rows(cursor, count, parser):
    return [parser(cursor.next()) for _ in range(count)]


def _parse_route_cursor(line):
    matched = re.fullmatch(
        r'route_cursor pin=([0-9a-f]{64}) run=([0-9a-f]{64}) mailbox=([0-9a-f]{64}) '
        r'position=([0-9]+)', line)
    if matched is None:
        raise OwnershipError('Owned command returned an invalid status')
    return {
        'mailbox': matched.group(3),
        'pin': matched.group(1),
        'position': _bounded_int(matched.group(4), 0, _I64_MAX),
        'run': matched.group(2),
    }


def _parse_pending_download(line):
    matched = re.fullmatch(
        r'pending_download pin=([0-9a-f]{64}) run=([0-9a-f]{64}) mailbox=([0-9a-f]{64}) '
        r'hash=([0-9a-f]{64}) length=([0-9]+) attempts=([0-9]+) retry_at=([0-9]+)', line)
    if matched is None:
        raise OwnershipError('Owned command returned an invalid status')
    return {
        'attempts': _bounded_int(matched.group(6), 0, _I64_MAX),
        'hash': matched.group(4),
        'length': _bounded_int(matched.group(5), 0, _I64_MAX),
        'mailbox': matched.group(3),
        'pin': matched.group(1),
        'retry_at': _bounded_int(matched.group(7), 0, _I64_MAX),
        'run': matched.group(2),
    }


def _parse_download_rejection(line):
    matched = re.fullmatch(
        r'download_rejection pin=([0-9a-f]{64}) run=([0-9a-f]{64}) mailbox=([0-9a-f]{64}) '
        r'hash=([0-9a-f]{64}) reason=(?:other length=([0-9]+)|([a-z][a-z0-9_]{0,63}))', line)
    if matched is None:
        raise OwnershipError('Owned command returned an invalid status')
    return {
        'hash': matched.group(4),
        'mailbox': matched.group(3),
        'pin': matched.group(1),
        'reason': 'other' if matched.group(5) is not None else matched.group(6),
        'reason_length': None if matched.group(5) is None else _bounded_int(
            matched.group(5), 0, 64),
        'run': matched.group(2),
    }


def _parse_source_rejection(line):
    matched = re.fullmatch(
        r'source_rejection root=([0-9a-f]{64}) '
        r'reason=(?:other length=([0-9]+)|([a-z][a-z0-9_]{0,63}))', line)
    if matched is None:
        raise OwnershipError('Owned command returned an invalid status')
    return {
        'reason': 'other' if matched.group(2) is not None else matched.group(3),
        'reason_length': None if matched.group(2) is None else _bounded_int(matched.group(2), 0, 64),
        'root': matched.group(1),
    }


def _parse_upload_retry(line):
    matched = re.fullmatch(
        r'upload_retry message=([0-9a-f]{64}) recipient=([123]) hash=([0-9a-f]{64}) '
        r'pin=([0-9a-f]{64}) run=([0-9a-f]{64}) mailbox=([0-9a-f]{64}) '
        r'acknowledged=([01]) attempts=([0-9]+) retry_at=([0-9]+)', line)
    if matched is None:
        raise OwnershipError('Owned command returned an invalid status')
    return {
        'acknowledged': int(matched.group(7)),
        'attempts': _bounded_int(matched.group(8), 0, _I64_MAX),
        'hash': matched.group(3),
        'mailbox': matched.group(6),
        'message': matched.group(1),
        'pin': matched.group(4),
        'recipient': int(matched.group(2)),
        'retry_at': _bounded_int(matched.group(9), 0, _I64_MAX),
        'run': matched.group(5),
    }


def _parse_sample(line):
    matched = re.fullmatch(
        r'diagnostic_sample pin=([0-9a-f]{64}) run=([0-9a-f]{64}) mailbox=([0-9a-f]{64}) '
        r'sequence=([0-9]+) length=([0-9]+)', line)
    if matched is None:
        raise OwnershipError('Owned command returned an invalid status')
    return {
        'length': _bounded_int(matched.group(5), 0, _I64_MAX),
        'mailbox': matched.group(3),
        'pin': matched.group(1),
        'run': matched.group(2),
        'sequence': _bounded_int(matched.group(4), 0, _I64_MAX),
    }


def _send_one(context, member_bin, member, size, deadline):
    payload_dir = context.owner.root / 'payloads'
    _mkdir(payload_dir)
    blob = bytearray(secrets.token_bytes(size))
    path = payload_dir / f'{size}-{secrets.token_hex(4)}'
    try:
        _write_new(path, blob, 0o600)
    finally:
        blob[:] = b'\x00' * len(blob)
    request_id = secrets.token_hex(32)
    text = _member_text(context, member_bin, member, deadline, 'send', [
        '--payload-file', str(path), '--request-id', request_id,
    ])
    message_id, digest = _parse_send(text, request_id)
    return {
        'digest': digest,
        'id': message_id,
        'payload_length': size,
        'request_id': request_id,
    }


def _upload_until(context, member_bin, member, sent, deadline, *, require_stored, attempts=None):
    last = None
    for _ in range(attempts or _ACCEPTANCE_ATTEMPTS):
        _parse_upload_progress(_member_text(
            context, member_bin, member, deadline, 'upload', [], allow_empty=True))
        last = _member_status(context, member_bin, member, deadline, verify=False)
        if any(_one_stored(message, sent) for message in last['messages']):
            return last
    if require_stored or last is None:
        raise OwnershipError('Acceptance observation was not reached before the attempt bound')
    return last


def _one_stored(message, sent):
    return (message['id'] == sent['id'] and message['digest'] == sent['digest']
            and message['sender'] == _ALICE and message['kind'] == 'test'
            and message['readiness'] == 'ready' and message['stored_whole'] == '1'
            and message['needs_route'] == 0
            and set(message['stored_members']) == {_ALICE, _BOB, _CAROL}
            and all(value == 1 for value in message['stored_members'].values()))


def _require_quota_shape(status, sent):
    if len(status['messages']) != 1:
        raise OwnershipError('Quota fixture wire length was not 1024')
    message = status['messages'][0]
    if message['id'] != sent['id']:
        raise OwnershipError('Quota fixture wire length was not 1024')
    grouped = {}
    for obj in message['objects']:
        grouped.setdefault(obj['recipient'], []).append(obj)
    if set(grouped) != {_ALICE, _BOB, _CAROL}:
        raise OwnershipError('Quota fixture wire length was not 1024')
    for objects in grouped.values():
        if len(objects) != 1 or objects[0]['length'] != _WIRE_MULTIPLE:
            raise OwnershipError('Quota fixture wire length was not 1024')


def _reject_quota_message(status, sent, full_pair):
    message = _only_message(status, sent['id'])
    if message['stored_whole'] == '1' or any(
            item['acknowledged'] == 1 and (item['pin'], item['run']) in full_pair
            for item in message['uploads']):
        raise OwnershipError('Quota accepted a new object after capacity was reached')
    hashes = {obj['hash'] for obj in message['objects']}
    if any(item['hash'] in hashes and (item['pin'], item['run']) in full_pair
           for item in status['remote_entries']):
        raise OwnershipError('Quota accepted a new object after capacity was reached')


def _quota_upload_bindings(status, sent, pair, third, context):
    """Full preferred relays refuse the new message; the third accepts one copy.

    A single complete replica cannot establish whole-vault Stored. Retry
    scheduling and each saved receipt remain bound to their original route.
    """
    message = _only_message(status, sent['id'])
    rows = [
        row for row in status['diagnostics']['upload_retries'] if row['message'] == sent['id']]
    routes = {}
    for item in context.inboxes:
        key = (item['member'], item['pin'])
        if key in routes:
            raise OwnershipError('Owned command returned an invalid status')
        routes[key] = item
    pair_pins = {pin for pin, _run in pair}
    if third.receipt_key in pair_pins or len(pair_pins) != 2:
        raise OwnershipError('Whole-vault replicas are not one shared pair')
    objects = {}
    for obj in message['objects']:
        key = (obj['recipient'], obj['hash'])
        if obj['recipient'] not in (_ALICE, _BOB, _CAROL) or key in objects:
            raise OwnershipError('Owned command returned an invalid status')
        objects[key] = obj
    if not objects or {recipient for recipient, _obj_hash in objects} != {_ALICE, _BOB, _CAROL}:
        raise OwnershipError('Quota accepted a new object after capacity was reached')
    local = {
        (item['recipient'], item['hash'], item['pin'], item['run'], item['acknowledged'])
        for item in message['uploads']}
    seen = set()
    attempted = []
    unattempted = []
    for row in rows:
        obj = objects.get((row['recipient'], row['hash']))
        route = routes.get((row['recipient'], row['pin']))
        if obj is None or route is None or row['run'] != route['run'] or row['mailbox'] != route['mailbox']:
            raise OwnershipError('Owned command returned an invalid status')
        identity = (row['recipient'], row['hash'], row['pin'])
        if identity in seen:
            raise OwnershipError('Owned command returned an invalid status')
        seen.add(identity)
        bound = {
            'acknowledged': row['acknowledged'],
            'attempts': row['attempts'],
            'hash': row['hash'],
            'length': obj['length'],
            'mailbox': row['mailbox'],
            'pin': row['pin'],
            'recipient': row['recipient'],
            'run': row['run'],
        }
        if (row['pin'], row['run']) in pair:
            if row['attempts'] < 1 or row['acknowledged'] != 0:
                raise OwnershipError('Quota accepted a new object after capacity was reached')
            attempted.append(bound)
        elif row['pin'] == third.receipt_key and row['run'] == third.run_id:
            # attempts counts failed retry schedules; a successful first PUT is zero.
            if row['acknowledged'] != 1:
                raise OwnershipError('Available third relay did not preserve its accepted receipt')
            unattempted.append(bound)
        else:
            raise OwnershipError('Owned command returned an invalid status')
    expected = {
        (recipient, obj['hash'], pin)
        for (recipient, _obj_hash), obj in objects.items()
        for pin in pair_pins | {third.receipt_key}}
    if seen != expected or not attempted or not unattempted:
        raise OwnershipError('Quota accepted a new object after capacity was reached')
    diagnostic = {
        (row['recipient'], row['hash'], row['pin'], row['run'], row['acknowledged']) for row in rows}
    if local != diagnostic:
        raise OwnershipError('Owned command returned an invalid status')
    attempted.sort(key=lambda item: (item['recipient'], item['pin'], item['hash']))
    unattempted.sort(key=lambda item: (item['recipient'], item['pin'], item['hash']))
    return attempted, unattempted


def _only_message(status, message_id):
    rows = [message for message in status['messages'] if message['id'] == message_id]
    if len(rows) != 1:
        raise OwnershipError('Owned command returned an invalid status')
    return rows[0]


def _message_hashes(status, message_id):
    return {obj['hash'] for obj in _only_message(status, message_id)['objects']}


def _message_wire(status, message_id):
    message = _only_message(status, message_id)
    objects = tuple(sorted(
        (obj['recipient'], obj['ordinal'], obj['hash'], obj['length']) for obj in message['objects']))
    uploads = tuple(sorted(
        (item['recipient'], item['hash'], item['pin'], item['run'], item['acknowledged'],
         item['receipt_digest']) for item in message['uploads']))
    return message['digest'], message['stored_whole'], message['needs_route'], objects, uploads


def _remote_for_hashes(status, hashes):
    return tuple(sorted(
        (item['pin'], item['run'], item['mailbox'], item['sequence'], item['hash'], item['length'],
         item['receipt_digest'], item['retrieved_hash'], item['retrieved_length'])
        for item in status['remote_entries'] if item['hash'] in hashes))


def _remote_identity(status):
    return _remote_for_hashes(status, {item['hash'] for item in status['remote_entries']})


def _pin_entries(status, pin):
    return tuple(sorted(
        (item['run'], item['mailbox'], item['sequence'], item['hash'], item['length'],
         item['receipt_digest'], item['retrieved_hash'], item['retrieved_length'])
        for item in status['remote_entries'] if item['pin'] == pin))


def _require_retained_entries(before, after):
    if not set(before).issubset(set(after)):
        raise OwnershipError('Accepted ciphertext identity changed')


def _public_entries(status):
    return [{
        'hash': item['hash'],
        'length': item['length'],
        'pin': item['pin'],
        'receipt_digest': item['receipt_digest'],
        'sequence': item['sequence'],
    } for item in status['remote_entries']]


def _public_pin_entries(status, pin):
    return [item for item in _public_entries(status) if item['pin'] == pin]


def _local_receipts(status):
    rows = []
    for message in status['messages']:
        for item in message['uploads']:
            rows.append((message['id'], item['recipient'], item['hash'], item['pin'], item['run'],
                         item['acknowledged'], item['receipt_digest']))
    return tuple(sorted(rows))


def _acked_retries(diag, pins=None):
    rows = []
    for row in diag['upload_retries']:
        if row['acknowledged'] != 1:
            continue
        if pins is not None and row['pin'] not in pins:
            continue
        rows.append((row['message'], row['recipient'], row['hash'], row['pin'], row['run'],
                     row['mailbox'], row['attempts'], row['retry_at']))
    return tuple(sorted(rows))


def _known_cursors(diag, context, member_id):
    """An authenticated inbox with no saved cursor is still at position 0."""
    known = {
        (item['pin'], item['run'], item['mailbox'])
        for item in context.inboxes if item['member'] == member_id}
    found = {}
    for row in diag['route_cursors']:
        key = (row['pin'], row['run'], row['mailbox'])
        if key not in known or key in found:
            raise OwnershipError('Owned command returned an invalid status')
        found[key] = row['position']
    return tuple(sorted((*key, found.get(key, 0)) for key in known))


def _cursor_at(cursors, pin):
    rows = [position for cursor_pin, _run, _mailbox, position in cursors if cursor_pin == pin]
    if len(rows) != 1:
        raise OwnershipError('Owned command returned an invalid status')
    return rows[0]


def _stop_owned_relay(context, relay, deadline):
    owner = context.owner
    if not any(relay.child is child for child in owner._children):
        raise OwnershipError('Process handle is not owned by this controller')
    owner.stop(relay.child, timeout=min(2.0, _remaining(deadline)))
    if relay.child.poll() is None:
        raise OwnershipError('Owned processes must be stopped before the run is retained')


def _default_workspaces():
    communication = Path(__file__).resolve().parents[1]
    return communication, communication.parent / 'poc'


def _parse_cli(argv):
    if not argv or argv[0] not in ('acceptance', 'delete', 'faults'):
        raise OwnershipError('harness_arguments')
    command = argv[0]
    if command == 'acceptance':
        flags = _flag_values(argv[1:], {'--run-root': 1, '--ports': 3})
        return command, {
            'run_root': flags['--run-root'][0],
            'ports': tuple(_cli_port(value) for value in flags['--ports']),
        }
    if command == 'faults':
        return command, _parse_fault_options(argv[1:])
    flags = _flag_values(argv[1:], {'--run-root': 1, '--expected-run-id': 1})
    run_id = flags['--expected-run-id'][0]
    if re.fullmatch(r'[0-9a-f]{32}', run_id) is None:
        raise OwnershipError('harness_arguments')
    return command, {'run_root': flags['--run-root'][0], 'expected_run_id': run_id}


def _parse_fault_options(argv):
    root = None
    ports = None
    scenarios = []
    index = 0
    while index < len(argv):
        name = argv[index]
        if name == '--run-root' and root is None:
            root = _flag_token(argv, index)
            index += 2
        elif name == '--ports' and ports is None:
            values = argv[index + 1:index + 4]
            if len(values) != 3 or any(value == '' or value.startswith('--') for value in values):
                raise OwnershipError('harness_arguments')
            ports = tuple(_cli_port(value) for value in values)
            index += 4
        elif name == '--scenario':
            value = _flag_token(argv, index)
            if value not in _FAULT_SCENARIOS or value in scenarios:
                raise OwnershipError('harness_arguments')
            scenarios.append(value)
            index += 2
        else:
            raise OwnershipError('harness_arguments')
    if root is None or ports is None:
        raise OwnershipError('harness_arguments')
    return {
        'ports': ports,
        'run_root': root,
        'scenarios': tuple(scenarios) or None,
    }


def _flag_token(argv, index):
    if index + 1 >= len(argv):
        raise OwnershipError('harness_arguments')
    value = argv[index + 1]
    if value == '' or value.startswith('--'):
        raise OwnershipError('harness_arguments')
    return value


def _flag_values(argv, spec):
    seen = {}
    index = 0
    while index < len(argv):
        name = argv[index]
        count = spec.get(name)
        if count is None or name in seen or not name.startswith('--'):
            raise OwnershipError('harness_arguments')
        values = argv[index + 1:index + 1 + count]
        if len(values) != count or any(value == '' or value.startswith('--') for value in values):
            raise OwnershipError('harness_arguments')
        seen[name] = values
        index += 1 + count
    if set(seen) != set(spec):
        raise OwnershipError('harness_arguments')
    return seen


def _cli_port(text):
    if _PUBLIC_INT.fullmatch(text) is None:
        raise OwnershipError('harness_arguments')
    value = int(text)
    if not 1 <= value <= 65535:
        raise OwnershipError('harness_arguments')
    return value


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    try:
        command, options = _parse_cli(argv)
    except OwnershipError as error:
        print(error, file=sys.stderr)
        return 2
    communication, poc = _default_workspaces()
    try:
        if command == 'acceptance':
            result = run_acceptance(
                options['run_root'], options['ports'], communication_workspace=communication,
                poc_workspace=poc, timeout=_ACCEPTANCE_DEADLINE)
            sys.stdout.write(_json_bytes(result.public_report()).decode('ascii'))
            return 0
        if command == 'faults':
            result = run_faults(
                options['run_root'], options['ports'], communication_workspace=communication,
                poc_workspace=poc, timeout=_FAULT_DEADLINE, scenarios=options['scenarios'])
            sys.stdout.write(_json_bytes(result.public_report()).decode('ascii'))
            return 0 if result.public_report()['result'] == 'completed' else 1
        delete_retained_run(options['run_root'], options['expected_run_id'])
    except OwnershipError as error:
        print(error, file=sys.stderr)
        return 1
    sys.stdout.write(f"deleted run_id={options['expected_run_id']}\n")
    return 0


if __name__ == '__main__':
    sys.exit(main())
