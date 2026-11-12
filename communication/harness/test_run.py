import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from unittest.mock import Mock, patch
from types import SimpleNamespace

import run


class HarnessOwnership(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()

    def test_owned_root_lifecycle(self):
        owner = run.OwnedRun.create(self.base / 'run')
        saved = owner.root / 'saved'
        saved.write_bytes(b'retained')
        owner.close()
        self.assertEqual(saved.read_bytes(), b'retained')
        with self.assertRaises(run.OwnershipError):
            owner.delete(expected_run_id='0' * 32)
        self.assertEqual(saved.read_bytes(), b'retained')
        owner.delete(expected_run_id=owner.run_id)
        self.assertFalse(owner.root.exists())

    def test_outside_selected_run_refused(self):
        owner = run.OwnedRun.create(self.base / 'run')
        foreign = self.base / 'foreign'
        foreign.mkdir()
        saved = foreign / 'saved'
        saved.write_bytes(b'foreign')
        with self.assertRaises(run.OwnershipError):
            owner.delete(expected_run_id=owner.run_id, root=foreign)
        self.assertEqual(saved.read_bytes(), b'foreign')

    def test_unowned_root_refused(self):
        owner = run.OwnedRun.create(self.base / 'run')
        saved = owner.root / 'saved'
        saved.write_bytes(b'retained')
        (owner.root / owner.MARKER).unlink()
        with self.assertRaises(run.OwnershipError):
            owner.delete(expected_run_id=owner.run_id)
        self.assertEqual(saved.read_bytes(), b'retained')

    def test_mismatched_marker_refused(self):
        owner = run.OwnedRun.create(self.base / 'run')
        marker = owner.root / owner.MARKER
        marker.write_text('{"run_id": "foreign", "root": "foreign"}')
        with self.assertRaises(run.OwnershipError):
            owner.delete(expected_run_id=owner.run_id)
        self.assertTrue(marker.exists())

    def test_root_symlink_refused(self):
        owner = run.OwnedRun.create(self.base / 'run')
        retained = self.base / 'retained'
        owner.root.rename(retained)
        owner.root.symlink_to(retained, target_is_directory=True)
        with self.assertRaises(Exception) as raised:
            owner.delete(expected_run_id=owner.run_id)
        self.assertIsInstance(raised.exception, run.OwnershipError)
        self.assertTrue((retained / owner.MARKER).exists())

    def test_symlinked_ancestor_refused(self):
        parent = self.base / 'parent'
        parent.mkdir()
        owner = run.OwnedRun.create(parent / 'run')
        retained = self.base / 'retained'
        parent.rename(retained)
        parent.symlink_to(retained, target_is_directory=True)
        with self.assertRaises(run.OwnershipError):
            owner.delete(expected_run_id=owner.run_id)
        self.assertTrue((retained / 'run' / owner.MARKER).exists())

    def test_controller_helpers(self):
        run.preflight_ports([])
        binary = self.base / 'target' / 'debug' / 'member'
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b'fixture')
        binary.chmod(0o700)
        self.assertEqual(run.find_binary('member', workspace=self.base, env={}), binary)
        owner = run.OwnedRun.create(self.base / 'run')
        child = owner.start([sys.executable, '-c', 'import time; time.sleep(60)'],
                            cwd=owner.root)
        self.addCleanup(lambda: child.poll() is None and child.kill())
        self.addCleanup(owner.close)
        saved = owner.root / 'saved'
        saved.write_bytes(b'retained')
        owner.close()
        self.assertIsNotNone(child.poll())
        self.assertEqual(saved.read_bytes(), b'retained')

    def test_occupied_port_refused_without_killing(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as occupied:
            occupied.bind(('127.0.0.1', 0))
            occupied.listen()
            port = occupied.getsockname()[1]
            with patch.object(run.subprocess, 'Popen') as spawn:
                with self.assertRaises(run.OwnershipError):
                    run.preflight_ports([port])
                spawn.assert_not_called()
            with socket.create_connection(('127.0.0.1', port), timeout=1):
                accepted, _ = occupied.accept()
                accepted.close()

    def test_foreign_process_handle_refused(self):
        owner = run.OwnedRun.create(self.base / 'run')
        foreign = Mock(spec=subprocess.Popen)
        foreign.pid = os.getpid()
        foreign.poll.return_value = None
        with self.assertRaises(run.OwnershipError):
            owner.stop(foreign)
        foreign.terminate.assert_not_called()
        foreign.kill.assert_not_called()
        with self.assertRaises(run.OwnershipError):
            owner.stop(os.getpid())

    def test_live_children_block_deletion(self):
        owner = run.OwnedRun.create(self.base / 'run')
        child = owner.start([sys.executable, '-c', 'import time; time.sleep(60)'],
                            cwd=owner.root)
        self.addCleanup(owner.close)
        with self.assertRaises(run.OwnershipError):
            owner.delete(expected_run_id=owner.run_id)
        self.assertTrue(owner.root.exists())
        self.assertIsNone(child.poll())
        owner.close()
        owner.delete(expected_run_id=owner.run_id)

    def test_binary_lookup_uses_selected_target(self):
        default = self.base / 'target' / 'debug' / 'member'
        selected = self.base / 'selected' / 'debug' / 'member'
        for binary in (default, selected):
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b'fixture')
            binary.chmod(0o700)
        env = {'CARGO_TARGET_DIR': 'selected'}
        self.assertEqual(run.find_binary('member', workspace=self.base, env=env),
                         selected)
        selected.unlink()
        with self.assertRaises(run.OwnershipError):
            run.find_binary('member', workspace=self.base, env=env)
        self.assertEqual(run.find_binary('member', workspace=self.base,
                                        target_dir='target', env=env), default)

    def test_poc_acceptance_profile_is_explicit_and_never_falls_back(self):
        workspace = self.base / 'poc'
        binary = workspace / 'target/release/member'
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b'fixture')
        binary.chmod(0o700)
        env = {'LOKI_POC_BIN_PROFILE': 'release'}
        self.assertEqual(run.find_binary('member', workspace=workspace, env=env), binary)
        for profile in ('../debug', 'unexpected'):
            with self.assertRaises(run.OwnershipError):
                run.find_binary('member', workspace=workspace, env={'LOKI_POC_BIN_PROFILE': profile})
        with self.assertRaises(run.OwnershipError):
            run.find_binary('member', workspace=workspace, env={})

    def test_marker_symlink_refused(self):
        owner = run.OwnedRun.create(self.base / 'run')
        marker = owner.root / owner.MARKER
        saved_marker = self.base / 'saved-marker'
        marker.rename(saved_marker)
        marker.symlink_to(saved_marker)
        with self.assertRaises(run.OwnershipError):
            owner.delete(expected_run_id=owner.run_id)
        self.assertTrue(marker.is_symlink())
        self.assertTrue(saved_marker.exists())

    def test_replaced_root_refused(self):
        owner = run.OwnedRun.create(self.base / 'run')
        retained = self.base / 'retained'
        owner.root.rename(retained)
        owner.root.mkdir()
        (owner.root / owner.MARKER).write_bytes((retained / owner.MARKER).read_bytes())
        with self.assertRaises(run.OwnershipError):
            owner.delete(expected_run_id=owner.run_id)
        self.assertTrue((owner.root / owner.MARKER).exists())
        self.assertTrue((retained / owner.MARKER).exists())

    def test_create_through_symlink_refused(self):
        foreign = self.base / 'foreign'
        foreign.mkdir()
        link = self.base / 'link'
        link.symlink_to(foreign, target_is_directory=True)
        with self.assertRaises(run.OwnershipError):
            run.OwnedRun.create(link / 'run')
        self.assertEqual(list(foreign.iterdir()), [])

    def test_stop_uses_one_deadline(self):
        owner = run.OwnedRun.create(self.base / 'run')
        child = Mock(spec=subprocess.Popen)
        child.poll.return_value = None
        child.wait.side_effect = [subprocess.TimeoutExpired('owned', 1), 0]
        with patch.object(run.subprocess, 'Popen', return_value=child):
            owner.start([sys.executable], cwd=owner.root)
        with patch.object(run.time, 'monotonic', side_effect=[10, 10, 10.8]):
            owner.stop(child, timeout=1)
        self.assertLessEqual(child.wait.call_args_list[1].kwargs['timeout'], 0.25)
        child.terminate.assert_called_once()
        child.kill.assert_called_once()

    def test_start_rejects_shell_string_and_relative_binary(self):
        owner = run.OwnedRun.create(self.base / 'run')
        with patch.object(run.subprocess, 'Popen') as spawn:
            for argv in ('echo unsafe', ['relative-binary'], []):
                with self.subTest(argv=argv), self.assertRaises(run.OwnershipError):
                    owner.start(argv, cwd=owner.root)
            spawn.assert_not_called()

    def test_binary_cannot_escape_selected_build(self):
        outside = self.base / 'outside'
        outside.write_bytes(b'fixture')
        outside.chmod(0o700)
        binary = self.base / 'target' / 'debug' / 'member'
        binary.parent.mkdir(parents=True)
        binary.symlink_to(outside)
        with self.assertRaises(run.OwnershipError):
            run.find_binary('member', workspace=self.base, env={})

    def test_close_attempts_all_owned_children_on_timeout(self):
        owner = run.OwnedRun.create(self.base / 'run')
        first, second = Mock(spec=subprocess.Popen), Mock(spec=subprocess.Popen)
        for child in (first, second):
            child.poll.return_value = None
        first.wait.side_effect = subprocess.TimeoutExpired('owned', 0.1)
        second.wait.return_value = 0
        with patch.object(run.subprocess, 'Popen', side_effect=[first, second]):
            owner.start([sys.executable], cwd=owner.root)
            owner.start([sys.executable], cwd=owner.root)
        with self.assertRaises(run.OwnershipError):
            owner.close(timeout=0.1)
        second.terminate.assert_called_once()
        self.assertTrue(owner.root.exists())
        with self.assertRaises(run.OwnershipError):
            owner.delete(expected_run_id=owner.run_id)


EVIDENCE = Path('/private/tmp/relay-8.3a-evidence')
_BANNED_COMMANDS = {
    'address', 'backup', 'funding', 'fund', 'scan', 'sign', 'chain', 'send',
    'upload', 'poll', 'rotate-append',
}
_MEMBER_COMMANDS = {'identity', 'run', 'provision', 'export-config', 'import-config'}
_SIMULATOR = """#!/usr/bin/env python3
import fcntl
import json
import os
import re
import sys
from pathlib import Path

STATE = Path("__STATE__")


def log_invocation():
    line = json.dumps({"pid": os.getpid(), "argv": sys.argv}) + "\\n"
    descriptor = os.open(
        STATE / "invocations.jsonl", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        os.write(descriptor, line.encode("ascii"))
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def scenario():
    return json.loads((STATE / "scenario.json").read_text(encoding="ascii"))["scenario"]


def hx(prefix):
    text = prefix * 32
    if len(text) != 64 or any(char not in "0123456789abcdef" for char in text):
        raise SystemExit("bad simulated hex")
    return text


def flag(name):
    for index, arg in enumerate(sys.argv):
        if arg == name:
            return sys.argv[index + 1]
    raise SystemExit("missing simulated flag")


def emit(lines, revision, config_hash):
    sys.stdout.write(
        "config revision=" + str(revision) + " hash=" + config_hash + "\\n"
        + "".join(line + "\\n" for line in lines))


def main():
    log_invocation()
    kind = Path(sys.argv[0]).name
    command = sys.argv[1]
    mode = scenario()
    if kind == "loki-relay-server" and command == "init":
        root = Path(flag("--root"))
        listen = flag("--listen")
        index = "1" if mode == "duplicate-relay-key" else root.name
        root.mkdir(parents=True, exist_ok=True)
        (root / "manifest").write_text(
            "http://" + listen + "\\n" + hx("a" + index) + "\\n" + hx("b" + index) + "\\n",
            encoding="ascii")
        return
    if kind == "loki-relay-server" and command == "serve":
        import socket
        listen = flag("--listen")
        host, port = listen.rsplit(":", 1)
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, int(port)))
        server.listen(8)
        while True:
            connection, _address = server.accept()
            connection.close()
    if kind == "loki_setup_member" and command == "identity":
        member_id = int(sys.argv[3])
        key_id = 1 if mode == "duplicate-member-key" else member_id
        sys.stdout.write(json.dumps({
            "encryption": hx("d" + str(key_id)),
            "id": member_id,
            "signing": hx("c" + str(key_id)),
        }, separators=(",", ":")) + "\\n")
        return
    if kind == "loki_setup_member" and command == "fingerprint":
        sys.stdout.write(hx("e0") + "\\n")
        return
    if kind == "loki_setup_member" and command == "run":
        return
    if kind == "loki_relay_member" and command == "provision":
        member = Path(flag("--member-root")).name
        lines = []
        if mode == "route-error":
            lines.append("route_error simulated-label")
        manifests = Path(flag("--relay-manifest"))
        for index in ("1", "2", "3"):
            if mode == "short-inboxes" and index == "3":
                continue
            endpoint, run_id, pin = (
                manifests / index / "manifest").read_text(encoding="ascii").splitlines()
            mailbox = (member + index + ("ab" * 31))[:64]
            lines.append(
                "inbox member=" + member + " pin=" + pin + " run=" + run_id
                + " mailbox=" + mailbox + " append_revision=1 endpoint=" + endpoint)
        emit(lines, 1, hx("ab"))
        return
    if kind == "loki_relay_member" and command == "export-config":
        roster = json.loads(Path(flag("--roster")).read_text(encoding="ascii"))
        owner = int(Path(flag("--member-root")).name)
        directory = Path(flag("--courier-directory"))
        lines = []
        for peer in (1, 2, 3):
            if peer == owner:
                continue
            name = (
                roster["vault"] + "-relay-config-" + str(owner) + "-" + str(peer) + "-1.bin")
            body = (
                "SIMULATED-COURIER owner=" + str(owner) + " peer=" + str(peer)
                + " revision=1 not-ciphertext\\n").encode("ascii")
            path = directory / name
            path.write_bytes(body)
            os.link(path, directory / ("." + name + "." + ("cd" * 16) + ".tmp"))
            if mode == "courier-alias":
                os.link(path, directory / ("alias-" + str(peer)))
            lines.append("courier=" + name)
        emit(lines, 1, hx("ab"))
        return
    if kind == "loki_relay_member" and command == "import-config":
        matched = re.fullmatch(
            r"[0-9a-f]{64}-relay-config-([123])-([123])-([1-9][0-9]*)\\.bin",
            Path(flag("--courier-file")).name)
        owner, peer, revision = matched.groups()
        emit(
            ["imported owner=" + owner + " revision=" + revision + " digest=" + hx("e" + peer)],
            4, hx("ef"))
        return
    raise SystemExit("unexpected simulated command")


if __name__ == "__main__":
    main()
"""


def _free_ports():
    bound = []
    ports = []
    for _index in range(3):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(('127.0.0.1', 0))
        bound.append(listener)
        ports.append(listener.getsockname()[1])
    for listener in bound:
        listener.close()
    return tuple(ports)


def _records(state):
    log = state / 'invocations.jsonl'
    if not log.is_file():
        return []
    return [json.loads(line) for line in log.read_text(encoding='ascii').splitlines() if line]


def _alive(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _process_args(pid):
    completed = subprocess.run(
        ['ps', '-ww', '-p', str(pid), '-o', 'args='],
        capture_output=True, text=True, check=False)
    return completed.stdout.strip()


def _serve_targets(state, build):
    """Return live serve pids for this fixture executable and recorded argv.

    The evidence directory prefix is not authority. A reused pid qualifies
    only when its current arguments still equal that recorded serve invocation
    and the executable text embeds this state directory.
    """
    executable = (build / 'debug' / 'loki-relay-server').resolve()
    if not executable.is_file():
        return []
    script = executable.read_text(encoding='ascii')
    if 'STATE = Path("%s")' % state not in script:
        return []
    targets = []
    for record in _records(state):
        argv = record['argv']
        if len(argv) < 2 or argv[1] != 'serve':
            continue
        if Path(argv[0]).resolve() != executable:
            continue
        pid = record['pid']
        if _alive(pid) and _process_args(pid) == ' '.join(argv):
            targets.append((pid, argv))
    return targets


def _reap(state, build):
    """Stop leftover serve children of this fixture after controller close.

    Caller cleanup must already have used the controller Popen handles.
    This fallback signals only the exact recorded serve invocation.
    """
    targets = _serve_targets(state, build)
    for pid, argv in targets:
        if _alive(pid) and _process_args(pid) == ' '.join(argv):
            os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and any(
            _alive(pid) and _process_args(pid) == ' '.join(argv) for pid, argv in targets):
        time.sleep(0.05)
    for pid, argv in targets:
        if _alive(pid) and _process_args(pid) == ' '.join(argv):
            os.kill(pid, signal.SIGKILL)


class HarnessSetup(unittest.TestCase):
    """Real controller setup fed by labeled simulated child programs.

    The hex identities, config hashes, import digests, and courier bytes are
    fixtures. They are not RFC 9180 ciphertext and they are not built-binary
    acceptance.
    """

    def _allocate(self, scenario):
        token = uuid.uuid4().hex
        state = EVIDENCE / 'state' / ('%s-%s' % (scenario, token))
        build = EVIDENCE / 'build' / ('%s-%s' % (scenario, token))
        root = EVIDENCE / 'runs' / ('%s-%s' % (scenario, token))
        state.mkdir(parents=True, mode=0o700)
        (build / 'debug').mkdir(parents=True, mode=0o700)
        root.parent.mkdir(parents=True, exist_ok=True)
        (state / 'scenario.json').write_text(json.dumps({
            'scenario': scenario,
            'label': 'simulated identities, courier bytes, and digests are not ciphertext',
        }) + '\n', encoding='ascii')
        script = _SIMULATOR.replace('__STATE__', str(state))
        for name in ('loki-relay-server', 'loki_setup_member', 'loki_relay_member'):
            path = build / 'debug' / name
            path.write_text(script, encoding='ascii')
            path.chmod(0o700)
        return state, build, root

    def _prepare(self, scenario):
        state, build, root = self._allocate(scenario)
        ports = _free_ports()
        repo = Path(__file__).resolve().parents[2]
        self.addCleanup(_reap, state, build)
        try:
            context = run.prepare_certified_setup(
                root, ports,
                communication_workspace=repo / 'communication',
                poc_workspace=repo / 'poc',
                timeout=30,
                target_dir=str(build))
        except run.OwnershipError as error:
            return None, error, state, build, root, ports
        self.addCleanup(context.owner.close)
        return context, None, state, build, root, ports

    def _assert_stopped(self, state, build):
        alive = [record['pid'] for record in _records(state)
                 if record['argv'][1] == 'serve' and _alive(record['pid'])]
        if alive:
            _reap(state, build)
            self.fail('setup left serve children running')

    def _expect(self, scenario, message):
        context, error, state, build, root, _ports = self._prepare(scenario)
        self.assertIsNone(context)
        self.assertIsInstance(error, run.OwnershipError)
        self.assertIn(message, str(error))
        self._assert_stopped(state, build)
        self.assertFalse((root / 'setup-report.json').exists())

    def test_certified_setup_isolates_members_and_publishes_records(self):
        context, error, state, build, root, ports = self._prepare('ok')
        self.assertIsNone(error)
        records = _records(state)
        self.assertEqual(
            [record['argv'][1] for record in records].count('init'), 3)
        self.assertEqual(
            sorted(record['argv'][1] for record in records),
            sorted([
                'init', 'init', 'init', 'serve', 'serve', 'serve',
                'identity', 'identity', 'identity', 'fingerprint',
                'run', 'run', 'run', 'provision', 'provision', 'provision',
                'export-config', 'export-config', 'export-config',
                'import-config', 'import-config', 'import-config',
                'import-config', 'import-config', 'import-config',
            ]))
        self._assert_isolation(records, root, build)
        self.assertEqual(
            [relay.endpoint for relay in context.relays],
            ['http://127.0.0.1:%s' % port for port in ports])
        self.assertEqual(
            [relay.run_id for relay in context.relays],
            [('a%s' % index) * 32 for index in (1, 2, 3)])
        self.assertEqual(
            [relay.receipt_key for relay in context.relays],
            [('b%s' % index) * 32 for index in (1, 2, 3)])
        self.assertEqual(len({relay.run_id for relay in context.relays}), 3)
        self.assertEqual(len({relay.receipt_key for relay in context.relays}), 3)
        self.assertEqual([member.member_id for member in context.members], [1, 2, 3])
        for member in context.members:
            self.assertEqual(member.signing, ('c%s' % member.member_id) * 32)
            self.assertEqual(member.encryption, ('d%s' % member.member_id) * 32)
            self.assertEqual(member.config_revision, 4)
            self.assertEqual(member.config_hash, 'ef' * 32)
        self.assertEqual(context.fingerprint, 'e0' * 32)
        expected_inboxes = []
        for member_id in (1, 2, 3):
            for index, relay in enumerate(context.relays, start=1):
                expected_inboxes.append({
                    'member': member_id,
                    'pin': relay.receipt_key,
                    'run': relay.run_id,
                    'mailbox': ('%s%s' % (member_id, index) + 'ab' * 31)[:64],
                    'append_revision': 1,
                    'endpoint': relay.endpoint,
                })
        self.assertEqual(
            sorted(context.inboxes, key=lambda item: (item['member'], item['pin'])),
            sorted(expected_inboxes, key=lambda item: (item['member'], item['pin'])))
        self.assertEqual(len({inbox['mailbox'] for inbox in context.inboxes}), 9)
        self.assertEqual(
            {(courier.owner, courier.peer) for courier in context.couriers},
            {(left, right) for left in (1, 2, 3) for right in (1, 2, 3) if left != right})
        for courier in context.couriers:
            expected = (
                'SIMULATED-COURIER owner=%s peer=%s revision=%s not-ciphertext\n'
                % (courier.owner, courier.peer, courier.revision)).encode('ascii')
            self.assertEqual(courier.revision, 1)
            self.assertEqual(courier.path.stat().st_nlink, 1)
            self.assertEqual(courier.path.read_bytes(), expected)
            self.assertEqual(courier.digest, ('e%s' % courier.peer) * 32)
            self.assertNotEqual(courier.digest, hashlib.sha256(expected).hexdigest())
        self.assertEqual(list(root.rglob('*.tmp')), [])
        report = context.public_report()
        saved = json.loads((root / 'setup-report.json').read_text(encoding='ascii'))
        self.assertEqual(saved, report)
        self._assert_public_report(context, root)
        serve_pids = [record['pid'] for record in records if record['argv'][1] == 'serve']
        self.assertEqual(len(serve_pids), 3)
        for relay in context.relays:
            self.assertIsNone(relay.child.poll())
        context.owner.close()
        for relay in context.relays:
            self.assertIsNotNone(relay.child.poll())
        self._assert_stopped(state, build)

    def test_duplicate_relay_identity_refused(self):
        self._expect('duplicate-relay-key', 'Relay identities are not distinct')

    def test_duplicate_member_identity_refused(self):
        self._expect('duplicate-member-key', 'Member identities are not distinct')

    def test_route_error_is_not_setup_success(self):
        self._expect('route-error', 'Remote relay failure is not setup success')

    def test_short_provision_refuses_partial_inboxes(self):
        self._expect('short-inboxes', 'Provision did not publish three inboxes')

    def test_courier_alias_refuses_extra_link(self):
        self._expect('courier-alias', 'Courier directory has an unexpected file')

    def test_member_command_refuses_foreign_root_before_spawn(self):
        state, build, root = self._allocate('foreign-root')
        self.addCleanup(_reap, state, build)
        owner = run.OwnedRun.create(root)
        self.addCleanup(owner.close)
        relay_root = owner.root / 'relays' / '1'
        member_root = owner.root / 'members' / '1'
        other_root = owner.root / 'members' / '2'
        relay_root.mkdir(parents=True)
        member_root.mkdir(parents=True)
        other_root.mkdir(parents=True)
        passphrase = member_root / 'passphrase'
        other_pass = other_root / 'passphrase'
        passphrase.write_bytes(b'simulated-own-passphrase\n')
        other_pass.write_bytes(b'simulated-other-passphrase\n')
        roster = owner.root / 'roster.json'
        roster.write_text('{}\n', encoding='ascii')
        member = run.CertifiedMember(1, member_root, passphrase, 'aa' * 32, 'bb' * 32)
        other = run.CertifiedMember(2, other_root, other_pass, 'cc' * 32, 'dd' * 32)
        relay = run.RelayBinding(
            'http://127.0.0.1:9', 'aa' * 32, 'bb' * 32, relay_root, None)
        binary = build / 'debug' / 'loki_relay_member'
        extras = (
            ['--relay-manifest', str(relay_root)],
            ['--courier-file', str(other_pass)],
        )
        for extra in extras:
            with self.subTest(flag=extra[0]):
                with self.assertRaises(run.OwnershipError) as raised:
                    run._member_command(
                        owner, binary, member, (member, other), (relay,), roster,
                        time.monotonic() + 5, 'provision', extra)
                self.assertIn('another member or relay root', str(raised.exception))
        self.assertFalse((state / 'invocations.jsonl').exists())

    def test_close_after_authorized_delete_rejects_missing_replaced_and_foreign(self):
        parent = EVIDENCE / 'runs'
        parent.mkdir(parents=True, exist_ok=True)
        token = uuid.uuid4().hex

        deleted_root = parent / ('deleted-' + token)
        deleted = run.OwnedRun.create(deleted_root)
        self.addCleanup(deleted.close)
        deleted.close()
        deleted.delete(expected_run_id=deleted.run_id)
        self.assertFalse(deleted_root.exists())
        self.assertTrue(deleted._deleted)
        deleted.close()

        released_root = parent / ('released-' + token)
        released = run.OwnedRun.create(released_root)
        released._release_lock()
        with self.assertRaises(run.OwnershipError) as raised:
            released.close()
        self.assertIn('Retained run is incomplete', str(raised.exception))
        self.assertFalse(released._deleted)
        self.assertTrue((released_root / released.MARKER).is_file())

        missing_root = parent / ('missing-' + token)
        missing = run.OwnedRun.create(missing_root)
        missing.close()
        shutil.rmtree(missing_root)
        with self.assertRaises(run.OwnershipError) as raised:
            missing.close()
        self.assertIn('Retained run is incomplete', str(raised.exception))
        self.assertFalse(missing._deleted)

        replaced = run.OwnedRun.create(parent / ('replaced-' + token))
        kept = parent / ('replaced-kept-' + token)
        replaced.root.rename(kept)
        replaced.root.mkdir()
        (replaced.root / replaced.MARKER).write_bytes(
            (kept / replaced.MARKER).read_bytes())
        with self.assertRaises(run.OwnershipError) as raised:
            replaced.delete(expected_run_id=replaced.run_id)
        self.assertIn('Selected run root was replaced', str(raised.exception))
        self.assertFalse(replaced._deleted)
        self.assertTrue((kept / replaced.MARKER).is_file())
        self.assertTrue((replaced.root / replaced.MARKER).is_file())

        foreign = run.OwnedRun.create(parent / ('foreign-' + token))
        self.addCleanup(foreign.close)
        outside = parent / ('outside-' + token)
        outside.mkdir()
        saved = outside / 'saved'
        saved.write_bytes(b'foreign-fixture')
        with self.assertRaises(run.OwnershipError) as raised:
            foreign.delete(expected_run_id=foreign.run_id, root=outside)
        self.assertIn('Root is outside the selected run', str(raised.exception))
        self.assertFalse(foreign._deleted)
        self.assertEqual(saved.read_bytes(), b'foreign-fixture')
        self.assertTrue((foreign.root / foreign.MARKER).is_file())

    def _assert_isolation(self, records, root, build):
        for record in records:
            argv = record['argv']
            command = argv[1]
            self.assertEqual(Path(argv[0]).resolve().parent, (build / 'debug').resolve())
            self.assertNotIn(command, _BANNED_COMMANDS)
            for arg in argv:
                self.assertNotIn(arg, _BANNED_COMMANDS)
            if command in ('init', 'serve'):
                self.assertEqual(Path(argv[0]).name, 'loki-relay-server')
            elif command in ('identity', 'fingerprint', 'run'):
                self.assertEqual(Path(argv[0]).name, 'loki_setup_member')
            else:
                self.assertEqual(Path(argv[0]).name, 'loki_relay_member')
            if command in _MEMBER_COMMANDS:
                member_id = self._member_id(argv)
                own_root = root / 'members' / str(member_id)
                own_pass = own_root / 'passphrase'
                if command == 'identity':
                    self.assertEqual(Path(argv[2]).resolve(), own_root.resolve())
                    self.assertEqual(Path(argv[4]).resolve(), own_pass.resolve())
                    self.assertNotIn('--roster', argv)
                elif command == 'run':
                    self.assertEqual(Path(argv[2]).resolve(), own_root.resolve())
                    self.assertEqual(Path(argv[3]).resolve(), own_pass.resolve())
                    self.assertEqual(Path(argv[4]).resolve(), (root / 'roster.json').resolve())
                    self.assertEqual(Path(argv[5]).resolve(), (root / 'exchange').resolve())
                    self.assertEqual(argv[6], 'e0' * 32)
                else:
                    self.assertEqual(
                        Path(self._flag(argv, '--member-root')).resolve(), own_root.resolve())
                    self.assertEqual(
                        Path(self._flag(argv, '--passphrase-file')).resolve(),
                        own_pass.resolve())
                    self.assertEqual(
                        Path(self._flag(argv, '--roster')).resolve(),
                        (root / 'roster.json').resolve())
                self._reject_private_paths(argv, root, member_id)
            else:
                self._reject_member_paths(argv, root)

    def _member_id(self, argv):
        command = argv[1]
        if command == 'identity':
            return int(argv[3])
        if command == 'run':
            return int(Path(argv[2]).name)
        return int(Path(self._flag(argv, '--member-root')).name)

    def _flag(self, argv, name):
        for index, arg in enumerate(argv):
            if arg == name:
                return argv[index + 1]
        self.fail('member command omitted %s' % name)

    def _reject_private_paths(self, argv, root, member_id):
        for arg in argv:
            if not arg.startswith(os.sep):
                continue
            path = Path(arg).resolve()
            for other in (1, 2, 3):
                if other == member_id:
                    continue
                foreign_root = (root / 'members' / str(other)).resolve()
                self.assertFalse(path == foreign_root or foreign_root in path.parents)
                self.assertNotEqual(path, foreign_root / 'passphrase')
            for index in (1, 2, 3):
                relay_root = (root / 'relays' / str(index)).resolve()
                self.assertFalse(path == relay_root or relay_root in path.parents)

    def _reject_member_paths(self, argv, root):
        for arg in argv:
            if not arg.startswith(os.sep):
                continue
            path = Path(arg).resolve()
            for member_id in (1, 2, 3):
                member_root = (root / 'members' / str(member_id)).resolve()
                self.assertFalse(path == member_root or member_root in path.parents)
                self.assertNotEqual(path, member_root / 'passphrase')

    def _assert_public_report(self, context, root):
        blob = (root / 'setup-report.json').read_bytes()
        for member in context.members:
            secret = member.passphrase_file.read_bytes().strip()
            if secret and secret in blob:
                self.fail('passphrase bytes appeared in setup-report.json')
            if str(member.root).encode('ascii') in blob:
                self.fail('member root appeared in setup-report.json')
            if str(member.passphrase_file).encode('ascii') in blob:
                self.fail('passphrase path appeared in setup-report.json')
        for relay in context.relays:
            secret = (root / 'capabilities' / relay.receipt_key).read_bytes()
            if secret in blob or secret.hex().encode('ascii') in blob:
                self.fail('capability bytes appeared in setup-report.json')
            if str(relay.root).encode('ascii') in blob:
                self.fail('relay root appeared in setup-report.json')
        for courier in context.couriers:
            if str(courier.path).encode('ascii') in blob:
                self.fail('courier path appeared in setup-report.json')
        self.assertNotIn('route_error', blob.decode('ascii'))
        self.assertNotIn('retrieval_error', blob.decode('ascii'))


class OfflineDelivery(unittest.TestCase):
    def test_built_members_deliver_after_author_stops(self):
        repo = Path(__file__).resolve().parents[2]
        parent = Path('/private/tmp/relay-8.4-evidence')
        parent.mkdir(exist_ok=True)
        result = run.run_acceptance(
            parent / uuid.uuid4().hex, _free_ports(),
            communication_workspace=repo / 'communication', poc_workspace=repo / 'poc',
            timeout=300)
        report = result.public_report()
        self.assertEqual(report['result'], 'accepted')
        self.assertEqual(len(report['pair']), 2)
        self.assertEqual(sorted(m['payload_length'] for m in report['messages']), [64, 65537])
        self.assertEqual(len(report['acknowledgements']), 4)
        self.assertEqual(report['self_effect']['self_acknowledgements'], 0)
        for message in report['messages']:
            self.assertTrue(message['received_whole'])
            self.assertEqual([m['value'] for m in message['received_members']], [False, True, True])
        self.assertEqual(report['remote_before'], report['remote_after'])
        self.assertTrue(all(child.poll() is not None for child in result.context.owner._children))


class HarnessFaultEvidence(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.cargo = self.base / 'cargo'
        self.cargo.write_text('#!' + sys.executable + '\n'
                              'import sys\n'
                              'selector = sys.argv[sys.argv.index("--") - 1]\n'
                              'print("test " + selector + " ... ok")\n'
                              'print("test result: ok. 1 passed; 0 failed; 0 ignored;")\n')
        self.cargo.chmod(0o700)

    def dispatch(self):
        owner = run.OwnedRun.create(self.base / 'campaign')
        self.addCleanup(owner.close)
        (owner.root / 'scenarios').mkdir()
        repo = Path(__file__).resolve().parents[2]
        with patch.dict(os.environ, {'PATH': str(self.base)}):
            return run._run_fault_scenario(
                owner, 'missing_chunk', (39001, 39002, 39003),
                time.monotonic() + 10, None, 'debug', repo / 'communication', repo / 'poc')

    def test_dispatch_executes_fixture_and_labels_injection(self):
        report = self.dispatch()
        self.assertEqual(report['outcome'], 'passed')
        self.assertTrue(report['simulation'])
        self.assertFalse(report['power_loss'])
        self.assertGreater(report['observation']['checks'][0]['passed'], 0)

    def test_zero_cases_cannot_pass(self):
        self.cargo.write_text('#!' + sys.executable + '\n'
                              'print("test result: ok. 0 passed; 0 failed; 0 ignored")\n')
        report = self.dispatch()
        self.assertEqual(report['outcome'], 'failed')

    def test_runner_preserves_cargo_multicall_symlink_name(self):
        launcher = self.base / 'launcher'
        self.cargo.rename(launcher)
        launcher.write_text('#!' + sys.executable + '\n'
                            'import os, sys\n'
                            'if os.path.basename(sys.argv[0]) != "cargo": raise SystemExit(1)\n'
                            'selector = sys.argv[sys.argv.index("--") - 1]\n'
                            'print("test " + selector + " ... ok")\n'
                            'print("test result: ok. 1 passed; 0 failed;")\n')
        self.cargo.symlink_to(launcher)
        self.assertEqual(self.dispatch()['outcome'], 'passed')

    def test_failure_output_is_not_published(self):
        self.cargo.write_text('#!' + sys.executable + '\n'
                              'print("Bearer fixture-secret plaintext-payload")\n'
                              'raise SystemExit(1)\n')
        report = self.dispatch()
        self.assertEqual(report['outcome'], 'failed')
        self.assertNotIn('fixture-secret', json.dumps(report))
        self.assertNotIn('plaintext-payload', json.dumps(report))

    def test_inventory_requires_every_observation_for_each_case(self):
        reports = [{'scenario': name, 'outcome': 'passed', 'reason': None,
                    'simulation': name in run._TEST_FAULTS}
                   for name in run._FAULT_SCENARIOS]
        rows = run._fault_inventory(reports)
        self.assertEqual(len(rows), 26)
        self.assertTrue(all(row['outcome'] == 'passed' for row in rows))
        crash = next(report for report in reports if report['scenario'] == 'crash_recovery')
        crash.update(outcome='failed', reason='native fixture failed')
        rows = {row['case_id']: row for row in run._fault_inventory(reports)}
        self.assertEqual(rows['spec10-05']['outcome'], 'failed')
        self.assertEqual(rows['spec10-06']['outcome'], 'failed')
        self.assertEqual(rows['spec10-01']['outcome'], 'passed')

    def test_retention_allows_new_ack_entries_but_refuses_missing_or_changed_original(self):
        original = ('run', 'mailbox', 1, 'hash', 1024, 'receipt', 'hash', 1024)
        ack = ('run', 'mailbox', 2, 'ack-hash', 1024, 'ack-receipt', 'ack-hash', 1024)
        run._require_retained_entries((original,), (original, ack))
        with self.assertRaises(run.OwnershipError):
            run._require_retained_entries((original,), (ack,))
        changed = (*original[:5], 'different-receipt', *original[6:])
        with self.assertRaises(run.OwnershipError):
            run._require_retained_entries((original,), (changed, ack))

    def test_quota_rejects_full_pair_while_allowing_third_relay_failover(self):
        message = {'id': 'message', 'stored_whole': '0',
                   'objects': [{'hash': 'ciphertext'}],
                   'uploads': [{'acknowledged': 1, 'pin': 'third', 'run': 'run'}]}
        status = {'messages': [message], 'remote_entries': [
            {'hash': 'ciphertext', 'pin': 'third', 'run': 'run'}]}
        sent = {'id': 'message'}
        pair = {('first', 'run'), ('second', 'run')}
        run._reject_quota_message(status, sent, pair)
        message['uploads'][0]['pin'] = 'first'
        with self.assertRaises(run.OwnershipError):
            run._reject_quota_message(status, sent, pair)

    def test_quota_successful_third_receipt_needs_no_failed_attempts(self):
        objects = [{'recipient': member, 'hash': str(member), 'length': 1024}
                   for member in (1, 2, 3)]
        rows = [{'message': 'message', 'recipient': member, 'hash': str(member),
                 'pin': pin, 'run': pin, 'mailbox': str(member) + pin,
                 'acknowledged': int(pin == 'third'), 'attempts': int(pin != 'third')}
                for member in (1, 2, 3) for pin in ('first', 'second', 'third')]
        message = {'id': 'message', 'objects': objects, 'uploads': rows}
        status = {'messages': [message], 'diagnostics': {'upload_retries': rows}}
        context = SimpleNamespace(inboxes=[
            {'member': member, 'pin': pin, 'run': pin, 'mailbox': str(member) + pin}
            for member in (1, 2, 3) for pin in ('first', 'second', 'third')])
        third = SimpleNamespace(receipt_key='third', run_id='third')
        rejected, accepted = run._quota_upload_bindings(
            status, {'id': 'message'}, {('first', 'first'), ('second', 'second')}, third, context)
        self.assertEqual(len(rejected), 6)
        self.assertEqual(len(accepted), 3)
        self.assertTrue(all(row['acknowledged'] == 1 for row in accepted))


if __name__ == '__main__':
    unittest.main()
