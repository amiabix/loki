"""Local test relay services and per-member provisioning for the shared courier."""

import fcntl
import json
import os
import re
import secrets
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVER = HERE.parents[1] / 'communication' / 'target' / os.environ.get('LOKI_POC_BIN_PROFILE', 'debug') / 'loki-relay-server'


def save(path, value):
    fd, temporary = tempfile.mkstemp(prefix='.relay-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as out:
            json.dump(value, out)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def private_write(path, data):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(data)


def listening(port):
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=.2):
            return True
    except OSError:
        return False


def network_root(exchange):
    root = exchange / '.payment-relays'
    settings = root / 'settings.json'
    if settings.is_file():
        name = json.loads(settings.read_text()).get('network', 'network')
        if name != 'network' and not re.fullmatch(r'[0-9a-f]{64}', name):
            raise ValueError('Saved local relay network is invalid')
        return root / name
    current = root / 'network'
    if root.is_dir() and not (current / 'relays').is_dir():
        saved = [path for path in root.iterdir() if re.fullmatch(r'[0-9a-f]{64}', path.name)
                 and expandable_network(path)]
        if len(saved) == 1:
            return saved[0]
    return current


def expandable_network(root):
    try:
        for slot in (1, 2, 3):
            database = root / 'relays' / str(slot) / 'relay.sqlite3'
            connection = sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)
            try:
                count = connection.execute('SELECT mailbox_count FROM metadata WHERE singleton=1').fetchone()[0]
                if count < 1024:
                    return False
            finally:
                connection.close()
        return True
    except (sqlite3.Error, OSError, TypeError):
        return False


def ensure_network(root):
    if not SERVER.is_file():
        raise ValueError('Build the local relay server: cargo build --locked --manifest-path communication/Cargo.toml -p loki-relay-server')
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (root / '.setup.lock').open('a+b') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        for directory in ('relays', 'manifests', 'capabilities', 'couriers'):
            (root / directory).mkdir(mode=0o700, exist_ok=True)
        ports = []
        for slot in (1, 2, 3):
            relay = root / 'relays' / str(slot)
            operator = root / f'.operator-{slot}'
            if not (relay / 'manifest').exists():
                if not operator.exists():
                    private_write(operator, secrets.token_bytes(32))
                with socket.socket() as available:
                    available.bind(('127.0.0.1', 0))
                    port = available.getsockname()[1]
                result = subprocess.run([str(SERVER), 'init', '--root', str(relay),
                    '--provision-capability-file', str(operator), '--total-bytes', '67108864',
                    '--mailbox-bytes', '1048576', '--mailbox-count', '1024',
                    '--listen', f'127.0.0.1:{port}'], capture_output=True, text=True, timeout=30)
                if result.returncode:
                    raise ValueError(f'Could not initialize local relay {slot}: {result.stderr.strip()}')
            manifest = (relay / 'manifest').read_bytes()
            lines = manifest.decode('ascii').splitlines()
            if len(lines) != 3 or not re.fullmatch(r'http://127\.0\.0\.1:[0-9]+', lines[0]) \
                    or any(not re.fullmatch(r'[0-9a-f]{64}', pin) for pin in lines[1:]):
                raise ValueError('Saved local relay manifest is invalid')
            ports.append(int(lines[0].rsplit(':', 1)[1]))
            projection = root / 'manifests' / str(slot)
            projection.mkdir(mode=0o700, exist_ok=True)
            for path, data in ((projection / 'manifest', manifest),
                               (projection / 'mailbox-bytes', b'1048576\n'),
                               (root / 'capabilities' / lines[2], operator.read_bytes())):
                if path.exists():
                    if path.read_bytes() != data:
                        raise ValueError('Saved local relay configuration changed')
                else:
                    private_write(path, data)
        process = None
        with (root / '.serve.lock').open('a+b') as service_lock:
            try:
                fcntl.flock(service_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                running = True
            else:
                running = False
        if not running:
            with (root / 'supervisor.log').open('ab') as log:
                process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), 'serve', str(root)],
                    stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
            threading.Thread(target=process.wait, daemon=True).start()
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if all(listening(port) for port in ports):
                return
            if process and process.poll() not in (None, 0):
                raise ValueError('Local relay service could not start. Check supervisor.log in the saved relay directory.')
            time.sleep(.1)
        raise ValueError('Local relays did not become reachable; their saved data has been retained for retry')


def supervise(root):
    children = []
    with (root / '.serve.lock').open('a+b') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        def stop(_signal, _frame):
            raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, stop)
        try:
            for slot in (1, 2, 3):
                relay = root / 'relays' / str(slot)
                endpoint = (relay / 'manifest').read_text().splitlines()[0]
                log = (relay / 'service.log').open('ab')
                try:
                    children.append(subprocess.Popen([str(SERVER), 'serve', '--root', str(relay),
                        '--listen', endpoint.removeprefix('http://')], stdout=log, stderr=log,
                        stdin=subprocess.DEVNULL))
                finally:
                    log.close()
            save(root / 'supervisor.json', {'pid': os.getpid()})
            while all(child.poll() is None for child in children):
                time.sleep(.5)
        except KeyboardInterrupt:
            pass
        finally:
            for child in children:
                if child.poll() is None:
                    child.terminate()
            for child in children:
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
            (root / 'supervisor.json').unlink(missing_ok=True)


def configure_member(wallet, vault):
    member, local = wallet.vault_dir(vault)
    state_path = member / 'relay-setup.json'
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    networks = wallet.exchange / '.payment-relays'
    legacy = networks / vault
    network = legacy if state.get('managed') and (legacy / 'relays').is_dir() else network_root(wallet.exchange)
    common = ('--member-root', member, '--passphrase-file', '@pass', '--roster', member / 'roster.json')
    def relay(action, *extra):
        return wallet.command(action, *common, *extra, binary=wallet.relay_binary, timeout=120)
    if not state.get('managed'):
        existing = relay('status')
        if 'config absent=1' not in existing.splitlines():
            raise ValueError('This membership already has relay configuration. Its existing relays have been retained.')
    save(state_path, {**state, 'phase': 'starting', 'detail': 'Starting three local test relays.'})
    ensure_network(network)
    if not state.get('exported'):
        save(state_path, {**state, 'managed': True, 'phase': 'starting', 'detail': 'Provisioning this member’s relay inboxes.'})
        relay('provision', '--relay-manifest', network / 'manifests',
              '--provision-capability-files', network / 'capabilities')
        with tempfile.TemporaryDirectory(prefix='.relay-export-', dir=wallet.data) as temp:
            output = relay('export-config', '--courier-directory', temp)
            for name in re.findall(r'^courier=(.+)$', output, re.MULTILINE):
                match = re.fullmatch(rf'{vault}-relay-config-{local["slot"]}-([1-4])-1\.bin', name)
                if not match or int(match[1]) == local['slot'] or int(match[1]) > local['members']:
                    raise ValueError('Relay exported a configuration for an unexpected member')
                target_dir = network / 'couriers' / match[1]
                target_dir.mkdir(mode=0o700, exist_ok=True)
                target = target_dir / name
                raw = (Path(temp) / name).read_bytes()
                if target.exists():
                    if target.read_bytes() != raw:
                        raise ValueError('A saved relay configuration differs from the exported configuration')
                else:
                    private_write(target, raw)
        state = {'managed': True, 'exported': True, 'imported': [], 'phase': 'waiting'}
        save(state_path, state)
    imported = set(state.get('imported', []))
    inbox = network / 'couriers' / str(local['slot'])
    for owner in range(1, local["members"] + 1):
        if owner == local['slot'] or owner in imported:
            continue
        courier = inbox / f'{vault}-relay-config-{owner}-{local["slot"]}-1.bin'
        if not courier.is_file():
            continue
        with tempfile.TemporaryDirectory(prefix='.relay-import-', dir=wallet.data) as temp:
            private = Path(temp) / courier.name
            private_write(private, courier.read_bytes())
            relay('import-config', '--courier-file', private)
        imported.add(owner)
        state['imported'] = sorted(imported)
        save(state_path, state)
    missing = sorted(set(range(1, local["members"] + 1)) - imported - {local['slot']})
    if missing:
        state.update(phase='waiting', detail='Waiting for member ' + ' and '.join(map(str, missing)) + ' to unlock their signer and connect automatically.')
    else:
        output = relay('status', '--verify-relays')
        verified = re.findall(r'^remote_inbox .+ result=ok$', output, re.MULTILINE)
        if len(verified) != 3:
            raise ValueError('Not all three local relay inboxes passed verification')
        state.update(phase='ready', detail='Local test relays are configured and verified for this member.')
    save(state_path, state)


if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] != 'serve':
        raise SystemExit('local_relays.py serve <saved-network-directory>')
    supervise(Path(sys.argv[2]))
