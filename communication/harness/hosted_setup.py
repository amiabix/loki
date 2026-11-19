#!/usr/bin/env python3
"""Owned hosted setup acceptance, with public evidence and explicit unmet gates."""
import argparse
from contextlib import closing
import hashlib
import importlib.util
import json
import os
import platform
from pathlib import Path
import re
import select
import signal
import time
import subprocess
import sqlite3
import shutil
import tempfile
import sys

import run
import three_members

CASE = 'owned_real_services_provision_creator_inboxes_and_save_invites_for_both_policies'
PHASES = tuple(range(9))


class HostedRun(run.OwnedRun):
    def capture_group(self, jobs, *, timeout, output_limit=16384):
        if len(jobs) != 1 or not 0 < timeout <= 1800:
            raise run.OwnershipError('Hosted fixture requires one bounded owned process group')
        argv, cwd = self._command(*jobs[0])
        self._authorize_spawn()
        child = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, start_new_session=True)
        self._children.append(child)
        streams = {child.stdout: True, child.stderr: False}
        output = bytearray()
        diagnostics = bytearray()
        deadline = time.monotonic() + timeout
        settled = False
        try:
            while streams:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise run.OwnershipError('Owned hosted fixture exceeded its deadline')
                ready, _, _ = select.select(list(streams), [], [], remaining)
                for stream in ready:
                    raw = os.read(stream.fileno(), 4096)
                    if not raw:
                        del streams[stream]
                        stream.close()
                    elif streams[stream]:
                        output.extend(raw)
                        if len(output) > output_limit:
                            raise run.OwnershipError('Hosted fixture exceeded its public output bound')
                    else:
                        diagnostics.extend(raw)
                        if len(diagnostics) > output_limit:
                            raise run.OwnershipError('Hosted fixture exceeded its private output bound')
            code = child.wait(timeout=5)
            settled = True
            if code:
                run._write_new(self.root / 'fixture-failure.private', bytes(output) + bytes(diagnostics), 0o600)
            return [run.CapturedOutput(code, bytes(output))]
        finally:
            if not settled:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait(timeout=5)
            for stream in streams:
                stream.close()

def fixture_binary(core):
    target = Path(os.environ.get('CARGO_TARGET_DIR', core / 'target'))
    if not target.is_absolute():
        target = core / target
    candidates = [path for path in (target / 'debug/deps').glob('setup_relay-*')
                  if path.is_file() and path.suffix == '' and os.access(path, os.X_OK)]
    if not candidates:
        raise run.OwnershipError('Build the setup_relay test artifact before acceptance')
    return max(candidates, key=lambda path: path.stat().st_mtime_ns).resolve()


def public_evidence(path, count):
    evidence = json.loads(path.read_text())
    fields = {'policy', 'vault', 'address', 'group_ak', 'ready_members', 'configuration_sha256',
              'config_key', 'native_binary_sha256', 'separate_host_https', 'process_kill'}
    if set(evidence) != fields or evidence['policy'] != f'2-of-{count}' \
            or evidence['ready_members'] != list(range(1, count + 1)) \
            or any(not isinstance(evidence[key], str) or re.fullmatch(r'[0-9a-f]{64}', evidence[key]) is None
                   for key in ('vault', 'group_ak', 'configuration_sha256', 'config_key', 'native_binary_sha256')) \
            or not isinstance(evidence['address'], str) or not evidence['address'].startswith('uregtest') \
            or evidence['separate_host_https'] is not False or type(evidence['process_kill']) is not bool:
        raise run.OwnershipError('Native fixture returned invalid public evidence')
    return evidence


def execute(owner, count, binary, *, phase=None, offline_relay=None, resume_runtime=None):
    runtime = resume_runtime if resume_runtime is not None else owner.root / 'runtime'
    environment = ['LOKI_HOSTED_RUN_ROOT=' + str(runtime), 'LOKI_HOSTED_MEMBERS=' + str(count)]
    if resume_runtime is not None:
        environment.append('LOKI_HOSTED_RESUME_ROOT=' + str(runtime))
    if offline_relay is not None:
        environment.append('LOKI_HOSTED_OFFLINE_RELAY=' + str(offline_relay))
    if phase is not None:
        environment.append('LOKI_HOSTED_KILL_PHASE=' + str(phase))
    result = owner.capture(['/usr/bin/env', *environment, str(binary), '--exact', CASE,
                            '--test-threads=1'], cwd=owner.root, timeout=1800)
    if result.returncode or re.search(rb'test result: ok\. 1 passed; 0 failed;', result.stdout) is None \
            or CASE.encode() not in result.stdout:
        raise run.OwnershipError('Hosted integration fixture failed; private diagnostics are excluded from reports')
    evidence = None if phase == 1 else public_evidence(runtime / 'handoff-evidence.json', count)
    if phase is not None:
        phases = (0, 2, 3, 4, 5, 6, 7, 8) if phase == 'all' else (phase,)
        checkpoints = []
        for expected_phase in phases:
            name = f'checkpoint-killed-{expected_phase}.json' if phase == 'all' else 'checkpoint-killed.json'
            killed = runtime / f'creator-{count}' / name
            if not killed.is_file():
                raise run.OwnershipError('The selected checkpoint was not actually killed')
            checkpoint = json.loads(killed.read_text())
            if set(checkpoint) != {'phase', 'generation', 'digest'} or checkpoint['phase'] != expected_phase \
                    or type(checkpoint['generation']) is not int or checkpoint['generation'] < 1 \
                    or re.fullmatch(r'[0-9a-f]{64}', checkpoint['digest']) is None:
                raise run.OwnershipError('Invalid public kill checkpoint')
            checkpoints.append(checkpoint)
    else:
        checkpoints = []
    return {'result': 'selected_checks_passed', 'members': count, 'handoff': evidence,
            'actual_process_kills': checkpoints, 'offline_relay': offline_relay,
            'resumed_saved_handoff': resume_runtime is not None,
            'backup_restoration_members': [slot for slot in range(1, count + 1)
                if evidence is not None and (resume_runtime is None or (runtime / (f'creator-{count}' if slot == 1 else f'peer-{count}-{slot}') / 'checked-words').is_file())], 'compiler': subprocess.run(['rustc', '+1.91.0', '--version'],
                    capture_output=True, text=True, check=True).stdout.strip(),
            'fixture_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
            'unmet_release_gates': ['distinct-host HTTPS', 'independent security review',
                                   'hosted-vault mined payment acceptance']}


def copy_transport_database(database_path, destination):
    with tempfile.TemporaryDirectory(prefix='snapshot-', dir=destination.parent) as temporary:
        snapshot = Path(temporary) / 'source.sqlite3'
        shutil.copyfile(database_path, snapshot)
        os.chmod(snapshot, 0o600)
        wal = database_path.with_name(database_path.name + '-wal')
        if wal.is_file():
            shutil.copyfile(wal, snapshot.with_name(snapshot.name + '-wal'))
            os.chmod(snapshot.with_name(snapshot.name + '-wal'), 0o600)
        output = Path(temporary) / 'output.sqlite3'
        with closing(sqlite3.connect(snapshot)) as database:
            with closing(sqlite3.connect(output)) as target:
                database.backup(target)
                target.execute('PRAGMA journal_mode=DELETE')
        os.chmod(output, 0o600)
        os.replace(output, destination)
        descriptor = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def export_hosted_source(runtime, destination, count):
    run._mkdir(destination)
    creator = runtime / f'creator-{count}'
    roster = (creator / 'roster.json').read_bytes()
    run._write_new(destination / 'roster.json', roster, 0o644)
    for slot in range(1, count + 1):
        original = creator if slot == 1 else runtime / f'peer-{count}-{slot}'
        member = destination / f'member-{slot}'
        run._mkdir(member)
        run._mkdir(member / 'secrets')
        run._mkdir(member / 'transport')
        run._mkdir(member / 'transport')
        for name in ('identity.sealed', 'vault.sealed', 'activation.sealed', 'relay-config-0000000000000001.sealed'):
            raw = (original / 'secrets' / name).read_bytes()
            run._write_new(member / 'secrets' / name, raw, 0o600)
        run._write_new(member / 'pass.txt', (original / 'drive-pass').read_bytes(), 0o600)
        copy_transport_database(original / 'transport/client.sqlite3', member / 'transport/client.sqlite3')
    return destination


def reuse_transport_journals(source, retained, count):
    if (retained.root / 'roster.json').read_bytes() != (source / 'roster.json').read_bytes():
        raise run.OwnershipError('Retained payment roster differs from certified source')
    for slot in range(1, count + 1):
        original = source / f'member-{slot}'
        saved = retained.root / 'members' / str(slot)
        for name in ('identity.sealed', 'vault.sealed', 'activation.sealed',
                     'relay-config-0000000000000001.sealed'):
            if three_members.read_source(original / 'secrets' / name, 4 * 1024 * 1024) != \
                    three_members.read_source(saved / 'secrets' / name, 4 * 1024 * 1024):
                raise run.OwnershipError('Retained payment member differs from certified source')
        if three_members.read_source(original / 'pass.txt', 65536) != \
                three_members.read_source(saved / 'passphrase', 65536):
            raise run.OwnershipError('Retained payment member differs from certified source')
    for slot in range(1, count + 1):
        copy_transport_database(retained.root / 'members' / str(slot) / 'transport/client.sqlite3',
                                source / f'member-{slot}/transport/client.sqlite3')


def payments(owner, source_owner, count, name, poc, offline_relay=None, selected_pairs=None,
             transport_source=None):
    runtime = source_owner.root / 'runtime'
    evidence = public_evidence(runtime / 'handoff-evidence.json', count)
    source = export_hosted_source(runtime, owner.root / 'source', count)
    if transport_source is not None:
        reuse_transport_journals(source, transport_source, count)
    sys.path.insert(0, str(core))
    from ths import THS
    chain = THS(name)
    chain.check()
    chain.fund(evidence['address'], 3)
    spec = importlib.util.spec_from_file_location('owned_recipient', core / 'run-member-payment.py')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    setup = run.find_binary('loki_setup_member', workspace=core)
    pay = run.find_binary('loki_member_payment', workspace=core)
    recipient_root = owner.root / 'recipient'
    _, _, address = helper.create_vault(recipient_root, 8, setup, chain.env(), count)
    if address == evidence['address']:
        raise run.OwnershipError('Recipient is not independent from hosted vault')
    run._mkdir(owner.root / 'cases')
    required_pairs = ('AB', 'AC', 'BC') if count == 3 else ('AB', 'AC', 'AD', 'BC', 'BD', 'CD')
    pairs = tuple(selected_pairs) if selected_pairs is not None else required_pairs
    if not pairs or len(set(pairs)) != len(pairs) or any(pair not in required_pairs for pair in pairs):
        raise run.OwnershipError('Selected payment pairs do not match the supported policy')
    reports = []
    for pair in pairs:
        case = owner.root / 'cases' / pair
        run._mkdir(case)
        work = case / 'payment'
        prepared = subprocess.run([str(pay), 'prepare', str(source / 'member-1'),
            str(source / 'member-1/pass.txt'), str(source / 'roster.json'), str(work), address,
            '1000000', 'hosted policy acceptance ' + pair, pair], env=chain.env(),
            capture_output=True, timeout=180)
        if prepared.returncode:
            raise run.OwnershipError('Hosted proposal preparation failed')
        argv = [sys.executable, str(Path(__file__).with_name('relay_payment.py')), '--payment-root', str(case),
                '--source', str(source), '--recipient-root', str(recipient_root), '--hosted-runtime', str(runtime),
                '--run-root', str(case / 'private-members'), '--name', name]
        if offline_relay is not None:
            argv.extend(['--offline-relay', str(offline_relay)])
        result = owner.capture(['/usr/bin/env', 'LOKI_RPC=' + chain.rpc_address, *argv], cwd=owner.root, timeout=1800)
        if result.returncode:
            raise run.OwnershipError('Hosted mined policy acceptance failed')
        report = json.loads((case / 'private-members/relay-payment-report.json').read_text())
        expected = [ord(letter) - ord('A') + 1 for letter in pair]
        if report.get('result') != 'accepted' or report.get('signers') != expected or not report.get('hosted_configuration')                 or not report.get('recipient_decrypted') or report.get('members') != count                 or report.get('independent_finishers') != [slot for slot in range(1, count + 1) if slot not in expected]:
            raise run.OwnershipError('Hosted payment report does not establish the required policy')
        reports.append(report)
        for slot in range(1, count + 1):
            copy_transport_database(case / f'private-members/members/{slot}/transport/client.sqlite3',
                                    source / f'member-{slot}/transport/client.sqlite3')
    return {'result': 'selected_checks_passed', 'members': count, 'payments': reports,
            'offline_relay': offline_relay, 'required_pairs': list(required_pairs),
            'selected_pairs': list(pairs), 'unmet_payment_pairs': [pair for pair in required_pairs if pair not in pairs],
            'unmet_release_gates': ['distinct-host HTTPS', 'independent security review']}

def device_evidence(owner, member_root, passphrase_file, core):
    native = run.find_binary('loki_setup_member', workspace=core)
    result = owner.capture([str(native), 'setup-evidence', str(member_root.resolve()), str(passphrase_file.resolve())],
                           cwd=owner.root, timeout=120)
    if result.returncode:
        raise run.OwnershipError('Native device evidence requires complete signed activation')
    evidence = json.loads(result.stdout)
    expected = {'policy', 'vault', 'own_slot', 'fingerprint', 'address', 'group_ak', 'handoff',
                'development', 'configuration_digest', 'native_checkpoint', 'relays'}
    if set(evidence) != expected or evidence['development'] is not False or evidence['handoff'] != 'ready'             or len(evidence['relays']) != 3 or any(not route['endpoint'].startswith('https://') for route in evidence['relays']):
        raise run.OwnershipError('Device evidence must use production verified HTTPS')
    return {'kind': 'operator_collected_device', 'host_id': hashlib.sha256(platform.node().encode()).hexdigest(),
            'native_binary_sha256': hashlib.sha256(native.read_bytes()).hexdigest(), 'native': evidence}


def compare_devices(paths, count):
    reports = [json.loads(path.read_text()) for path in paths]
    if len(reports) != count or any(set(report) != {'kind', 'host_id', 'native_binary_sha256', 'native'}
                                  or report['kind'] != 'operator_collected_device' for report in reports):
        raise run.OwnershipError('Select one collector report from every member device')
    host_count = len({report['host_id'] for report in reports})
    if host_count < 2:
        raise run.OwnershipError('Collector host metadata does not establish two distinct hosts')
    native = [report['native'] for report in reports]
    if {record['own_slot'] for record in native} != set(range(1, count + 1)):
        raise run.OwnershipError('Device reports omit a required member')
    for key in ('policy', 'vault', 'fingerprint', 'address', 'group_ak', 'handoff', 'configuration_digest', 'relays'):
        if any(record[key] != native[0][key] for record in native):
            raise run.OwnershipError('Device reports disagree on certified setup or pinned configuration')
    if native[0]['policy'] != f'2-of-{count}' or any(record['development'] is not False or record['handoff'] != 'ready' for record in native)             or any(not route['endpoint'].startswith('https://') for route in native[0]['relays']):
        raise run.OwnershipError('Device reports do not establish production HTTPS activation')
    return {'result': 'device_reports_consistent', 'members': count, 'distinct_hosts': host_count,
            'vault': native[0]['vault'],
            'configuration_digest': native[0]['configuration_digest'], 'devices': reports,
            'evidence_basis': 'native verified activation and operator-collected host metadata',
            'unmet_release_gates': ['independent security review']}

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('acceptance', 'resume-handoff', 'faults', 'payments', 'device-evidence', 'distinct-hosts', 'validate-config'))
    parser.add_argument('--run-root', type=Path)
    parser.add_argument('--members', type=int, choices=(3, 4))
    parser.add_argument('--fixture', type=Path)
    parser.add_argument('--phase', type=int, choices=PHASES)
    parser.add_argument('--resume-checkpoints', action='store_true')
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--trusted-key')
    parser.add_argument('--source-run', type=Path)
    parser.add_argument('--source-run-id')
    parser.add_argument('--transport-source-run', type=Path)
    parser.add_argument('--transport-source-run-id')
    parser.add_argument('--name')
    parser.add_argument('--pairs', nargs='+', choices=('AB', 'AC', 'AD', 'BC', 'BD', 'CD'))
    parser.add_argument('--offline-relay', type=int, choices=(1, 2, 3))
    parser.add_argument('--member-root', type=Path)
    parser.add_argument('--passphrase-file', type=Path)
    parser.add_argument('--device-reports', type=Path, nargs='+')
    args = parser.parse_args(argv)
    communication, core = run._default_workspaces()
    if args.command == 'validate-config':
        if args.bundle is None or args.trusted_key is None:
            parser.error('Configuration validation requires a bundle and trusted signing key')
        native = run.find_binary('loki_setup_member', workspace=core)
        result = subprocess.run([str(native), 'setup-config-check', str(args.bundle), '--operator-key',
                                 args.trusted_key], capture_output=True, timeout=30)
        if result.returncode:
            raise run.OwnershipError('Production operator configuration verification failed')
        print(result.stdout.decode().strip())
        return 0
    if args.run_root is None or (args.members is None and args.command != 'device-evidence'):
        parser.error('Acceptance requires a new owned root and member count')
    binary = args.fixture.resolve() if args.fixture else fixture_binary(core) if args.command in ("acceptance", "resume-handoff", "faults") else None
    owner = HostedRun.create(args.run_root)
    try:
        if args.command == 'device-evidence':
            if args.member_root is None or args.passphrase_file is None:
                parser.error('Device evidence requires this member root and private passphrase file')
            report = device_evidence(owner, args.member_root, args.passphrase_file, core)
        elif args.command == 'distinct-hosts':
            if not args.device_reports:
                parser.error('Select reports collected independently on every member host')
            report = compare_devices(args.device_reports, args.members)
        elif args.command == 'payments':
            if args.source_run is None or not args.source_run_id or not args.name:
                parser.error('Payments require a retained owned setup run, its exact run ID and a THS instance')
            source_owner = run.OwnedRun.reopen(args.source_run, expected_run_id=args.source_run_id)
            transport_source = None
            try:
                if args.transport_source_run is not None or args.transport_source_run_id is not None:
                    if args.transport_source_run is None or not args.transport_source_run_id:
                        raise run.OwnershipError('Transport reuse requires the exact stopped owner and run ID')
                    transport_source = run.OwnedRun.reopen(args.transport_source_run,
                        expected_run_id=args.transport_source_run_id)
                report = payments(owner, source_owner, args.members, args.name, poc,
                                  args.offline_relay, args.pairs, transport_source)
            finally:
                if transport_source is not None:
                    transport_source.close()
                source_owner.close()
        elif args.command == 'resume-handoff':
            if args.source_run is None or not args.source_run_id or args.phase is not None:
                parser.error('Handoff recovery requires a retained owned run and its exact run ID')
            source_owner = run.OwnedRun.reopen(args.source_run, expected_run_id=args.source_run_id)
            try:
                report = execute(owner, args.members, binary, offline_relay=args.offline_relay,
                                 resume_runtime=source_owner.root / 'runtime',
                                 phase='all' if args.resume_checkpoints else None)
            finally:
                source_owner.close()
        elif args.command == 'acceptance':
            if args.phase is not None:
                parser.error('Use faults for checkpoint process kills')
            report = execute(owner, args.members, binary, offline_relay=args.offline_relay)
        else:
            phases = (args.phase,) if args.phase is not None else ('all', 1)
            children = []
            for phase in phases:
                child = HostedRun.create(owner.root / f'phase-{phase}')
                try:
                    children.append(execute(child, args.members, binary, phase=phase, offline_relay=args.offline_relay))
                    run._write_new(child.root / 'report.json', run._json_bytes(children[-1]), 0o644)
                finally:
                    child.close()
            report = {'result': 'selected_checks_passed', 'members': args.members,
                      'checkpoints': children, 'distinct_host_https': 'not_run'}
        run._write_new(owner.root / 'hosted-report.json', run._json_bytes(report), 0o644)
        print(run._json_bytes(report).decode(), end='')
        return 0
    finally:
        owner.close()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (run.OwnershipError, OSError, ValueError, KeyError, subprocess.TimeoutExpired, RuntimeError, sqlite3.Error):
        print('hosted_setup_failed; inspect the retained owned run', file=sys.stderr)
        sys.exit(1)
