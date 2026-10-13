import json
import sqlite3
from types import SimpleNamespace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import hosted_setup
import run
import three_members
import relay_payment


class HostedAcceptanceTests(unittest.TestCase):
    def test_device_comparison_requires_two_hosts_and_every_certified_member(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for count in (3, 4):
                paths = [root / f'{count}-{slot}.json' for slot in range(1, count + 1)]
                reports = []
                for slot, path in enumerate(paths, 1):
                    native = {'policy': f'2-of-{count}', 'vault': 'a' * 64,
                              'own_slot': slot, 'fingerprint': 'fingerprint',
                              'address': 'address', 'group_ak': 'b' * 64,
                              'handoff': 'ready', 'configuration_digest': 'c' * 64,
                              'development': False, 'native_checkpoint': 'd' * 64,
                              'relays': [{'endpoint': f'https://relay{index}.example'}
                                         for index in range(1, 4)]}
                    report = {'kind': 'operator_collected_device',
                              'host_id': 'host-a' if slot == 1 else 'host-b',
                              'native_binary_sha256': 'e' * 64, 'native': native}
                    path.write_text(json.dumps(report))
                    reports.append(report)
                accepted = hosted_setup.compare_devices(paths, count)
                self.assertEqual(accepted['distinct_hosts'], 2)
                self.assertEqual(accepted['members'], count)
                with self.assertRaises(run.OwnershipError):
                    hosted_setup.compare_devices(paths[:-1], count)
                for report, path in zip(reports, paths):
                    path.write_text(json.dumps({**report, 'host_id': 'host-a'}))
                with self.assertRaises(run.OwnershipError):
                    hosted_setup.compare_devices(paths, count)
                for report, path in zip(reports, paths):
                    path.write_text(json.dumps(report))
                changed = {**reports[-1], 'native': {**reports[-1]['native'],
                                                    'configuration_digest': 'f' * 64}}
                paths[-1].write_text(json.dumps(changed))
                with self.assertRaises(run.OwnershipError):
                    hosted_setup.compare_devices(paths, count)

    def test_finished_payment_returns_saved_broadcast_result(self):
        process = SimpleNamespace(poll=lambda: 0, returncode=0,
                                  communicate=lambda **kwargs: (b'broadcast txid=hash', b''))
        with patch.object(run, '_remaining', return_value=10):
            output = relay_payment.await_members([process], 100, None)
        self.assertEqual(output, ['broadcast txid=hash'])

    def test_failed_finisher_keeps_bounded_private_diagnostics(self):
        with tempfile.TemporaryDirectory() as temporary:
            owner = SimpleNamespace(root=Path(temporary))
            diagnostic = b'node refused existing input' * 4000
            process = SimpleNamespace(poll=lambda: 1, returncode=1,
                communicate=lambda **kwargs: (b'', diagnostic))
            with patch.object(run, '_remaining', return_value=10), \
                    self.assertRaises(run.OwnershipError):
                relay_payment.await_members([process], 100, owner)
            saved = owner.root / 'finisher-failure-0.private'
            self.assertEqual(saved.read_bytes(), diagnostic[:run.OwnedRun.CAPTURE_OUTPUT_LIMIT])
            self.assertEqual(saved.stat().st_mode & 0o777, 0o600)

    def test_transport_reuse_requires_exact_certified_source_before_copying(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for count in (3, 4):
                source = root / f'source-{count}'
                retained = SimpleNamespace(root=root / f'retained-{count}')
                source.mkdir(); retained.root.mkdir()
                (source / 'roster.json').write_bytes(b'certified roster')
                (retained.root / 'roster.json').write_bytes(b'certified roster')
                for slot in range(1, count + 1):
                    original = source / f'member-{slot}'
                    saved = retained.root / 'members' / str(slot)
                    for member in (original, saved):
                        (member / 'secrets').mkdir(parents=True)
                        for name in ('identity.sealed', 'vault.sealed', 'activation.sealed',
                                     'relay-config-0000000000000001.sealed'):
                            (member / 'secrets' / name).write_bytes(f'{slot}:{name}'.encode())
                    (original / 'pass.txt').write_bytes(b'private fixture pass')
                    (saved / 'passphrase').write_bytes(b'private fixture pass')
                with patch.object(hosted_setup, 'copy_transport_database') as copy:
                    hosted_setup.reuse_transport_journals(source, retained, count)
                    self.assertEqual(copy.call_count, count)
                (retained.root / 'members' / str(count) / 'secrets/identity.sealed').write_bytes(b'foreign')
                with patch.object(hosted_setup, 'copy_transport_database') as copy:
                    with self.assertRaises(run.OwnershipError):
                        hosted_setup.reuse_transport_journals(source, retained, count)
                    copy.assert_not_called()
                (retained.root / 'roster.json').write_bytes(b'foreign roster')
                with patch.object(hosted_setup, 'copy_transport_database') as copy:
                    with self.assertRaises(run.OwnershipError):
                        hosted_setup.reuse_transport_journals(source, retained, count)
                    copy.assert_not_called()

    def test_foreign_or_existing_root_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / 'foreign'
            root.mkdir()
            saved = root / 'saved'
            saved.write_bytes(b'preserve')
            with self.assertRaises(run.OwnershipError):
                run.OwnedRun.create(root)
            self.assertEqual(saved.read_bytes(), b'preserve')

    def test_public_evidence_refuses_secret_fields_and_false_readiness(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'evidence.json'
            public = {'policy': '2-of-4', 'vault': 'a' * 64, 'address': 'uregtest1address',
                      'group_ak': 'b' * 64, 'ready_members': [1, 2, 3, 4],
                      'configuration_sha256': 'c' * 64, 'config_key': 'd' * 64,
                      'native_binary_sha256': 'e' * 64, 'separate_host_https': False, 'process_kill': False}
            path.write_text(json.dumps(public))
            self.assertEqual(hosted_setup.public_evidence(path, 4), public)
            for change in ({'passphrase': 'secret'}, {'ready_members': [1, 2, 3]}, {'separate_host_https': True}):
                path.write_text(json.dumps({**public, **change}))
                with self.assertRaises(run.OwnershipError):
                    hosted_setup.public_evidence(path, 4)

    def test_capacity_drains_saved_outbox_before_retry_and_other_failures_stop(self):
        capacity = run.OwnedCommandError(run.CapturedOutput(1, b'', b'capacity\n'))
        with patch.object(run, '_member_text', side_effect=[capacity, '', 'poll=ok\n']) as command:
            three_members.poll(None, None, None, 100)
            self.assertEqual([call.args[4] for call in command.call_args_list], ['poll', 'upload', 'poll'])
        identity = run.OwnedCommandError(run.CapturedOutput(1, b'', b'identity\n'))
        with patch.object(run, '_member_text', side_effect=identity) as command:
            with self.assertRaises(run.OwnershipError):
                three_members.poll(None, None, None, 100)
            self.assertEqual(command.call_count, 1)

    def test_payment_actions_wait_only_for_exact_missing_authenticated_messages(self):
        waiting = run.CapturedOutput(1, b'', b'error: waiting for member 2 Commitment; sync relay inbox and retry\n')
        accepted = run.CapturedOutput(0, b'payment package published')
        owner = SimpleNamespace(capture=lambda *args, **kwargs: None)
        member = SimpleNamespace(root=Path('/private/tmp'))
        with patch.object(owner, 'capture', side_effect=[waiting, accepted]) as capture, \
                patch.object(run, '_remaining', return_value=10), \
                patch.object(relay_payment.time, 'monotonic', return_value=0):
            pumps = []
            result = relay_payment.await_action(owner, ['command'], member, lambda: pumps.append(1), 100)
            self.assertEqual(result, accepted)
            self.assertEqual(pumps, [1])
            self.assertEqual(capture.call_count, 2)
        for error in (b'error: invalid signature\n', b'error: waiting for member 9 Share; sync relay inbox and retry\n', b'error: waiting for member 2 Commitment; sync relay inbox and retry\nprivate data'):
            with patch.object(owner, 'capture', return_value=run.CapturedOutput(1, b'', error)) as capture, \
                    patch.object(run, '_remaining', return_value=10):
                with self.assertRaises(run.OwnershipError):
                    relay_payment.await_action(owner, ['command'], member, lambda: self.fail('fatal error retried'), 100)
                self.assertEqual(capture.call_count, 1)

    def test_starting_kill_reports_no_unperformed_backup_restoration(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            binary = root / 'fixture'
            binary.write_bytes(b'owned fixture')
            creator = root / 'runtime/creator-3'
            creator.mkdir(parents=True)
            (creator / 'checkpoint-killed.json').write_text(json.dumps({
                'phase': 1, 'generation': 2, 'digest': 'a' * 64}))
            output = (hosted_setup.CASE + '\ntest result: ok. 1 passed; 0 failed;').encode()
            owner = SimpleNamespace(root=root, capture=lambda *args, **kwargs: run.CapturedOutput(0, output))
            with patch.object(hosted_setup.subprocess, 'run', return_value=SimpleNamespace(stdout='compiler')):
                report = hosted_setup.execute(owner, 3, binary, phase=1)
            self.assertIsNone(report['handoff'])
            self.assertEqual(report['backup_restoration_members'], [])
            self.assertEqual([item['phase'] for item in report['actual_process_kills']], [1])

    def test_coordinator_transport_advances_without_changing_saved_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            original = root / 'original.sqlite3'
            destination = root / 'coordinator.sqlite3'
            with sqlite3.connect(original) as database:
                database.execute('CREATE TABLE cursor (position INTEGER)')
                database.execute('INSERT INTO cursor VALUES (1)')
            database.close()
            initial = original.read_bytes()
            hosted_setup.copy_transport_database(original, destination)
            completed = root / 'completed.sqlite3'
            hosted_setup.copy_transport_database(original, completed)
            with sqlite3.connect(completed) as database:
                database.execute('UPDATE cursor SET position=2')
            database.close()
            hosted_setup.copy_transport_database(completed, destination)
            with sqlite3.connect(destination.as_uri() + '?mode=ro', uri=True) as database:
                self.assertEqual(database.execute('SELECT position FROM cursor').fetchone(), (2,))
            database.close()
            self.assertEqual(original.read_bytes(), initial)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)

    def test_four_member_incoming_consumes_exact_complete_roster(self):
        header = f"incoming sender=2 id={'a' * 64} digest={'b' * 64} kind=test session=- readiness=ready received_whole=0 received_author=1 root={'c' * 64}"
        rows = [f"incoming_received_member sender=2 id={'a' * 64} digest={'b' * 64} member={slot} value=1" for slot in range(1, 5)]
        cursor = run._StatusCursor([header, *rows, 'next-record'])
        parsed = run._parse_incoming(cursor, 4)
        self.assertEqual([item['member'] for item in parsed['members']], [1, 2, 3, 4])
        self.assertEqual(cursor.peek(), 'next-record')
        for incomplete in (rows[:-1], [*rows[:3], rows[2]]):
            with self.assertRaises(run.OwnershipError):
                run._parse_incoming(run._StatusCursor([header, *incomplete]), 4)

    def test_saved_configuration_export_preserves_source_and_copies_sqlite(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            runtime = root / 'runtime'
            runtime.mkdir()
            for slot in range(1, 4):
                member = runtime / ('creator-3' if slot == 1 else f'peer-3-{slot}')
                (member / 'secrets').mkdir(parents=True)
                (member / 'transport').mkdir()
                if slot == 1:
                    (member / 'roster.json').write_bytes(b'certified roster')
                (member / 'drive-pass').write_bytes(b'fixture pass')
                for name in ('identity.sealed', 'vault.sealed', 'activation.sealed', 'relay-config-0000000000000001.sealed'):
                    (member / 'secrets' / name).write_bytes(name.encode())
                with sqlite3.connect(member / 'transport/client.sqlite3') as database:
                    database.execute('PRAGMA journal_mode=WAL')
                    database.execute('CREATE TABLE fixture (slot INTEGER)')
                    database.execute('INSERT INTO fixture VALUES (?)', (slot,))
                database.close()
            before = {path: path.read_bytes() for path in runtime.rglob('*') if path.is_file()}
            destination = hosted_setup.export_hosted_source(runtime, root / 'export', 3)
            for slot in range(1, 4):
                member = destination / f'member-{slot}'
                with sqlite3.connect((member / 'transport/client.sqlite3').as_uri() + '?mode=ro', uri=True) as database:
                    self.assertEqual(database.execute('SELECT slot FROM fixture').fetchall(), [(slot,)])
                self.assertEqual((member / 'transport/client.sqlite3').stat().st_mode & 0o777, 0o600)
            self.assertEqual({path: path.read_bytes() for path in before}, before)

    def test_failed_fixture_and_zero_tests_cannot_report_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            owner = run.OwnedRun.create(Path(temporary).resolve() / 'owned')
            try:
                for result in (run.CapturedOutput(1, b'secret stderr'),
                               run.CapturedOutput(0, b'test result: ok. 0 passed; 0 failed;')):
                    with patch.object(owner, 'capture', return_value=result):
                        with self.assertRaisesRegex(run.OwnershipError, 'excluded') as error:
                            hosted_setup.execute(owner, 4, Path('/usr/bin/true'))
                        self.assertNotIn('secret', str(error.exception))
            finally:
                owner.close()


if __name__ == '__main__':
    unittest.main()
