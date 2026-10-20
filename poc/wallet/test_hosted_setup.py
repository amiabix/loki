import base64
import http.client
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
from member_app import Wallet, SignerSessions, make_signer_server
from hosted_setup import HostedSetup
from local_funding import fund_member, funding_status


class HostedControllerTests(unittest.TestCase):
    def test_fallback_native_secrets_have_no_visible_files(self):
        with tempfile.TemporaryDirectory() as temp:
            binary = Path(temp) / "read-secrets"
            binary.write_text("#!/usr/bin/env python3\n"
                              "import json, pathlib, sys\n"
                              "passfile, private, words = map(pathlib.Path, sys.argv[3:6])\n"
                              "with passfile.open() as source:\n"
                              "    pass1 = source.read()\n"
                              "    source.seek(0)\n"
                              "    pass2 = source.read()\n"
                              "print(json.dumps({'pass1': pass1, "
                              "'pass2': pass2, 'private': private.read_bytes().hex(), "
                              "'words': words.read_text(), "
                              "'visible': [p.name for p in pathlib.Path(sys.argv[2]).parent.iterdir() "
                              "if p.name.startswith('.hosted-command-')]}))\n")
            binary.chmod(0o700)
            self.wallet.setup = binary
            vault = self.wallet.data / "vault"
            result = json.loads(self.controller._native("setup-join", vault, "@private", "@words",
                                                         private=b"secret", words="backup words"))
            self.assertEqual(result["pass1"], self.wallet.passphrase)
            self.assertEqual(result["pass2"], self.wallet.passphrase)
            self.assertEqual(result["private"], b"secret".hex())
            self.assertEqual(result["words"], "backup words")
            self.assertEqual(result["visible"], [])

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        bundle = root / 'operators'
        bundle.write_bytes(b'public signed operator bundle')
        grant = root / 'grant'
        grant.write_bytes(b'scoped enrollment')
        self.wallet = Wallet(root / 'member', root / 'exchange', transport='hosted',
                             operator_bundle=bundle, operator_key='a' * 64, enrollment_grant=grant)
        self.addCleanup(self.wallet.close)
        (self.wallet.data / 'profile').mkdir()
        (self.wallet.data / 'profile/profile.sealed').write_bytes(b'opaque saved profile fixture')
        self.wallet.profile_data = {'id': 'alice', 'name': 'Alice'}
        self.wallet.passphrase = 'alice test passphrase'
        self.controller = self.wallet.hosted
        # These cases cover the per-command path; test_member_service covers the service.
        self.controller.service = None
        self.calls = []
        self.count = 4
        self.threshold = 2
        self.slot = 1
        self.vault = 'b' * 64
        self.fail_once = False
        self.controller.native = self.native

    def native(self, action, folder, *args, **kwargs):
        self.calls.append((action, folder))
        if action == 'identity':
            (folder / 'secrets').mkdir(exist_ok=True)
            (folder / 'secrets' / 'identity.sealed').write_bytes(b'saved identity')
            return '{}'
        if action in ('setup-create', 'setup-join'):
            if action == 'setup-create':
                policy = next(arg for arg in args if isinstance(arg, str) and '-of-' in arg)
                self.threshold, self.count = map(int, policy.split('-of-'))
            (folder / 'secrets').mkdir(exist_ok=True)
            (folder / 'secrets' / 'hosted-context.sealed').write_bytes(b'exact saved native context')
            (folder / 'setup-status.json').write_text(json.dumps({'phase': 'waiting_joins',
                'handoff': 'pending', 'joined_slots': [self.slot], 'missing_slots': list(range(2, self.count + 1))}))
            if self.fail_once:
                self.fail_once = False
                raise ValueError('Lost response after saved context')
        if action == 'setup-info':
            return json.dumps({'vault': self.vault, 'own_slot': self.slot, 'member_count': self.count,
                               'threshold': self.threshold,
                               'fingerprint': 'c' * 64, 'network': 'regtest', 'members': []})
        if action == 'setup-invite':
            args[1].write_bytes(b'private invitation')
        return json.dumps({'phase': 'payment_handoff', 'handoff': 'pending'})

    def test_poke_during_schedule_read_keeps_worker_running(self):
        entered, resume, attempted = threading.Event(), threading.Event(), threading.Event()

        class PausedSchedule(dict):
            def __iter__(self):
                names = super().__iter__()
                yield next(names)
                entered.set()
                resume.wait(2)
                yield from names

            def items(self):
                entries = iter(super().items())
                yield next(entries)
                entered.set()
                resume.wait(2)
                yield from entries

        self.controller.schedule = PausedSchedule({"one": {"due": 0.0}, "two": {"due": 0.0}})
        self.addCleanup(self.controller.stop)
        self.controller.start()
        self.assertTrue(entered.wait(2))
        def poke():
            attempted.set()
            self.controller.poke("three")
        caller = threading.Thread(target=poke)
        caller.start()
        self.assertTrue(attempted.wait(1))
        time.sleep(0.05)
        resume.set()
        caller.join(2)
        self.assertFalse(caller.is_alive())
        time.sleep(0.05)
        self.assertTrue(self.controller.worker.is_alive(), "concurrent poke stopped setup scheduling")

    def test_create_retry_keeps_identity_and_context_for_both_policies(self):
        for count in (3, 4):
            self.count, self.vault = count, str(count) * 64
            self.fail_once = True
            with self.assertRaisesRegex(ValueError, 'Lost response'):
                self.wallet.create(f'Vault {count}', count)
            pending = next((self.wallet.data / 'vaults').glob('.hosted-*'))
            identity = (pending / 'secrets' / 'identity.sealed').read_bytes()
            result = self.wallet.create(f'Vault {count}', count)
            folder, local = self.wallet.vault_dir(result['vault'])
            self.assertEqual(local['members'], count)
            self.assertEqual((folder / 'secrets' / 'identity.sealed').read_bytes(), identity)
            self.assertEqual(self.wallet.create(f'Vault {count}', count), result)
        self.assertEqual(sum(action == 'identity' for action, _ in self.calls), 2)
        self.assertEqual(sum(action == 'setup-create' for action, _ in self.calls), 2)

    def test_three_of_four_policy_is_bound_to_native_setup(self):
        with self.assertRaisesRegex(ValueError, 'supported vault policy'):
            self.wallet.create('All must sign', 3, 3)
        self.threshold = 3
        result = self.wallet.create('Three member quorum', 4, 3)
        _, local = self.wallet.vault_dir(result['vault'])
        self.assertEqual((local['threshold'], local['members']), (3, 4))
        self.assertIn('setup-create', [action for action, _ in self.calls])
        native = self.controller.native

        def mismatched(action, folder, *args, **kwargs):
            result = native(action, folder, *args, **kwargs)
            if action == 'setup-info':
                return json.dumps({**json.loads(result), 'threshold': 2})
            return result

        self.controller.native = mismatched
        with self.assertRaisesRegex(ValueError, 'policy differs'):
            self.wallet.create('Mismatch', 4, 3)

    def test_join_is_native_verified_and_reuses_pending_slot_four(self):
        self.slot = 4
        invitation = 'loki-hosted-v1:' + base64.urlsafe_b64encode(b'signed invite').decode().rstrip('=')
        self.fail_once = True
        with self.assertRaises(ValueError):
            self.wallet.join(invitation)
        result = self.wallet.join(invitation)
        _, local = self.wallet.vault_dir(result['vault'])
        self.assertEqual(local['slot'], 4)
        self.assertEqual(local['transport'], 'hosted')
        with self.assertRaises(ValueError):
            self.wallet.join('unknown-version:abc')
        self.assertNotIn('identity', [action for action, _ in self.calls])

    def test_hosted_vault_from_another_network_is_not_attached(self):
        native = self.controller.native

        def wrong_network(action, folder, *args, **kwargs):
            result = native(action, folder, *args, **kwargs)
            if action == 'setup-info':
                return json.dumps({**json.loads(result), 'network': 'testnet'})
            return result

        self.controller.native = wrong_network
        with self.assertRaisesRegex(ValueError, 'another network'):
            self.wallet.create('Treasury', 3)
        self.assertEqual(self.wallet.vaults(), [])

    def test_testnet_creation_binds_native_policy_to_the_member_network(self):
        self.wallet.network = 'testnet'
        original = self.controller.native
        create_args = []

        def testnet_native(action, folder, *args, **kwargs):
            if action == 'setup-create':
                create_args.extend(args)
            result = original(action, folder, *args, **kwargs)
            if action == 'setup-info':
                return json.dumps({**json.loads(result), 'network': 'testnet', 'birth_height': 4_465_026})
            return result

        self.controller.native = testnet_native
        created = self.wallet.create('Testnet vault', 3)
        self.assertEqual(self.wallet.vault_dir(created['vault'])[1]['network'], 'testnet')
        self.assertEqual(self.wallet.status(created['vault'])['birth_height'], 4_465_026)
        self.assertEqual(create_args[-2:], ['--network', 'testnet'])

    def test_testnet_membership_requires_a_certified_scan_start(self):
        self.wallet.network = 'testnet'
        original = self.controller.native

        def missing_birth(action, folder, *args, **kwargs):
            result = original(action, folder, *args, **kwargs)
            if action == 'setup-info':
                return json.dumps({**json.loads(result), 'network': 'testnet'})
            return result

        self.controller.native = missing_birth
        with self.assertRaisesRegex(ValueError, 'birth height'):
            self.wallet.create('No scan start', 3)
        self.assertEqual(self.wallet.vaults(), [])

    def test_existing_regtest_membership_without_network_can_resume(self):
        vault = self.wallet.create('Treasury', 3)['vault']
        membership = self.wallet.data / 'vaults' / vault / 'membership.json'
        saved = json.loads(membership.read_text())
        saved.pop('network')
        membership.write_text(json.dumps(saved))
        self.assertEqual(self.wallet.create('Treasury', 3)['vault'], vault)
        self.assertEqual(self.wallet.status(vault)['network'], 'regtest')

    def test_waiting_member_four_is_distinct_from_retry_and_ready(self):
        result = self.wallet.create('Treasury', 4)
        folder, _ = self.wallet.vault_dir(result['vault'])
        (folder / 'final-backup-checked').touch()
        (folder / 'setup-status.json').write_text(json.dumps({'phase': 'payment_handoff', 'handoff': 'pending',
                                                            'joined_slots': [1, 2, 3, 4], 'missing_slots': [4]}))
        state = self.wallet.status(self.vault)
        self.assertEqual(state['phase'], 'connecting_relays')
        self.assertEqual(state['missing_slots'], [4])
        self.assertIsNone(state['error'])
        self.controller.errors[self.vault] = 'Connection interrupted. Saved setup will retry.'
        self.assertIn('retry', self.wallet.status(self.vault)['error'])
        (folder / 'setup-status.json').write_text(json.dumps({'phase': 'active', 'handoff': 'ready',
                                                            'joined_slots': [1, 2, 3, 4], 'missing_slots': []}))
        self.assertEqual(self.wallet.status(self.vault)['phase'], 'active')
        with self.assertRaisesRegex(ValueError, 'activation'):
            self.wallet.address(self.vault)
        with self.assertRaisesRegex(ValueError, 'automatically'):
            self.wallet.setup_all_relays()
        with patch('local_funding.faucet_origin') as endpoint:
            self.assertFalse(funding_status(self.wallet, self.vault)['available'])
            with self.assertRaisesRegex(ValueError, 'hosted'):
                fund_member(self.wallet, self.vault, 'd' * 32)
            endpoint.assert_not_called()

    def _joiner_vault(self, phases, fingerprints):
        """A joined slot-2 vault whose native step and info replay the given sequences."""
        self.slot, self.count = 2, 3
        invitation = 'loki-hosted-v1:' + base64.urlsafe_b64encode(b'signed invite').decode().rstrip('=')
        self.wallet.join(invitation)
        folder, _ = self.wallet.vault_dir(self.vault)
        self.controller.information.clear()
        steps, infos = iter(phases), iter(fingerprints)

        def native(action, root, *args, **kwargs):
            self.calls.append((action, root))
            if action == 'setup-step':
                phase = next(steps)
                joined = [1, 2, 3] if phase == 'roster_proposed' else [2]
                status = {'phase': phase, 'policy': '2-of-3', 'own_slot': 2, 'joined_slots': joined,
                          'missing_slots': [slot for slot in (1, 2, 3) if slot not in joined],
                          'agreed_fingerprint': None, 'retryable': False, 'handoff': 'pending'}
                (root / 'setup-status.json').write_text(json.dumps(status))
                return json.dumps(status)
            if action == 'setup-info':
                return json.dumps({'vault': self.vault, 'own_slot': 2, 'member_count': 3,
                                   'fingerprint': next(infos), 'network': 'regtest', 'members': []})
            raise AssertionError(action)
        self.controller.native = native
        return folder

    def test_joiner_sees_fingerprint_when_proposal_arrives(self):
        folder = self._joiner_vault(['join_published', 'join_published', 'roster_proposed'], [None, 'c' * 64])
        for expected in ('waiting_for_members', 'waiting_for_members', 'compare_roster'):
            self.controller.step_folder(folder, 'alice')
            state = self.wallet.status(self.vault)
            self.assertEqual(state['phase'], expected)
        self.assertEqual(state['fingerprint'], 'c' * 64)
        self.assertIsNone(state['error'])
        self.assertEqual([action for action, _ in self.calls[-5:]],
                         ['setup-step', 'setup-info', 'setup-step', 'setup-step', 'setup-info'])

    def test_missing_fingerprint_is_refetched_without_a_phase_change(self):
        folder = self._joiner_vault(['roster_proposed'] * 3, [None, 'c' * 64])
        self.controller.step_folder(folder, 'alice')
        self.assertIsNone(self.wallet.status(self.vault)['fingerprint'])
        self.controller.step_folder(folder, 'alice')
        self.assertIsNone(self.wallet.status(self.vault)['fingerprint'], 'refetch is rate limited')
        self.controller.information_at[self.vault] -= 5
        self.controller.step_folder(folder, 'alice')
        state = self.wallet.status(self.vault)
        self.assertEqual((state['phase'], state['fingerprint']), ('compare_roster', 'c' * 64))

    def test_roster_mismatch_is_reported_as_stopped(self):
        folder = self._joiner_vault([], [])

        def native(action, root, *args, **kwargs):
            raise ValueError('setup_roster')
        self.controller.native = native
        self.controller.step_folder(folder, 'alice')
        state = self.wallet.status(self.vault)
        self.assertEqual(state['phase'], 'stopped')
        self.assertIn('does not match the admitted members', state['error'])

    def test_hosted_wallet_needs_no_exchange_and_refuses_local_routes(self):
        root = Path(self.temporary.name)
        with self.assertRaisesRegex(ValueError, 'exchange'):
            Wallet(root / 'local-member', None)
        wallet = Wallet(root / 'hosted-member', None, transport='hosted', operator_bundle=root / 'operators',
                        operator_key='a' * 64, enrollment_grant=root / 'grant')
        self.addCleanup(wallet.close)
        self.assertIsNone(wallet.exchange)
        wallet.profile_data = {'id': 'alice', 'name': 'Alice'}
        self.assertEqual(wallet.vaults(), [])
        with self.assertRaisesRegex(ValueError, 'Invalid vault ID'):
            wallet.vault_dir('../escape')
        with self.assertRaisesRegex(ValueError, 'hosted transport'):
            wallet.exchange_vault('a' * 64)
        with self.assertRaisesRegex(ValueError, 'automatically'):
            wallet.setup_all_relays()

    def test_user_action_on_one_vault_does_not_wait_for_another(self):
        started, release = threading.Event(), threading.Event()
        blocked, free = Path(self.temporary.name) / 'vault-a', Path(self.temporary.name) / 'vault-b'
        seen = []

        def native(action, root, *args, **kwargs):
            seen.append((action, root.name))
            if root == blocked:
                started.set()
                release.wait(5)
            return '{}'
        del self.controller.native
        self.controller._native = native
        worker = threading.Thread(target=lambda: self.controller.native('setup-step', blocked))
        worker.start()
        self.assertTrue(started.wait(2))
        begun = __import__('time').monotonic()
        with self.controller.user_action(free):
            self.controller.native('setup-agree', free, 'f' * 64)
        self.assertLess(__import__('time').monotonic() - begun, 1)
        waiter = threading.Thread(target=lambda: self.controller.native('setup-agree', blocked, 'f' * 64))
        self.assertFalse(self.controller.user_pending(blocked))
        waiter.start()
        __import__('time').sleep(0.1)
        self.assertEqual(seen.count(('setup-agree', 'vault-a')), 0, 'same-vault calls never overlap')
        release.set()
        worker.join(5)
        waiter.join(5)
        self.assertEqual(seen.count(('setup-agree', 'vault-a')), 1)

    def test_worker_skips_vault_with_pending_user_action_and_retries_native_lock(self):
        folder = Path(self.temporary.name) / 'vault-c'
        calls = []

        def native(action, root, *args, **kwargs):
            calls.append(action)
            if len(calls) < 3:
                raise ValueError('setup_worker_locked')
            return '{}'
        del self.controller.native
        self.controller._native = native
        with self.controller.user_action(folder):
            self.assertEqual(self.controller._background_step(folder, 'alice'), ('busy', None))
            self.assertEqual(self.controller.native('setup-agree', folder, 'f' * 64), '{}')
        self.assertEqual(calls, ['setup-agree'] * 3)
        calls.clear()
        self.controller._native = lambda *a, **k: (_ for _ in ()).throw(ValueError('setup_worker_locked'))
        with self.controller.user_action(folder):
            with self.assertRaisesRegex(ValueError, 'busy in another tool'):
                self.controller.native('setup-agree', folder, 'f' * 64)
        with self.assertRaisesRegex(ValueError, 'setup_worker_locked'):
            self.controller.native('setup-step', folder)

    def test_schedule_steps_again_after_progress_and_backs_off_when_idle(self):
        name = 'd' * 64
        self.controller._reschedule(name, ('progress', {}))
        self.assertEqual(self.controller.schedule[name]['due'] <= __import__('time').monotonic(), True)
        delays = []
        for _ in range(5):
            before = __import__('time').monotonic()
            self.controller._reschedule(name, ('idle', {}))
            delays.append(round(self.controller.schedule[name]['due'] - before, 2))
        self.assertEqual(delays, [0.25, 0.5, 1.0, 2.0, 2.0])
        before = __import__('time').monotonic()
        self.controller._reschedule(name, ('human', {}))
        self.assertAlmostEqual(self.controller.schedule[name]['due'] - before, 5, places=1)
        errors = []
        for _ in range(6):
            before = __import__('time').monotonic()
            self.controller._reschedule(name, ('error', None))
            errors.append(round(self.controller.schedule[name]['due'] - before))
        self.assertEqual(errors, [2, 4, 8, 16, 30, 30])
        for _ in range(20):
            self.controller._reschedule(name, ('progress', {}))
        before = __import__('time').monotonic()
        self.controller._reschedule(name, ('progress', {}))
        self.assertGreater(self.controller.schedule[name]['due'] - before, 0.2, 'immediate re-steps are capped')

    def test_lock_stops_a_blocked_step_within_five_seconds(self):
        del self.controller.native
        script = Path(self.temporary.name) / 'slow-native'
        script.write_text('#!/bin/sh\nexec sleep 30\n')
        script.chmod(0o700)
        self.wallet.setup = script
        worker = threading.Thread(target=lambda: self.assertRaises(ValueError, self.controller.native, 'setup-step', Path(self.temporary.name)))
        worker.start()
        __import__('time').sleep(0.5)
        begun = __import__('time').monotonic()
        self.controller.stop()
        worker.join(6)
        self.assertFalse(worker.is_alive())
        self.assertLess(__import__('time').monotonic() - begun, 5)

    def test_status_lists_backup_checks_from_native_receipts(self):
        self.count = 3
        result = self.wallet.create('Treasury', 3)
        folder, _ = self.wallet.vault_dir(result['vault'])
        (folder / 'setup-status.json').write_text(json.dumps({'phase': 'awaiting_backups', 'handoff': 'pending',
                                                            'joined_slots': [1, 2, 3], 'missing_slots': [3]}))
        self.assertEqual([(row['slot'], row['backup_checked']) for row in self.wallet.status(self.vault)['backups']],
                         [(1, True), (2, True), (3, False)])
        (folder / 'setup-status.json').write_text(json.dumps({'phase': 'certified', 'handoff': 'pending',
                                                            'joined_slots': [1, 2, 3], 'missing_slots': []}))
        self.assertTrue(all(row['backup_checked'] for row in self.wallet.status(self.vault)['backups']))
        (folder / 'setup-status.json').write_text(json.dumps({'phase': 'round1_saved', 'handoff': 'pending',
                                                            'joined_slots': [1, 2, 3], 'missing_slots': [2, 3]}))
        self.assertEqual(self.wallet.status(self.vault)['backups'], [])

    def test_membership_publication_recovers_before_directory_rename(self):
        folder = self.controller._pending('Treasury', 'create', '2-of-4')
        with patch.object(Path, 'rename', side_effect=OSError('interrupted rename')):
            with self.assertRaises(OSError):
                self.controller._attach(folder, 'Treasury')
        self.assertTrue((folder / 'membership.json').is_file())
        self.assertEqual(self.controller._attach(folder, 'Treasury'), {'vault': self.vault})
        self.assertEqual(len(self.wallet.vaults()), 1)

    def test_dashboard_receives_public_pending_state_and_lock_revokes_session(self):
        self.wallet.create('Treasury', 4)
        origin = 'http://127.0.0.1:18802'
        server, token = make_signer_server(self.wallet, 0, 18802)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        connection = http.client.HTTPConnection('127.0.0.1', server.server_address[1])
        self.addCleanup(connection.close)
        connection.request('POST', '/api/session/request', body='{}', headers={'Origin': origin, 'Content-Type': 'application/json'})
        response = connection.getresponse()
        key = json.loads(response.read())['request']
        connection.request('POST', '/api/session/approve', body=json.dumps({'request': key}), headers={'X-Loki-Token': token, 'Content-Type': 'application/json'})
        response = connection.getresponse()
        response.read()
        self.assertEqual(response.status, 200)
        connection.request('GET', '/api/session/vaults', headers={'Origin': origin, 'X-Loki-Session': key})
        response = connection.getresponse()
        data = json.loads(response.read())
        self.assertEqual(response.status, 200)
        self.assertEqual(data['vaults'][0]['total_members'], 4)
        self.assertEqual(data['vaults'][0]['transport'], 'hosted')
        for secret in ('identity_secret', 'read_capability', 'backup_words', 'passphrase'):
            self.assertNotIn(secret, json.dumps(data))
        connection.request('POST', '/api/lock', body='{}', headers={'X-Loki-Token': token, 'Content-Type': 'application/json'})
        response = connection.getresponse()
        response.read()
        self.assertEqual(response.status, 200)
        connection.request('GET', '/api/session/vaults', headers={'Origin': origin, 'X-Loki-Session': key})
        response = connection.getresponse()
        response.read()
        self.assertEqual(response.status, 403)
        self.assertIsNone(self.wallet.passphrase)
        self.assertTrue(self.controller.stop_event.is_set())


if __name__ == '__main__':
    unittest.main()
