import base64
import http.client
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
from member_app import Wallet, SignerSessions, make_signer_server
from local_funding import fund_member, funding_status


class HostedControllerTests(unittest.TestCase):
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
