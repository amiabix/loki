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
            (folder / 'secrets').mkdir(exist_ok=True)
            (folder / 'secrets' / 'hosted-context.sealed').write_bytes(b'exact saved native context')
            (folder / 'setup-status.json').write_text(json.dumps({'phase': 'waiting_joins',
                'handoff': 'pending', 'joined_slots': [self.slot], 'missing_slots': list(range(2, self.count + 1))}))
            if self.fail_once:
                self.fail_once = False
                raise ValueError('Lost response after saved context')
        if action == 'setup-info':
            return json.dumps({'vault': self.vault, 'own_slot': self.slot, 'member_count': self.count,
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

    def test_restored_membership_can_connect_operator_relays_in_hosted_app(self):
        card = base64.b64encode(b'LOKISEAL\x01' + b'opaque final card').decode()
        identity = {'id': 1, 'signing': 'a' * 64, 'encryption': 'b' * 64}
        roster = {'vault': self.vault, 'threshold': 2,
                  'members': [identity, {'id': 2}, {'id': 3}]}

        def command(action, folder, *_args, **_kwargs):
            if action == 'restore':
                (folder / 'secrets').mkdir()
                (folder / 'secrets' / 'activation.sealed').write_bytes(b'opaque')
                (folder / 'roster.json').write_text(json.dumps(roster))
                return 'uregtest1recovered'
            if action == 'identity-public': return json.dumps(identity)
            if action == 'address': return 'uregtest1recovered'
            if action == 'validate-roster': return 'fingerprint'
            if action == 'provision': return 'provisioned'
            raise AssertionError(action)

        with patch.object(self.wallet, 'command', side_effect=command):
            self.wallet.restore_vault('Recovered', 'saved recovery words', card)
            kit = self.wallet.data / 'operator-kit'
            (kit / 'manifests').mkdir(parents=True)
            (kit / 'capabilities').mkdir()
            self.assertEqual(self.wallet.relay_provision(self.vault, str(kit)), {'provisioned': True})
        self.assertEqual(self.wallet.relay_status(self.vault)['phase'], 'waiting')

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
