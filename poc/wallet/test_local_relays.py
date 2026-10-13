import base64
import hashlib
import json
import re
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from member_app import SignerSessions, Wallet
from local_relays import ensure_network, network_root, save


class LocalRelayTest(unittest.TestCase):
    def test_shared_network_selection_preserves_capacity_and_saved_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            exchange = Path(temp)
            network = exchange / '.payment-relays' / ('a' * 64)
            for slot in (1, 2, 3):
                relay = network / 'relays' / str(slot)
                relay.mkdir(parents=True)
                connection = sqlite3.connect(relay / 'relay.sqlite3')
                connection.execute('CREATE TABLE metadata (singleton INTEGER, mailbox_count INTEGER)')
                connection.execute('INSERT INTO metadata VALUES (1, 3)')
                connection.commit()
                connection.close()
            self.assertEqual(network_root(exchange).name, 'network')
            for slot in (1, 2, 3):
                connection = sqlite3.connect(network / 'relays' / str(slot) / 'relay.sqlite3')
                connection.execute('UPDATE metadata SET mailbox_count=1024')
                connection.commit()
                connection.close()
            self.assertEqual(network_root(exchange), network)
            settings = network.parent / 'settings.json'
            save(settings, {'enabled': True, 'network': network.name})
            self.assertEqual(network_root(exchange), network)
            save(settings, {'enabled': True, 'network': '../member'})
            with self.assertRaisesRegex(ValueError, 'network is invalid'):
                network_root(exchange)

    def test_dashboard_request_requires_approved_session_and_valid_vault(self):
        sessions = SignerSessions('http://127.0.0.1:18802')
        key = sessions.request(sessions.origin)
        request = {'kind': 'relay-setup', 'vault': 'a' * 64, 'name': 'Gold'}
        with self.assertRaisesRegex(ValueError, 'Connect your signer'):
            sessions.request_action(key, sessions.origin, request)
        sessions.approve(key)
        with self.assertRaisesRegex(ValueError, 'vault'):
            sessions.request_action(key, sessions.origin, {**request, 'vault': '../another-member'})
        action = sessions.request_action(key, sessions.origin, request)
        self.assertEqual(sessions.pending_actions()[0]['kind'], 'relay-setup')
        self.assertEqual(sessions.take_action(action), request)
        with self.assertRaisesRegex(ValueError, 'Unsupported vault request'):
            sessions.request_action(key, sessions.origin, {'kind': 'relay-setup-all'})

    def test_setup_rejects_inactive_vault(self):
        with tempfile.TemporaryDirectory() as temp:
            wallet = Wallet(Path(temp) / 'member', Path(temp) / 'exchange')
            self.addCleanup(wallet.close)
            wallet.profile_data = {'id': 'alice'}
            vault = 'a' * 64
            member = wallet.data / 'vaults' / vault
            member.mkdir(parents=True)
            (member / 'membership.json').write_text(json.dumps({
                'vault': vault, 'profile': 'alice', 'name': 'Gold', 'slot': 1, 'members': 3}))
            with self.assertRaisesRegex(ValueError, 'final backup'):
                wallet.setup_relays(vault)

    def test_three_members_provision_exchange_and_retry_without_changing_keys(self):
        temporary = tempfile.TemporaryDirectory(prefix='loki-relay-button-')
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        wallets = [Wallet(root / f'member-{slot}', root / 'exchange') for slot in (1, 2, 3)]
        for wallet in wallets:
            self.addCleanup(wallet.close)
        for slot, wallet in enumerate(wallets, 1):
            wallet.create_profile(f'Member {slot}', f'member {slot} test passphrase')
        vault = self.create_active_vault(wallets, 'Relay test')
        preserved = {path: hashlib.sha256(path.read_bytes()).digest()
                     for wallet in wallets for path in (wallet.data / 'vaults' / vault / 'secrets').glob('*.sealed')}
        addresses = [wallet.address(vault) for wallet in wallets]
        self.assertEqual(network_root(root / 'exchange').name, 'network')
        network = root / 'exchange' / '.payment-relays' / vault
        self.addCleanup(lambda: self.stop_supervisor(network))
        ensure_network(network)
        wallets[2].lock_profile()
        wallets[0].setup_all_relays()
        self.assertEqual(network_root(root / 'exchange'), network)
        self.assertFalse((root / 'exchange' / '.payment-relays' / 'network').exists())
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            states = [wallet.relay_status(vault) for wallet in wallets[:2]]
            if all(state['phase'] == 'waiting' for state in states):
                break
            time.sleep(.2)
        self.assertTrue(all(state['phase'] == 'waiting' for state in states), states)
        self.assertFalse((wallets[2].data / 'vaults' / vault / 'relay-setup.json').exists())
        wallets[2].unlock('member 3 test passphrase')
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            states = [wallet.relay_status(vault) for wallet in wallets]
            self.assertFalse(any(state['phase'] == 'failed' for state in states), states)
            if all(state['phase'] == 'ready' for state in states):
                break
            time.sleep(.2)
        self.assertTrue(all(state['phase'] == 'ready' for state in states), states)
        pins = [(network / 'manifests' / str(slot) / 'manifest').read_bytes() for slot in (1, 2, 3)]
        wallets[0].setup_relays(vault)
        wallets[0].relay_jobs[vault].join(60)
        self.assertEqual(wallets[0].relay_status(vault)['phase'], 'ready')
        self.assertEqual(pins, [(network / 'manifests' / str(slot) / 'manifest').read_bytes() for slot in (1, 2, 3)])
        self.assertEqual(addresses, [wallet.address(vault) for wallet in wallets])
        for path, digest in preserved.items():
            self.assertEqual(hashlib.sha256(path.read_bytes()).digest(), digest)
        for wallet in wallets:
            self.assertEqual(wallet.sync_payments(vault)['payments'], [])
        sender = wallets[0]
        member = sender.data / 'vaults' / vault
        common = ('--member-root', member, '--passphrase-file', '@pass', '--roster', member / 'roster.json')
        payload = sender.data / 'relay-test-message'
        payload.write_bytes(b'local relay setup transport check')
        sent = sender.command('send', *common, '--payload-file', payload, '--request-id', 'd' * 64,
                              binary=sender.relay_binary)
        message = re.search(r'\brequest message=([0-9a-f]{64})', sent).group(1)
        sender.command('upload', *common, binary=sender.relay_binary)
        for wallet in wallets[1:]:
            member = wallet.data / 'vaults' / vault
            common = ('--member-root', member, '--passphrase-file', '@pass', '--roster', member / 'roster.json')
            wallet.command('poll', *common, '--once', binary=wallet.relay_binary)
            status = wallet.command('status', *common, binary=wallet.relay_binary).splitlines()
            delivered = [row for row in status if row.startswith(f'incoming sender=1 id={message} ')]
            self.assertEqual(len(delivered), 1)
            self.assertIn('kind=test session=- readiness=ready', delivered[0])
            self.assertIn('received_author=1', delivered[0])
        member = sender.data / 'vaults' / vault
        common = ('--member-root', member, '--passphrase-file', '@pass', '--roster', member / 'roster.json')
        sender.command('poll', *common, '--once', binary=sender.relay_binary)
        status = sender.command('status', *common, binary=sender.relay_binary).splitlines()
        acknowledged = [row for row in status if row.startswith(f'message sender=1 id={message} ')]
        self.assertEqual(len(acknowledged), 1)
        self.assertIn('received_whole=1 received_author=1', acknowledged[0])

        self.stop_supervisor(network)
        wallets[0].setup_all_relays()
        self.assertEqual(pins, [(network / 'manifests' / str(slot) / 'manifest').read_bytes() for slot in (1, 2, 3)])
        future_vault = self.create_active_vault(wallets, 'Future vault')
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            states = [wallet.relay_status(future_vault) for wallet in wallets]
            self.assertFalse(any(state['phase'] == 'failed' for state in states), states)
            if all(state['phase'] == 'ready' for state in states):
                break
            time.sleep(.2)
        self.assertTrue(all(state['phase'] == 'ready' for state in states), states)
        endpoints = {pin.decode().splitlines()[0] for pin in pins}
        for wallet in wallets:
            member = wallet.data / 'vaults' / future_vault
            output = wallet.command('status', '--member-root', member, '--passphrase-file', '@pass',
                                    '--roster', member / 'roster.json', binary=wallet.relay_binary)
            self.assertEqual(set(re.findall(r'^inbox .+ endpoint=(\S+)$', output, re.MULTILINE)), endpoints)
        self.assertFalse((root / 'exchange' / '.payment-relays' / future_vault).exists())

    def create_active_vault(self, wallets, name):
        created = wallets[0].create(name)
        vault = created['vault']
        for wallet, invite in zip(wallets[1:], created['invites']):
            wallet.join(invite)
        fingerprint = wallets[0].roster(vault)['fingerprint']
        for wallet in wallets:
            wallet.agree(vault, fingerprint)
        for wallet in wallets:
            wallet.workers[vault].join(90)
            self.assertIsNone(wallet.setup_errors.get(vault))
        words = [wallet.backup(vault)['words'] for wallet in wallets]
        for wallet, value in zip(wallets, words):
            wallet.verify(vault, value)
        for wallet, value in zip(wallets, words):
            wallet.activate(vault)
            wallet.finalize_backup(vault, value)
            card = (wallet.data / 'vaults' / vault / 'final-card' / 'vault.card').read_bytes()
            wallet.verify_final_backup(vault, value, base64.b64encode(card).decode())
        return vault

    @staticmethod
    def stop_supervisor(network):
        import os
        import signal
        state = network / 'supervisor.json'
        if state.exists():
            try:
                os.kill(json.loads(state.read_text())['pid'], signal.SIGTERM)
                deadline = time.monotonic() + 8
                while state.exists() and time.monotonic() < deadline:
                    time.sleep(.1)
            except ProcessLookupError:
                pass


if __name__ == '__main__':
    unittest.main()
