import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
from member_app import Wallet
from local_funding import faucet_origin, fund_member, funding_status


class FundingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.wallet = Wallet(Path(temporary.name) / 'member', Path(temporary.name) / 'exchange')
        self.addCleanup(self.wallet.close)
        self.wallet.profile_data = {'id': 'alice'}
        self.vault = 'a' * 64
        self.member = self.wallet.data / 'vaults' / self.vault
        self.member.mkdir(parents=True)
        (self.member / 'membership.json').write_text(json.dumps({
            'vault': self.vault, 'profile': 'alice', 'slot': 1, 'members': 3, 'name': 'Gold'}))
        (self.member / 'final-backup-checked').touch()
        self.wallet.address = lambda vault: 'uregtest1test-address'
        self.requests = []
        self.effects = {}
        self.fail_after_commit = False
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                payload = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                owner.requests.append(payload)
                if self.path != '/api/v1/faucet/address':
                    self.send_error(404)
                    return
                key = payload['idempotency_key']
                owner.effects.setdefault(key, {**payload, 'txid': 'b' * 64,
                                              'block_hash': 'c' * 64, 'status': 'confirmed'})
                status = 500 if owner.fail_after_commit else 200
                owner.fail_after_commit = False
                body = json.dumps({'error': 'Lost confirmation response'} if status == 500 else owner.effects[key]).encode()
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.origin = f'http://127.0.0.1:{server.server_address[1]}'
        patcher = patch('local_funding.faucet_origin', return_value=self.origin)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_fixed_five_zec_and_confirmed_retry_does_not_send_again(self):
        result = fund_member(self.wallet, self.vault, 'd' * 32)
        self.assertEqual(result['amount_zatoshi'], 500000000)
        self.assertEqual(result['status'], 'confirmed')
        self.assertEqual(self.requests[0]['address'], 'uregtest1test-address')
        self.assertEqual(self.requests[0]['amount_zatoshi'], 500000000)
        self.assertEqual(fund_member(self.wallet, self.vault, 'd' * 32), result)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(funding_status(self.wallet, self.vault)['phase'], 'confirmed')
        fund_member(self.wallet, self.vault, 'e' * 32)
        self.assertEqual(len(self.effects), 2)

    def test_unknown_result_retries_same_key_and_blocks_a_new_funding(self):
        self.fail_after_commit = True
        with self.assertRaisesRegex(ValueError, 'Lost confirmation'):
            fund_member(self.wallet, self.vault, 'd' * 32)
        self.assertEqual(funding_status(self.wallet, self.vault)['phase'], 'failed')
        with self.assertRaisesRegex(ValueError, 'Retry the previous'):
            fund_member(self.wallet, self.vault, 'e' * 32)
        fund_member(self.wallet, self.vault, 'd' * 32)
        self.assertEqual(len(self.effects), 1)
        self.assertEqual(self.requests[0]['idempotency_key'], self.requests[1]['idempotency_key'])

    def test_invalid_request_inactive_vault_and_other_profile_never_reach_faucet(self):
        with self.assertRaisesRegex(ValueError, 'request'):
            fund_member(self.wallet, self.vault, '../another-vault')
        (self.member / 'final-backup-checked').unlink()
        with self.assertRaisesRegex(ValueError, 'final backup'):
            fund_member(self.wallet, self.vault, 'd' * 32)
        (self.member / 'final-backup-checked').touch()
        self.wallet.profile_data = {'id': 'bob'}
        with self.assertRaisesRegex(ValueError, 'belong'):
            fund_member(self.wallet, self.vault, 'd' * 32)
        self.assertEqual(self.requests, [])


class FaucetEndpointTests(unittest.TestCase):
    def test_requires_loopback_regtest_and_the_same_rpc_as_the_signer(self):
        good = {'network': 'regtest', 'rpc': 'http://127.0.0.1:18232',
                'dashboard': 'http://127.0.0.1:32805'}
        with patch.dict(os.environ, {'LOKI_RPC': '127.0.0.1:18232'}):
            for changed in ({'network': 'mainnet'}, {'rpc': 'http://127.0.0.1:18862'},
                            {'dashboard': 'http://example.com:32805'}):
                with patch('local_funding.subprocess.run') as run:
                    run.return_value.returncode = 0
                    run.return_value.stdout = json.dumps({**good, **changed})
                    with self.assertRaises(ValueError):
                        faucet_origin()
            with patch('local_funding.subprocess.run') as run:
                run.return_value.returncode = 0
                run.return_value.stdout = json.dumps(good)
                self.assertEqual(faucet_origin(), good['dashboard'])


if __name__ == '__main__':
    unittest.main()
