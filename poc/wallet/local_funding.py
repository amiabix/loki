"""Fixed-amount, replay-safe funding from the selected local THS regtest faucet."""

import http.client
import json
import os
import re
import subprocess
from urllib.parse import urlsplit

from local_relays import save

AMOUNT = 500_000_000


def loopback_url(value):
    parts = urlsplit(value)
    if parts.scheme != 'http' or parts.hostname != '127.0.0.1' or not parts.port \
            or parts.username or parts.password or parts.query or parts.fragment \
            or parts.path not in ('', '/'):
        raise ValueError('The test faucet must use a local loopback endpoint')
    return value.rstrip('/')


def faucet_origin():
    instance = os.environ.get('LOKI_THS_INSTANCE', 'loki')
    try:
        result = subprocess.run(['ths', '--name', instance, 'endpoints', '--json'],
                                capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError('Could not find the local THS faucet. Start THS and set LOKI_THS_INSTANCE for this app.') from error
    if result.returncode:
        raise ValueError(f'THS instance {instance} is unavailable. Start it before funding this vault.')
    endpoints = json.loads(result.stdout)
    if endpoints.get('network') != 'regtest':
        raise ValueError('Vault funding requires a local regtest THS instance')
    rpc = loopback_url(endpoints['rpc'])
    if urlsplit(rpc).netloc != os.environ.get('LOKI_RPC', '127.0.0.1:18232'):
        raise ValueError('The THS faucet and signer must use the same local chain')
    return loopback_url(endpoints['dashboard'])


def funding_status(wallet, vault):
    member, local = wallet.vault_dir(vault)
    if getattr(wallet, 'transport', 'local') == 'hosted' or local.get('transport') == 'hosted':
        return {'available': False, 'phase': 'unavailable', 'detail': ''}
    path = member / 'funding.json'
    record = json.loads(path.read_text()) if path.is_file() else {}
    return {'available': local.get('members') in (3, 4) and (member / 'final-backup-checked').is_file(),
            'phase': record.get('phase', 'idle'), 'request_id': record.get('request_id'),
            'detail': record.get('detail', ''), 'txid': record.get('result', {}).get('txid')}


def fund_member(wallet, vault, request_id):
    if not isinstance(request_id, str) or not re.fullmatch(r'[0-9a-f]{32}', request_id):
        raise ValueError('Invalid funding request ID')
    member, local = wallet.vault_dir(vault)
    if getattr(wallet, 'transport', 'local') == 'hosted' or local.get('transport') == 'hosted':
        raise ValueError('The local test faucet is unavailable in hosted mode')
    if not (member / 'final-backup-checked').is_file():
        raise ValueError('Check your final backup before funding this vault')
    if local.get('members') not in (3, 4):
        raise ValueError('Test funding requires a supported vault policy')
    path = member / 'funding.json'
    prior = json.loads(path.read_text()) if path.is_file() else {}
    if prior.get('request_id') == request_id and prior.get('phase') == 'confirmed':
        return prior['result']
    if prior.get('request_id') != request_id and prior.get('phase') in ('pending', 'failed'):
        raise ValueError('Retry the previous funding request before starting another')
    address = wallet.address(vault)
    origin = faucet_origin()
    instance = os.environ.get('LOKI_THS_INSTANCE', 'loki')
    if prior.get('request_id') == request_id and prior.get('instance') != instance:
        raise ValueError('Retry funding with the original THS instance')
    request = {'address': address, 'amount_zatoshi': AMOUNT,
               'idempotency_key': f'loki-{vault}-fund-{request_id}'}
    record = {'request_id': request_id, 'instance': instance, 'phase': 'pending',
              'detail': 'Funding 5 test ZEC; waiting for confirmation.'}
    save(path, record)
    parts = urlsplit(origin)
    connection = http.client.HTTPConnection(parts.hostname, parts.port, timeout=600)
    try:
        connection.request('POST', '/api/v1/faucet/address', body=json.dumps(request),
                           headers={'Content-Type': 'application/json'})
        response = connection.getresponse()
        result = json.loads(response.read())
        if response.status != 200:
            raise ValueError(result.get('error', 'The local faucet request failed'))
        if result.get('address') != address or result.get('amount_zatoshi') != AMOUNT \
                or result.get('status') != 'confirmed' \
                or any(not isinstance(result.get(field), str) or not re.fullmatch(r'[0-9a-f]{64}', result[field])
                       for field in ('txid', 'block_hash')):
            raise ValueError('Funding has not been confirmed. Retry the same request to check it.')
        record.update(phase='confirmed', detail='5 test ZEC confirmed.', result=result)
        save(path, record)
        return result
    except Exception as error:
        record.update(phase='failed', detail=f'Funding could not be confirmed: {error}. Retry funding to check the same request.')
        save(path, record)
        raise
    finally:
        connection.close()
