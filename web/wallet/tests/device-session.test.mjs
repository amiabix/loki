import assert from 'node:assert/strict';
import { test } from 'node:test';
import { api, pairDevice, logout, forgetPairing } from '../src/lib/api.ts';

test('a paired tab sends its capability only to its manually selected device', async () => {
  const storage = new Map();
  globalThis.sessionStorage = { getItem: (k) => storage.get(k) ?? null, setItem: (k, v) => storage.set(k, v), removeItem: (k) => storage.delete(k) };
  globalThis.window = { dispatchEvent() {} };
  const member = { slot: 1, signing_pubkey: '11'.repeat(32), relay_pubkey: '22'.repeat(32), advertise_url: 'http://127.0.0.1:3601' };
  const capability = 'a'.repeat(43);
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init = {}) => {
    calls.push({ url, init });
    if (url === '/api/members') {
      assert(!init.headers, 'coordinator receives no member capability');
      return Response.json({ slots: [member] });
    }
    assert(url.startsWith('http://127.0.0.1:3601/api/'));
    assert.equal(init.headers['X-Loki-Token'], capability);
    assert.equal(init.redirect, 'error');
    assert.equal(init.credentials, 'omit');
    if (url.endsWith('/registration')) return Response.json(member);
    return Response.json({ phase: 'home' });
  };
  try {
    await assert.rejects(pairDevice(`https://device.example/#${capability}`), /local pairing/);
    assert.deepEqual(await pairDevice(`${member.advertise_url}/#${capability}`), member);
    member.advertise_url = 'https://signer.example';
    assert.deepEqual(await pairDevice(`http://127.0.0.1:3601/#${capability}`), member);
    await api('payment-approve', { vault: 'public', review_token: 'device-review' });
    assert(calls.some((c) => c.url.endsWith('/api/payment-approve')));
    await assert.rejects(api('../api/members'), /invalid device API path/);
    globalThis.fetch = async () => { throw new Error('device offline'); };
    assert.equal(await logout(), false);
    await assert.rejects(api('status'), /Pair your local member device/);
    forgetPairing();
  } finally { globalThis.fetch = originalFetch; delete globalThis.window; delete globalThis.sessionStorage; }
});
