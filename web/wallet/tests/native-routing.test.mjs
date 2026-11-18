import assert from 'node:assert/strict';
import { test } from 'node:test';
import { api, pairDevice, signerKind, logout } from '../src/lib/api.ts';

test('a tab paired with a native member routes member calls to it, with its capability', async () => {
  const sess = new Map();
  globalThis.sessionStorage = { getItem: (k) => sess.get(k) ?? null, setItem: (k, v) => sess.set(k, v), removeItem: (k) => sess.delete(k) };
  globalThis.localStorage = { getItem: () => null, setItem: () => {}, removeItem: () => {} };
  globalThis.window = { dispatchEvent: () => {} };
  const member = { slot: 2, signing_pubkey: '11'.repeat(32), relay_pubkey: '22'.repeat(32), advertise_url: 'http://127.0.0.1:3602' };
  const capability = 'A'.repeat(43);
  const calls = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    calls.push({ url, token: init.headers?.['X-Loki-Token'], body: init.body });
    if (url === '/api/members') return Response.json({ slots: [member] });
    if (url === 'http://127.0.0.1:3602/api/registration') return Response.json(member);
    if (url === 'http://127.0.0.1:3602/api/status') return Response.json({ phase: 'home' });
    if (url === 'http://127.0.0.1:3602/api/payment-approve') return Response.json({ phase: 'signing' });
    if (url === 'http://127.0.0.1:3602/api/lock') return Response.json({});
    throw new Error(`unexpected fetch ${url}`);
  };
  try {
    assert.equal(signerKind(), 'browser');
    // Malformed links never reach the network.
    await assert.rejects(pairDevice('http://example.com:3602/#' + capability), /pairing link/);
    await assert.rejects(pairDevice('http://127.0.0.1:3602/#short'), /pairing link/);
    assert.equal(calls.length, 0);

    assert.equal((await pairDevice(`http://127.0.0.1:3602/#${capability}`)).slot, 2);
    assert.equal(signerKind(), 'native');
    const approve = { vault: 'a'.repeat(64), attempt: 'b'.repeat(64), review_token: 't', intent_hash: 'h' };
    assert.equal((await api('payment-approve', approve)).phase, 'signing');
    const last = calls.at(-1);
    assert.equal(last.url, 'http://127.0.0.1:3602/api/payment-approve');
    assert.equal(last.token, capability);
    assert.deepEqual(JSON.parse(last.body), approve, 'the reviewed intent_hash reaches the member');

    assert.equal(await logout(), true);
    assert.equal(calls.at(-1).url, 'http://127.0.0.1:3602/api/lock');
    assert.equal(signerKind(), 'browser', 'logout forgets the pairing');
  } finally {
    globalThis.fetch = originalFetch;
  }
});
