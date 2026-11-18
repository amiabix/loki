import assert from 'node:assert/strict';
import { test } from 'node:test';
import { api, listSlots, createSigner, unlock, hasSigner, logout, forgetSession } from '../src/lib/api.ts';

test('member calls run in the in-browser signer; only the coordinator is fetched', async () => {
  const sess = new Map(), local = new Map(), events = [];
  globalThis.sessionStorage = { getItem: (k) => sess.get(k) ?? null, setItem: (k, v) => sess.set(k, v), removeItem: (k) => sess.delete(k) };
  globalThis.localStorage = { getItem: (k) => local.get(k) ?? null, setItem: (k, v) => local.set(k, v), removeItem: (k) => local.delete(k) };
  globalThis.window = { dispatchEvent: (e) => events.push(e.type) };
  const originalFetch = globalThis.fetch;
  const member = { slot: 1, signing_pubkey: '11'.repeat(32), relay_pubkey: '22'.repeat(32), advertise_url: 'http://127.0.0.1:3601' };
  const fetched = [];
  globalThis.fetch = async (url, init = {}) => {
    fetched.push(url);
    assert(url === '/api/members', 'the only network call is the public roster');
    assert(!init.headers, 'coordinator receives no signer capability');
    return Response.json({ slots: [member] });
  };
  try {
    // Fresh browser: no sealed share yet → Create, not Unlock.
    assert.equal(await hasSigner(), false);
    await assert.rejects(api('status'), /Unlock your signer/); // locked → no session

    // Create a signer in this browser (passphrase fallback path); session opens.
    const created = await createSigner({ name: 'Alex', method: 'passphrase', passphrase: 'correct horse' });
    assert.equal(created.profile.name, 'Alex');
    assert.equal(await hasSigner(), true);
    const status = await api('status');
    assert.equal(status.phase, 'home');
    assert.equal(status.secure_element, 'software');
    assert.deepEqual(status.vaults, []);

    // Vault/DKG/payment paths belong to the wasm core (W1); the mock says so, it never fakes them.
    await assert.rejects(api('create', { name: 'v', members: 3, threshold: 2 }), /does not serve/);
    await assert.rejects(api('../api/members'), /invalid signer API path/);

    // The public roster still comes from the coordinator over HTTP.
    assert.deepEqual(await listSlots(), [member]);
    assert.deepEqual(fetched, ['/api/members']);

    // Lock ends the session; member calls 401 and bounce the UI to Login.
    assert.equal(await logout(), true);
    await assert.rejects(api('status'), /Unlock your signer/);
    assert(events.includes('loki:auth-lost'));

    // The sealed share persists in this browser → Unlock reopens it without re-creating.
    assert.equal(await hasSigner(), true);
    assert.equal((await unlock({ method: 'passphrase', passphrase: 'correct horse' })).profile.name, 'Alex');
    assert.equal((await api('status')).phase, 'home');
    forgetSession();
  } finally {
    globalThis.fetch = originalFetch;
    delete globalThis.window; delete globalThis.sessionStorage; delete globalThis.localStorage;
  }
});
