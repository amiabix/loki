import assert from 'node:assert/strict';
import { test } from 'node:test';
import { exportRecoveryBackup, removeBrowserSigner, restoreSigner, setupBrowserRecovery } from '../src/lib/api.ts';

test('browser recovery calls go only to the browser signer, never to a paired native member', async () => {
  const sess = new Map();
  globalThis.sessionStorage = { getItem: (k) => sess.get(k) ?? null, setItem: (k, v) => sess.set(k, v), removeItem: (k) => sess.delete(k) };
  globalThis.localStorage = { getItem: () => null, setItem: () => {}, removeItem: () => {} };
  globalThis.window = { dispatchEvent: () => {} };
  const fetched = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => { fetched.push(url); throw new Error('no network expected'); };
  const calls = [setupBrowserRecovery, () => exportRecoveryBackup('a'.repeat(64)),
    () => restoreSigner({ name: 'A', method: 'passphrase' }), removeBrowserSigner];
  try {
    // Browser kind: each call is dispatched to the signer (the Node mock serves none of them;
    // the signer origin does; locked, it asks to unlock first), and nothing is fetched here.
    for (const call of calls) await assert.rejects(call(), /does not serve|Unlock your signer/);
    // A tab paired with a native member refuses them before any request.
    sess.set('loki_device_session', JSON.stringify({ endpoint: 'http://127.0.0.1:3602', capability: 'A'.repeat(43) }));
    for (const call of calls) await assert.rejects(call(), /native member/);
    assert.deepEqual(fetched, []);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
