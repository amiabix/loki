import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkShare } from '../src/lib/signer.ts';

// The signer origin's storage was cleared (evicted) while this wallet origin still remembers a
// share was sealed here: say the share is missing and how to restore it, not "Create".
test('a share this browser had but the signer lost is reported missing', () => {
  const store = new Map();
  globalThis.localStorage = { getItem: (k) => store.get(k) ?? null, setItem: (k, v) => store.set(k, v), removeItem: (k) => store.delete(k) };
  assert.equal(checkShare(false), false); // never had one: offer Create
  assert.equal(checkShare(true), true);
  store.set('loki_signer_sealed', '1');
  assert.equal(checkShare(true), true);
  assert.throws(() => checkShare(false), (e) => e.status === 404 && /missing/.test(e.message) && /recovery words/.test(e.message));
});
