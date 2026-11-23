import assert from 'node:assert/strict';
import { test } from 'node:test';
import { browserVaultStatus } from '../src/lib/signer.ts';

test('the browser signer reports a joined vault as active, and one it is still joining as creating keys', () => {
  const vault = 'ab'.repeat(32);
  assert.deepEqual(browserVaultStatus([{ vault, active: true }], vault), { phase: 'active' });
  assert.deepEqual(browserVaultStatus([{ vault, active: false }], vault), { phase: 'creating_keys' });
  assert.deepEqual(browserVaultStatus(undefined, vault), { phase: 'creating_keys' });
  assert.deepEqual(browserVaultStatus([{ vault: 'cd'.repeat(32), active: true }], vault), { phase: 'creating_keys' });
});
