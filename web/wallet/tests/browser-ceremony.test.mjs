import assert from 'node:assert/strict';
import { test } from 'node:test';
import { browserVaultStatus } from '../src/lib/signer.ts';

// After a browser member's join resolves, the wallet opens the setup screen, which polls
// `status?vault=`. It must get that vault's phase, or the screen renders nothing.
test('the browser signer reports a joined vault as active, and one it is still joining as creating keys', () => {
  const vault = 'ab'.repeat(32);
  assert.deepEqual(browserVaultStatus([{ vault, active: true }], vault), { phase: 'active' });
  assert.deepEqual(browserVaultStatus([{ vault, active: false }], vault), { phase: 'creating_keys' });
  // While a join holds the signer its vault list is refused (undefined).
  assert.deepEqual(browserVaultStatus(undefined, vault), { phase: 'creating_keys' });
  assert.deepEqual(browserVaultStatus([{ vault: 'cd'.repeat(32), active: true }], vault), { phase: 'creating_keys' });
});
