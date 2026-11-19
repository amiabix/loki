import assert from 'node:assert/strict';
import { test } from 'node:test';
import { storageLabel } from '../src/lib/wallet-ui.ts';

// The in-browser signer reports `passkey` or `software` (passphrase) as its secure element; a
// native member reports `apple` (Enclave) or `software` (development backend).
test('the storage badge names what actually protects the share', () => {
  assert.equal(storageLabel('apple', 'native').label, 'Enclave-protected wrapping key');
  assert.equal(storageLabel('software', 'native').label, 'Software device storage');
  assert.equal(storageLabel('passkey', 'browser').label, 'Sealed under your passkey in this browser');
  assert.equal(storageLabel('software', 'browser').label, 'Sealed under your passphrase in this browser');
  assert.equal(storageLabel('apple', 'native').enclave, true);
  assert.equal(storageLabel('passkey', 'browser').enclave, false);
});
