import assert from 'node:assert/strict';
import { beforeEach, test } from 'node:test';
import { admitAttempt, admitClient, canonicalAddress } from '../src/lib/admission-limits.ts';

beforeEach(() => { globalThis.lokiAdmissionBuckets = {}; });

test('IPv6 clients are counted by their /64, IPv4-mapped addresses as IPv4', () => {
  assert.equal(canonicalAddress('2001:DB8:0:1::5'), '2001:db8:0:1::/64');
  assert.equal(canonicalAddress('2001:db8::1'), '2001:db8:0:0::/64');
  assert.equal(canonicalAddress('::1'), '0:0:0:0::/64');
  assert.equal(canonicalAddress('2001:db8:1:2:3:4:5:6'), '2001:db8:1:2::/64');
  assert.equal(canonicalAddress('::ffff:203.0.113.9'), '203.0.113.9');
  assert.equal(canonicalAddress('fe80::1%en0'), undefined);

  for (let i = 1; i <= 60; i++) admitAttempt(canonicalAddress(`2001:db8:0:1::${i.toString(16)}`), 0);
  assert.throws(() => admitAttempt(canonicalAddress('2001:db8:0:1::ffff'), 0), /Too many registration attempts/);
  admitAttempt(canonicalAddress('2001:db8:0:2::1'), 0);
});

test('per-minute limits forget a client after a minute, so a full table does not lock out new ones', () => {
  for (let i = 0; i < 10_000; i++) admitAttempt(`10.${i >> 8}.${i & 255}.1`, 0);
  const later = 61_000;
  for (let i = 0; i < 60; i++) admitAttempt('203.0.113.9', later);
  admitAttempt('198.51.100.7', later);
});

test('the pairing limit still counts a rolling day', () => {
  for (let i = 0; i < 30; i++) admitClient('203.0.113.9', i * 60_000);
  assert.throws(() => admitClient('203.0.113.9', 60 * 60_000), (error) => error.retryAfter > 3600);
});
