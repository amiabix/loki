import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { api, pairDevice, requestPairingLink, signerKind, logout } from '../src/lib/api.ts';
import * as members from '../src/lib/members.ts';

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

test('the wallet asks for a pairing link, then for the same slot again only once it expired', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'loki-wallet-pairing-'));
  process.env.LOKI_REGISTRY = join(dir, 'roster.json');
  const origin = 'http://localhost:3001';
  const bodies = [];
  let reply = null; // replaces the real coordinator for one request
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    assert.equal(url, '/api/members/pairing');
    assert.equal(init.method, 'POST');
    const body = JSON.parse(init.body);
    bodies.push(body);
    if (reply) { const r = reply(body); reply = null; return r; }
    try { return Response.json(await members.issuePairingChallenge(body, origin)); }
    catch (e) { return Response.json({ error: e.message }, { status: 400 }); }
  };
  try {
    const first = await requestPairingLink();
    assert.deepEqual(bodies[0], {}, 'the first link lets the coordinator pick the slot');
    assert.equal(first.slot, 1);
    assert(first.url.startsWith('loki://pair?') && first.expires > Date.now());
    // Another member's link takes the next slot, so a request without a slot no longer returns 1.
    assert.equal((await members.issuePairingChallenge({}, origin)).slot, 2);

    // While the link is live its slot is reserved; the member reads a sentence, not the coordinator's.
    await assert.rejects(requestPairingLink(first.slot), (e) => /^Slot 1 is already registered or reserved\. /.test(e.message));

    // Once it expired, a new link is for slot 1 again, with a new claim.
    const file = process.env.LOKI_REGISTRY + '.challenges';
    writeFileSync(file, JSON.stringify(JSON.parse(readFileSync(file)).map((c) => c.pairing_slot === 1 ? { ...c, expires: 0 } : c)));
    const again = await requestPairingLink(first.slot);
    assert.deepEqual(bodies.at(-1), { slot: 1 });
    assert.equal(again.slot, 1);
    assert.notEqual(new URL(again.url).searchParams.get('challenge'), new URL(first.url).searchParams.get('challenge'));

    // A link for another slot than the one asked for is refused.
    reply = () => Response.json({ ...again, slot: 3, url: again.url.replace('slot=1', 'slot=3') });
    await assert.rejects(requestPairingLink(1), /would not accept/);

    // Only a plain `loki://pair?` link from the coordinator becomes a link target.
    for (const url of ['javascript:alert(1)//loki://pair?slot=1', 'https://evil.example/?u=loki://pair?slot=1', 'loki://pairing?slot=1',
      'loki://pair?', ' loki://pair?slot=1', 'LOKI://pair?slot=1', 'loki://pair?slot=1"><img src=x onerror=alert(1)>', 'loki://pair?slot=1\njavascript:alert(1)']) {
      reply = () => Response.json({ slot: 4, url, expires: Date.now() + 120_000 });
      await assert.rejects(requestPairingLink(), /would not accept/, url);
    }
    // An unknown refusal is described in the wallet's words; its text never reaches the page.
    reply = () => Response.json({ error: '<a href="javascript:alert(1)">fix it here</a>' }, { status: 400 });
    await assert.rejects(requestPairingLink(), (e) => e.message === 'The coordinator refused a pairing link (HTTP 400). Try again, or ask whoever runs it.');
    reply = () => new Response('<html>Bad gateway</html>', { status: 502 });
    await assert.rejects(requestPairingLink(), /HTTP 502/);
  } finally {
    globalThis.fetch = originalFetch;
    rmSync(dir, { recursive: true, force: true }); delete process.env.LOKI_REGISTRY;
  }
});
