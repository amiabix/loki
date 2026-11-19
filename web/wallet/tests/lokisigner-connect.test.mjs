import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { registerHooks } from 'node:module';
import { test } from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import ts from 'typescript';
import { api, connectLokiSigner, hasLokiSignerSession, lastLokiSignerSlot } from '../src/lib/api.ts';

// Compile just this JSX module so the existing Node test command can render the production component.
const componentUrl = new URL('../src/components/NativeTabConnection.tsx', import.meta.url);
const jsx = registerHooks({ load(url, context, next) {
  if (url !== componentUrl.href) return next(url, context);
  return { format: 'module', shortCircuit: true, source: ts.transpileModule(readFileSync(componentUrl, 'utf8'), {
    compilerOptions: { module: ts.ModuleKind.ESNext, jsx: ts.JsxEmit.ReactJSX },
  }).outputText };
} });
const { NativeTabConnection } = await import(componentUrl.href);
jsx.deregister();

const member = { slot: 7, signing_pubkey: '11'.repeat(32), relay_pubkey: '22'.repeat(32), advertise_url: 'https://peer.example' };
const old = 'http://127.0.0.1:40117';
const current = 'http://[::1]:41227';
const sessionKey = 'loki_device_session';
const token = (letter) => letter.repeat(43);
const stored = (tab) => JSON.parse(tab.get(sessionKey) ?? 'null');

function tabFixture(t, fakeFetch) {
  let active;
  const events = [];
  t.mock.method(globalThis, 'fetch', fakeFetch);
  globalThis.window = { dispatchEvent: (event) => events.push(event.type) };
  globalThis.sessionStorage = {
    getItem: (key) => active.get(key) ?? null,
    setItem: (key, value) => active.set(key, value),
    removeItem: (key) => active.delete(key),
  };
  t.after(() => { delete globalThis.window; delete globalThis.sessionStorage; });
  return { events, use: (tab) => { active = tab; } };
}

function streamed(...parts) {
  const encoder = new TextEncoder();
  return new Response(new ReadableStream({ start(controller) {
    for (const part of parts) controller.enqueue(encoder.encode(part));
    controller.close();
  } }), { headers: { 'content-type': 'application/x-ndjson' } });
}

test('the real native login component chooses Connect for LokiSigner and paste for headless or older apps', () => {
  const render = (row) => renderToStaticMarkup(createElement(NativeTabConnection, {
    slot: row.slot, member: row, disabled: false, onBusy() {}, onConnected() {},
  }));
  const lokiSigner = render({ ...member, lokisigner_url: current });
  assert.match(lokiSigner, /<button[^>]*>Connect LokiSigner<\/button>/);
  assert.doesNotMatch(lokiSigner, /<input|Pair this tab/);
  const headless = render(member);
  assert.match(headless, /<input[^>]*type="password"/);
  assert.match(headless, /<button[^>]*>Pair this tab<\/button>/);
  assert.doesNotMatch(headless, /Connect LokiSigner/);
});

test('a new tab waits for registration, receives its own grant, and reconnects after the port changes', async (t) => {
  let launch = 1, ready = false, requests = 0;
  const posts = [], progress = [];
  const tab1 = new Map(), tab2 = new Map();
  const fixture = tabFixture(t, async (url, options = {}) => {
    if (url === '/api/members') {
      // The first launch's row is visible before the app has consumed its registration reply.
      const endpoint = launch === 1 ? old : current;
      return Response.json({ slots: [{ ...member, lokisigner_url: endpoint }] });
    }
    if (url.endsWith('/api/connect')) {
      posts.push(url);
      assert.deepEqual(options.headers, { 'Content-Type': 'application/json' });
      assert.equal(options.redirect, 'error');
      assert.deepEqual(JSON.parse(options.body), { slot: member.slot, signing_pubkey: member.signing_pubkey, relay_pubkey: member.relay_pubkey });
      if (!ready) { ready = true; return new Response(null, { status: 425 }); }
      return streamed('{"co', 'de":"061274"}\n', JSON.stringify({ token: token(String(++requests)) }) + '\n');
    }
    assert.match(url, /\/api\/status$/);
    if (launch === 2 && url.startsWith(old)) return new Response(null, { status: 401 });
    assert.equal(options.headers['X-Loki-Token'], token(String(requests)));
    return Response.json({ phase: 'home' });
  });
  const connect = () => connectLokiSigner(member.slot, (event) => progress.push(event), new AbortController().signal);

  fixture.use(tab1);
  const connecting = connect();
  assert.deepEqual(progress, [{ phase: 'starting' }]);
  assert.equal(stored(tab1), null);
  await connecting;
  assert.deepEqual(posts, [`${old}/api/connect`, `${old}/api/connect`]);
  assert.deepEqual(progress, [{ phase: 'starting' }, { phase: 'compare', code: '061274' }]);
  const first = stored(tab1);
  assert.equal(first.capability, token('1'));
  assert.equal((await api('status')).phase, 'home');

  fixture.use(tab2);
  assert.equal(hasLokiSignerSession(), false);
  await connect();
  assert.equal(stored(tab2).capability, token('2'));
  assert.equal((await api('status')).phase, 'home');
  assert.deepEqual(stored(tab1), first);

  fixture.use(tab1);
  launch = 2;
  await assert.rejects(api('status'), { status: 401 });
  assert.deepEqual(fixture.events, ['loki:auth-lost']);
  assert.equal(stored(tab1), null);
  assert.equal(lastLokiSignerSlot(), member.slot);
  await connect();
  assert.equal(posts.at(-1), `${current}/api/connect`);
  assert.equal(stored(tab1).capability, token('3'));
  assert.equal((await api('status')).phase, 'home');
});

test('a stale loopback port retries discovery; a foreign URL or a refused response cannot set a session', async (t) => {
  const tab = new Map();
  let endpoint = old, posts = 0;
  const fixture = tabFixture(t, async (url) => {
    if (url === '/api/members') return Response.json({ slots: [{ ...member, lokisigner_url: endpoint }] });
    posts++;
    if (url === `${old}/api/connect`) { endpoint = current; throw new TypeError('connection refused'); }
    assert.equal(url, `${current}/api/connect`);
    return streamed('{"code":"061274"}\n', '{"refused":true}\n');
  });
  fixture.use(tab);
  const events = [];
  const connect = () => connectLokiSigner(member.slot, (event) => events.push(event), new AbortController().signal);
  await assert.rejects(connect(), /did not allow/);
  assert.deepEqual(events, [{ phase: 'starting' }, { phase: 'compare', code: '061274' }]);
  assert.equal(stored(tab), null);
  assert.equal(posts, 2, 'an explicit refusal does not retry');

  for (const invalid of ['http://example.com:41227', 'http://127.0.0.1:41227/', 'http://user@127.0.0.1:41227', 'http://[::1]:41227#x']) {
    endpoint = invalid;
    await assert.rejects(connect(), /valid LokiSigner loopback address/);
  }
  assert.equal(posts, 2, 'no invalid roster address is contacted');
});
