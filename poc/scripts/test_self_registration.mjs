#!/usr/bin/env node
// Isolated S4a smoke: the test/member starts signers; Next only handles public registration.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

const poc = fileURLToPath(new URL('../', import.meta.url));
const web = fileURLToPath(new URL('../../web/wallet/', import.meta.url));
const root = mkdtempSync(join(tmpdir(), 'loki-self-registration-'));
const registry = join(root, 'public-roster.json');
const processes = new Set();
const claimedPairing = process.argv.includes('--pairing');
async function port() {
  const server = createServer();
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const value = server.address().port;
  await new Promise((resolve) => server.close(resolve)); return value;
}
function launch(command, args, options = {}) {
  const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'], ...options });
  processes.add(child);
  child.errors = '';
  child.stderr.on('data', (data) => { child.errors += data; });
  child.stdout.on('data', (data) => {
    // Recovery words are deliberately neither saved nor printed by this test.
    const match = String(data).match(/Local pairing: (http:\/\/127\.0\.0\.1:\d+\/#[A-Za-z0-9_-]+)/);
    if (match) child.pairing = new URL(match[1]);
  });
  return child;
}
async function until(label, check, child) {
  for (let i = 0; i < 600; i++) {
    if (await check()) return;
    assert(child.exitCode === null, `${label}: process exited: ${child.errors}`);
    await delay(100);
  }
  throw new Error(`${label} timed out: ${child.errors}`);
}
async function stop(child) {
  if (child.exitCode === null && child.signalCode === null) {
    const done = once(child, 'exit'); child.kill('SIGTERM'); await done;
  }
  processes.delete(child);
}
let webPort;
let origin;
let next;
function startWeb() {
  return launch(process.execPath, [join(web, 'node_modules/next/dist/bin/next'), 'start', '--hostname', '127.0.0.1', '-p', String(webPort)], {
    cwd: web, env: { ...process.env, LOKI_REGISTRY: registry },
  });
}
async function webReady() {
  await until('coordinator', async () => { try { return (await fetch(`${origin}/api/members`)).ok; } catch { return false; } }, next);
}
async function startMember(slot, memberPort, restart = false) {
  const data = join(root, `member-${slot}`);
  mkdirSync(data, { recursive: true, mode: 0o700 });
  const unlock = join(data, 'local.passphrase');
  writeFileSync(unlock, `independent-dev-unlock-${slot}`, { mode: 0o600 });
  let registration = ['--coordinator-url', origin, '--registration-slot', String(slot)];
  if (claimedPairing && !restart) {
    const reply = await fetch(`${origin}/api/members/pairing`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: origin }, body: JSON.stringify({ slot }) });
    assert.equal(reply.status, 200);
    const pairing = await reply.json();
    assert.equal(pairing.slot, slot);
    registration = ['--pairing-url', pairing.url];
  }
  return launch(process.env.LOKI_MEMBER_APP_BIN ?? join(poc, 'target/debug/loki_member_app'), [
    ...(process.env.LOKI_NATIVE_SIGNER === '1' ? ['serve'] : []),
    '--data', data, '--port', String(memberPort), '--advertise-url', `http://127.0.0.1:${memberPort}`,
    '--network', 'regtest', '--secure-element', 'software', '--development-http',
    ...registration, '--local-passphrase-file', unlock,
    '--profile-name', `Member ${slot}`,
  ]);
}
async function direct(child, path, method = 'GET', body) {
  return fetch(`${child.pairing.origin}/api/${path}`, { method, headers: { Origin: origin, 'X-Loki-Token': child.pairing.hash.slice(1), 'Content-Type': 'application/json' }, body: body && JSON.stringify(body) });
}
try {
  webPort = await port();
  origin = `http://127.0.0.1:${webPort}`;
  next = startWeb(); await webReady();
  const p1 = await port(), p2 = await port();
  let first = await startMember(1, p1);
  const second = await startMember(2, p2);
  for (const member of [first, second]) await until('self-registration', () => Boolean(member.pairing), member);
  const roster = (await (await fetch(`${origin}/api/members`)).json()).slots;
  assert.equal(roster.length, 2);
  assert.notEqual(roster[0].signing_pubkey, roster[1].signing_pubkey);
  assert.notEqual(roster[0].relay_pubkey, roster[1].relay_pubkey);
  for (const entry of roster) assert.deepEqual(Object.keys(entry).sort(), ['advertise_url', 'relay_pubkey', 'signing_pubkey', 'slot']);
  for (const member of [first, second]) {
    const reply = await direct(member, 'status');
    assert.equal(reply.headers.get('access-control-allow-origin'), origin);
    assert.equal((await reply.json()).phase, 'home');
    assert.equal((await fetch(`${member.pairing.origin}/api/status`)).status, 401);
    assert.equal((await fetch(`${member.pairing.origin}/api/status`, { headers: { Origin: 'http://evil.example', 'X-Loki-Token': member.pairing.hash.slice(1) } })).status, 403);
  }
  assert.equal((await direct(first, 'lock', 'POST', {})).status, 200);
  assert.equal((await (await direct(first, 'status')).json()).phase, 'locked');
  await stop(first);
  first = await startMember(1, p1, true);
  await until('member restart and self-registration', () => Boolean(first.pairing), first);
  assert.deepEqual((await (await fetch(`${origin}/api/members`)).json()).slots, roster);
  await stop(next); next = startWeb(); await webReady();
  assert.deepEqual((await (await fetch(`${origin}/api/members`)).json()).slots, roster);
  assert.equal((await (await direct(first, 'status')).json()).phase, 'home');
  assert.equal((await (await direct(second, 'status')).json()).phase, 'home');
  for (const path of ['signup', 'login', 'logout', 'u/status']) {
    assert.equal((await fetch(`${origin}/api/${path}`, { method: 'POST' })).status, 404, path);
  }
  const raw = readFileSync(registry, 'utf8');
  assert(!/token|passphrase|pid/.test(raw));
  for (const member of [first, second]) assert(!raw.includes(member.pairing.hash.slice(1)));
  console.log(`PASS: two independently started devices ${claimedPairing ? 'claim pairing links and ' : ''}self-register; public-only roster; direct authenticated sessions; local lock/restart; coordinator restart; no hosted login/proxy routes.`);
} finally {
  for (const child of [...processes]) await stop(child);
  rmSync(root, { recursive: true, force: true });
}
