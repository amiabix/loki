// G3 drills, across three browser engines.
//
// Real browsers, real IndexedDB, real tabs, real process kills, a real profile directory
// copied out and copied back, and THREE separate relay processes signing receipts with
// real Ed25519 keys that the page pins at setup and verifies through WebCrypto.
//
// The three relays are SIMULATED OPERATORS. They are local Node processes on loopback
// sharing a kernel, a disk, a clock and whoever can run `kill`. A 2-of-3 threshold rests
// on "at least one of the three is honest", and local processes cannot demonstrate that.
//
// ENGINES. `G3_ENGINE` selects chromium, webkit or firefox; `G3_SUITE=portable` runs only
// the five categories that are meaningful on every engine. Playwright's WebKit is a
// WebKit build shipped by Playwright; it is NOT Safari, and no result here is a Safari
// result. See G3-RESULTS.md.
//
// Each drill gets a fresh profile and fresh relays, so one drill cannot contaminate the
// next. Every drill ends by running `extractOnReuse` over the counterparty's view: a
// drill passes because no key could be recovered, not because nothing printed an error.

import { chromium, firefox, webkit } from 'playwright-core';
import { spawn, execSync } from 'node:child_process';
import { createServer } from 'node:http';
import { readFile, writeFile } from 'node:fs/promises';
import { rmSync, cpSync } from 'node:fs';
import { join, extname } from 'node:path';

const ENGINE = process.env.G3_ENGINE || 'chromium';
const ENGINES = { chromium, firefox, webkit };
const BROWSER = ENGINES[ENGINE];
if (!BROWSER) { console.error(`unknown G3_ENGINE: ${ENGINE}`); process.exit(2); }

const TMP = join(process.env.G3_TMP || '/tmp/loki-g3', ENGINE);
const WEB = Number(process.env.G3_WEB_PORT || 18764);
const PORTS = [
  Number(process.env.RELAY_PORT || 18765),
  Number(process.env.RELAY_PORT_B || 18766),
  Number(process.env.RELAY_PORT_C || 18767),
];
const BASE = `http://127.0.0.1:${WEB}`;
const ROOT = import.meta.dirname;
const IDS = PORTS.map((p) => `relay-${p}`);
const [A, B, C] = IDS;

/// The five categories the portable suite covers on every engine.
const PORTABLE = new Set([
  // receipt gate
  'gate-three-honest', 'gate-only-one-reachable',
  // two-tab race
  'two-tabs-no-lock', 'two-tabs-same-package-no-lock',
  // crash recovery
  'hard-kill-after-consume',
  // profile restore
  'restore-three-honest', 'restore-all-acknowledgers-lying',
  // strict durability
  'durability-unsupported-is-not-a-pass',
]);
const SUITE = process.env.G3_SUITE || 'full';

/// Renderer-crash injection is engine specific. Only Chromium exposes a URL that crashes
/// the renderer without touching the browser process. Where it is absent, the drill is
/// recorded UNSUPPORTED rather than quietly substituted with something weaker; the
/// process-kill drill covers the same boundary on every engine.
const RENDERER_CRASH_URL = { chromium: 'chrome://crash' }[ENGINE] ?? null;

const results = [];
const only = process.argv[2];

// Drills expected NOT to pass, because what they test cannot be made safe at this layer.
// They are run and recorded rather than omitted, so the gap stays visible.
const EXPECTED_FAILURES = new Set([
  'restore-all-acknowledgers-lying',
  'restore-one-relay-baseline',
  'restore-one-liar-honest-acknowledger-offline',
]);
// Drills whose point is that the platform cannot be counted as passing.
const INCONCLUSIVE = new Set(['durability-unsupported-is-not-a-pass']);

// ── plumbing ───────────────────────────────────────────────────────────────

const TYPES = { '.html': 'text/html', '.js': 'text/javascript' };
const web = createServer(async (req, res) => {
  const u = new URL(req.url, 'http://x');
  const p = join(ROOT, u.pathname === '/' ? 'page.html' : u.pathname.slice(1));
  try {
    const f = await readFile(p);
    res.writeHead(200, { 'content-type': TYPES[extname(p)] || 'application/octet-stream' });
    res.end(f);
  } catch { res.writeHead(404); res.end('not found'); }
});
await new Promise((r) => web.listen(WEB, r));

/// Start the three simulated operators. A `null` mode means that relay is DOWN for this
/// drill, which is how an outage is expressed: the process simply is not there.
async function startRelays(modes) {
  const out = [];
  for (const [i, mode] of modes.entries()) {
    const base = `http://127.0.0.1:${PORTS[i]}`;
    if (!mode) { out.push({ relay_id: IDS[i], base, down: true }); continue; }
    const proc = spawn(process.execPath, [join(ROOT, 'relay.mjs')], {
      env: { ...process.env, RELAY_MODE: mode, RELAY_PORT: String(PORTS[i]), RELAY_ID: IDS[i] },
      stdio: ['ignore', 'pipe', 'inherit'],
    });
    try {
      await new Promise((res, rej) => {
        const timeout = setTimeout(() => rej(new Error('relay did not start')), 30000);
        proc.stdout.on('data', (d) => {
          if (String(d).includes('relay ')) { clearTimeout(timeout); res(); }
        });
        proc.on('exit', (c) => { clearTimeout(timeout); rej(new Error(`relay exited ${c}`)); });
      });
      const pk = await fetch(`${base}/pubkey`).then((r) => r.json());
      out.push({ relay_id: pk.relay_id, base, mode, proc, spki: pk.spki });
    } catch (e) {
      proc.kill('SIGKILL');
      stopRelays(out);
      throw e;
    }
  }
  return out;
}
const stopRelays = (rs) => { for (const r of rs) r.proc?.kill('SIGKILL'); };

function takeDown(relays, ids) {
  for (const r of relays) {
    if (ids.includes(r.relay_id) && r.proc) { r.proc.kill('SIGKILL'); r.proc = undefined; r.down = true; }
  }
}

/// Bring a relay up that was absent earlier, with a FRESH memory.
///
/// A fresh process is exactly the right model for "an operator that never acknowledged
/// this record": it is reachable, it is honest, and it has nothing to report. It is NOT a
/// model for an operator that acknowledged and then lost its state, which would be a
/// different experiment and is not drilled.
async function bringUp(relays, ids, mode = 'honest') {
  for (const [i, r] of relays.entries()) {
    if (!ids.includes(r.relay_id) || r.proc) continue;
    const started = await startRelays(PORTS.map((_, k) => (k === i ? mode : null)));
    Object.assign(r, started[i], { down: false });
  }
}

const launch = (dir) => BROWSER.launchPersistentContext(dir, {
  timeout: 60000,
  ...(process.env.G3_EXECUTABLE ? { executablePath: process.env.G3_EXECUTABLE } : {}),
  ...(ENGINE === 'chromium' ? { args: ['--no-first-run', '--no-default-browser-check'] } : {}),
});

/// Open the page. `relays` is what the store is told to use; a relay that is down stays in
/// the list so the store experiences a failed fetch rather than silently working with
/// fewer. `pinned` is what it will trust.
async function openPage(ctx, relays, pinned, opts = {}) {
  const { required = 2, noDurability = false } = opts;
  const page = await ctx.newPage();
  await page.addInitScript(
    `window.__RELAYS = ${JSON.stringify(relays.map(({ relay_id, base }) => ({ relay_id, base })))};
     window.__PINNED = ${JSON.stringify(pinned)};
     window.__REQUIRED = ${required};
     window.__NO_DURABILITY = ${noDurability};`,
  );
  await page.goto(BASE, { waitUntil: 'domcontentloaded' });
  await page.waitForFunction('window.__ready === true', null, { timeout: 15000 });
  return page;
}

const pinOf = (rs) => rs.filter((r) => r.spki).map(({ relay_id, spki }) => ({ relay_id, spki }));

/// Crash the renderer. No unload handlers, nothing flushed on the way out; whatever
/// IndexedDB already committed lives in the browser process and survives.
async function crashRenderer(page) {
  if (!RENDERER_CRASH_URL) return false;
  await page.goto(RENDERER_CRASH_URL, { timeout: 3000 }).catch(() => {});
  await page.waitForEvent('crash', { timeout: 5000 }).catch(() => {});
  return true;
}

/// SIGKILL the whole browser. IndexedDB lives in the browser process, so this is the only
/// drill that could lose an already-committed transaction.
function killBrowser(dir) {
  try {
    const pids = execSync(
      `ps -axo pid=,command= | grep -F ${JSON.stringify(dir)} | grep -v grep | awk '{print $1}'`,
      { shell: '/bin/sh' },
    ).toString().trim().split('\n').filter(Boolean);
    for (const p of pids) { try { process.kill(Number(p), 'SIGKILL'); } catch {} }
    return pids.length;
  } catch { return 0; }
}

const ev = (page, fn, ...a) => page.evaluate(fn, ...a);
const shares = (p) => ev(p, () => window.__store.sharesOut());
const states = (p) => ev(p, () => window.__store.states());
const wal = (p) => ev(p, () => window.__store.walOut());
const say = (r) => `${r.event} ${r.code ?? ''} ${r.detail ? JSON.stringify(r.detail) : ''}`.trim();

async function noReuse(page, hist, notes) {
  const leaks = await ev(page, (s) => window.__extractOnReuse(s), hist);
  if (leaks.length) {
    notes.push(`NONCE REUSE, signing key recovered: ${leaks[0].recovered_key.slice(0, 32)}...`);
    notes.push(`  from messages ${JSON.stringify(leaks[0].messages)}`);
    return false;
  }
  notes.push('no reuse: the oracle recovered nothing');
  return true;
}

async function drill(name, modes, body) {
  if (only && only !== name) return;
  if (SUITE === 'portable' && !PORTABLE.has(name)) return;
  const dir = join(TMP, name);
  rmSync(dir, { recursive: true, force: true });
  rmSync(`${dir}-snapshot`, { recursive: true, force: true });
  const relays = await startRelays(modes);
  const notes = [];
  let ok = null, err = null;
  try { ok = await body({ dir, notes, relays }); } catch (e) { err = e; }
  stopRelays(relays);
  const expected = EXPECTED_FAILURES.has(name) && !err;
  const unsupported = ok === 'unsupported';
  const inconclusive = INCONCLUSIVE.has(name) || unsupported;
  results.push({
    name, ok: ok === true, expected_failure: expected, inconclusive, unsupported,
    err: err && String(err), notes,
  });
  const tag = unsupported ? 'UNSUPPORTED'
    : inconclusive ? 'INCONCLUSIVE'
      : ok === true ? 'PASS'
        : expected ? 'EXPECTED FAILURE' : 'FAIL';
  console.log(`  ${name.padEnd(36)} ${tag}`);
  for (const n of notes) console.log(`      ${n}`);
  if (err) console.log(`      ERROR ${err.message}`);
}

// ── one spend, many configurations ─────────────────────────────────────────

/// Generate one nonce and try to spend it. `expect` is either null (the share must be
/// released by `required` distinct relays) or a refusal code that must fire with no share.
async function spendDrill(name, modes, opts, expect) {
  const { pin, required = 2, noDurability = false, downBeforeSpend, downAfterStartup } = opts;
  await drill(name, modes, async ({ dir, notes, relays }) => {
    const ctx = await launch(dir);
    const pinned = (pin ?? pinOf)(relays);
    // The relay list the store is handed. `listTwice` duplicates one entry, which is how
    // "the same operator reached at two addresses" is expressed.
    const list = opts.listTwice ? [relays[0], relays[0], relays[1]] : relays;
    const page = await openPage(ctx, list, pinned, { required, noDurability });

    const dur = await ev(page, () => window.__store.durabilityReport());
    await ev(page, () => window.__store.startup());
    const gen = await ev(page, () => window.__store.generate(1));
    const id = gen.ids[0];

    if (downBeforeSpend) { takeDown(relays, downBeforeSpend); notes.push(`down before spend: ${downBeforeSpend.join(',')}`); }
    if (downAfterStartup) {
      // Startup is run a SECOND time here deliberately. The first startup on a brand new
      // profile returns `fresh` without contacting anybody, so using it would have meant
      // this drill never observed the relays at all and the window it claims to test
      // would not exist. The second startup really does query all three.
      const seen = await ev(page, () => window.__store.startup());
      notes.push(`startup contacted ${seen.reported?.length ?? 0} relay(s): ${JSON.stringify(seen.reported ?? seen)}`);
      if ((seen.reported?.length ?? 0) !== relays.filter((r) => !r.down).length) {
        throw new Error('startup did not contact every live relay; the window under test is not set up');
      }
      takeDown(relays, downAfterStartup);
      notes.push(`THEN taken down, after startup and before receipt collection: ${downAfterStartup.join(',')}`);
    }

    const r = await ev(page, ([id]) =>
      window.__store.spend('rid-1', id, 'pay alice 1', undefined), [id]);
    const sh = await shares(page);
    notes.push(`pinned: ${pinned.map((p) => p.relay_id).join(',') || 'none'}`);
    notes.push(`spend: ${say(r)}`);
    notes.push(`acknowledgers: ${JSON.stringify(r.receipts ?? [])}`);
    notes.push(`shares released: ${sh.length}`);
    notes.push(`durability requested=${dur.requested} attrPresent=${dur.attrPresent} accepted=${dur.optionsAccepted} reflected=${dur.reflected} supported=${dur.supported} policy=${dur.policy} simulated=${dur.simulated}`);
    const clean = await noReuse(page, sh, notes);
    await ctx.close();

    if (expect === null) {
      return clean && r.event === 'share_saved' && sh.length === 1 && r.receipts.length >= required;
    }
    return clean && r.event === 'refused' && r.code === expect && sh.length === 0;
  });
}

// ── two tabs racing ────────────────────────────────────────────────────────

/// `samePackage` makes both tabs sign the SAME message. An honest relay will happily
/// issue both tabs a receipt then, because the package digest matches and it is not a
/// replay from the relay's point of view. That leaves the local compare-and-set as the
/// only thing between the two tabs, which is exactly what needs testing: the
/// differing-message variants are intercepted by the relays before the local check is
/// ever reached, so on their own they would leave the local check unexercised.
async function twoTabs(name, locked, samePackage = false) {
  await drill(name, ['honest', 'honest', 'honest'], async ({ dir, notes, relays }) => {
    const ctx = await launch(dir);
    const pinned = pinOf(relays);
    const a = await openPage(ctx, relays, pinned);
    await ev(a, () => window.__store.startup());
    const id = (await ev(a, () => window.__store.generate(1))).ids[0];
    const b = await openPage(ctx, relays, pinned);

    // A wall-clock barrier, so both tabs are inside the consume transaction at the same
    // moment. Without it `Promise.all` only proves both renderers were busy, not that
    // their IndexedDB transactions ever overlapped, and the drill could pass by accident.
    const at = Date.now() + 1500;
    const m = locked ? 'spendLocked' : 'spend';
    const race = (p, rid, msg) => ev(p, ([m, id, rid, msg, at]) => {
      while (Date.now() < at) { /* spin to the barrier */ }
      return window.__store[m](rid, id, msg, undefined);
    }, [m, id, rid, msg, at]);
    const [ra, rb] = await Promise.all([
      race(a, 'rid-A', 'pay alice 1'),
      race(b, 'rid-B', samePackage ? 'pay alice 1' : 'pay mallory 99'),
    ]);
    notes.push(`tab A: ${say(ra)}`);
    notes.push(`tab B: ${say(rb)}`);
    const sh = await shares(a);
    notes.push(`shares on disk: ${sh.length}`);
    const clean = await noReuse(a, sh, notes);
    await ctx.close();
    return clean && sh.length === 1
      && [ra, rb].filter((r) => r.event === 'share_saved').length === 1
      && [ra, rb].filter((r) => r.event === 'refused').length === 1;
  });
}

// ── crashes ────────────────────────────────────────────────────────────────

async function crashDrill(name, crashAt, expect) {
  await drill(name, ['honest', 'honest', 'honest'], async ({ dir, notes, relays }) => {
    const pinned = pinOf(relays);
    let ctx = await launch(dir);
    let page = await openPage(ctx, relays, pinned);
    await ev(page, () => window.__store.startup());
    const id = (await ev(page, () => window.__store.generate(1))).ids[0];

    const hard = crashAt === 'hard_kill_after_consume';
    const stopAt = hard ? 'after_consume' : crashAt;
    const reached = await ev(page, ([id, at]) =>
      window.__store.spend('rid-1', id, 'pay alice 1', at), [id, stopAt]);
    notes.push(`reached ${reached.at ?? say(reached)}`);

    if (hard) {
      notes.push(`SIGKILL sent to ${killBrowser(dir)} browser process(es)`);
      await new Promise((r) => setTimeout(r, 1500));
    } else {
      const injected = await crashRenderer(page);
      if (!injected) {
        notes.push(`renderer-crash injection UNSUPPORTED on ${ENGINE}: no equivalent of `
          + `chrome://crash. Drill skipped rather than quietly weakened; `
          + `hard-kill-after-consume covers this boundary on every engine.`);
        await ctx.close();
        return 'unsupported';
      }
      await ctx.close();
    }

    ctx = await launch(dir);
    page = await openPage(ctx, relays, pinned);
    const before = await states(page);
    const start = await ev(page, () => window.__store.startup());
    notes.push(`restart saw: ${before.map((n) => `${n.state}/${n.has_secret ? 'secret' : 'nosecret'}`).join(',')}`);
    notes.push(`startup: ${JSON.stringify(start)}`);
    notes.push(`wal: ${(await wal(page)).map((w) => `${w.rid}=${w.phase}`).join(',')}`);

    const retry = await ev(page, ([id]) =>
      window.__store.spend('rid-2', id, 'pay mallory 99', undefined), [id]);
    notes.push(`retry: ${retry.event} ${retry.code ?? ''}`.trim());
    const sh = await shares(page);
    const st = (await states(page)).find((n) => n.id === id);
    notes.push(`final: ${JSON.stringify(st)} shares=${sh.length}`);
    const clean = await noReuse(page, sh, notes);
    await ctx.close();
    return clean && expect({ retry, st, shares: sh, start });
  });
}

// ── restore ────────────────────────────────────────────────────────────────

/// A profile with two unspent nonces is copied out, both are spent (recording WHICH relays
/// acknowledged), then the profile is copied back. The store now believes nothing was
/// spent while a counterparty still holds the shares.
///
/// `downAfterSpend` takes relays away between the spend and the restart, so the drill can
/// isolate the real detection condition: at least one relay that ACKNOWLEDGED the original
/// record must be honest AND reachable now.
async function restoreDrill(name, modes, opts, expect) {
  const { downBeforeSpend = [], downAfterSpend = [], upAfterSpend = [], required = 2 } = opts;
  await drill(name, modes, async ({ dir, notes, relays }) => {
    const snap = `${dir}-snapshot`;
    const pinned = pinOf(relays);

    // 1. a healthy device with two published nonces
    let ctx = await launch(dir);
    let page = await openPage(ctx, relays, pinned, { required });
    await ev(page, () => window.__store.startup());
    const ids = (await ev(page, () => window.__store.generate(2))).ids;
    await ctx.close();

    // 2. back the profile up, exactly as a cloud backup or a profile copy would
    cpSync(dir, snap, { recursive: true });
    notes.push(`snapshot taken of ${ids.length} unspent nonces`);

    if (downBeforeSpend.length) {
      takeDown(relays, downBeforeSpend);
      notes.push(`down during the spend: ${downBeforeSpend.join(',')}`);
    }

    // 3. spend both
    ctx = await launch(dir);
    page = await openPage(ctx, relays, pinned, { required });
    await ev(page, () => window.__store.startup());
    let acknowledgers = [];
    for (const [i, id] of ids.entries()) {
      const r = await ev(page, ([id, i]) =>
        window.__store.spend(`rid-${i}`, id, `pay alice ${i}`, undefined), [id, i]);
      if (i === 0) {
        acknowledgers = r.receipts ?? [];
        notes.push(`spend 0: ${r.event} acknowledgers=${JSON.stringify(acknowledgers)}`);
      }
    }
    // These shares LEFT THE DEVICE. A counterparty holds them and no rollback takes them
    // back; they are the other half of any reuse that follows.
    const preShares = await shares(page);
    notes.push(`${preShares.length} shares emitted to the counterparty`);
    await ctx.close();

    // 4. roll the profile back
    rmSync(dir, { recursive: true, force: true });
    cpSync(snap, dir, { recursive: true });
    notes.push('profile restored: the store now believes nothing was spent');

    // 5. change the relay picture, then restart. A relay is never restarted under a new
    //    mode: that would reset its memory and be a different experiment. An outage is
    //    only ever a process going away, so a survivor keeps its real record.
    if (downAfterSpend.length) {
      takeDown(relays, downAfterSpend);
      notes.push(`down after the spend: ${downAfterSpend.join(',')}`);
    }
    if (upAfterSpend.length) {
      await bringUp(relays, upAfterSpend);
      notes.push(`up after the spend, honest with an EMPTY record: ${upAfterSpend.join(',')}`);
    }
    const honestAckReachable = relays.filter(
      (r) => !r.down && r.mode === 'honest' && acknowledgers.includes(r.relay_id),
    ).map((r) => r.relay_id);
    notes.push(`acknowledgers still honest AND reachable: ${JSON.stringify(honestAckReachable)}`);

    ctx = await launch(dir);
    page = await openPage(ctx, relays, pinned, { required });
    notes.push(`restored view: ${(await states(page)).map((n) => `${n.state}/${n.has_secret ? 'secret' : 'nosecret'}`).join(',')}`);
    const start = await ev(page, () => window.__store.startup());
    notes.push(`startup: ${JSON.stringify(start)}`);

    // 6. replay the first nonce with a DIFFERENT message
    const retry = await ev(page, ([id]) =>
      window.__store.spend('rid-replay', id, 'pay mallory 99', undefined), [ids[0]]);
    notes.push(`replay: ${say(retry)}`);

    // The oracle runs over the COUNTERPARTY's view: the pre-restore shares plus whatever
    // the replay produced. That is what makes reuse real rather than hypothetical.
    const hist = [...preShares, ...(await shares(page))];
    const clean = await noReuse(page, hist, notes);
    for (const r of relays.filter((x) => !x.down)) {
      const d = await fetch(`${r.base}/dump`, {
        method: 'POST', body: '{}', headers: { 'content-type': 'application/json' },
      }).then((x) => x.json()).catch(() => null);
      notes.push(`${r.relay_id} mode=${r.mode} really acknowledged ${d ? (d.acked[0]?.[1]?.length ?? 0) : 'n/a'}`);
    }
    await ctx.close();
    return expect({ start, retry, clean, honestAckReachable });
  });
}

function expectedReuse({ start, retry, clean }) {
  if (start.decision !== 'continue' || retry.event !== 'share_saved' || clean) {
    throw new Error('expected nonce reuse was not reproduced');
  }
  return false;
}

// ── run ────────────────────────────────────────────────────────────────────

// Engine identity, recorded exactly, before any drill runs.
//
// A launch failure is RECORDED, not crashed on: the exact command and the exact engine
// error go into the summary and the engine is marked NOT RUN. An engine that will not
// start must never read as an engine that passed.
let ENGINE_VERSION = 'not-run';
try {
  const idProbe = await launch(join(TMP, '__version'));
  ENGINE_VERSION = idProbe.browser()?.version() ?? 'unreported';
  await idProbe.close();
  rmSync(join(TMP, '__version'), { recursive: true, force: true });
} catch (e) {
  const engineErrors = (e.message.match(/\[err\] \S.*/g) || []).map((x) => x.replace(/\u001b\[\d+m/g, '').trim());
  const summary = {
    engine: ENGINE, engine_version: 'not-run', suite: SUITE,
    playwright_core: (await import('playwright-core/package.json', { with: { type: 'json' } })).default.version,
    status: 'NOT RUN: launch failed',
    launch_error: e.message.split('\n')[0],
    engine_stderr: engineErrors.slice(-4),
    drills: [],
  };
  await writeFile(join(process.env.G3_TMP || '/tmp/loki-g3', `summary-${ENGINE}.json`),
    JSON.stringify(summary, null, 2));
  console.log(`\n### engine: ${ENGINE}   NOT RUN: the browser would not launch`);
  console.log(`###   playwright call: ${summary.launch_error}`);
  for (const line of summary.engine_stderr) console.log(`###   engine stderr: ${line}`);
  console.log('###   no drill was run, and no result is claimed for this engine');
  web.close();
  process.exit(0);
}
console.log(`\n### engine: ${ENGINE} ${ENGINE_VERSION}   suite: ${SUITE}`);
if (ENGINE === 'webkit') {
  console.log('### Playwright WebKit is NOT Safari. This is not a Safari result.');
}

console.log('\n== three simulated operators, 2-of-3 receipt threshold ==');
await spendDrill('gate-three-honest', ['honest', 'honest', 'honest'], {}, null);
await spendDrill('gate-only-one-reachable', ['honest', null, null], {}, 'receipts_required');
await spendDrill('gate-relay-not-pinned', ['honest', 'honest', 'honest'],
  { pin: (rs) => pinOf(rs).slice(0, 1) }, 'receipts_required');

console.log('\n== approval succeeds with any ONE operator down ==');
await spendDrill('one-down-A', [null, 'honest', 'honest'], {}, null);
await spendDrill('one-down-B', ['honest', null, 'honest'], {}, null);
await spendDrill('one-down-C', ['honest', 'honest', null], {}, null);

console.log('\n== an operator going down between startup and receipt collection ==');
await spendDrill('down-after-startup-one', ['honest', 'honest', 'honest'],
  { downAfterStartup: [C] }, null);
await spendDrill('down-after-startup-two', ['honest', 'honest', 'honest'],
  { downAfterStartup: [B, C] }, 'receipts_required');

console.log('\n== duplicate and forged receipts never count as two ==');
await spendDrill('duplicate-same-relay-listed-twice', ['honest', null, null],
  { listTwice: true }, 'receipts_required');
await spendDrill('impersonated-receipt-counts-once', ['honest', `impersonate:${A}`, null],
  {}, 'receipts_required');
await spendDrill('forged-signature-rejected', ['honest', 'forge', null],
  {}, 'receipts_required');
// The complement, so the threshold is not merely strict but useful: with a third honest
// operator available, one forger is tolerated and the share is released by the other two.
await spendDrill('tolerates-one-bad-operator', ['honest', 'forge', 'honest'], {}, null);

console.log('\n== receipts bind the exact commitment, epoch and package digest ==');
await spendDrill('receipt-binds-commitment', ['honest', 'mismatch:commitment', null],
  {}, 'receipts_required');
await spendDrill('receipt-binds-epoch', ['honest', 'mismatch:epoch', null],
  {}, 'receipts_required');
await spendDrill('receipt-binds-package', ['honest', 'mismatch:package', null],
  {}, 'receipts_required');

console.log('\n== strict IndexedDB durability ==');
await spendDrill('durability-unsupported-is-not-a-pass', ['honest', 'honest', 'honest'],
  { noDurability: true }, 'durability_unsupported');

if (only === 'strict-fails-mid-spend') {
  await drill(only, ['honest', 'honest', 'honest'], async ({ dir, notes, relays }) => {
    const ctx = await launch(dir);
    const page = await openPage(ctx, relays, pinOf(relays));
    await ev(page, () => window.__store.startup());
    const id = (await ev(page, () => window.__store.generate(1))).ids[0];
    let error = null;
    try {
      const result = await ev(page, (id) => {
        const original = IDBDatabase.prototype.transaction;
        let once = true;
        IDBDatabase.prototype.transaction = function (stores, mode, options) {
          if (once && mode === 'readwrite' && options?.durability === 'strict') {
            once = false;
            throw new TypeError('injected strict failure');
          }
          return original.call(this, stores, mode, options);
        };
        return window.__store.spend('rid-1', id, 'pay alice 1');
      }, id);
      notes.push(`spend: ${say(result)}`);
    } catch (e) { error = String(e); notes.push(`spend error: ${error}`); }
    const sh = await shares(page);
    const st = (await states(page)).find((n) => n.id === id);
    const retry = await ev(page, (id) => window.__store.spend('rid-2', id, 'pay mallory 99'), id);
    notes.push(`shares=${sh.length} nonce=${st.state}/${st.has_secret ? 'secret' : 'nosecret'}`);
    notes.push(`retry: ${say(retry)}`);
    await ctx.close();
    return error?.includes('injected strict failure')
      && sh.length === 0 && st.state === 'Generated' && st.has_secret
      && retry.event === 'refused' && retry.code === 'durability_unsupported';
  });
}

console.log('\n== two tabs racing for one commitment ==');
await twoTabs('two-tabs-web-lock', true);
await twoTabs('two-tabs-no-lock', false);
await twoTabs('two-tabs-same-package-lock', true, true);
await twoTabs('two-tabs-same-package-no-lock', false, true);

console.log('\n== crashes around the write-ahead record and the share save ==');
await crashDrill('crash-after-wal', 'after_wal',
  ({ retry, st }) => retry.event === 'refused' && st.state === 'Retired' && !st.has_secret);
await crashDrill('crash-after-receipts', 'after_receipts',
  ({ retry, st }) => retry.event === 'refused' && st.state === 'Retired' && !st.has_secret);
await crashDrill('crash-after-receipt-save', 'after_receipt_save',
  ({ retry, st }) => retry.event === 'refused' && st.state === 'Retired' && !st.has_secret);
await crashDrill('crash-after-consume', 'after_consume',
  ({ retry, st, shares }) => retry.event === 'refused' && st.state === 'Spent' && !st.has_secret && shares.length === 0);
await crashDrill('crash-before-share-save', 'before_share_save',
  ({ retry, st, shares }) => retry.event === 'refused' && st.state === 'Spent' && !st.has_secret && shares.length === 0);
await crashDrill('hard-kill-after-consume', 'hard_kill_after_consume',
  ({ retry, st, shares }) => retry.event === 'refused' && st.state === 'Spent' && !st.has_secret && shares.length === 0);

console.log('\n== restoration of old browser storage ==');
// All three honest: everyone acknowledged, everyone reports it.
await restoreDrill('restore-three-honest', ['honest', 'honest', 'honest'], {},
  ({ start, retry, clean }) => clean && start.cause === 'rollback_detected' && retry.event === 'refused');

// Two acknowledgers, one of them lying, both still reachable.
await restoreDrill('restore-one-honest-one-lying', ['honest', 'lying', null], {},
  ({ start, retry, clean }) => clean && start.cause === 'rollback_detected' && retry.event === 'refused');

// THE DETECTION CONDITION, isolated. C is down during the spend, so the acknowledgers are
// exactly {A honest, B lying}. Then B is taken away and C is brought up honest with an
// empty record: C is reachable and honest but never acknowledged anything, so it has
// nothing to report. A is the SOLE honest reachable acknowledger, and A alone must be
// enough.
await restoreDrill('restore-stopped-by-sole-honest-acknowledger',
  ['honest', 'lying', 'honest'],
  { downBeforeSpend: [C], downAfterSpend: [B], upAfterSpend: [C] },
  ({ start, retry, clean, honestAckReachable }) => clean
    && honestAckReachable.length === 1 && honestAckReachable[0] === A
    && start.cause === 'rollback_detected' && retry.event === 'refused');

// Every acknowledger unreachable afterwards, with C up, honest and empty. Nothing can
// detect the rollback: an honest relay that never acknowledged has nothing to report. The
// device also cannot reach the threshold, so no share is released and no reuse follows.
// Safety here comes from the outage, not from the detection.
await restoreDrill('restore-no-acknowledger-reachable',
  ['honest', 'honest', 'honest'],
  { downBeforeSpend: [C], downAfterSpend: [A, B], upAfterSpend: [C] },
  ({ start, retry, clean }) => clean
    && start.decision === 'degraded' && retry.event === 'refused');

// BOTH acknowledgers lying, and a third operator that is honest, reachable and empty.
// Kept visible: this is the failure the threshold does not remove, and it also shows that
// "one honest relay" is not the condition. It has to be one honest relay THAT
// ACKNOWLEDGED; C is honest and up and cannot help.
await restoreDrill('restore-all-acknowledgers-lying',
  ['lying', 'lying', 'honest'],
  { downBeforeSpend: [C], upAfterSpend: [C] },
  expectedReuse);

// A and B acknowledge the first share. After restore, A is offline, B lies, and C is
// honest but empty. The two quorums intersect only at B, so even one liar can enable reuse.
if (only === 'restore-one-liar-honest-acknowledger-offline') {
  await restoreDrill(only, ['honest', 'lying', 'honest'],
    { downBeforeSpend: [C], downAfterSpend: [A], upAfterSpend: [C] }, expectedReuse);
}

console.log('\n== the one-relay baseline, kept because it fails ==');
// The SAME drill with the threshold set back to 1 and a single lying operator. Keeping the
// one-relay design runnable is the only way the results above mean anything: without it, a
// pass could be coming from some unrelated change rather than from the threshold.
await restoreDrill('restore-one-relay-baseline', ['lying', null, null], { required: 1 },
  expectedReuse);

// Durability, read from a real page on this engine rather than asserted.
let realDurability = null;
{
  const dir = join(TMP, '__durability');
  rmSync(dir, { recursive: true, force: true });
  const ctx = await launch(dir);
  const page = await openPage(ctx, [], []);
  realDurability = await ev(page, () => window.__store.durabilityReport());
  await ctx.close();
  console.log(`\n== strict IndexedDB durability, measured on ${ENGINE} ${ENGINE_VERSION} ==`);
  console.log(`  ${JSON.stringify(realDurability)}`);
}

const failed = results.filter((r) => !r.ok && !r.inconclusive);
const unexpected = failed.filter((r) => !r.expected_failure);
const inconclusive = results.filter((r) => r.inconclusive);
const passed = results.filter((r) => r.ok && !r.inconclusive);

console.log(`\n${passed.length} passed, ${failed.length} failed, ${inconclusive.length} inconclusive, of ${results.length} drills`);
for (const f of failed) {
  console.log(`  ${f.expected_failure ? 'expected failure' : 'NOT PASSED'}: ${f.name}`);
}
for (const i of inconclusive) {
  console.log(`  inconclusive, NOT counted as a pass: ${i.name}`);
}
console.log('\nG3 PARTIAL: real device crash tests and the platform restore matrix are not run.');
if (unexpected.length) console.log('G3 INCOMPLETE: an unexpected drill failed.');
await writeFile(join(process.env.G3_TMP || '/tmp/loki-g3', `summary-${ENGINE}.json`),
  JSON.stringify({
    engine: ENGINE, engine_version: ENGINE_VERSION, suite: SUITE,
    playwright_core: (await import('playwright-core/package.json', { with: { type: 'json' } })).default.version,
    renderer_crash_url: RENDERER_CRASH_URL,
    real_durability: realDurability,
    counts: {
      passed: passed.length, failed: failed.length,
      inconclusive: inconclusive.length, total: results.length,
    },
    drills: results.map(({ name, ok, expected_failure, inconclusive, unsupported }) =>
      ({ name, ok, expected_failure, inconclusive, unsupported })),
  }, null, 2));
web.close();
process.exit(unexpected.length ? 1 : 0);
