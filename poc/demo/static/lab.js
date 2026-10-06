/* Loki POC lab.
 *
 * Thin client. It names a step, polls /api/state, and renders the runner's own event
 * buffer. It decides nothing about what happened: a tamper verdict comes from the `ok` or
 * `fail` event the runner emitted after checking the exit status AND whether a share file
 * exists on disk. The page never infers success from "no error appeared".
 */

'use strict';

const $ = (id) => document.getElementById(id);
const el = (t, c, x) => { const n = document.createElement(t); if (c) n.className = c; if (x != null) n.textContent = x; return n; };

const STEPS = [
  { id: 'setup',       label: 'Create the vault',     d: '2-of-3 distributed key generation. No complete spending key is ever assembled.' },
  { id: 'start-chain', label: 'Start the chain',      d: 'Launches zebrad in the sandbox and mines to height 20. Takes about a minute.' },
  { id: 'scan',        label: 'Find the coin',        d: 'Trial-decrypts every shielded output to find what the vault owns.' },
  { id: 'commit',      label: 'Publish nonces',       d: 'Each member commits one single-use nonce per candidate.' },
  { id: 'propose',     label: 'Build 3 candidates',   d: 'One unfinished transaction per possible pair: AB, AC, BC.' },
  { id: 'sign-alice',  label: 'Alice reviews + signs', d: 'Re-derives every fact from the bytes, then emits a partial signature.' },
  { id: 'sign-carol',  label: 'Carol reviews + signs', d: 'Same, in her own process. Bob never participates.' },
  { id: 'finish',      label: 'Prove and broadcast',  d: 'Aggregate, install the anchor AFTER signing, prove, mine. Slowest step.' },
];

const CASE_COPY = {
  'memo': 'a different message',
  'recipient': 'a different payee',
  'amount': 'one more zatoshi to the payee',
  'change-amount': 'one more zatoshi back to the vault',
  'change-address': 'change to an address the intent never named',
  'input': 'a different coin of the vault’s',
  'expiry': 'a later expiry height',
  'transparent': 'a transparent output grafted on',
  'sapling': 'a Sapling output grafted on',
};

let LAST_SEQ = 0;
let VERDICTS = {};        // case -> 'refused' | 'accepted' | 'running'
let PENDING = null;       // the case currently running, so its event lands on the right tile
let QUEUE = [];           // for "run all"

/* ── posting a step ──────────────────────────────────────────────────────── */

async function run(step, cse) {
  const r = await fetch('/api/run', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(cse ? { step, case: cse } : { step }),
  });
  const j = await r.json();
  if (!j.started) appendLine({ kind: 'fail', text: `not started: ${j.reason}` });
  return j.started;
}

/* ── console ─────────────────────────────────────────────────────────────── */

const consoleEl = () => $('console');

function appendLine(e) {
  const c = consoleEl();
  const atEnd = c.scrollHeight - c.scrollTop - c.clientHeight < 60;
  const prefix = { cmd: '$ ', ok: '✓ ', fail: '✗ ', err: '! ', info: '· ', tick: '· ', done: '✓ ', stop: '✗ ' }[e.kind] ?? '  ';
  c.append(el('span', `ln k-${e.kind}`, prefix + e.text + '\n'));
  while (c.childNodes.length > 700) c.removeChild(c.firstChild);
  if (atEnd) c.scrollTop = c.scrollHeight;
}

/* ── rendering ───────────────────────────────────────────────────────────── */

function renderSteps(st) {
  const box = $('steps');
  if (!box.dataset.built) {
    STEPS.forEach((s, i) => {
      const b = el('button', 'step');
      b.type = 'button';
      b.id = `step-${s.id}`;
      const top = el('span', 'n', String(i + 1).padStart(2, '0'));
      b.append(top, el('span', 'l', s.label), el('span', 'd', s.d), el('span', 'tag', ''));
      b.addEventListener('click', () => run(s.id));
      box.append(b);
    });
    box.dataset.built = '1';
  }
  for (const s of STEPS) {
    const b = $(`step-${s.id}`);
    const running = st.busy === s.id;
    const done = st.done.includes(s.id);
    b.classList.toggle('is-running', running);
    b.classList.toggle('is-done', done && !running);
    b.disabled = !!st.busy || !st.loki_built;
    b.querySelector('.tag').textContent = running ? 'running…' : done ? 'done' : '';
  }
}

function renderTamper(st) {
  const box = $('tamper');
  if (!box.dataset.built) {
    for (const c of st.tamper_cases) {
      const b = el('button', 'tcase');
      b.type = 'button';
      b.id = `case-${c}`;
      b.append(el('span', 'f', c), el('span', 'w', CASE_COPY[c] ?? ''), el('span', 'verdict', ''));
      b.addEventListener('click', () => { PENDING = c; VERDICTS[c] = 'running'; run('tamper', c); });
      box.append(b);
    }
    const ctl = el('button', 'tcase control');
    ctl.type = 'button';
    ctl.id = 'case-control';
    ctl.append(el('span', 'f', 'honest control'),
               el('span', 'w', 'nothing altered — she must ACCEPT this one'),
               el('span', 'verdict', ''));
    ctl.addEventListener('click', () => { PENDING = 'control'; VERDICTS.control = 'running'; run('honest-control'); });
    box.append(ctl);
    box.dataset.built = '1';
  }

  // The runner only adds a step to `done` when its check passed: for a tamper case that
  // means refused AND no share file. Reconstructing from it keeps the tiles honest across
  // a reload, and never overwrites a failure the page saw live.
  for (const d of st.done) {
    const c = d.startsWith('tamper:') ? d.slice(7) : d === 'honest-control' ? 'control' : null;
    if (c && !VERDICTS[c]) VERDICTS[c] = 'refused';
  }

  const ready = st.done.includes('propose');
  for (const c of [...st.tamper_cases, 'control']) {
    const b = $(`case-${c}`);
    const v = VERDICTS[c];
    b.disabled = !!st.busy || !ready || !st.loki_built;
    b.classList.toggle('running', v === 'running');
    b.classList.toggle('refused', v === 'refused');
    b.classList.toggle('accepted', v === 'accepted');
    b.querySelector('.verdict').textContent =
      v === 'running' ? 'running…'
      : v === 'refused' ? (c === 'control' ? 'accepted ✓' : 'refused, 0 shares ✓')
      : v === 'accepted' ? 'NOT REFUSED ✗' : '';
  }

  const tried = Object.keys(VERDICTS).filter((k) => VERDICTS[k] !== 'running');
  const good = tried.filter((k) => VERDICTS[k] === 'refused').length;
  const out = $('verdicts');
  out.replaceChildren();
  if (!ready) {
    out.append(el('p', null, 'Build the candidates first: run steps 1 to 5 above.'));
  } else if (!tried.length) {
    out.append(el('p', null, 'Nothing tried yet. Start with the honest control, so you know '
      + 'the signer is capable of saying yes.'));
  } else {
    out.append(el('p', 'score', `${good} of ${tried.length} behaved correctly`));
    const missing = !('control' in VERDICTS);
    out.append(el('p', null, missing
      ? 'Run the honest control: until a signer is shown accepting a correct candidate, '
        + 'a refusal is not evidence of anything.'
      : 'Each result above is the runner checking two things: a non-zero exit AND no share '
        + 'file on disk. A refusal that still wrote a share would show as NOT REFUSED.'));
  }
}

function renderChips(st) {
  const box = $('sysChips');
  box.replaceChildren();
  const chips = [
    st.loki_built
      ? { s: 'demonstrated', t: 'loki built' }
      : { s: 'blocked', t: 'loki NOT built — run: cd poc && cargo build' },
    st.chain_running
      ? { s: 'demonstrated', t: `chain up · pid ${st.chain_pid} · tip ${st.tip ?? '…'}` }
      : { s: 'not-established', t: 'chain stopped' },
    { s: st.busy ? 'partial' : 'not-established', t: st.busy ? `running: ${st.busy}` : 'idle' },
  ];
  for (const c of chips) box.append(el('span', `chip ${c.s}`, c.t));

  $('liveBadge').textContent = st.busy ? `running: ${st.busy}` : 'Idle';
  $('sandboxPath').textContent = st.sandbox;
  $('dangerNote').textContent =
    `Everything the lab writes is under ${st.sandbox}, including its zebrad config and its `
    + `chain state. Deleting it removes that directory and nothing else. The chain runs on `
    + `port ${st.rpc_port} and stops when this server stops.`;

  for (const [id, on] of [['stopChain', st.chain_running], ['reset', true]]) {
    $(id).disabled = !!st.busy || (id === 'stopChain' && !on);
  }
  $('runAll').disabled = !!st.busy || !st.loki_built;
}

/* ── verdict capture ─────────────────────────────────────────────────────── */

function noteVerdict(e) {
  if (!PENDING) return;
  if (e.kind === 'ok' && (e.text.includes('no share was written') || e.text.includes('was accepted and a share'))) {
    VERDICTS[PENDING] = 'refused';     // correct behaviour for both kinds of tile
    PENDING = null;
  } else if (e.kind === 'fail' && e.text.startsWith('UNEXPECTED')) {
    VERDICTS[PENDING] = 'accepted';
    PENDING = null;
  } else if (e.kind === 'stop') {
    VERDICTS[PENDING] = 'accepted';
    PENDING = null;
  }
}

/* ── poll ────────────────────────────────────────────────────────────────── */

let wasBusy = false;

async function poll() {
  let st;
  try {
    st = await (await fetch('/api/state')).json();
  } catch {
    return;
  }
  for (const e of st.events) {
    if (e.seq > LAST_SEQ) { LAST_SEQ = e.seq; appendLine(e); noteVerdict(e); }
  }
  renderChips(st);
  renderSteps(st);
  renderTamper(st);

  // Drain the "run all" queue only when the runner has actually gone idle.
  if (wasBusy && !st.busy && QUEUE.length) {
    const next = QUEUE.shift();
    if (st.done.includes(next)) { wasBusy = false; return poll(); }
    run(next);
  }
  if (!st.busy && !QUEUE.length) wasBusy = false;
  if (st.busy) wasBusy = true;
}

/* ── boot ────────────────────────────────────────────────────────────────── */

$('runAll').addEventListener('click', () => {
  QUEUE = STEPS.map((s) => s.id);
  const first = QUEUE.shift();
  wasBusy = true;
  run(first);
});
$('clearLog').addEventListener('click', () => consoleEl().replaceChildren());
$('stopChain').addEventListener('click', () => run('stop-chain'));
$('reset').addEventListener('click', () => {
  if (!confirm('Delete poc/demo/.sandbox and stop the sandbox chain?')) return;
  VERDICTS = {};
  run('reset');
});

poll();
setInterval(poll, 800);
