/* Loki Vault — multisig account UI over the real prototype.
 *
 * The shape is a shared-custody wallet: an account, owners, a queue of transactions
 * waiting on signatures, history. Underneath, every control runs the actual CLI against a
 * sandboxed chain. Nothing is mocked and no balance is invented: if a value has not been
 * produced by a real step it renders as "—", never as a plausible number.
 *
 * Two endpoints: /api/wallet for account shape, /api/state for the runner's event buffer.
 */

'use strict';

const $ = (id) => document.getElementById(id);
const el = (t, c, x) => { const n = document.createElement(t); if (c) n.className = c; if (x != null) n.textContent = x; return n; };
const zec = (z) => (z == null ? '—' : (z / 1e8).toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' ZEC');
const short = (s, a = 10, b = 8) => (!s ? '—' : s.length <= a + b + 1 ? s : `${s.slice(0, a)}…${s.slice(-b)}`);

const SETUP = [
  { id: 'setup',       t: 'Create the account',  d: '2-of-3 key generation across three devices' },
  { id: 'start-chain', t: 'Start the test network', d: 'a throwaway regtest chain, mines to height 20' },
  { id: 'scan',        t: 'Scan for funds',      d: 'trial-decrypts every shielded output' },
  { id: 'commit',      t: 'Prepare signing material', d: 'each owner publishes single-use nonce commitments' },
  { id: 'propose',     t: 'Create the transaction', d: 'one candidate per possible pair of signers' },
];

const CASES = {
  'memo': 'send a different message',
  'recipient': 'pay a different person',
  'amount': 'pay one zatoshi more',
  'change-amount': 'return one zatoshi less',
  'change-address': 'send change somewhere else',
  'input': 'spend a different coin',
  'expiry': 'extend the deadline',
  'transparent': 'add a transparent output',
  'sapling': 'add a Sapling output',
};

let W = null, S = null, LAST = 0, VERDICTS = {}, PENDING = null, VIEW = 'home';

/* ── calls ───────────────────────────────────────────────────────────────── */

async function run(step, cse) {
  const r = await fetch('/api/run', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify(cse ? { step, case: cse } : { step }),
  });
  const j = await r.json();
  if (!j.started) line({ kind: 'fail', text: `not started: ${j.reason}` });
  return j.started;
}

function line(e) {
  const c = $('console');
  const at = c.scrollHeight - c.scrollTop - c.clientHeight < 60;
  const p = { cmd: '$ ', ok: '✓ ', fail: '✗ ', err: '! ', info: '· ', tick: '· ', done: '✓ ', stop: '✗ ' }[e.kind] ?? '  ';
  c.append(el('span', `ln k-${e.kind}`, p + e.text + '\n'));
  while (c.childNodes.length > 700) c.removeChild(c.firstChild);
  if (at) c.scrollTop = c.scrollHeight;
}

/* ── sidebar ─────────────────────────────────────────────────────────────── */

function renderSide() {
  const pct = W.transaction ? (W.confirmations / W.threshold) * 100 : 0;
  $('acctRing').style.setProperty('--pct', `${Math.min(100, pct)}%`);
  $('acctRing').querySelector('span').innerHTML =
    W.transaction ? `${W.confirmations}<small>/${W.threshold}</small>` : `2<small>/3</small>`;

  const a = $('addr');
  a.textContent = W.address ? short(W.address, 12, 8) : 'no account yet';
  a.title = W.address || '';
  a.onclick = () => W.address && navigator.clipboard?.writeText(W.address)
    .then(() => { a.textContent = 'copied'; setTimeout(renderSide, 900); }).catch(() => {});
  $('bal').textContent = W.balance_zat != null ? zec(W.balance_zat) : '—';

  const n = W.transaction && W.status !== 'executed' ? 1 : 0;
  const pill = $('queuePill');
  pill.textContent = n; pill.dataset.n = n;

  const sys = $('sys');
  sys.replaceChildren();
  for (const [cls, txt] of [
    [S.loki_built ? 'go' : 'bad', S.loki_built ? 'prototype built' : 'not built: cargo build'],
    [S.chain_running ? 'go' : '', S.chain_running ? `network up · block ${S.tip ?? '…'}` : 'network down'],
    [S.busy ? 'wait' : '', S.busy ? `running ${S.busy}` : 'idle'],
  ]) {
    const d = el('div'); d.append(el('i', cls), el('span', null, txt)); sys.append(d);
  }
  const sp = $('statePill');
  sp.textContent = S.busy ? `running · ${S.busy}` : 'idle';
  sp.classList.toggle('busy', !!S.busy);
  $('stopChain').disabled = !!S.busy || !S.chain_running;
  $('reset').disabled = !!S.busy;
}

/* ── overview ────────────────────────────────────────────────────────────── */

function renderHome() {
  $('sBal').textContent = W.balance_zat != null ? zec(W.balance_zat) : '—';
  $('sBalS').textContent = W.balance_zat != null
    ? `${W.note.value_zat ? zec(W.note.value_zat) + ' selected to spend' : 'scanned'}` : 'not scanned yet';
  $('sQueue').textContent = W.transaction && W.status !== 'executed' ? '1' : '0';
  $('sQueueS').textContent = W.transaction
    ? (W.status === 'executed' ? 'last transaction executed' : `${W.confirmations} of ${W.threshold} confirmations`)
    : 'no pending transaction';
  $('sNet').textContent = S.chain_running ? `block ${S.tip ?? '…'}` : 'down';
  $('sNetS').textContent = S.chain_running ? 'regtest, port 18242' : 'start it in step 2';

  const b = $('banner');
  b.className = 'banner';
  b.replaceChildren();
  const msg = {
    no_account: ['', 'This account does not exist yet. Work down the list below; each step runs the real prototype.'],
    no_transaction: ['', 'Account is funded. Create a transaction to see it enter the queue.'],
    awaiting_confirmations: ['wait', `Waiting on signatures: ${W.confirmations} of ${W.threshold}.`],
    ready: ['go', `Threshold met: ${W.confirmations} of ${W.threshold} owners have signed. Ready to execute.`],
    executed: ['go', 'Transaction executed and mined.'],
  }[W.status] ?? ['', ''];
  // `classList.add('')` throws, and two of the five statuses carry no tone. Leaving this
  // unguarded aborted the whole Overview render at this line.
  if (msg[0]) b.classList.add(msg[0]);
  b.append(el('span', null, msg[1]));
  if (W.status === 'awaiting_confirmations' || W.status === 'ready') {
    const go = el('button', 'btn btn-sm', 'Open queue');
    go.type = 'button'; go.onclick = () => show('queue');
    b.append(go);
  }

  const list = $('setup');
  list.replaceChildren();
  for (const s of SETUP) {
    const done = S.done.includes(s.id);
    const busy = S.busy === s.id;
    const li = el('li', busy ? 'busy' : done ? 'done' : '');
    const mid = el('div');
    mid.append(el('div', 't', s.t), el('div', 'd', s.d));
    const btn = el('button', 'btn btn-sm' + (done ? ' btn-ghost' : ''), busy ? 'running…' : done ? 'run again' : 'Run');
    btn.type = 'button';
    btn.disabled = !!S.busy || !S.loki_built;
    btn.onclick = () => run(s.id);
    li.append(mid, btn);
    list.append(li);
  }
}

/* ── queue ───────────────────────────────────────────────────────────────── */

function txCard(t, executed) {
  const card = el('div', 'tx');
  const head = el('div', 'tx-head');
  const ring = el('div', 'tx-ring');
  ring.style.setProperty('--pct', `${(W.confirmations / W.threshold) * 100}%`);
  ring.append(el('b', null, `${W.confirmations}/${W.threshold}`));
  const sum = el('div', 'tx-sum');
  sum.append(el('div', 'amt', zec(Number(t.amount_zat))));
  sum.append(el('div', 'to', `to ${short(t.recipient, 16, 10)}`));
  head.append(ring, sum);
  head.append(el('span', `tx-status ${executed ? 'go' : W.confirmations >= W.threshold ? 'go' : 'wait'}`,
    executed ? 'Executed' : W.confirmations >= W.threshold ? 'Ready to execute' : 'Awaiting confirmations'));
  card.append(head);

  // who has signed
  const sigs = el('div', 'sigs');
  for (const o of W.owners) {
    const row = el('div', 'sig' + (o.confirmed_ac ? ' ok' : ''));
    row.append(el('span', 'av', o.name[0].toUpperCase()));
    const who = el('div');
    who.append(el('div', 'who', o.name[0].toUpperCase() + o.name.slice(1)));
    row.append(who);
    row.append(el('span', 'st', o.confirmed_ac ? 'signed' : o.in_ac ? 'not signed' : 'not in this pair'));
    sigs.append(row);
  }
  card.append(sigs);

  // the detail an owner is actually agreeing to
  const det = el('details', 'tx-detail');
  det.append(el('summary', null, 'What exactly is being signed'));
  const dl = el('dl', 'dl');
  const memo = t.memo ? (t.memo.match(/../g) || []).map((h) => String.fromCharCode(parseInt(h, 16))).join('') : '';
  for (const [k, v] of [
    ['Recipient', t.recipient],
    ['Amount', `${Number(t.amount_zat).toLocaleString()} zat  (${zec(Number(t.amount_zat))})`],
    ['Memo', memo ? `"${memo}"` : '—'],
    ['Change back to account', `${Number(t.change_zat).toLocaleString()} zat`],
    ['Fee', `${Number(t.fee_zat).toLocaleString()} zat`],
    ['Spends coin', t.input_nullifier],
    ['Expires at block', t.expiry_height],
    ['Proposal id', t.proposal_id],
    ['Candidates built', W.candidates.join(', ') || '—'],
  ]) {
    const d = el('div'); d.append(el('dt', null, k), el('dd', null, v ?? '—')); dl.append(d);
  }
  det.append(dl);
  card.append(det);
  return card;
}

function renderQueue() {
  const box = $('queueBody');
  box.replaceChildren();

  if (!W.transaction || W.status === 'executed') {
    const c = el('div', 'card');
    const e = el('div', 'empty');
    e.append(el('strong', null, 'Nothing waiting'),
      el('span', null, W.status === 'executed'
        ? 'The last transaction was executed. See History.'
        : 'Create a transaction from the Overview to see it here.'));
    c.append(e); box.append(c);
    return;
  }

  box.append(txCard(W.transaction, false));

  const acts = el('div', 'tx-acts');
  for (const o of W.owners.filter((x) => x.in_ac)) {
    const b = el('button', 'btn btn-sm' + (o.confirmed_ac ? ' btn-ghost' : ''),
      o.confirmed_ac ? `${o.name} signed` : `Sign as ${o.name}`);
    b.type = 'button';
    b.disabled = !!S.busy || o.confirmed_ac;
    b.onclick = () => run(`sign-${o.name}`);
    acts.append(b);
  }
  const ex = el('button', 'btn btn-sm', 'Execute');
  ex.type = 'button';
  ex.disabled = !!S.busy || W.confirmations < W.threshold;
  ex.title = W.confirmations < W.threshold ? 'needs two signatures' : 'prove, broadcast and mine';
  ex.onclick = () => run('finish');
  acts.append(ex);
  box.querySelector('.tx').append(acts);

  const n = el('p', 'note');
  n.textContent = 'Each owner reviews in its own process and re-derives every fact above from '
    + 'the transaction bytes. Nothing is taken on trust from the proposal.';
  box.append(n);
}

/* ── history ─────────────────────────────────────────────────────────────── */

function renderHistory() {
  const box = $('historyBody');
  box.replaceChildren();
  if (!W.executed?.txid) {
    const c = el('div', 'card');
    const e = el('div', 'empty');
    e.append(el('strong', null, 'No history yet'), el('span', null, 'Executed transactions appear here.'));
    c.append(e); box.append(c);
    return;
  }
  const card = el('div', 'tx');
  const head = el('div', 'tx-head');
  const ring = el('div', 'tx-ring');
  ring.style.setProperty('--pct', '100%');
  ring.append(el('b', null, '✓'));
  const sum = el('div', 'tx-sum');
  sum.append(el('div', 'amt', W.transaction ? zec(Number(W.transaction.amount_zat)) : '—'));
  sum.append(el('div', 'to', W.transaction ? `to ${short(W.transaction.recipient, 16, 10)}` : ''));
  head.append(ring, sum, el('span', 'tx-status go', 'Executed'));
  card.append(head);
  const dl = el('dl', 'dl');
  for (const [k, v] of [
    ['Transaction id', W.executed.txid],
    ['Anchor', W.executed.anchor],
    ['Broadcast at block', W.executed.broadcast_at_height],
    ['Signed by', W.owners.filter((o) => o.confirmed_ac).map((o) => o.name).join(' + ') || '—'],
  ]) { const d = el('div'); d.append(el('dt', null, k), el('dd', null, v ?? '—')); dl.append(d); }
  const wrap = el('div'); wrap.style.padding = '.9rem 0 0'; wrap.append(dl);
  card.append(wrap);
  box.append(card);
  const n = el('p', 'note');
  n.textContent = 'The signature was produced before this transaction had a proof or an anchor. '
    + 'Both were installed afterwards and the signed content was checked to be unchanged.';
  box.append(n);
}

/* ── owners ──────────────────────────────────────────────────────────────── */

function renderOwners() {
  const box = $('ownerList');
  box.replaceChildren();
  for (const o of W.owners) {
    const row = el('div', 'owner' + (o.confirmed_ac ? ' signed' : ''));
    row.append(el('span', 'av', o.name[0].toUpperCase()));
    const mid = el('div');
    mid.append(el('div', 'n', o.name));
    mid.append(el('div', 'r', o.committed ? 'holds a share · signing material published' : 'holds a share'));
    row.append(mid);
    row.append(el('span', 'badge', o.confirmed_ac ? 'signed' : 'owner'));
    box.append(row);
  }
}

/* ── security ────────────────────────────────────────────────────────────── */

function renderSecurity() {
  const ready = S.done.includes('propose');
  $('secNote').textContent = ready
    ? 'Run the honest control too. Until you have seen an owner accept a correct transaction, a rejection proves nothing: an owner that rejects everything would score full marks.'
    : 'Create a transaction first (Overview, steps 1 to 5).';

  const grid = $('tgrid');
  if (!grid.dataset.built && S.tamper_cases) {
    for (const c of S.tamper_cases) {
      const b = el('button', 'tcase'); b.type = 'button'; b.id = `c-${c}`;
      b.append(el('span', 'f', c), el('span', 'w', CASES[c] ?? ''), el('span', 'v', ''));
      b.onclick = () => { PENDING = c; VERDICTS[c] = 'run'; run('tamper', c); };
      grid.append(b);
    }
    const ctl = el('button', 'tcase control'); ctl.type = 'button'; ctl.id = 'c-control';
    ctl.append(el('span', 'f', 'honest control'), el('span', 'w', 'nothing changed — must be ACCEPTED'), el('span', 'v', ''));
    ctl.onclick = () => { PENDING = 'control'; VERDICTS.control = 'run'; run('honest-control'); };
    grid.append(ctl);
    grid.dataset.built = '1';
  }

  // `done` only gains a case when the runner's check passed: rejected AND no signature.
  for (const d of S.done) {
    const c = d.startsWith('tamper:') ? d.slice(7) : d === 'honest-control' ? 'control' : null;
    if (c && !VERDICTS[c]) VERDICTS[c] = 'ok';
  }

  for (const c of [...(S.tamper_cases || []), 'control']) {
    const b = $(`c-${c}`); if (!b) continue;
    const v = VERDICTS[c];
    b.disabled = !!S.busy || !ready || !S.loki_built;
    b.classList.toggle('ok', v === 'ok');
    b.classList.toggle('bad', v === 'bad');
    b.classList.toggle('run', v === 'run');
    b.querySelector('.v').textContent =
      v === 'run' ? 'running…'
      : v === 'ok' ? (c === 'control' ? 'accepted ✓' : 'rejected · no signature ✓')
      : v === 'bad' ? 'GOT THROUGH ✗' : '';
  }

  const tried = Object.keys(VERDICTS).filter((k) => VERDICTS[k] !== 'run');
  const good = tried.filter((k) => VERDICTS[k] === 'ok').length;
  const s = $('tscore'); s.replaceChildren();
  if (tried.length) {
    s.append(el('b', null, `${good} of ${tried.length} behaved correctly`));
    s.append(el('span', null, 'Each result is checked two ways: the owner rejected it, and no '
      + 'signature file was produced. A rejection that still produced one would show as GOT THROUGH.'));
  }
}

function noteVerdict(e) {
  if (!PENDING) return;
  if (e.kind === 'ok' && (e.text.includes('no share was written') || e.text.includes('was accepted and a share'))) {
    VERDICTS[PENDING] = 'ok'; PENDING = null;
  } else if ((e.kind === 'fail' && e.text.startsWith('UNEXPECTED')) || e.kind === 'stop') {
    VERDICTS[PENDING] = 'bad'; PENDING = null;
  }
}

/* ── views ───────────────────────────────────────────────────────────────── */

const TITLES = { home: 'Overview', queue: 'Transaction queue', history: 'History', owners: 'Owners', security: 'Security tests', console: 'Console' };

function show(v) {
  VIEW = v;
  for (const b of $('nav').children) b.classList.toggle('on', b.dataset.view === v);
  for (const s of document.querySelectorAll('.view')) s.classList.toggle('on', s.dataset.view === v);
  $('viewTitle').textContent = TITLES[v] ?? v;
  draw();
}

function draw() {
  if (!W || !S) return;
  renderSide();
  if (VIEW === 'home') renderHome();
  if (VIEW === 'queue') renderQueue();
  if (VIEW === 'history') renderHistory();
  if (VIEW === 'owners') renderOwners();
  if (VIEW === 'security') renderSecurity();
}

/* ── poll ────────────────────────────────────────────────────────────────── */

async function poll() {
  try {
    const [w, s] = await Promise.all([
      fetch('/api/wallet').then((r) => r.json()),
      fetch('/api/state').then((r) => r.json()),
    ]);
    W = w; S = s;
  } catch { return; }
  for (const e of S.events) if (e.seq > LAST) { LAST = e.seq; line(e); noteVerdict(e); }
  draw();
}

for (const b of $('nav').children) b.onclick = () => show(b.dataset.view);
$('clearLog').onclick = () => $('console').replaceChildren();
$('stopChain').onclick = () => run('stop-chain');
$('reset').onclick = () => {
  if (!confirm('Delete the sandbox account and stop the test network?')) return;
  VERDICTS = {}; run('reset');
};

poll();
setInterval(poll, 900);
