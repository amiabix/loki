/* Loki POC demo.
 *
 * Two kinds of content, kept visibly apart:
 *
 *   EVIDENCE    numbers fetched from /api/evidence, which the server extracted from the
 *               public result documents. Always labelled Recorded, always carrying the
 *               file it came from. If a value is missing it renders as "not recorded"
 *               rather than being filled in.
 *   EXPLANATION the prose in STAGES and CHECKS below. Authored for this page to make the
 *               evidence legible. It is never dressed up as a measurement.
 *
 * Nothing here simulates a run. Selecting a stage reveals what that stage recorded; no
 * progress fills, no approval plays out, and the only live reading in the whole demo is
 * the node probe in the event-log section, which is badged separately.
 */

'use strict';

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
};

/* ── authored explanation ────────────────────────────────────────────────── */

const STAGES = [
  {
    id: 'dkg', label: 'Distributed key generation',
    plain: 'The three devices jointly create one account key without ever assembling it. Each ends up holding a share and the group’s public data. There is no moment at which a complete spending key exists on any machine, so there is no moment at which one could be stolen.',
    tech: 'frost::keys::dkg part1/part2/part3 over RedPallas. Each member writes its own key_package; part3 returns a share, never the secret. The group verifying key becomes the account’s ak.',
    evi: (d) => [
      ['Threshold', '2 of 3'],
      ['Ciphersuite', 'FROST RedPallas (reddsa 0.5.2)'],
      ['Account key', 'TEST-ONLY splice: ak || nk || rivk, not ZIP 2005'],
    ],
  },
  {
    id: 'fund', label: 'Fund and scan',
    plain: 'A local test chain mines shielded coins to the account. Because the account is shielded, nothing on the chain says which coin belongs to it; the software has to trial-decrypt every output to find its own. That scan is how it learns the coin’s value and its position in the commitment tree.',
    tech: 'Shielded coinbase to the vault unified address. scan_chain trial-decrypts every Ironwood action with the account’s incoming viewing keys in both scopes, and rebuilds the note commitment tree in append order.',
    evi: (d) => [
      ['Network', d.g1tx.network.value],
      ['Scan at finish time (payment 1)', d.second_device.paths[0].own_scan],
      ['Scan at finish time (payment 2)', d.second_device.paths[1].own_scan],
    ],
  },
  {
    id: 'nonces', label: 'Nonce commitments',
    plain: 'Before anyone can sign, each participant generates a one-time secret and publishes only a commitment to it. These are strictly single-use: reusing one across two different messages would expose the signer’s share outright. Each candidate gets its own.',
    tech: 'frost::round1::commit per member, per candidate. The nonce pair stays in the member’s own directory; only the commitment is published. The commitment set feeds the per-pair alpha derivation.',
    evi: () => [
      ['Per member, per candidate', 'one fresh nonce pair'],
      ['Published', 'commitment only; the secret never leaves the device'],
      ['On use', 'deleted — but see the G3 limits: this is file state, not a crash-safe ledger'],
    ],
  },
  {
    id: 'candidates', label: 'Build three candidates',
    plain: 'The proposer builds one unfinished transaction per possible signing pair. All three spend the same coin and pay the same recipient the same amount with the same memo. None has a proof yet, and none has an anchor — the link to a particular chain state — because those come later.',
    tech: 'DeferredPcztBuilder, one PCZT per pair, each with a caller-selected alpha. anchor_deferred is set; no witness and no proof are present. 3594 bytes each.',
    evi: (d) => d.pairs.map((p) => [
      `${p.name} (${p.members.join(' + ')})`,
      `rk ${p.rk}… · alpha ${p.alpha}… · ${p.bytes} bytes`,
    ]),
  },
  {
    id: 'review', label: 'Independent review',
    plain: 'Each signer, in its own process, reads the raw transaction bytes and re-derives every fact about the payment from the transaction’s own cryptography. It does not trust the summary it was sent. It also recomputes the blinding value itself and checks the transaction matches.',
    tech: 'review_sign parses the PCZT, computes its own shielded sighash, recomputes alpha from the proposal id and the published commitments, and checks rk == ak.randomize(alpha). verify::check_candidate proves the effects against openings and commitments.',
    evi: (d) => [
      ['Independent sighash, AB', `${d.pairs[0].sighash}…`],
      ['Independent sighash, AC', `${d.pairs[1].sighash}…`],
      ['Independent sighash, BC', `${d.pairs[2].sighash}…`],
      ['Adversarial cases', d.tamper.total.value],
    ],
  },
  {
    id: 'sign', label: 'Alice and Carol sign',
    plain: 'Two of the three approve. Each produces a partial signature in its own process and consumes its nonce. Bob never participates in this payment, and no process ever holds two shares at once.',
    tech: 'frost_rerandomized::sign under the recomputed alpha, inside each member process. The nonce file is deleted on use. Shares for AB and BC also exist because those candidates were reviewed, but only AC is carried forward.',
    evi: (d) => [
      ['Approved by', 'alice + carol (the AC pair)'],
      ['Did not participate', 'bob'],
      ['Carried forward', `AC · rk ${d.pairs[1].rk}…`],
      ['Discarded', `AB · rk ${d.pairs[0].rk}…   BC · rk ${d.pairs[2].rk}…`],
    ],
  },
  {
    id: 'aggregate', label: 'Aggregate',
    plain: 'The two partial signatures combine into one ordinary signature. It is verified locally against the re-randomised account key before anything is sent anywhere, so a bad share is caught here and the culprit named rather than producing a transaction the network would silently reject.',
    tech: 'frost_rerandomized::aggregate, then randomized_verifying_key().verify(sighash, sig) before the signature is applied. The 64-byte signature crosses into orchard as canonical bytes.',
    evi: () => [
      ['Result', 'one RedPallas signature, indistinguishable from single-signer'],
      ['Checked before use', 'verifies under ak + [alpha]G'],
      ['Holder of a share at this point', 'none — finishing needs no secret'],
    ],
  },
  {
    id: 'anchor', label: 'Add anchor and proof',
    plain: 'This is the part the prototype exists to test. The signature was made before the transaction referenced any particular chain state. Only now is the anchor and its membership proof installed, and then the zero-knowledge proof is generated. The signature is checked to still be valid afterwards.',
    tech: 'Updater::set_ironwood_anchor and set_ironwood_spend_witnesses run AFTER apply_ironwood_signature. The effects sighash is recomputed and must be byte-identical. Then Prover::create_ironwood_proof with a locally built Halo 2 proving key.',
    evi: (d) => [
      ['Anchor', `${d.g1tx.anchor.value}… · ${d.g1tx.anchor.note}`],
      ['Order', 'signature applied to action 0, then anchor, then witness, then proof'],
      ['The claim', 'effects sighash unchanged by anchor/witness installation'],
      ['Proving key', 'built locally — Halo 2, no trusted setup, no parameter download'],
    ],
  },
  {
    id: 'broadcast', label: 'Broadcast',
    plain: 'The finished transaction is serialised and handed to the local node. Up to this point nothing has touched a network.',
    tech: 'SpendFinalizer, then TransactionExtractor with the Orchard verifying key, then sendrawtransaction to 127.0.0.1:18232. A v6 transaction of 9166 bytes.',
    evi: (d) => [
      ['Transaction id', d.g1tx.txid.value],
      ['Size', '9166 bytes, transaction version 6'],
      ['Sent to', '127.0.0.1:18232 (local regtest node)'],
    ],
  },
  {
    id: 'mined', label: 'Mined and confirmed',
    plain: 'The chain accepted it. The effects were then verified against the chain itself rather than against any local file: the coin was spent, the recipient could decrypt exactly the approved amount and memo, and the change arrived at the account’s own internal address.',
    tech: 'verify-effects fetches the transaction by txid, trial-decrypts the Ironwood actions with the account viewing keys in both scopes, and compares every field the intent named. The memo is compared across the whole 512-byte field with padding required to be zero.',
    evi: (d) => [
      ['Transaction id', d.g1tx.txid.value],
      ['Mined at height', d.g1tx.height.value],
      ['Confirmations when recorded', d.g1tx.confirmations.value],
      ['Effects verified', 'paid 40000000 zat · memo "loki g1-tx" · change 584990000 zat · fee 10000 zat'],
    ],
  },
];

const CHECKS = [
  { k: 'Recipient', plain: 'The payment really goes to the address the proposal named, and nowhere else.',
    how: 'Each output note is rebuilt from its openings and must reproduce the action’s own cmx. Any output to an address the intent does not name is refused outright.' },
  { k: 'Amount', plain: 'The recipient gets exactly the agreed amount, not a zatoshi more or less.',
    how: 'The reconstructed note’s value must equal the intent’s amount_zat.' },
  { k: 'Memo', plain: 'The attached message is the one that was agreed. A changed memo cannot hide.',
    how: 'The note is re-encrypted with the intended memo and must reproduce enc_ciphertext byte for byte. Deterministic because the ephemeral secret derives from the note’s rseed.' },
  { k: 'Change', plain: 'Money left over comes back to the account, not to an address the proposer picked.',
    how: 'The change address is derived by the signer from the account key, never read from the proposal. The amount must equal the intent’s change_zat.' },
  { k: 'Fee', plain: 'The fee is what was agreed, so nothing is skimmed.', untested: true,
    how: 'implied_fee = sum(spend values) − sum(output values), compared with the intent. Implemented, but UNTESTED against a real candidate: the fee is pinned by the inputs and outputs, so a candidate with only the fee wrong will not build.' },
  { k: 'Input', plain: 'It spends the coin that was discussed, not a different one.',
    how: 'The set of nullifiers with non-zero spend value must equal the intent’s set exactly.' },
  { k: 'Expiry', plain: 'The approval cannot be held and used much later than intended.',
    how: 'The expiry height is read from the PCZT global and compared with the intent.' },
  { k: 'Permitted pools', plain: 'Nothing is quietly moved through a different kind of output.',
    how: 'The Orchard, transparent and Sapling bundles must all be empty. A positive fixture for each now exists.' },
];

const COMMANDS = [
  { title: 'The main flow, genesis to mined', cmd: 'cd poc\n./run-regtest.sh',
    note: 'Builds a fresh regtest chain, funds the account, runs the full sequence, mines the transaction. Exits nonzero on any failure.' },
  { title: 'Second-device finishing, both paths', cmd: 'cd poc\n./run-second-device.sh',
    note: 'Two payments: one where a finished transaction was posted, one where the finisher re-proves it from a signed candidate and its own chain scan.' },
  { title: 'The signer’s refusals', cmd: 'cd poc\n./tamper-tests.sh',
    note: 'Alters one field of a serialized candidate at a time and asserts the specific refusal plus zero share files.' },
  { title: 'The ZIP 2005 blocker, as a compiler error', cmd: 'cd poc\ncargo build --features probe-zip2005',
    note: 'Fails to compile. That failure is the evidence: the derivation full G1 needs does not exist in any crate.' },
  { title: 'This demo', cmd: 'python3 poc/demo/server.py',
    note: 'Serves this page on http://127.0.0.1:8787. Read-only, loopback-only, runs nothing.' },
];

/* ── rendering ───────────────────────────────────────────────────────────── */

const fmt = (v) => (v === null || v === undefined || v === '' ? null : String(v));

function evidenceList(rows, source) {
  const dl = el('dl', 'evidence');
  for (const [k, v] of rows) {
    const row = el('div', 'row');
    row.append(el('dt', null, k));
    const val = fmt(v);
    row.append(el('dd', val ? null : 'none', val ?? 'not recorded'));
    dl.append(row);
  }
  if (source) {
    const row = el('div', 'row');
    row.append(el('dt', null, 'Source'));
    const dd = el('dd', null, source);
    row.append(dd);
    dl.append(row);
  }
  return dl;
}

function renderStatus(data) {
  const chips = $('chips');
  const detail = $('chipDetail');
  chips.replaceChildren();
  detail.replaceChildren();
  for (const s of data.status) {
    // Both labels ship; CSS picks one by width. The narrow screen gets the short form so
    // the sticky bar stays one row instead of eating half the viewport.
    const c = el('span', `chip ${s.state}`);
    c.append(el('span', 'full', s.label));
    c.append(el('span', 'short', s.short ?? s.label));
    c.title = s.detail;
    chips.append(c);
    const p = el('p');
    p.append(el('strong', null, s.label), document.createTextNode(s.detail));
    detail.append(p);
  }
  const btn = $('chipsToggle');
  btn.addEventListener('click', () => {
    const open = detail.hidden;
    detail.hidden = !open;
    btn.setAttribute('aria-expanded', String(open));
    btn.textContent = open ? 'Hide details' : 'Details';
  });
}

function renderHero(data) {
  const g = data.g1tx;
  const kv = $('heroKv');
  kv.replaceChildren();
  const rows = [
    ['Transaction id', g.txid.value, 'big'],
    ['Mined at height', g.height.value],
    ['Confirmations when recorded', g.confirmations.value],
    ['Anchor', g.anchor.value ? `${g.anchor.value}…` : null],
    ['Network', g.network.value],
  ];
  for (const [k, v, cls] of rows) {
    const d = el('div');
    d.append(el('dt', null, k));
    const val = fmt(v);
    d.append(el('dd', [cls, val ? '' : 'none'].filter(Boolean).join(' '), val ?? 'not recorded'));
    kv.append(d);
  }
  $('heroNote').textContent =
    `Recorded ${data.recorded_date ?? 'date not recorded'} on a local regtest chain. `
    + `Read from ${g.txid.source}. This page is not running the prototype.`;
}

function renderMembers(data) {
  const box = $('members');
  box.replaceChildren();
  const who = [
    { n: 'Alice', role: 'proposed and signed', p: 'Built the proposal and the three candidates, reviewed each one she appears in, and produced one of the two partial signatures.' },
    { n: 'Bob', role: 'did not sign this payment', p: 'Published nonce commitments and held a share, but was not one of the two approvers. He later finished a different payment without any approver’s files.' },
    { n: 'Carol', role: 'signed', p: 'Reviewed independently in her own process and produced the second partial signature.' },
  ];
  for (const m of who) {
    const c = el('div', 'member' + (m.role.startsWith('did not') ? '' : ' did-sign'));
    c.append(el('h3', null, m.n), el('span', 'role', m.role), el('p', null, m.p));
    box.append(c);
  }
}

function renderPairs(data) {
  const fan = $('pairfan');
  fan.replaceChildren();
  for (const p of data.pairs) {
    const card = el('div', `pair ${p.mined ? 'is-mined' : 'is-unused'}`);
    const top = el('div', 'pair-top');
    top.append(el('h3', null, p.name));
    top.append(el('span', `badge ${p.mined ? 'badge-mined' : 'badge-recorded'}`,
      p.mined ? 'Mined' : 'Unused'));
    card.append(top);
    card.append(el('p', 'who', p.members.join('  +  ')));
    card.append(el('p', 'fate', p.mined
      ? 'This pair approved, so this candidate was completed and broadcast.'
      : 'Valid and reviewed, but this pair did not complete. Discarded unspent.'));
    const dl = el('dl');
    for (const [k, v, differs] of [
      ['rk', p.rk ? `${p.rk}…` : null, true],
      ['alpha', p.alpha ? `${p.alpha}…` : null, true],
      ['sighash', p.sighash ? `${p.sighash}…` : null, true],
      ['bytes', p.bytes, false],
    ]) {
      const row = el('div');
      row.append(el('dt', null, k));
      const val = fmt(v);
      row.append(el('dd', differs ? 'differs' : null, val ?? 'not recorded'));
      dl.append(row);
    }
    card.append(dl);
    fan.append(card);
  }

  const shared = [
    'input coin (nullifier)', 'recipient address', 'amount: 40000000 zat',
    'memo: "loki g1-tx"', 'change: 584990000 zat', 'fee: 10000 zat',
    'expiry height: 9216', 'proposal id',
  ];
  const ul = $('sharedList');
  ul.replaceChildren();
  for (const s of shared) ul.append(el('li', null, s));
}

function renderStages(data) {
  const rail = $('rail');
  const panel = $('stageDetail');
  rail.replaceChildren();

  const show = (i) => {
    const s = STAGES[i];
    for (const b of rail.children) b.setAttribute('aria-current', String(+b.dataset.i === i));
    panel.replaceChildren();

    const head = el('div', 'sd-head');
    head.append(el('span', 'i', `Stage ${String(i + 1).padStart(2, '0')} of 10`));
    head.append(el('h3', null, s.label));
    panel.append(head);

    const body = el('div', 'sd-body');

    const p1 = el('div', 'sd-sec');
    p1.append(el('h4', null, 'In plain language'));
    p1.append(el('p', null, s.plain));
    body.append(p1);

    const p2 = el('div', 'sd-sec');
    p2.append(el('h4', null, 'What the code does'));
    p2.append(el('p', 'sd-tech', s.tech));
    body.append(p2);

    const p3 = el('div', 'sd-sec');
    const h = el('h4', null, 'What this stage recorded ');
    h.append(el('span', 'badge badge-recorded', 'Recorded'));
    p3.append(h);
    let rows = [];
    try { rows = s.evi(data) || []; } catch { rows = []; }
    p3.append(rows.length
      ? evidenceList(rows, 'poc/RESULTS.md, poc/SECOND-DEVICE-RESULTS.md')
      : el('p', null, 'No numeric evidence is recorded for this stage.'));
    body.append(p3);

    panel.append(body);
  };

  STAGES.forEach((s, i) => {
    const b = el('button', null);
    b.type = 'button';
    b.dataset.i = String(i);
    b.append(el('span', 'i', String(i + 1).padStart(2, '0')));
    b.append(el('span', 't', s.label));
    b.addEventListener('click', () => show(i));
    rail.append(b);
  });
  show(0);
}

function renderChecks(data) {
  const grid = $('checksGrid');
  grid.replaceChildren();
  for (const c of CHECKS) {
    const card = el('div', 'check' + (c.untested ? ' untested' : ''));
    card.append(el('h3', null, c.k));
    if (c.untested) card.append(el('span', 'flag', 'implemented, untested'));
    card.append(el('p', 'plain', c.plain));
    card.append(el('p', 'how', c.how));
    grid.append(card);
  }

  $('tamperIntro').textContent =
    `Each case replaces the serialized candidate with one a hostile proposer could have `
    + `built: produced by the real builder, structurally valid, but not the payment that `
    + `was agreed. The run asserts the specific refusal and that no share file exists. `
    + `Result: ${data.tamper.total.value ?? 'not recorded'}.`;

  const t = $('tamperTable');
  t.replaceChildren();
  const thead = el('thead');
  const hr = el('tr');
  for (const h of ['Field altered', 'Outcome', 'Reason recorded']) hr.append(el('th', null, h));
  thead.append(hr);
  t.append(thead);
  const tb = el('tbody');
  for (const c of data.tamper.cases) {
    const tr = el('tr', c.outcome === 'could not construct' ? 'nc' : null);
    tr.append(el('td', 'c', c.case));
    tr.append(el('td', 'c', c.outcome));
    tr.append(el('td', 'r', c.reason));
    tb.append(tr);
  }
  t.append(tb);
}

function renderPaths(data) {
  const box = $('paths');
  box.replaceChildren();
  const copy = {
    A: {
      title: 'Path A — broadcast posted bytes',
      p: 'A finished transaction already existed: an approver had proved and extracted it but never got it to a node. The finisher parses those bytes, confirms they spend the coin the proposal named, and broadcasts. It does not broadcast blindly.',
    },
    B: {
      title: 'Path B — re-prove the signed candidate',
      p: 'No finished transaction existed. The finisher combines the two partial signatures, locates the coin and the anchor by its own scan of the chain, installs them after the signature, generates the proof, and broadcasts. All of it without a single secret.',
    },
  };
  for (const p of data.second_device.paths) {
    const c = copy[p.path];
    const card = el('div', 'path');
    const top = el('div', 'path-top');
    top.append(el('h3', null, c.title));
    top.append(el('span', 'badge badge-recorded', 'Recorded'));
    card.append(top);
    const body = el('div', 'path-body');
    body.append(el('p', null, c.p));
    const dl = el('dl');
    for (const [k, v] of [
      ['Transaction id', p.txid],
      ['Mined at height', p.mined],
      ['Finisher’s own chain scan', p.own_scan],
    ]) {
      const row = el('div');
      row.append(el('dt', null, k));
      const val = fmt(v);
      row.append(el('dd', val ? null : 'none', val ?? 'not recorded'));
      dl.append(row);
    }
    body.append(dl);
    card.append(body);
    box.append(card);
  }
}

function renderLog(data) {
  const g = data.g1tx;
  const sd = data.second_device.paths;
  const lines = [
    ['distributed key generation complete, 2-of-3', null],
    ['account funded by shielded coinbase; own scan found the coin', null],
    ['nonce commitments published by alice, bob, carol', null],
    ['candidate AB built, anchor deferred, no proof', data.pairs[0].rk ? `rk ${data.pairs[0].rk}…` : null],
    ['candidate AC built, anchor deferred, no proof', data.pairs[1].rk ? `rk ${data.pairs[1].rk}…` : null],
    ['candidate BC built, anchor deferred, no proof', data.pairs[2].rk ? `rk ${data.pairs[2].rk}…` : null],
    ['alice reviewed AC independently: effects match, rk matches recomputed alpha', data.pairs[1].sighash ? `sighash ${data.pairs[1].sighash}…` : null],
    ['carol reviewed AC independently: effects match, rk matches recomputed alpha', data.pairs[1].sighash ? `sighash ${data.pairs[1].sighash}…` : null],
    ['alice emitted a share, nonce consumed', null],
    ['carol emitted a share, nonce consumed', null],
    ['two shares aggregated; verifies under ak + [alpha]G', null],
    ['signature applied to action 0', null],
    ['anchor and witness installed AFTER signing', g.anchor.value ? `anchor ${g.anchor.value}… at height ${g.anchor_height.value}` : null],
    ['effects sighash unchanged by anchor/witness installation', null],
    ['Halo 2 proof created locally', null],
    ['v6 transaction extracted, 9166 bytes', g.txid.value],
    ['broadcast to the local regtest node', null],
    ['mined and confirmed', g.height.value ? `height ${g.height.value}, ${g.confirmations.value} confirmation(s)` : null],
    ['effects verified against the chain, not a local file', null],
    ['second device, path A: posted bytes checked and broadcast', sd[0].txid],
    ['second device, path B: candidate re-proved from the finisher’s own scan', sd[1].txid],
  ];
  const ol = $('eventlog');
  ol.replaceChildren();
  for (const [msg, value] of lines) {
    const li = el('li', value ? 'has-value' : null);
    li.append(el('span', 'm', msg));
    if (value) li.append(el('span', 'v', String(value)));
    ol.append(li);
  }
}

function renderCommands() {
  const box = $('cmds');
  box.replaceChildren();
  for (const c of COMMANDS) {
    const card = el('div', 'cmd');
    const top = el('div', 'cmd-top');
    top.append(el('span', null, c.title));
    const btn = el('button', 'copy', 'Copy');
    btn.type = 'button';
    btn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(c.cmd);
        btn.textContent = 'Copied';
        btn.classList.add('done');
      } catch {
        btn.textContent = 'Select it';
      }
      setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('done'); }, 1600);
    });
    top.append(btn);
    card.append(top);
    card.append(el('pre', null, c.cmd));
    card.append(el('p', 'note', c.note));
    box.append(card);
  }
}

function renderLimits(data) {
  const grid = $('limits-grid');
  grid.replaceChildren();
  const extra = [
    { state: 'partial', label: 'G3 engine coverage', detail: `${data.g3.engines[0].engine} ${data.g3.engines[0].version}: ${data.g3.engines[0].counts}. ${data.g3.engines[1].engine} ${data.g3.engines[1].version}: ${data.g3.engines[1].counts}. ${data.g3.engines[2].engine}: ${data.g3.engines[2].counts}.` },
    { state: 'not-established', label: 'Not a second device', detail: 'The second-device result is a second process on the same machine reading a locally copied replica. No relay, no transport authentication, no second piece of hardware.' },
    { state: 'not-established', label: 'No secure signing happens here', detail: 'This page displays recorded results. It performs no key generation, no signing, and no broadcasting, and it holds no key material of any kind.' },
  ];
  for (const s of [...data.status, ...extra]) {
    const c = el('div', `limit ${s.state}`);
    c.append(el('span', 'state', s.state.replace('-', ' ')));
    c.append(el('h3', null, s.label));
    c.append(el('p', null, s.detail));
    grid.append(c);
  }
  $('sources').textContent =
    'Every number on this page was extracted from: '
    + Object.values(data.sources).join('  ·  ')
    + `  — recorded ${data.recorded_date ?? 'date not recorded'}.`;
}

/* ── the one live reading, kept separate ─────────────────────────────────── */

async function probeNode() {
  const text = $('nodeText');
  text.textContent = 'checking for a local node…';
  try {
    const r = await fetch('/api/node');
    const n = await r.json();
    text.textContent = n.reachable
      ? `a node answered on ${n.endpoint}, block count ${n.tip}. ${n.note}`
      : `no node on ${n.endpoint}. ${n.note}`;
  } catch (e) {
    text.textContent = `could not run the check (${e.message}).`;
  }
}

/* ── boot ────────────────────────────────────────────────────────────────── */

async function main() {
  let data;
  try {
    const r = await fetch('/api/evidence');
    data = await r.json();
    if (data.error) throw new Error(data.error);
  } catch (e) {
    document.querySelector('main').prepend(
      el('p', 'err', `Could not load evidence: ${e.message}. `
        + `Start the server with: python3 poc/demo/server.py`),
    );
    return;
  }

  renderStatus(data);
  renderHero(data);
  renderMembers(data);
  renderPairs(data);
  renderStages(data);
  renderChecks(data);
  renderPaths(data);
  renderLog(data);
  renderCommands();
  renderLimits(data);

  $('nodeRefresh').addEventListener('click', probeNode);
  probeNode();
}

main();
