'use strict';
const token = location.hash.slice(1);
const $ = (id) => document.getElementById(id);
let cardBytes = null;

function message(text, error = false) {
  $('message').textContent = text;
  $('message').hidden = !text;
  $('message').classList.toggle('error', error);
}
async function api(path, body) {
  if (!token) throw new Error('Open the private local app link printed by the server.');
  const response = await fetch(`/api/${path}`, {
    method: body ? 'POST' : 'GET',
    headers: {'X-Loki-Token': token, ...(body ? {'Content-Type': 'application/json'} : {})},
    body: body ? JSON.stringify(body) : undefined,
    cache: 'no-store',
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Request failed');
  return result;
}
function fields(form) { return Object.fromEntries(new FormData(form)); }
function action(id, task) {
  $(id).addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = event.target.querySelector('button');
    button.disabled = true;
    button.classList.add('busy');
    try { await task(event.target); event.target.reset(); await refresh(); }
    catch (error) { message(error.message, true); }
    finally { button.disabled = false; button.classList.remove('busy'); }
  });
}
/* One card at a time. Idempotent, so the poll does not restart its entrance. */
const show = (() => {
  let current = null;
  return (id) => {
    if (current === id) return;
    if (current) $(current).hidden = true;
    if (id) $(id).hidden = false;
    current = id;
  };
})();



/* ── seed words ─────────────────────────────────────────────────────────────
   Twenty-four words as a numbered grid, not a paragraph. The numbers are the
   point: they are what makes a transcription error visible while you write
   them down, and they match how the words are checked back in. */

function drawWords(text) {
  const target = $('words');
  target.replaceChildren();
  target.classList.add('grid');
  text.trim().split(/\s+/).forEach((word, index) => {
    const cell = document.createElement('span');
    const number = document.createElement('i');
    number.textContent = String(index + 1).padStart(2, '0');
    cell.append(number, document.createTextNode(word));
    target.append(cell);
  });
}

/* ── fingerprint echo ───────────────────────────────────────────────────────
   Compares what is being typed against the roster fingerprint and says where
   the two diverge. Advisory only: the server still decides, and a wrong
   fingerprint must fail there, not here. */

function echo(typed) {
  const expected = $('fingerprint').textContent.trim();
  const line = $('echo');
  const clean = typed.trim();
  if (!clean || !expected || expected.includes(' when all three join')) {
    line.hidden = true;
    return;
  }
  line.hidden = false;
  let same = 0;
  while (same < clean.length && same < expected.length && clean[same] === expected[same]) same += 1;
  const exact = clean === expected;
  line.classList.toggle('ok', exact);
  line.classList.toggle('bad', !exact && same < clean.length);
  /* Never phrase an exact match as verification: this only compares against the
     value on THIS screen, which is the value an attacker would have poisoned.
     It catches typing mistakes. The out-of-band comparison is the real check. */
  line.textContent = exact
    ? 'Matches this screen. It still has to match the other two members\u2019 screens.'
    : same < clean.length
      ? `Diverges at character ${same + 1}. Stop and compare again.`
      : `${same} of ${expected.length} characters so far.`;
}

/* ── roster sigil ───────────────────────────────────────────────────────────
   A deterministic emblem drawn from the roster fingerprint. Two people holding
   different rosters get visibly different marks, which is far faster to spot
   across a video call than 32 hex characters. It is an AID, not the check: the
   characters are still the thing that must match, and the copy says so. */

const SVG = 'http://www.w3.org/2000/svg';
const SIGIL_INK = ['#00e0a4', '#49d6ff', '#f4b728', '#c07bff', '#ff6b7a'];

function digest(text) {
  /* FNV-1a, then stretched: enough spread for 25 cells and two colours. */
  let hash = 0x811c9dc5;
  for (const character of text) {
    hash ^= character.codePointAt(0);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  const stream = [];
  let state = hash;
  for (let index = 0; index < 16; index += 1) {
    state = Math.imul(state ^ (state >>> 13), 0x5bd1e995) >>> 0;
    stream.push(state);
  }
  return stream;
}

function node(name, attributes) {
  const element = document.createElementNS(SVG, name);
  for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, value);
  return element;
}

function drawSigil(text) {
  const target = $('sigil');
  if (target.dataset.of === text) return;   /* the poll must not recast it every 2s */
  target.dataset.of = text;
  target.replaceChildren();
  target.classList.toggle('ready', Boolean(text));
  $('sigilCaption').textContent = text
    ? 'Roster sigil · the same mark on all three screens. The characters are still the check.'
    : 'Roster sigil · appears when all three join';
  if (!text) {
    /* an empty frame reads as broken, so hold the shape until there is a roster */
    target.append(node('circle', {
      cx: 60, cy: 60, r: 42, fill: 'none', stroke: '#22323f',
      'stroke-width': 1, 'stroke-dasharray': '3 7',
    }));
    target.append(node('rect', {
      x: 54, y: 54, width: 12, height: 12, transform: 'rotate(45 60 60)', fill: '#22323f',
    }));
    return;
  }

  const stream = digest(text);
  const ink = SIGIL_INK[stream[0] % SIGIL_INK.length];
  const glint = SIGIL_INK[(stream[1] >>> 3) % SIGIL_INK.length];

  /* outer ring of ticks: twelve positions, length set by the hash */
  for (let index = 0; index < 12; index += 1) {
    const angle = (index / 12) * Math.PI * 2 - Math.PI / 2;
    const long = (stream[2 + (index % 8)] >>> index) & 1;
    const inner = long ? 44 : 49;
    target.append(node('line', {
      x1: 60 + Math.cos(angle) * inner, y1: 60 + Math.sin(angle) * inner,
      x2: 60 + Math.cos(angle) * 55, y2: 60 + Math.sin(angle) * 55,
      stroke: long ? ink : '#334a5c', 'stroke-width': long ? 2 : 1,
    }));
  }

  /* a 5x5 field, mirrored down the middle, so the mark reads as an emblem */
  for (let row = 0; row < 5; row += 1) {
    for (let column = 0; column < 3; column += 1) {
      const bit = (stream[4 + row] >>> (column * 3)) & 7;
      if (bit < 3) continue;
      const size = bit > 5 ? 9 : 6;
      for (const x of new Set([column, 4 - column])) {
        target.append(node('rect', {
          x: 24 + x * 15 - size / 2, y: 24 + row * 15 - size / 2,
          width: size, height: size,
          transform: `rotate(45 ${24 + x * 15} ${24 + row * 15})`,
          fill: bit > 5 ? ink : glint,
          opacity: bit > 5 ? 1 : .55,
        }));
      }
    }
  }
  target.append(node('circle', {cx: 60, cy: 60, r: 57, fill: 'none', stroke: ink, 'stroke-width': 1, opacity: .35}));
}

const HEADLINE = {
  new: ['Step 01 of 05', 'Start or join a vault'],
  waiting_for_members: ['Step 01 of 05', 'Waiting for the other two'],
  compare_roster: ['Step 02 of 05', 'Compare the roster, character by character'],
  creating_keys: ['Step 03 of 05', 'Creating the group keys'],
  back_up: ['Step 04 of 05', 'Back up your share'],
  waiting_for_backups: ['Step 04 of 05', 'Waiting for the other backups'],
  active: ['Step 05 of 05', 'The vault is live'],
  stopped: ['Setup stopped', 'Start a fresh vault session'],
};

const STEP = {
  new: 0, waiting_for_members: 0, compare_roster: 1, creating_keys: 2,
  back_up: 3, waiting_for_backups: 3, active: 4,
};
function steps(phase) {
  const at = STEP[phase];
  document.body.dataset.phase = phase;
  for (const item of $('steps').children) {
    const index = Number(item.dataset.step);
    item.classList.toggle('done', at !== undefined && index < at);
    item.classList.toggle('now', index === at);
  }
}

async function refresh() {
  try {
    const state = await api('status');
    steps(state.phase);
    const [kicker, headline] = HEADLINE[state.phase] || ['', ''];
    $('kicker').textContent = kicker;
    $('headline').textContent = headline;
    $('title').textContent = state.name || 'Your wallet';
    $('slot').textContent = state.slot ? `0${state.slot}` : '';
    $('slot').hidden = !state.slot;
    $('subtitle').textContent = state.slot ? `Member ${state.slot} of 3 · threshold 2 · regtest` : 'Create or join a vault from this member’s own app.';
    drawSigil(state.fingerprint || '');
    if (state.invites) {
      $('invite2').textContent = state.invites[0];
      $('invite3').textContent = state.invites[1];
      $('invites').hidden = state.phase === 'active';
    }
    if (state.phase === 'new') show('new');
    else if (state.phase === 'waiting_for_members') {
      show('setup');
      $('progress').textContent = `${state.members} of 3 members have joined. Waiting for the other members.`;
      $('agree').hidden = true;
      $('fingerprint').textContent = 'Available when all three join';
    } else if (state.phase === 'compare_roster' || state.phase === 'creating_keys') {
      show('setup');
      $('agree').hidden = state.phase === 'creating_keys';
      $('progress').textContent = state.phase === 'creating_keys' ? 'Creating group keys with the other member apps…' : 'All three members joined.';
      $('fingerprint').textContent = state.fingerprint;
    } else if (state.phase === 'back_up') show('backup');
    else if (state.phase === 'waiting_for_backups') show('waiting');
    else if (state.phase === 'active') show('active');
    else if (state.phase === 'stopped') { show(null); message('Setup stopped: ' + state.error + '. Start a fresh vault session.', true); }
    /* only offer a copy once a real address has replaced the placeholder */
    document.querySelector('[data-copy="address"]').hidden = !$('address').dataset.ready;
    if (state.error) message(state.error, true);
  } catch (error) { message(error.message, true); }
}
action('create', async (form) => {
  const value = await api('create', fields(form));
  $('invite2').textContent = value.invites[0];
  $('invite3').textContent = value.invites[1];
  $('invites').hidden = false;
  message('Vault draft created. Invite the other two members.');
});
action('join', async (form) => { await api('join', fields(form)); message('Joined. Waiting for the other members.'); });
action('agree', async (form) => { await api('agree', fields(form)); message('Key creation started. Each member must compare and confirm the roster.'); });
action('make-backup', async (form) => {
  const result = await api('backup', fields(form));
  drawWords(result.words);
  $('backup-made').hidden = false;
  message('Save both artifacts, then load them back below.');
});
$('download').addEventListener('click', async () => {
  const result = await api('card');
  const bytes = Uint8Array.from(atob(result.card), c => c.charCodeAt(0));
  const link = document.createElement('a');
  link.href = URL.createObjectURL(new Blob([bytes], {type: 'application/octet-stream'}));
  link.download = 'loki-vault.card';
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
});
action('check-backup', async (form) => {
  const value = fields(form);
  const bytes = new Uint8Array(await value.card.arrayBuffer());
  if (bytes.length > 65536) throw new Error('Backup card is too large');
  let raw = ''; for (const byte of bytes) raw += String.fromCharCode(byte);
  await api('verify', {words: value.words, passphrase: value.passphrase, card: btoa(raw)});
  message('Your backup checked. Waiting for the other members.');
});
function showAddress(address) {
  $('address').textContent = address;
  $('address').classList.remove('muted');
  $('address').dataset.ready = '1';
  document.querySelector('[data-copy="address"]').hidden = false;
}
action('activate', async (form) => {
  showAddress((await api('activate', fields(form))).address);
  message('All three backups checked. Vault active on regtest.');
});
action('show-address', async (form) => {
  showAddress((await api('activate', fields(form))).address);
});
refresh(); setInterval(refresh, 2000);

for (const button of document.querySelectorAll('[data-copy]')) {
  button.addEventListener('click', async () => {
    const text = $(button.dataset.copy).textContent.trim();
    if (!text) return;
    await navigator.clipboard.writeText(text);
    const label = button.textContent;
    button.textContent = 'Copied';
    button.classList.add('copied');
    setTimeout(() => { button.textContent = label; button.classList.remove('copied'); }, 1400);
  });
}

$('agree').querySelector('[name="fingerprint"]').addEventListener('input', (event) => echo(event.target.value));
