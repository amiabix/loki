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
    /* the column scrolls inside the shell, so a shorter step would otherwise
       open halfway down the page; move the reader to the top of the new one */
    document.querySelector('main').scrollTop = 0;
    if (id) $(id).focus({preventScroll: true});
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
  /* keyed off the element's own flag, not off the placeholder sentence: the
     copy can change without silently turning this into a diff against prose */
  if (!clean || !$('fingerprint').dataset.live) {
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

const HEADLINE = {
  new: ['Step 01 of 05', 'Start or join a vault'],
  waiting_for_members: ['Step 01 of 05', 'Waiting for the other two'],
  compare_roster: ['Step 02 of 05', 'Compare the roster, character by character'],
  creating_keys: ['Step 03 of 05', 'Creating the group keys'],
  back_up: ['Step 04 of 05', 'Back up your share'],
  waiting_for_backups: ['Step 04 of 05', 'Waiting for the other backups'],
  active: ['Step 05 of 05', 'The vault is live'],
  stopped: ['Setup stopped', 'Key creation stopped'],
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
    if (index === at) item.setAttribute('aria-current', 'step');
    else item.removeAttribute('aria-current');
  }
}

/* ── flip ───────────────────────────────────────────────────────────────────
   Characters scramble and settle left to right as a value lands. Used only on
   values that actually arrive — the roster fingerprint, the receive address,
   the step counter — never as idle decoration.

   Two rules it must not break: the element always ends holding exactly the
   string it was given, and a newer flip cancels an older one, so a value can
   never be left half-scrambled by an overlapping call. */

const FLIP_GLYPHS = '0123456789abcdefghijklmnopqrstuvwxyz';
const FLIP_FRAMES = 2;   /* frames each character waits before it settles */

function flipInto(element, text) {
  const calm = matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (calm || element.textContent === text || !text) {
    element.textContent = text;
    return;
  }
  const chars = [...text];
  const run = String(Number(element.dataset.flip || 0) + 1);
  element.dataset.flip = run;
  let frame = 0;
  const tick = () => {
    if (element.dataset.flip !== run) return;     /* a newer value took over */
    frame += 1;
    const settled = Math.floor(frame / FLIP_FRAMES);
    if (settled >= chars.length) {
      element.textContent = text;                 /* exact, always */
      return;
    }
    element.textContent = chars
      .map((character, index) => (index < settled || character === ' '
        ? character
        : FLIP_GLYPHS[Math.floor(Math.random() * FLIP_GLYPHS.length)]))
      .join('');
    requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

let lastPhase = null;
let lastPrint = null;

async function refresh() {
  try {
    const state = await api('status');
    if (state.phase !== lastPhase) {
      if (lastPhase !== null) message('');   /* belongs to the step that ended */
      lastPhase = state.phase;
    }
    steps(state.phase);
    const [kicker, headline] = HEADLINE[state.phase] || ['', ''];
    flipInto($('kicker'), kicker);
    $('headline').textContent = headline;
    $('title').textContent = state.name || 'Your wallet';
    $('slot').textContent = state.slot ? `0${state.slot}` : '';
    $('slot').hidden = !state.slot;
    $('subtitle').textContent = state.slot ? `Member ${state.slot} of 3 · threshold 2 · regtest` : 'Create or join a vault from this member’s own app.';
    if (state.invites) {
      $('invite2').textContent = state.invites[0];
      $('invite3').textContent = state.invites[1];
      /* the codes are only of use while someone still has to join */
      $('invites').hidden = state.phase !== 'waiting_for_members';
    }
    $('fingerprint').dataset.live = state.fingerprint ? '1' : '';
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
      if (state.fingerprint !== lastPrint) {
        lastPrint = state.fingerprint;
        flipInto($('fingerprint'), state.fingerprint);
      }
    } else if (state.phase === 'back_up') show('backup');
    else if (state.phase === 'waiting_for_backups') show('waiting');
    else if (state.phase === 'active') show('active');
    else if (state.phase === 'stopped') {
      /* agree() clears the error and starts a fresh round, so the retry has to
         stay reachable; hiding every card left the only way out off screen */
      if (state.fingerprint) {
        show('setup');
        $('agree').hidden = false;
        $('progress').textContent = 'Key creation stopped. Confirm the roster again to retry.';
        $('fingerprint').textContent = state.fingerprint;
      } else {
        show(null);
      }
      message('Setup stopped: ' + state.error, true);
    }
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
  flipInto($('address'), address);
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

/* ── theme ──────────────────────────────────────────────────────────────────
   No stored choice means follow the system, which is what the media query in
   app.css already does. A stored choice pins data-theme on the root and wins.
   Nothing else in the app reads this: every rule below the token block uses
   semantic names, so a third theme would be a palette and one more case. */

const THEME_KEY = 'loki-theme';

/* Storage throws rather than returning null in a few real cases — Safari in
   private browsing, embedded webviews, storage disabled by policy. A theme
   preference is not worth taking the page down for, so both sides fail quiet
   and the app falls back to following the system. */
const store = {
  read() {
    try { return localStorage.getItem(THEME_KEY); } catch { return null; }
  },
  write(value) {
    try { localStorage.setItem(THEME_KEY, value); } catch { /* not fatal */ }
  },
};

function currentTheme() {
  return document.documentElement.dataset.theme
    || (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
}

function applyTheme(mode) {
  if (mode) document.documentElement.dataset.theme = mode;
  /* the button offers the other one */
  $('theme').textContent = currentTheme() === 'dark' ? 'Light' : 'Dark';
}

applyTheme(store.read());
$('theme').addEventListener('click', () => {
  const next = currentTheme() === 'dark' ? 'light' : 'dark';
  store.write(next);
  applyTheme(next);
});
matchMedia('(prefers-color-scheme: light)').addEventListener('change', () => {
  if (!store.read()) applyTheme(null);
});
