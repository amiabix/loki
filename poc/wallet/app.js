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
    try { await task(event.target); event.target.reset(); await refresh(); }
    catch (error) { message(error.message, true); }
    finally { button.disabled = false; }
  });
}
async function refresh() {
  try {
    const state = await api('status');
    $('title').textContent = state.name || 'Your wallet';
    $('subtitle').textContent = state.slot ? `Member ${state.slot} · 2 of 3 · regtest` : 'Create or join a vault from this member’s own app.';
    if (state.invites) {
      $('invite2').textContent = state.invites[0];
      $('invite3').textContent = state.invites[1];
      $('invites').hidden = state.phase === 'active';
    }
    for (const id of ['new', 'setup', 'backup', 'waiting', 'active']) $(id).hidden = true;
    if (state.phase === 'new') $('new').hidden = false;
    else if (state.phase === 'waiting_for_members') {
      $('setup').hidden = false;
      $('progress').textContent = `${state.members} of 3 members have joined. Waiting for the other members.`;
      $('agree').hidden = true;
      $('fingerprint').textContent = 'Available when all three join';
    } else if (state.phase === 'compare_roster' || state.phase === 'creating_keys') {
      $('setup').hidden = false;
      $('agree').hidden = state.phase === 'creating_keys';
      $('progress').textContent = state.phase === 'creating_keys' ? 'Creating group keys with the other member apps…' : 'All three members joined.';
      $('fingerprint').textContent = state.fingerprint;
    } else if (state.phase === 'back_up') $('backup').hidden = false;
    else if (state.phase === 'waiting_for_backups') $('waiting').hidden = false;
    else if (state.phase === 'active') $('active').hidden = false;
    else if (state.phase === 'stopped') message('Setup stopped: ' + state.error + '. Start a fresh vault session.', true);
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
  $('words').textContent = result.words;
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
action('activate', async (form) => {
  const value = await api('activate', fields(form));
  $('address').textContent = value.address;
  message('All three backups checked. Vault active on regtest.');
});
action('show-address', async (form) => {
  const value = await api('activate', fields(form));
  $('address').textContent = value.address;
});
refresh(); setInterval(refresh, 2000);
