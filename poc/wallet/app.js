'use strict';
const token = location.hash.slice(1);
const $ = (id) => document.getElementById(id);
let selectedVault = null;
let linkChallenge = null;

function selectVault(vault) {
  selectedVault = vault;
  linkChallenge = null;
  $('address').textContent = 'Open this vault to view the address.';
  $('balance').textContent = "Scan this device's chain view to see the balance.";
  $('words').textContent = '';
  $('backup-made').hidden = true;
}

function message(text, error = false) {
  $('message').textContent = text;
  $('message').hidden = !text;
  $('message').classList.toggle('error', error);
}
async function api(path, body) {
  if (!token) throw new Error('Open the private local app link printed by the server.');
  const response = await fetch(`/api/${path}`, {
    method: body === undefined ? 'GET' : 'POST',
    headers: {'X-Loki-Token': token, ...(body === undefined ? {} : {'Content-Type': 'application/json'})},
    body: body === undefined ? undefined : JSON.stringify(body),
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
function vaultList(vaults) {
  const list = $('vault-list');
  list.replaceChildren();
  if (!vaults.length) { list.textContent = 'No vaults yet.'; return; }
  for (const vault of vaults) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'secondary';
    button.textContent = `${vault.name} · member ${vault.slot}`;
    button.addEventListener('click', () => { selectVault(vault.vault); refresh(); });
    list.append(button);
  }
}
async function refreshSignerRequests(unlocked) {
  const section = $('signer-requests');
  const actionsSection = $('signer-actions');
  section.hidden = true;
  actionsSection.hidden = true;
  if (!unlocked) return;
  const {requests} = await api('session/pending');
  const list = $('signer-request-list');
  list.replaceChildren();
  for (const request of requests) {
    const item = document.createElement('div');
    const description = document.createElement('p');
    description.textContent = `${request.origin} · ${request.network} · ${request.access}`;
    const approve = document.createElement('button');
    approve.type = 'button';
    approve.textContent = 'Approve dashboard access';
    approve.addEventListener('click', async () => {
      try { await api('session/approve', {request: request.request}); message('Dashboard connected. Each vault creation still needs your approval.'); await refresh(); }
      catch (error) { message(error.message, true); }
    });
    const reject = document.createElement('button');
    reject.type = 'button';
    reject.className = 'secondary';
    reject.textContent = 'Reject';
    reject.addEventListener('click', async () => {
      try { await api('session/reject', {request: request.request}); await refresh(); }
      catch (error) { message(error.message, true); }
    });
    item.append(description, approve, reject);
    list.append(item);
  }
  section.hidden = !requests.length;
  const {actions} = await api('session/actions');
  const actionList = $('signer-action-list');
  actionList.replaceChildren();
  for (const action of actions) {
    const item = document.createElement('div');
    const description = document.createElement('p');
    description.textContent = `${action.origin} requests a new vault named “${action.name}” on regtest.`;
    const approve = document.createElement('button');
    approve.type = 'button';
    approve.textContent = 'Create this vault';
    approve.addEventListener('click', async () => {
      approve.disabled = true;
      try {
        const result = await api('session/action-approve', {action: action.action});
        selectVault(result.created);
        message('Vault draft created. Continue setup and invites in this signer window.');
        await refresh();
      } catch (error) { message(error.message, true); approve.disabled = false; }
    });
    const reject = document.createElement('button');
    reject.type = 'button';
    reject.className = 'secondary';
    reject.textContent = 'Reject';
    reject.addEventListener('click', async () => {
      try { await api('session/action-reject', {action: action.action}); await refresh(); }
      catch (error) { message(error.message, true); }
    });
    item.append(description, approve, reject);
    actionList.append(item);
  }
  actionsSection.hidden = !actions.length;
}
async function refresh() {
  try {
    const state = await api('status' + (selectedVault ? `?vault=${encodeURIComponent(selectedVault)}` : ''));
    if (state.phase === 'new_profile' || state.phase === 'locked') selectedVault = null;
    for (const id of ['new-profile', 'locked', 'home', 'invites', 'connect-account', 'setup', 'backup', 'waiting', 'active']) $(id).hidden = true;
    $('back').hidden = !selectedVault;
    $('lock').hidden = !state.profile && state.phase !== 'home';
    $('title').textContent = state.name || state.profile?.name || 'Your wallet';
    $('subtitle').textContent = selectedVault ? `Member ${state.slot} · 2 of 3 · regtest` : 'One local profile, separate keys for each vault.';
    $('linked-account').hidden = !state.account_ak;
    if (state.account_ak) $('linked-account').textContent = `Proved Orchard account key: ${state.account_ak.slice(0, 16)}…`;
    if (state.phase === 'new_profile') $('new-profile').hidden = false;
    else if (state.phase === 'locked') $('locked').hidden = false;
    else if (state.phase === 'home') {
      $('home').hidden = false;
      vaultList(state.vaults);
    } else {
      $('connect-account').hidden = state.account_linked;
      if (state.invites) {
        $('invite2').textContent = state.invites[0];
        $('invite3').textContent = state.invites[1];
        $('invites').hidden = state.phase === 'active';
      }
      if (state.phase === 'waiting_for_members') {
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
    }
    if (state.error) message(state.error, true);
    await refreshSignerRequests(!!state.profile);
  } catch (error) { message(error.message, true); }
}
action('profile-create', async (form) => { await api('profile-create', fields(form)); message('Profile created. You can now create or join vaults.'); });
action('unlock', async (form) => { await api('unlock', fields(form)); message('Profile unlocked.'); });
action('create', async (form) => {
  const value = await api('create', fields(form));
  selectVault(value.vault);
  message('Vault draft created. Invite the other two members.');
});
action('join', async (form) => {
  const value = await api('join', fields(form));
  selectVault(value.vault);
  message('Joined. Waiting for the other members.');
});
function challengeDownload() {
  const link = document.createElement('a');
  link.href = URL.createObjectURL(new Blob([JSON.stringify(linkChallenge)], {type: 'application/json'}));
  link.download = 'loki-account-challenge.json';
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}
$('begin-link').addEventListener('click', async () => {
  try {
    linkChallenge = await api('begin-link', {vault: selectedVault});
    $('link-challenge').textContent = JSON.stringify(linkChallenge, null, 2);
    $('link-challenge').hidden = false;
    $('download-challenge').hidden = false;
    message('Challenge ready. Download it and sign it with the separate reference wallet command.');
  } catch (error) { message(error.message, true); }
});
$('download-challenge').addEventListener('click', challengeDownload);
action('link-account', async (form) => {
  const proof = JSON.parse(fields(form).proof);
  const result = await api('link', {vault: selectedVault, proof});
  message(`Account proof verified: ${result.account_ak}. You can continue vault setup.`);
});
action('agree', async (form) => { await api('agree', {vault: selectedVault, ...fields(form)}); message('Key creation started. Each member must compare and confirm the roster.'); });
action('make-backup', async () => {
  const result = await api('backup', {vault: selectedVault});
  $('words').textContent = result.words;
  $('backup-made').hidden = false;
  message('Save both artifacts, then load them back below.');
});
$('download').addEventListener('click', async () => {
  try {
    const result = await api(`card?vault=${encodeURIComponent(selectedVault)}`);
    const bytes = Uint8Array.from(atob(result.card), c => c.charCodeAt(0));
    const link = document.createElement('a');
    link.href = URL.createObjectURL(new Blob([bytes], {type: 'application/octet-stream'}));
    link.download = 'loki-vault.card';
    link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  } catch (error) { message(error.message, true); }
});
action('check-backup', async (form) => {
  const value = fields(form);
  const bytes = new Uint8Array(await value.card.arrayBuffer());
  if (bytes.length > 65536) throw new Error('Backup card is too large');
  let raw = ''; for (const byte of bytes) raw += String.fromCharCode(byte);
  await api('verify', {vault: selectedVault, words: value.words, card: btoa(raw)});
  $('words').textContent = '';
  $('backup-made').hidden = true;
  message('Your backup checked. Waiting for the other members.');
});
action('activate', async () => {
  const value = await api('activate', {vault: selectedVault});
  $('address').textContent = value.address;
  message('All three backups checked. Vault active on regtest.');
});
action('show-address', async () => {
  const value = await api('activate', {vault: selectedVault});
  $('address').textContent = value.address;
});
$('refresh-balance').addEventListener('click', async () => {
  const button = $('refresh-balance');
  button.disabled = true;
  try {
    const value = await api('balance', {vault: selectedVault});
    const zat = BigInt(value.balance_zat);
    const amount = `${zat / 100000000n}.${(zat % 100000000n).toString().padStart(8, '0')}`;
    $('balance').textContent = `${amount} ZEC · ${value.unspent_notes} unspent notes · block ${value.height}`;
  } catch (error) { message(error.message, true); }
  finally { button.disabled = false; }
});
$('back').addEventListener('click', () => { selectVault(null); refresh(); });
$('lock').addEventListener('click', async () => {
  try { await api('lock', {}); selectVault(null); await refresh(); }
  catch (error) { message(error.message, true); }
});
refresh(); setInterval(refresh, 2000);
