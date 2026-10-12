'use strict';
const signer = document.body.dataset.signerOrigin;
const $ = (id) => document.getElementById(id);
let session = sessionStorage.getItem('lokiSignerSession');

function message(text, error = false) {
  $('message').textContent = text;
  $('message').hidden = !text;
  $('message').classList.toggle('error', error);
}

async function call(path, body, key = session) {
  const response = await fetch(`${signer}/api/session/${path}`, {
    method: body === undefined ? 'GET' : 'POST',
    headers: {...(body === undefined ? {} : {'Content-Type': 'application/json'}),
              ...(key ? {'X-Loki-Session': key} : {})},
    body: body === undefined ? undefined : JSON.stringify(body),
    cache: 'no-store',
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Signer request failed');
  return result;
}

async function refresh() {
  if (!session) {
    $('connect').hidden = false;
    $('vaults').hidden = true;
    $('create-vault-card').hidden = true;
    $('disconnect').hidden = true;
    return;
  }
  try {
    const result = await call('vaults');
    $('connect').hidden = true;
    $('vaults').hidden = false;
    $('create-vault-card').hidden = false;
    $('disconnect').hidden = false;
    $('profile-name').textContent = `${result.profile}'s vaults`;
    const list = $('vault-list');
    list.replaceChildren();
    if (!result.vaults.length) list.textContent = 'No vaults yet. Create or join one in your signer window.';
    for (const vault of result.vaults) {
      const item = document.createElement('p');
      item.textContent = `${vault.name} · member ${vault.slot} · ${vault.phase.replaceAll('_', ' ')}`;
      list.append(item);
    }
  } catch (error) {
    if (error.message === 'Connect your signer') {
      session = null;
      sessionStorage.removeItem('lokiSignerSession');
      await refresh();
    }
    message(error.message, true);
  }
}

$('connect-button').addEventListener('click', async () => {
  $('connect-button').disabled = true;
  try {
    const request = (await call('request', {}, null)).request;
    message(`Approve the request for ${location.origin} in your separate Loki signer window.`);
    for (let i = 0; i < 300; i++) {
      await new Promise(resolve => setTimeout(resolve, 1000));
      const {state} = await call('poll', {request}, null);
      if (state === 'approved') {
        session = request;
        sessionStorage.setItem('lokiSignerSession', session);
        message('Signer connected for vault status.');
        await refresh();
        return;
      }
      if (state !== 'pending') throw new Error(`Connection ${state}. Try again.`);
    }
    throw new Error('Connection request expired. Try again.');
  } catch (error) { message(error.message, true); }
  finally { $('connect-button').disabled = false; }
});

$('disconnect').addEventListener('click', async () => {
  try {
    await call('disconnect', {});
    session = null;
    sessionStorage.removeItem('lokiSignerSession');
    message('Disconnected. Your vault membership and signer keys remain on this device.');
    await refresh();
  } catch (error) { message(error.message, true); }
});

$('create-vault').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = event.target.querySelector('button');
  button.disabled = true;
  try {
    const name = new FormData(event.target).get('name');
    const members = Number(new FormData(event.target).get('members'));
    const {action} = await call('action', {kind: 'create', name, members});
    message(`Approve creation of the 2-of-${members} “${name}” vault in your signer window.`);
    for (let i = 0; i < 300; i++) {
      await new Promise(resolve => setTimeout(resolve, 1000));
      const result = await call('action-poll', {action});
      if (result.state === 'done') {
        message('Vault draft created. Continue invites and setup in your signer window.');
        event.target.reset();
        await refresh();
        return;
      }
      if (result.state !== 'pending' && result.state !== 'executing')
        throw new Error(result.error || `Vault request ${result.state}.`);
    }
    throw new Error('Vault request expired. Try again.');
  } catch (error) { message(error.message, true); }
  finally { button.disabled = false; }
});

refresh();
setInterval(() => { if (session) refresh(); }, 5000);
