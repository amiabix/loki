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
    $('relay-network').hidden = true;
    $('vaults').hidden = true;
    $('create-vault-card').hidden = true;
    $('disconnect').hidden = true;
    return;
  }
  try {
    const result = await call('vaults');
    $('dashboard-network').textContent = `Vault dashboard · ${result.network === 'testnet' ? 'Testnet' : 'Regtest'}`;
    $('funding-note').textContent = result.network === 'testnet'
      ? 'Fund a Testnet vault from a wallet that can send to the Ironwood pool. Refresh its balance in the signer.'
      : 'Fund Vault adds 5 local test ZEC after the final backup is checked.';
    $('connect').hidden = true;
    $('vaults').hidden = false;
    $('create-vault-card').hidden = false;
    $('disconnect').hidden = false;
    $('relay-network').hidden = false;
    $('setup-relays').hidden = result.relay_network?.transport === 'hosted';
    $('relay-network-mode').textContent = result.relay_network?.transport === 'hosted' ? 'Hosted vaults connect automatically while their signers are unlocked.' : 'One setup connects all eligible vaults in this local environment. Other members connect automatically when they unlock their signers.';
    $('setup-relays').textContent = result.relay_network?.enabled ? 'Retry connections' : 'Set up relays';
    $('setup-relays').disabled = relayPending;
    $('relay-network-detail').textContent = relayPending ? 'Starting local relays and connecting eligible vaults…' : result.relay_network?.detail || '';
    $('profile-name').textContent = `${result.profile}'s vaults`;
    const list = $('vault-list');
    list.replaceChildren();
    if (!result.vaults.length) list.textContent = 'No vaults yet. Create or join one in your signer window.';
    for (const vault of result.vaults) {
      const item = document.createElement('div');
      item.className = 'vault-item';
      const name = document.createElement('p');
      name.textContent = `${vault.name} · 2 of ${vault.total_members || 3} · member ${vault.slot} · ${vault.phase.replaceAll('_', ' ')} · ${vault.network || result.network}`;
      const fund = document.createElement('button');
      fund.type = 'button';
      fund.className = 'secondary';
      const funding = vault.funding || {};
      const busy = fundingRequests.has(vault.vault);
      const storageKey = `lokiFundingRequest:${vault.vault}`;
      if (!busy && funding.phase === 'confirmed' && funding.request_id === sessionStorage.getItem(storageKey))
        sessionStorage.removeItem(storageKey);
      fund.textContent = busy ? 'Funding…' : ['failed', 'pending'].includes(funding.phase) ? 'Retry funding' : 'Fund Vault';
      fund.setAttribute('aria-label', `${fund.textContent} for ${vault.name}`);
      fund.title = 'Add 5 local test ZEC to this vault';
      fund.hidden = vault.transport === 'hosted' || vault.network === 'testnet';
      fund.disabled = !funding.available || busy;
      fund.addEventListener('click', () => fundVault(vault));
      const relay = vault.relay_setup || {};
      const detail = document.createElement('small');
      detail.className = 'relay-detail';
      detail.setAttribute('role', 'status');
      detail.textContent = vault.error || (vault.missing_slots?.length && vault.handoff !== 'ready' ? `Waiting for members ${vault.missing_slots.join(', ')}. ` : '') + (relay.detail || '');
      const funded = document.createElement('small');
      funded.className = 'relay-detail';
      funded.setAttribute('role', 'status');
      funded.textContent = busy ? 'Sending 5 test ZEC; waiting for confirmation.' : funding.detail || '';
      funded.hidden = !funded.textContent;
      item.append(name, fund, detail, funded);
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

const fundingRequests = new Map();
async function fundVault(vault) {
  if (fundingRequests.has(vault.vault)) return;
  const storageKey = `lokiFundingRequest:${vault.vault}`;
  const requestId = sessionStorage.getItem(storageKey)
    || (['pending', 'failed'].includes(vault.funding?.phase) && vault.funding.request_id)
    || crypto.randomUUID().replaceAll('-', '');
  sessionStorage.setItem(storageKey, requestId);
  fundingRequests.set(vault.vault, requestId);
  try {
    await refresh();
    const result = await call('fund', {vault: vault.vault, request_id: requestId});
    if (result.status !== 'confirmed' || result.amount_zatoshi !== 500000000)
      throw new Error('Funding is not confirmed yet. Retry funding to check the same request.');
    sessionStorage.removeItem(storageKey);
    message(`Funded “${vault.name}” with 5 local test ZEC. Open the vault in your signer and refresh its balance.`);
  } catch (error) { message(error.message, true); }
  finally { fundingRequests.delete(vault.vault); await refresh(); }
}

let relayPending = false;
async function requestRelaySetup() {
  if (relayPending) return;
  relayPending = true;
  $('setup-relays').disabled = true;
  try {
    message('Starting local relays and connecting eligible vaults…');
    await refresh();
    await call('relay-setup-all', {});
    message('Local relays are running. All eligible vaults connect automatically as their signers unlock.');
  } catch (error) { message(error.message, true); }
  finally { relayPending = false; await refresh(); }
}

$('setup-relays').addEventListener('click', requestRelaySetup);

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
    const [threshold, members] = new FormData(event.target).get('policy').split('-of-').map(Number);
    const {action} = await call('action', {kind: 'create', name, members, threshold});
    message(`Approve creation of the ${threshold}-of-${members} “${name}” vault in your signer window.`);
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
