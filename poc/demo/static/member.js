'use strict';

const token = decodeURIComponent(location.hash.slice(1));
const $ = (id) => document.getElementById(id);
const make = (tag, className, content) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (content !== undefined) node.textContent = content;
  return node;
};
const zec = (zat) => `${(zat / 1e8).toLocaleString(undefined, {maximumFractionDigits: 8})} ZEC`;
const short = (value) => value && value.length > 35 ? `${value.slice(0, 20)}…${value.slice(-12)}` : value;

let state = null;
let activeView = 'overview';
let requestPending = false;
let defaultRecipient = null;

function show(view) {
  activeView = view;
  for (const section of document.querySelectorAll('.view')) section.classList.toggle('active', section.id === view);
  for (const button of document.querySelectorAll('.nav-item')) button.classList.toggle('active', button.dataset.view === view);
  $('page-title').textContent = {
    overview: 'Overview', queue: 'Transaction queue', history: 'History', relay: 'Relay network',
  }[view];
  if (view === 'relay' && typeof refreshRelay === 'function') refreshRelay();
}

function memberRole() {
  return state ? state.role : null;
}

function demoState() {
  return state;
}

function notice(message, error = false) {
  const target = $(error ? 'error' : 'info');
  target.textContent = message;
  target.hidden = !message;
  if (message) $(error ? 'info' : 'error').hidden = true;
}

async function api(path, body) {
  const response = await fetch(path, {
    method: body === undefined ? 'GET' : 'POST',
    headers: {'X-Loki-Token': token, ...(body === undefined ? {} : {'Content-Type': 'application/json'})},
    ...(body === undefined ? {} : {body: JSON.stringify(body)}),
    cache: 'no-store',
  });
  const value = await response.json();
  if (!response.ok) throw new Error(value.error || `Server returned ${response.status}`);
  return value;
}

async function act(path, body) {
  if (requestPending) return;
  requestPending = true;
  try {
    await api(path, body);
    notice('Action received. The page will update as the transaction progresses.');
    await refresh();
  } catch (error) {
    notice(error.message, true);
  } finally {
    requestPending = false;
  }
}

function detail(label, value) {
  const row = make('div', 'detail');
  row.append(make('span', '', label), make('strong', '', value));
  return row;
}

function render() {
  if (!state) return;
  const s = state;
  const payment = s.payment;
  const approved = s.approvals_count;
  const roleName = {alice: 'Alice · member 1', bob: 'Bob · member 2', carol: 'Carol · member 3'}[s.role];
  $('side-role').textContent = roleName;
  $('threshold-value').textContent = `${approved} / 2`;
  $('approval-total').textContent = `${approved} of 2`;
  $('queue-count').textContent = payment && s.phase !== 'confirmed' ? '1' : '0';
  $('source-address').textContent = s.vaults?.source || 'Not created yet';
  $('source-address').title = s.vaults?.source || '';
  $('network-badge').textContent = s.network?.chain_running ? `Test network · block ${s.network.tip}` : 'Test network offline';
  $('network-badge').classList.toggle('live', !!s.network?.chain_running);

  const phases = {
    idle: ['Vault not created', 'Any member can start the vault.'],
    creating_vault: ['Creating vault', 'Three local member stores and an independent recipient are being created.'],
    vault_ready: ['Vault created', 'Add test funds to start making payments.'],
    funding: ['Funding vault', 'Waiting for the test chain to fund the source vault.'],
    funded: ['Vault funded', 'Any member can propose a payment.'],
    preparing_payment: ['Preparing payment', 'Building the candidate and publishing it to the local relays.'],
    waiting_for_reviews: ['Waiting for approvals', 'The selected members check and approve in their own windows.'],
    ready_to_send: ['Ready to send', 'Two verified approvals are stored by the relays. Any member can send.'],
    sending: ['Proving and sending', 'The transaction is being proved and broadcast.'],
    broadcast: ['Broadcast', 'Waiting for the local chain to mine and verify it.'],
    confirmed: ['Confirmed', 'The payment was verified on chain.'],
    declined: ['Declined', 'A member declined. Reset to create a fresh attempt.'],
    failed: ['Stopped', s.error || 'Reset to start a fresh attempt.'],
    interrupted: ['Interrupted', 'The server restarted during an attempt. Reset to create fresh signing material.'],
  };
  const phase = phases[s.phase] || [s.phase, ''];
  $('phase-label').textContent = phase[0];
  $('phase-help').textContent = phase[1];
  if (s.error) notice(s.error, true);

  $('intro-title').textContent = `${s.role[0].toUpperCase() + s.role.slice(1)}'s vault`;
  $('intro-copy').textContent = 'Start a vault, propose a payment, review one assigned to you, or send one with two approvals.';
  $('create-panel').hidden = s.phase !== 'idle';
  $('fund-panel').hidden = s.phase !== 'vault_ready';
  $('start-panel').hidden = s.phase !== 'funded';
  if (s.vaults?.recipient && s.vaults.recipient !== defaultRecipient) {
    if (!$('recipient').value || $('recipient').value === defaultRecipient) $('recipient').value = s.vaults.recipient;
    defaultRecipient = s.vaults.recipient;
  }

  const pending = payment && s.phase !== 'confirmed';
  $('queue-empty').hidden = !!pending;
  $('payment-card').hidden = !pending;
  if (payment) {
    $('payment-amount').textContent = zec(payment.amount_zat);
    $('payment-recipient').textContent = `To ${short(payment.recipient)}`;
    $('payment-recipient').title = payment.recipient;
    $('payment-status').textContent = s.phase === 'ready_to_send' ? 'Ready to send' :
      s.phase === 'broadcast' ? 'Broadcast' : s.phase === 'sending' ? 'Sending' :
      s.phase === 'declined' ? 'Declined' : s.phase === 'failed' ? 'Stopped' : 'Awaiting approvals';
    $('payment-status').classList.toggle('success', s.phase === 'ready_to_send');
    $('payment-details').replaceChildren(
      detail('Memo', payment.memo), detail('Network fee', `${payment.fee_zat.toLocaleString()} zat`),
      detail('Change to vault', zec(payment.change_zat)), detail('Expires at block', `${payment.expiry_height}`),
      detail('Payment ID', short(payment.id)),
      detail('Selected approvers', payment.pair.map(name => name[0].toUpperCase() + name.slice(1)).join(' + ')),
    );
    $('approval-heading').textContent = 'Your approval';
    const box = $('approvals'); box.replaceChildren();
    const row = make('div', 'approval-row');
    row.append(make('span', 'avatar', s.role[0].toUpperCase()), make('strong', '', s.role[0].toUpperCase() + s.role.slice(1)));
    const status = s.own_status;
    row.append(make('span', status === 'approved' ? 'approved' : '', {
      not_requested: 'Not selected for this payment', waiting: 'Waiting for review',
      reviewing: 'Needs confirmation', signing: 'Signing', approved: 'Approved',
      delivery_pending: 'Relay delivery pending', declined: 'Declined', failed: 'Failed',
    }[status] || status));
    box.append(row);
    const reviewReady = s.own_status === 'reviewing' && s.review;
    $('review-panel').hidden = !reviewReady;
    $('retry-panel').hidden = s.own_status !== 'delivery_pending';
    if (reviewReady) {
      const lines = $('review-lines'); lines.replaceChildren();
      for (const line of s.review.split('\n')) lines.append(make('div', '', line));
    }
    $('finish-panel').hidden = s.phase !== 'ready_to_send';
  }
  $('history-empty').hidden = s.phase === 'confirmed';
  $('history-item').hidden = s.phase !== 'confirmed';
  $('history-amount').textContent = payment ? `${zec(payment.amount_zat)} sent` : 'Payment confirmed';
  $('history-recipient').textContent = payment ? `To ${payment.recipient}` : '';
  $('history-memo').textContent = payment ? `Memo: ${payment.memo} · Fee: ${payment.fee_zat.toLocaleString()} zat` : '';
  $('history-txid').textContent = s.txid || '';
  $('history-evidence').textContent = payment?.recipient_verified
    ? 'Source and recipient vaults verified this payment.' : 'The source vault verified this payment on chain.';
  $('reset').hidden = (s.role !== s.creator && s.phase !== 'interrupted') || s.phase === 'idle' ||
    ['creating_vault', 'funding', 'preparing_payment', 'sending', 'broadcast'].includes(s.phase);
}

async function refresh() {
  if (!token) { notice('Open your member link printed by the local server.', true); return; }
  try {
    const firstLoad = !state;
    const hadPayment = !!state?.payment;
    const wasConfirmed = state?.phase === 'confirmed';
    state = await api('/api/state');
    render();
    if (activeView === 'relay' && typeof refreshRelay === 'function') await refreshRelay();
    if (state.phase === 'confirmed' && !wasConfirmed && activeView === 'queue') show('history');
    else if (state.payment && (firstLoad || !hadPayment))
      show(state.phase === 'confirmed' ? 'history' : 'queue');
  } catch (error) {
    notice(error.message, true);
  }
}

for (const button of document.querySelectorAll('.nav-item')) button.addEventListener('click', () => show(button.dataset.view));
$('create-vault').addEventListener('click', () => act('/api/create-vault', {}));
$('fund').addEventListener('click', () => act('/api/fund', {}));
$('start-form').addEventListener('submit', (event) => {
  event.preventDefault();
  const raw = $('amount').value;
  if (!/^\d+(?:\.\d{1,8})?$/.test(raw)) { notice('Enter an amount with at most 8 decimal places.', true); return; }
  const [whole, fraction = ''] = raw.split('.');
  const amount = Number(whole) * 100_000_000 + Number(fraction.padEnd(8, '0'));
  act('/api/propose', {amount_zat: amount, memo: $('memo').value,
                       pair: $('pair').value, recipient: $('recipient').value.trim()});
});
$('approve').addEventListener('click', () => act('/api/decide', {action: 'approve'}));
$('decline').addEventListener('click', () => act('/api/decide', {action: 'decline'}));
$('retry').addEventListener('click', () => act('/api/decide', {action: 'retry'}));
$('finish').addEventListener('click', () => act('/api/finish', {}));
$('reset').addEventListener('click', () => act('/api/reset', {}));
refresh();
setInterval(refresh, 1500);
