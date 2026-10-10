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

function show(view) {
  activeView = view;
  for (const section of document.querySelectorAll('.view')) section.classList.toggle('active', section.id === view);
  for (const button of document.querySelectorAll('.nav-item')) button.classList.toggle('active', button.dataset.view === view);
  $('page-title').textContent = {overview: 'Overview', queue: 'Transaction queue', history: 'History'}[view];
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
  const approved = Object.values(s.signers).filter((value) => value === 'approved').length;
  const roleName = {admin: 'Coordinator', alice: 'Alice · member 1', bob: 'Bob · member 2'}[s.role];
  $('side-role').textContent = roleName;
  $('threshold-value').textContent = `${approved} / 2`;
  $('approval-total').textContent = `${approved} of 2`;
  $('queue-count').textContent = payment && s.phase !== 'confirmed' ? '1' : '0';
  $('source-address').textContent = payment?.source || 'Created when the test starts';
  $('source-address').title = payment?.source || '';
  $('network-badge').textContent = s.network?.chain_running ? `Regtest · block ${s.network.tip}` : 'Regtest offline';
  $('network-badge').classList.toggle('live', !!s.network?.chain_running);

  const phases = {
    idle: ['Not started', 'Create a test payment to begin.'],
    preparing: ['Preparing vaults', 'Three separate member stores and the recipient vault are being created. This can take several minutes.'],
    waiting_for_reviews: ['Waiting for member review', 'Open Alice and Bob in separate browser sessions.'],
    ready_to_send: ['Ready to send', 'Two verified approvals are saved. Carol can finish the transaction.'],
    sending: ['Proving and sending', 'The transaction is being proved and broadcast.'],
    broadcast: ['Broadcast', 'Waiting for the local chain to mine and verify it.'],
    confirmed: ['Confirmed', 'Both vaults verified the mined payment.'],
    declined: ['Declined', 'A member declined. Reset to create a fresh attempt.'],
    failed: ['Stopped', s.error || 'Reset to start a fresh attempt.'],
    interrupted: ['Interrupted', 'The server restarted during an attempt. Reset to create fresh signing material.'],
  };
  const phase = phases[s.phase] || [s.phase, ''];
  $('phase-label').textContent = phase[0];
  $('phase-help').textContent = phase[1];
  if (s.error) notice(s.error, true);

  $('start-panel').hidden = s.role !== 'admin' || s.phase !== 'idle';
  $('links-panel').hidden = s.role !== 'admin' || !payment;
  if (s.links) {
    const box = $('member-links'); box.replaceChildren();
    for (const name of ['alice', 'bob']) {
      const row = make('div', 'link-row');
      const label = make('div');
      label.append(make('strong', '', name[0].toUpperCase() + name.slice(1)), make('small', '', ` · member ${name === 'alice' ? 1 : 2}`));
      const link = make('a', '', 'Open review');
      link.href = s.links[name]; link.target = '_blank'; link.rel = 'noreferrer';
      row.append(label, link); box.append(row);
    }
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
      detail('Payment ID', short(payment.id)), detail('Recipient vault', short(payment.recipient)),
    );
    const box = $('approvals'); box.replaceChildren();
    for (const name of ['alice', 'bob']) {
      const row = make('div', 'approval-row');
      row.append(make('span', 'avatar', name[0].toUpperCase()), make('strong', '', name[0].toUpperCase() + name.slice(1)));
      const status = s.signers[name] || 'waiting';
      row.append(make('span', status === 'approved' ? 'approved' : '', {
        waiting: 'Waiting for review', reviewing: 'Needs confirmation', signing: 'Signing',
        approved: 'Confirmed', declined: 'Declined', failed: 'Failed',
      }[status] || status));
      box.append(row);
    }
    const reviewReady = ['alice', 'bob'].includes(s.role) && s.signers[s.role] === 'reviewing' && s.review;
    $('review-panel').hidden = !reviewReady;
    if (reviewReady) {
      const lines = $('review-lines'); lines.replaceChildren();
      for (const line of s.review.split('\n')) lines.append(make('div', '', line));
    }
    $('finish-panel').hidden = s.role !== 'admin' || s.phase !== 'ready_to_send';
  }
  $('history-empty').hidden = s.phase === 'confirmed';
  $('history-item').hidden = s.phase !== 'confirmed';
  $('history-txid').textContent = s.txid || '';
  $('reset').hidden = s.role !== 'admin' || s.phase === 'idle' || ['preparing', 'sending', 'broadcast'].includes(s.phase);
}

async function refresh() {
  if (!token) { notice('Open the coordinator or member link printed by the server.', true); return; }
  try {
    const firstLoad = !state;
    state = await api('/api/state');
    render();
    if (firstLoad && state.role !== 'admin') show('queue');
  } catch (error) {
    notice(error.message, true);
  }
}

for (const button of document.querySelectorAll('.nav-item')) button.addEventListener('click', () => show(button.dataset.view));
$('start-form').addEventListener('submit', (event) => {
  event.preventDefault();
  const raw = $('amount').value;
  if (!/^\d+(?:\.\d{1,8})?$/.test(raw)) { notice('Enter an amount with at most 8 decimal places.', true); return; }
  const [whole, fraction = ''] = raw.split('.');
  const amount = Number(whole) * 100_000_000 + Number(fraction.padEnd(8, '0'));
  act('/api/start', {amount_zat: amount, memo: $('memo').value});
});
$('approve').addEventListener('click', () => act('/api/decide', {action: 'approve'}));
$('decline').addEventListener('click', () => act('/api/decide', {action: 'decline'}));
$('finish').addEventListener('click', () => act('/api/finish', {}));
$('reset').addEventListener('click', () => act('/api/reset', {}));
refresh();
setInterval(refresh, 1500);
