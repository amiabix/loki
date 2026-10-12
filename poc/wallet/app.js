'use strict';
const token = location.hash.slice(1);
const $ = (id) => document.getElementById(id);
let selectedVault = null;
let linkChallenge = null;
let memberSlot = null;
let renderedPaymentVault = null;
const paymentReviews = new Map();

function selectVault(vault) {
  selectedVault = vault;
  linkChallenge = null;
  memberSlot = null;
  renderedPaymentVault = null;
  paymentReviews.clear();
  $('address').textContent = 'Open this vault to view the address.';
  $('balance').textContent = "Scan this device's chain view to see the balance.";
  $('words').textContent = '';
  $('backup-made').hidden = true;
  $('download-final').hidden = true;
  $('draft-result').hidden = true;
  $('payment-draft').reset();
  $('payment-list').replaceChildren();
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
async function cardBase64(file) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (bytes.length > 65536) throw new Error('Backup card is too large');
  let raw = ''; for (const byte of bytes) raw += String.fromCharCode(byte);
  return btoa(raw);
}
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
function paymentButton(label, run) {
  const button = document.createElement('button');
  button.type = 'button';
  button.textContent = label;
  button.addEventListener('click', async () => {
    button.disabled = true;
    try {
      const result = await run();
      message(result?.phase ? `Payment: ${result.phase.replaceAll('_', ' ')}.` : 'Payment updated.');
      await refreshPayments();
    } catch (error) { message(error.message, true); }
    finally { button.disabled = false; }
  });
  return button;
}
async function refreshPayments() {
  if (!selectedVault) return;
  const vault = selectedVault;
  const {payments} = await api(`payments?vault=${encodeURIComponent(vault)}`);
  if (selectedVault !== vault) return;
  renderedPaymentVault = vault;
  const list = $('payment-list');
  list.replaceChildren();
  if (!payments.length) { list.textContent = 'No payments in this member’s app.'; return; }
  for (const payment of payments) {
    const card = document.createElement('section');
    card.className = 'card';
    const title = document.createElement('h3');
    title.textContent = `Payment ${payment.payment?.slice(0, 12) || payment.attempt.slice(0, 12)}…`;
    const status = document.createElement('p');
    status.textContent = `This device: ${payment.phase.replaceAll('_', ' ')} · selected signers: members ${payment.pair.join(' and ')}`;
    card.append(title, status);
    const request = (path, extra = {}) => api(path, {vault, attempt: payment.attempt, ...extra});
    const isSigner = payment.pair.includes(memberSlot);
    if (payment.phase === 'draft') card.append(paymentButton('Send proposal to members', () => request('payment-publish')));
    if (isSigner && ['published', 'received'].includes(payment.phase)) {
      card.append(paymentButton('Publish signing commitment', () => request('payment-commit')));
    }
    if (memberSlot === payment.pair[0] && payment.phase === 'commitments') {
      card.append(paymentButton('Build transaction package', () => request('payment-package')));
    }
    if (isSigner && ['commitments', 'package'].includes(payment.phase)) {
      card.append(paymentButton('Review exact transaction', async () => {
        const review = await request('payment-review');
        paymentReviews.set(payment.attempt, review);
        return {phase: 'reviewed'};
      }));
    }
    const review = paymentReviews.get(payment.attempt);
    if (isSigner && review) {
      const summary = document.createElement('pre');
      summary.textContent = `Recipient: ${review.recipient}\nAmount: ${review.amount_zat} zat\nMemo: ${review.memo_utf8 == null ? 'Cannot display memo bytes' : JSON.stringify(review.memo_utf8)}\nNetwork fee: ${review.fee_zat} zat\nChange to vault: ${review.change_zat} zat\nExpires at block: ${review.expiry_height}`;
      card.append(summary);
      if (review.memo_utf8 !== null && review.memo_utf8 !== undefined) {
        card.append(paymentButton('Approve this exact transaction', async () => {
          const result = await request('payment-approve', {review_token: review.review_token});
          paymentReviews.delete(payment.attempt);
          return result;
        }));
      }
    }
    if (isSigner && payment.phase === 'approval_pending_delivery') {
      card.append(paymentButton('Retry saved signing messages', () => request('payment-resend')));
    }
    if (['published', 'received', 'commitments', 'package', 'approval_pending_delivery'].includes(payment.phase)) {
      card.append(paymentButton('Try to finish (waits for two shares)', () => request('payment-finish')));
    }
    if (payment.phase === 'broadcast' || payment.phase === 'confirmation_needs_recheck') {
      const form = document.createElement('form');
      const label = document.createElement('label');
      label.textContent = 'Broadcast transaction ID';
      const input = document.createElement('input');
      input.name = 'txid';
      input.value = payment.txid || '';
      input.pattern = '[0-9a-f]{64}';
      input.required = true;
      const button = document.createElement('button');
      button.textContent = 'Check on chain';
      label.append(input);
      form.append(label, button);
      form.addEventListener('submit', async (event) => {
        event.preventDefault();
        button.disabled = true;
        try {
          const result = await request('payment-verify', {txid: input.value});
          message(`Confirmed on this device with ${result.confirmations} confirmation(s).`);
          await refreshPayments();
        } catch (error) { message(error.message, true); }
        finally { button.disabled = false; }
      });
      card.append(form);
    }
    list.append(card);
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
    description.textContent = `${action.origin} requests a 2-of-${action.members} vault named “${action.name}” on regtest.`;
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
    if ((state.phase === 'new_profile' || state.phase === 'locked') && selectedVault) selectVault(null);
    for (const id of ['new-profile', 'locked', 'home', 'invites', 'connect-account', 'setup', 'backup', 'waiting', 'final-backup', 'active']) $(id).hidden = true;
    $('back').hidden = !selectedVault;
    $('lock').hidden = !state.profile && state.phase !== 'home';
    $('title').textContent = state.name || state.profile?.name || 'Your signer';
    $('subtitle').textContent = selectedVault ? `Member ${state.slot} · ${state.threshold} of ${state.total_members} · regtest` : 'One local profile, separate keys for each vault.';
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
        $('invite4-row').hidden = state.total_members !== 4;
        if (state.total_members === 4) $('invite4').textContent = state.invites[2];
        $('invites').hidden = state.phase === 'active';
      }
      if (state.phase === 'waiting_for_members') {
        $('setup').hidden = false;
        $('progress').textContent = `${state.members} of ${state.total_members} members have joined. Waiting for the other members.`;
        $('agree').hidden = true;
        $('fingerprint').textContent = 'Available when all members join';
      } else if (state.phase === 'compare_roster' || state.phase === 'creating_keys') {
        $('setup').hidden = false;
        $('agree').hidden = state.phase === 'creating_keys';
        $('progress').textContent = state.phase === 'creating_keys' ? 'Creating group keys with the other member apps…' : 'All members joined.';
        $('fingerprint').textContent = state.fingerprint;
      } else if (state.phase === 'back_up') $('backup').hidden = false;
      else if (state.phase === 'waiting_for_backups') $('waiting').hidden = false;
      else if (state.phase === 'final_backup') $('final-backup').hidden = false;
      else if (state.phase === 'active') {
        $('active').hidden = false;
        memberSlot = state.slot;
        const paymentAvailable = state.total_members === 3;
        $('payment-unavailable').hidden = paymentAvailable;
        $('payment-draft').hidden = !paymentAvailable;
        $('refresh-payments').hidden = !paymentAvailable;
        $('payment-list').hidden = !paymentAvailable;
        for (const option of $('payment-draft').elements.pair.options) {
          option.disabled = state.total_members === 3 && option.value.includes('D');
        }
        if (paymentAvailable && renderedPaymentVault !== selectedVault) await refreshPayments();
      }
      else if (state.phase === 'stopped') message('Setup stopped: ' + state.error + '. Start a fresh vault session.', true);
    }
    if (state.error) message(state.error, true);
    else if (state.account_link_error) message(`${state.account_link_error}. Vault keys are unaffected.`, true);
    await refreshSignerRequests(!!state.profile);
  } catch (error) { message(error.message, true); }
}
action('profile-create', async (form) => { await api('profile-create', fields(form)); message('Profile created. You can now create or join vaults.'); });
action('unlock', async (form) => { await api('unlock', fields(form)); message('Profile unlocked.'); });
action('create', async (form) => {
  const inputs = fields(form);
  const value = await api('create', {...inputs, members: Number(inputs.members)});
  selectVault(value.vault);
  message(`Vault draft created. Invite the other ${inputs.members - 1} members.`);
});
action('join', async (form) => {
  const value = await api('join', fields(form));
  selectVault(value.vault);
  message('Joined. Waiting for the other members.');
});
action('restore-vault', async (form) => {
  const value = fields(form);
  const result = await api('restore-vault', {name: value.name, words: value.words,
                                           card: await cardBase64(value.card)});
  selectVault(result.vault);
  message(`Restored member ${result.slot}. Check your vault address before receiving funds.`);
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
  message(`Optional account link saved: ${result.account_ak}. Vault signing still uses your Loki share.`);
});
action('agree', async (form) => { await api('agree', {vault: selectedVault, ...fields(form)}); message('Key creation started. Each member must compare and confirm the roster.'); });
action('make-backup', async () => {
  const result = await api('backup', {vault: selectedVault});
  $('words').textContent = result.words;
  $('backup-made').hidden = false;
  message('Save the words and first card separately, then load the card back below. A final card follows after the group checks its backups.');
});
async function downloadCard(path, filename) {
  try {
    const result = await api(`${path}?vault=${encodeURIComponent(selectedVault)}`);
    const bytes = Uint8Array.from(atob(result.card), c => c.charCodeAt(0));
    const link = document.createElement('a');
    link.href = URL.createObjectURL(new Blob([bytes], {type: 'application/octet-stream'}));
    link.download = filename;
    link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  } catch (error) { message(error.message, true); }
}
$('download').addEventListener('click', () => downloadCard('card', 'loki-provisional.card'));
$('download-final').addEventListener('click', () => downloadCard('final-card', 'loki-vault.card'));
action('check-backup', async (form) => {
  const value = fields(form);
  await api('verify', {vault: selectedVault, words: value.words, card: await cardBase64(value.card)});
  $('words').textContent = '';
  $('backup-made').hidden = true;
  message('Your first card checked. Waiting for the other members before you save the final card.');
});
action('activate', async () => {
  await api('activate', {vault: selectedVault});
  message('The signed backup checks are complete. Save and check your final recovery card.');
});
action('make-final-backup', async (form) => {
  await api('finalize-backup', {vault: selectedVault, words: fields(form).words});
  $('download-final').hidden = false;
  message('Download the final card, then load the saved file to check it.');
});
action('check-final-backup', async (form) => {
  const value = fields(form);
  await api('verify-final-backup', {vault: selectedVault, words: value.words,
                                   card: await cardBase64(value.card)});
  message('Your final card checked. Ask every member to do the same before depositing.');
});
action('show-address', async () => {
  const value = await api('address', {vault: selectedVault});
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
action('payment-draft', async (form) => {
  const vault = selectedVault;
  const draft = await api('payment-draft', {vault, ...fields(form)});
  if (selectedVault !== vault) return;
  $('draft-result').textContent = `LOCAL DRAFT · no member has approved or sent this payment\nPayment ID: ${draft.payment}\nSelected pair: members ${draft.pair.join(' and ')}`;
  $('draft-result').hidden = false;
  message('Saved a local draft. Send it to the other members before collecting signing commitments.');
  await refreshPayments();
});
$('refresh-payments').addEventListener('click', async () => {
  try { await api('payment-sync', {vault: selectedVault}); await refreshPayments(); }
  catch (error) { message(error.message, true); }
});
$('back').addEventListener('click', () => { selectVault(null); refresh(); });
$('lock').addEventListener('click', async () => {
  try { await api('lock', {}); selectVault(null); await refresh(); }
  catch (error) { message(error.message, true); }
});
refresh(); setInterval(refresh, 2000);
