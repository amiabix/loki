'use strict';
const token = location.hash.slice(1);
const $ = (id) => document.getElementById(id);
const OPEN_VAULT = 'loki-open-vault';
const OPEN_ACCOUNT = 'loki-open-account';
let selectedVault;
try { selectedVault = sessionStorage.getItem(OPEN_VAULT); }
catch { selectedVault = null; }
let activeAccount = null;
let renderedAccounts = null;
let refreshVersion = 0;
let linkChallenge = null;
let memberSlot = null;
let memberCount = null;
let memberThreshold = null;
let renderedPaymentVault = null;
let paymentsLive = false;
let refreshingPayments = false;
let relaySetupPhase = null;
let currentNetwork = 'regtest';
const paymentReviews = new Map();
/* last failed review read per attempt: the 2 s list refresh retries at most every 10 s */
const reviewTried = new Map();
const REVIEW_RETRY_MS = 10000;
const paymentCards = new Map();   /* attempt → {card, sig}; rebuilt only when sig changes */

function selectVault(vault) {
  selectedVault = vault;
  try {
    if (vault) sessionStorage.setItem(OPEN_VAULT, vault);
    else sessionStorage.removeItem(OPEN_VAULT);
  } catch { /* Private browsing may disable session storage. */ }
  linkChallenge = null;
  memberSlot = null;
  memberCount = null;
  renderedPaymentVault = null;
  relaySetupPhase = null;
  paymentReviews.clear();
  reviewTried.clear();
  paymentCards.clear();
  $('address').textContent = 'Open this vault to view the address.';
  $('balance').textContent = "Scan this device's chain view to see the balance.";
  $('words').textContent = '';
  $('backup-made').hidden = true;
  $('download-final').hidden = true;
  $('draft-result').hidden = true;
  $('payment-draft').reset();
  $('amount-zat').textContent = 'Up to 8 decimal places.';
  $('payment-list').replaceChildren();
  $('payment-updates').hidden = true;
  $('payment-updates').textContent = '';
  $('relay-state').textContent = 'Relay connection has not been checked on this device.';
  $('relay-downloads').replaceChildren();
  $('link-challenge').textContent = '';
  $('link-challenge').hidden = true;
  $('download-challenge').hidden = true;
  renderedInvites = null;
}

let notice = null;
function message(text, error = false) {
  $('message').textContent = text;
  $('message').hidden = !text;
  $('message').classList.toggle('error', error);
  /* A confirmation describes what just happened; left on screen it starts
     reading as the state of the step the member is now on. Failures stay:
     they still need an answer. */
  clearTimeout(notice);
  if (text && !error) notice = setTimeout(() => message(''), 8000);
}

/* A failure belongs beside the control that caused it. The server tags each one
   with the route that raised it, so an unlock that fails lands on the unlock
   form and never reads as though the step on screen went wrong. Anything with
   no slot of its own still falls back to the page-level line. */
function clearFailures() {
  for (const slot of document.querySelectorAll('.form-error')) {
    slot.hidden = true;
    slot.textContent = '';
  }
}

function failure(error) {
  if (error.stale) return;
  clearFailures();
  const slot = error.surface && document.getElementById(`fail-${error.surface}`);
  if (!slot) { message(error.message, true); return; }
  message('');
  slot.hidden = false;
  slot.textContent = error.retry
    ? `${error.message} Nothing was changed — you can try again.`
    : error.message;
  slot.closest('form')?.querySelector('input, textarea, select')?.focus();
}
async function api(path, body) {
  if (!token) throw new Error('Open the private local app link printed by the server.');
  const version = refreshVersion;
  const response = await fetch(`/api/${path}`, {
    method: body === undefined ? 'GET' : 'POST',
    headers: {'X-Loki-Token': token, ...(body === undefined ? {} : {'Content-Type': 'application/json'})},
    body: body === undefined ? undefined : JSON.stringify(body),
    cache: 'no-store',
  });
  const result = await response.json();
  if (version !== refreshVersion && !['accounts', 'account-create', 'account-switch'].includes(path)) {
    const stale = new Error('Account changed');
    stale.stale = true;
    throw stale;
  }
  if (!response.ok) {
    const failure = new Error(result.error || 'Request failed');
    failure.surface = result.surface || '';   /* which action raised it */
    failure.retry = !!result.retry;           /* nothing is known to have failed */
    throw failure;
  }
  return result;
}
function fields(form) { return Object.fromEntries(new FormData(form)); }
async function cardBase64(file, kind = 'Backup card') {
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (bytes.length > 65536) throw new Error(`${kind} is too large`);
  let raw = ''; for (const byte of bytes) raw += String.fromCharCode(byte);
  return btoa(raw);
}
function action(id, task) {
  $(id).addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = event.target.querySelector('button');
    button.disabled = true;
    clearFailures();
    try { await task(event.target); event.target.reset(); await refresh(); }
    catch (error) { failure(error); }
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
    button.className = 'vault-row';
    const name = document.createElement('strong');
    name.className = 'vault-name';
    name.textContent = vault.name;
    const meta = document.createElement('span');
    meta.className = 'vault-meta';
    meta.textContent = `Member ${vault.slot} · ${vault.threshold ?? 2} of ${vault.members ?? 3}`;
    button.append(name, meta);
    button.addEventListener('click', () => { selectVault(vault.vault); refresh(); });
    const item = document.createElement('div');
    item.className = 'vault-item';
    const relay = vault.relay_setup || {};
    const detail = document.createElement('small');
    detail.className = 'relay-detail';
    detail.textContent = relay.detail || 'Relay connection is available after the final backup.';
    detail.setAttribute('role', 'status');
    item.append(button, detail);
    list.append(item);
  }
}

async function refreshAccounts(version) {
  const {active, accounts} = await api('accounts');
  if (version !== refreshVersion) return;
  let previous = null;
  try { previous = sessionStorage.getItem(OPEN_ACCOUNT); }
  catch { /* Private browsing may disable session storage. */ }
  if (active !== activeAccount) {
    ++refreshVersion;
    if (activeAccount !== null || previous !== active) selectVault(null);
    activeAccount = active;
    try { sessionStorage.setItem(OPEN_ACCOUNT, active); }
    catch { /* Private browsing may disable session storage. */ }
  }
  const shown = JSON.stringify([active, accounts]);
  if (shown === renderedAccounts) return refreshVersion;
  renderedAccounts = shown;
  const list = $('account-list');
  list.replaceChildren();
  for (const account of accounts) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'vault-row';
    button.textContent = account.name + (account.id === active ? ' · Active' : '');
    button.disabled = account.id === active;
    button.addEventListener('click', async () => {
      button.disabled = true;
      try {
        ++refreshVersion;
        selectVault(null);
        await api('account-switch', {account: account.id});
        await refresh();
      } catch (error) { failure(error); button.disabled = false; }
    });
    list.append(button);
  }
  return refreshVersion;
}
/* ── one payment, five stages ───────────────────────────────────────────────
   A member is told where the payment is, never which protocol call comes next.
   Every mechanical step — delivery, commit, package, resend, the on-chain
   check — is performed by the app's payment worker while the profile is
   unlocked, whether or not this page is open. The human decisions are approving
   an exact transaction that is on screen, and sending it. */

const STAGES = [
  ['Propose', 'the proposal reaches every member'],
  ['Review', 'each signer checks the exact transaction'],
  ['Approve', 'the selected members approve'],
  ['Ready to send', 'the signed transaction goes to the network'],
  ['Confirmed', 'mined on this device’s chain view'],
];

/* protocol phase → [stage, row state, what this member sees] */
const PHASES = {
  draft: [0, 'waiting', 'sending the proposal to the other members'],
  queued_for_delivery: [0, 'waiting', 'sending the proposal to the other members'],
  published: [1, 'waiting', 'waiting for the other members’ apps'],
  received: [1, 'waiting', 'preparing your signing commitment'],
  commitments: [1, 'waiting', 'building the exact transaction to check'],
  package: [1, 'waiting', 'building the exact transaction to check'],
  approval_pending_delivery: [2, 'waiting', 'delivering your approval'],
  approval_interrupted: [2, 'differs', 'your saved approval could not be reopened — retrying it'],
  approved: [2, 'waiting', 'your approval reached the relays; waiting for another member'],
  broadcast: [4, 'waiting', 'sent — waiting for a confirmation'],
  confirmation_needs_recheck: [4, 'waiting', 'checking this device’s chain view again'],
  confirmed: [4, 'agreed', 'confirmed on chain'],
};

/* Local approval still needs chain updates; only confirmed is done. */

const ZAT = 100000000n;

/* Money is parsed as a decimal string and converted with integers only. A
   float would turn 0.1 ZEC into 9999999 or 10000001 zat. */
function zatFromZec(text) {
  const value = String(text ?? '').trim();
  if (!/^[0-9]+(\.[0-9]{1,8})?$/.test(value)) {
    const error = new Error('Enter an amount in ZEC — digits, and at most 8 decimal places.');
    error.surface = 'payment-draft';
    throw error;
  }
  const [whole, fraction = ''] = value.split('.');
  const zat = BigInt(whole) * ZAT + BigInt((fraction + '00000000').slice(0, 8));
  if (zat <= 0n) {
    const error = new Error('Enter an amount greater than zero.');
    error.surface = 'payment-draft';
    throw error;
  }
  return zat.toString();
}

function zecFromZat(amount) {
  const zat = BigInt(amount);
  return `${zat / ZAT}.${(zat % ZAT).toString().padStart(8, '0')}`;
}

function amountEcho() {
  const slot = $('amount-zat');
  const raw = $('payment-draft').elements.amount_zec.value.trim();
  if (!raw) { slot.textContent = 'Up to 8 decimal places.'; return; }
  try { slot.textContent = `Sends exactly ${zatFromZec(raw)} zat.`; }
  catch (error) { slot.textContent = error.message; }
}

function paymentButton(label, run) {
  const button = document.createElement('button');
  button.type = 'button';
  button.textContent = label;
  button.addEventListener('click', async () => {
    button.disabled = true;
    button.classList.add('busy');
    try {
      await run();
      await refreshPayments();
    } catch (error) { message(error.message, true); }
    finally { button.disabled = false; button.classList.remove('busy'); }
  });
  return button;
}

function stageList(current, state, detail, threshold) {
  const list = document.createElement('div');
  list.className = 'roster';
  STAGES.forEach(([name, says], index) => {
    const row = document.createElement('div');
    row.className = 'roster-row';
    const stage = document.createElement('strong');
    stage.textContent = name;
    const says_now = document.createElement('span');
    if (index < current) { row.classList.add('agreed'); says_now.textContent = 'done'; }
    else if (index === current) { row.classList.add(state); says_now.textContent = detail; }
    else says_now.textContent = index === 2 ? `${threshold} selected members approve` : says;
    row.append(stage, says_now);
    list.append(row);
  });
  return list;
}

function note(text, className = 'muted') {
  const line = document.createElement('p');
  line.className = className;
  line.textContent = text;
  return line;
}

function buildPaymentCard(payment, vault, {current, rowState, detail, isSigner, review, readiness}) {
  const card = document.createElement('section');
  card.className = 'card';
  const title = document.createElement('h3');
  title.textContent = `Payment ${payment.payment?.slice(0, 12) || payment.attempt.slice(0, 12)}…`;
  const signers = payment.signers || payment.pair;
  card.append(title, stageList(current, rowState, detail, signers.length));
  card.append(note(`Signers: members ${signers.join(', ')}${isSigner ? ' — you are one of them' : ''}`
                   + (payment.txid ? ` · transaction ${payment.txid.slice(0, 16)}…` : '')));
  if (payment.phase === 'draft') {
    card.append(paymentButton('Send this proposal', async () => {
      await api('payment-publish', {vault, attempt: payment.attempt});
      message('Proposal sent to the other members.');
    }));
  }

  if (review) {
    const summary = document.createElement('pre');
    summary.textContent = `Recipient: ${review.recipient}\n`
      + `Amount: ${zecFromZat(review.amount_zat)} ZEC (${review.amount_zat} zat)\n`
      + `Memo: ${review.memo_utf8 == null ? 'Cannot display memo bytes' : JSON.stringify(review.memo_utf8)}\n`
      + `Network fee: ${review.fee_zat} zat\n`
      + `Change back to the vault: ${review.change_zat} zat\n`
      + `Expires at block: ${review.expiry_height}`;
    card.append(summary);
    if (review.memo_utf8 == null) card.append(note('This memo does not render as text, so this payment cannot be approved here.', 'warning'));
    else card.append(paymentButton('Approve this exact transaction', async () => {
      await api('payment-approve', {vault, attempt: payment.attempt, review_token: review.review_token});
      paymentReviews.delete(payment.attempt);
      message('Approved. Your approval is on its way to the other members.');
    }));
  }

  if (payment.ready_to_send) {
    const scanned = readiness.scan_height == null
      ? 'Payment chain scan has not run on this device yet.'
      : `Payment chain scan reached block ${readiness.scan_height}.`;
    if (readiness.relay_ready === true) {
      card.append(note(`${readiness.relay_detail || 'The relay is reachable.'} ${scanned}`));
      card.append(paymentButton('Send this payment', async () => {
        await api('payment-finish', {vault, attempt: payment.attempt});
        message('Sent. Waiting for a confirmation on this device’s chain view.');
      }));
    } else {
      card.append(note(`Cannot send yet. ${readiness.relay_detail || 'This device cannot reach the relay.'} ${scanned}`, 'warning'));
    }
  }
  return card;
}

async function refreshPayments() {
  if (!selectedVault) return;
  const vault = selectedVault;
  const state = await api(`payments?vault=${encodeURIComponent(vault)}`);
  if (selectedVault !== vault) return;
  renderedPaymentVault = vault;
  const updates = state.updates || {};
  $('payment-updates').textContent = updates.error ? `Payment updates failed: ${updates.error} Retrying automatically; Check for updates to retry now.` : '';
  $('payment-updates').hidden = !updates.error;
  const list = $('payment-list');
  if (!state.payments.length) {
    list.replaceChildren();
    paymentCards.clear();
    list.textContent = 'No payments in this member’s app.';
    return;
  }
  if (!paymentCards.size) list.replaceChildren();   /* drop the empty-state text node */
  const seen = new Set();
  for (let index = 0; index < state.payments.length; index++) {
    const payment = state.payments[index];
    const signers = payment.signers || payment.pair;
    const isSigner = signers.includes(memberSlot);
    /* the exact transaction is fetched as soon as it can be read: checking it
       is not a decision, so it is not a button */
    if (isSigner && ['commitments', 'package'].includes(payment.phase)
        && !paymentReviews.has(payment.attempt)
        && Date.now() - (reviewTried.get(payment.attempt) || 0) >= REVIEW_RETRY_MS) {
      try {
        paymentReviews.set(payment.attempt, await api('payment-review', {vault, attempt: payment.attempt}));
        reviewTried.delete(payment.attempt);
      } catch { /* the package is not readable yet; retried after REVIEW_RETRY_MS */
        reviewTried.set(payment.attempt, Date.now());
      }
      if (selectedVault !== vault) return;
    }
    const review = isSigner ? paymentReviews.get(payment.attempt) : null;
    let [current, rowState, detail] =
      PHASES[payment.phase] || [0, 'waiting', payment.phase.replaceAll('_', ' ')];
    if (review && current === 1) [current, rowState, detail] = [2, 'waiting', 'your approval is the next step'];
    if (payment.ready_to_send) [current, rowState, detail] = [3, 'agreed', `${signers.length} approvals verified; ready to send`];
    const readiness = state.readiness || {};

    const sig = JSON.stringify([current, rowState, detail, signers, isSigner,
      payment.phase, !!payment.ready_to_send, payment.payment, payment.attempt, payment.txid,
      review ? [review.recipient, review.amount_zat, review.memo_utf8, review.fee_zat,
                review.change_zat, review.expiry_height, review.review_token] : null,
      payment.ready_to_send ? [readiness.relay_ready, readiness.relay_detail, readiness.scan_height] : null]);

    let entry = paymentCards.get(payment.attempt);
    if (!entry || entry.sig !== sig) {
      entry?.card.remove();
      entry = {card: buildPaymentCard(payment, vault, {current, rowState, detail, isSigner, review, readiness}), sig};
      paymentCards.set(payment.attempt, entry);
    }
    if (list.children[index] !== entry.card) list.insertBefore(entry.card, list.children[index] || null);
    seen.add(payment.attempt);
  }
  for (const [attempt, entry] of [...paymentCards]) {
    if (!seen.has(attempt)) { entry.card.remove(); paymentCards.delete(attempt); }
  }
}

/* ── payment updates ─────────────────────────────────────────────────────────
   The page only reads: the list is cheap saved state, refreshed every 2 s while
   payments are live. "Check for updates" asks the worker for one pass now. */
async function refreshPaymentsQuietly(force = false) {
  if (refreshingPayments || (!paymentsLive && !force) || !selectedVault) return;
  refreshingPayments = true;
  try { await refreshPayments(); } catch { /* the next refresh tries again */ }
  finally { refreshingPayments = false; }
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
    const relaySetup = action.kind === 'relay-setup';
    description.textContent = relaySetup
      ? `${action.origin} requests local test relay setup for “${action.name}”. This configures only your own membership; the other members do the same in their apps.`
      : `${action.origin} requests a ${action.threshold ?? 2}-of-${action.members} vault named “${action.name}” on ${currentNetwork}.`;
    const approve = document.createElement('button');
    approve.type = 'button';
    approve.textContent = relaySetup ? 'Set up local relays' : 'Create this vault';
    approve.addEventListener('click', async () => {
      approve.disabled = true;
      try {
        const result = await api('session/action-approve', {action: action.action});
        selectVault(result.created || null);
        message(relaySetup ? 'Local relays are running. Vaults connect automatically; check progress in your vault list.'
          : 'Vault draft created. Continue setup and invites in this signer window.');
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
/* ── invitations ─────────────────────────────────────────────────────────────
   One row per other member. The state is read from the vault: Waiting until
   that member's app has published an identity, then Joined. Opening the share
   sheet is not a state of the invitation — Loki never learns whether anything
   was sent — so it is transient feedback on the control that was pressed. */

function expiryLine(at) {
  const left = at ? at * 1000 - Date.now() : 0;
  if (!at) return '';
  if (left <= 0) return 'These invites have expired.';
  const hours = Math.floor(left / 3600000);
  const minutes = Math.floor((left % 3600000) / 60000);
  const span = hours ? `${hours} h ${minutes} min` : `${minutes} min`;
  return `These invites expire in ${span}, at ${new Date(at * 1000).toLocaleString()}.`;
}

function reachLine(origin) {
  if (!origin) {
    return 'This app was started without an invite address, so these codes only work for an app '
      + "that can read this computer's setup folder.";
  }
  if (origin.startsWith('https://')) {
    return `Each member joins from their own device at ${origin}. Keep this app open until setup finishes.`;
  }
  return `Same-machine demo: another Loki app on this computer joins at ${origin}. `
    + 'A separate device needs an https address.';
}

function inviteMessage(invite, state) {
  return `Join my Loki vault \u201c${state.name}\u201d as member ${invite.slot}.\n\n`
    + 'Open your Loki signer app, choose \u201cJoin a vault\u201d and paste this invite:\n\n'
    + `${invite.code}\n\n`
    + `It is for member ${invite.slot} only, and for one app. ${expiryLine(state.invites_expire_at)}`;
}

function rowButton(label, className, run) {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = className;
  button.textContent = label;
  button.addEventListener('click', async () => {
    button.disabled = true;
    try { await run(button); } finally { button.disabled = false; }
  });
  return button;
}

function inviteRow(invite, state, expired) {
  const standing = invite.joined ? 'joined' : expired ? 'expired' : 'waiting';
  const row = document.createElement('div');
  row.className = `invite-row ${standing}`;
  const who = document.createElement('div');
  who.className = 'invite-who';
  const name = document.createElement('strong');
  name.textContent = `Member ${invite.slot}`;
  const mark = document.createElement('span');
  mark.className = `invite-state ${standing}`;
  mark.textContent = invite.joined ? 'Joined' : expired ? 'Expired' : 'Waiting';
  who.append(name, mark);
  row.append(who);
  const note = document.createElement('p');
  note.className = 'invite-note';
  note.setAttribute('role', 'status');
  note.hidden = true;
  const say = (text, bad = false) => {
    note.textContent = text;
    note.hidden = false;
    note.classList.toggle('bad', bad);
  };
  if (invite.joined) return row;
  if (expired) {
    row.append(note);
    say('Loki cannot re-issue an invite in this build. Create a new vault to invite this member.');
    return row;
  }
  const actions = document.createElement('div');
  actions.className = 'invite-actions';
  const code = document.createElement('pre');
  code.className = 'invite-code';
  code.hidden = true;
  code.textContent = invite.code;
  const copy = async (text, done) => {
    try { await navigator.clipboard.writeText(text); say(done); }
    catch { code.hidden = false; say('This browser would not let Loki use the clipboard. The code is shown below.', true); }
  };
  actions.append(rowButton('Share invite', 'primary', async () => {
    const text = inviteMessage(invite, state);
    if (!navigator.share) {
      await copy(text, 'No share sheet here, so the invitation is copied. Paste it into Signal yourself.');
      return;
    }
    try {
      await navigator.share({title: `Loki invite for member ${invite.slot}`, text});
      say(`Share sheet opened for member ${invite.slot}. Loki cannot tell whether it was sent, so this member stays Waiting until their app joins.`);
    } catch (error) {
      if (error.name === 'AbortError') { say('Share cancelled. Nothing was sent.'); return; }
      await copy(text, 'The share sheet did not open, so the invitation is copied instead.');
    }
  }));
  actions.append(rowButton('Copy code', 'secondary', () => copy(invite.code, 'Invite code copied.')));
  const show = rowButton('Show code', 'quiet', (button) => {
    code.hidden = !code.hidden;
    button.textContent = code.hidden ? 'Show code' : 'Hide code';
    button.setAttribute('aria-expanded', String(!code.hidden));
  });
  show.setAttribute('aria-expanded', 'false');
  actions.append(show);
  row.append(actions, note, code);
  return row;
}

/* The page polls every two seconds. Rebuilding these rows on every poll would
   wipe what a member was just told, close a code they opened, and could pull a
   Share button out of the document while the OS share sheet is still on it. So
   the rows are rebuilt only when the data they show changes. */
let renderedInvites = null;

function inviteRows(state) {
  const expired = !!state.invites_expire_at && state.invites_expire_at * 1000 <= Date.now();
  const shown = JSON.stringify([selectedVault, expired,
                                state.invites.map((i) => [i.slot, i.code, i.joined, i.origin])]);
  if (shown !== renderedInvites) {
    renderedInvites = shown;
    const rows = $('invite-rows');
    rows.replaceChildren();
    for (const invite of state.invites) rows.append(inviteRow(invite, state, expired));
    $('invite-reach').textContent = state.transport === 'hosted' ? 'Share each invitation privately with its member. Hosted invitations work on separate devices.' : reachLine(state.invites[0]?.origin);
  }
  $('invite-expiry').textContent = expiryLine(state.invites_expire_at);
}

function progressLine(state) {
  if (state.phase === 'waiting_for_members') {
    return `${state.members} of ${state.total_members} members have joined.`;
  }
  if (state.phase === 'compare_roster') return 'All members joined.';
  if (state.phase === 'connecting_relays') return state.missing_slots?.length ? `Waiting for member${state.missing_slots.length === 1 ? '' : 's'} ${state.missing_slots.join(', ')} to finish connecting.` : 'Connecting hosted relays automatically; saved work will retry.';
  if (state.phase === 'creating_keys' && state.setup_phase === 'acceptance_pending' && state.missing_slots?.length) return `Waiting for member${state.missing_slots.length === 1 ? '' : 's'} ${state.missing_slots.join(', ')} to confirm the roster.`;
  if (state.phase === 'creating_keys') return 'Creating group keys with the other member apps…';
  return '';
}

const steps = {
  new_profile: ['', 'Create your profile'],
  locked: ['', 'Unlock your profile'],
  home: ['', 'Your vaults'],
  waiting_for_members: ['Setup · step 2 of 6', 'Waiting for the other members'],
  compare_roster: ['Setup · step 3 of 6', 'Compare the roster fingerprint'],
  creating_keys: ['Setup · step 4 of 6', 'Creating the group keys'],
  back_up: ['Setup · step 5 of 6', 'Write down your recovery words'],
  waiting_for_backups: ['Setup · step 5 of 6', 'Waiting for the other members to check their cards'],
  final_backup: ['Setup · step 6 of 6', 'Save your final recovery card'],
  connecting_relays: ['Setup · step 6 of 6', 'Connecting payment relays'],
  active: ['', 'Receive and pay'],
  stopped: ['', 'Setup stopped'],
};
/* ── who has answered the roster ────────────────────────────────────────────
   Read from the shared courier, so every row is a claim by that member's app
   and not evidence. Agreement is a readiness signal; a disagreement is the
   thing worth drawing in red, because it is the case a human must act on. */

function rosterList(state) {
  const list = $('roster-list');
  list.replaceChildren();
  for (const entry of state.confirmations || []) {
    const row = document.createElement('div');
    row.className = 'roster-row';
    const who = document.createElement('strong');
    who.textContent = entry.slot === state.slot ? `Member ${entry.slot} · you` : `Member ${entry.slot}`;
    const said = document.createElement('span');
    if (!entry.confirmed) {
      row.classList.add('waiting');
      said.textContent = 'has not confirmed yet';
    } else if (entry.matches) {
      row.classList.add('agreed');
      said.textContent = 'confirmed the same fingerprint';
    } else {
      row.classList.add('differs');
      said.textContent = 'confirmed a DIFFERENT fingerprint — stop and compare again';
    }
    row.append(who, said);
    list.append(row);
  }
  list.hidden = !(state.confirmations || []).length;
}

function backupList(state) {
  const list = $('backup-list');
  list.replaceChildren();
  for (const entry of state.backups || []) {
    const row = document.createElement('div');
    row.className = 'roster-row';
    const who = document.createElement('strong');
    who.textContent = entry.slot === state.slot ? `Member ${entry.slot} · you` : `Member ${entry.slot}`;
    const said = document.createElement('span');
    if (state.transport === 'hosted') {
      // Hosted setups carry each member's signed backup receipt, not a final-card report.
      said.textContent = entry.backup_checked ? 'checked their backup card' : 'backup check not received yet';
      row.classList.add(entry.backup_checked ? 'agreed' : 'waiting');
      row.append(who, said);
      list.append(row);
      continue;
    }
    said.textContent = entry.reported ? 'reported checking a final card'
      : entry.invalid ? 'invalid report — check with this member' : 'no report yet';
    row.classList.add(entry.reported ? 'agreed' : entry.invalid ? 'differs' : 'waiting');
    row.append(who, said);
    list.append(row);
  }
}

async function refresh() {
  let version = refreshVersion;
  try {
    version = await refreshAccounts(version);
    if (version === undefined) return;
    let state;
    try {
      state = await api('status' + (selectedVault ? `?vault=${encodeURIComponent(selectedVault)}` : ''));
    } catch (error) {
      if (!selectedVault) throw error;
      const home = await api('status');
      if (home.vaults?.some((vault) => vault.vault === selectedVault)) throw error;
      selectVault(null);
      state = home;
    }
    if (version !== refreshVersion) return;
    if ((state.phase === 'new_profile' || state.phase === 'locked') && selectedVault) selectVault(null);
    currentNetwork = state.network || 'regtest';
    const testnet = currentNetwork === 'testnet';
    $('network-chip').textContent = testnet ? 'ZCASH TESTNET' : 'REGTEST';
    $('build-note').textContent = testnet
      ? 'Testnet research build. Use disposable test funds only. Each member needs their own app and a synced Testnet node; payments need configured relays.'
      : 'Regtest test build. No real funds. Payment delivery and signing require configured relays.';
    paymentsLive = false;
    for (const id of ['new-profile', 'locked', 'home', 'invites', 'connect-account', 'setup', 'backup', 'waiting', 'final-backup', 'backup-status', 'active', 'relay-setup']) $(id).hidden = true;
    const inVault = !!selectedVault;
    $('back').hidden = !inVault;
    $('lock').hidden = !state.profile && state.phase !== 'home';
    $('vault-chip').hidden = !inVault;
    if (inVault) $('vault-chip').textContent = `MEMBER ${state.slot}`;
    $('title').textContent = state.name || state.profile?.name || 'Your signer';
    if (state.phase === 'home') {
      $('home-relays').hidden = !state.vaults?.length;
      $('setup-relays').hidden = state.relay_network?.transport === 'hosted';
      $('setup-relays').textContent = state.relay_network?.enabled ? 'Retry connections' : 'Set up relays';
      $('relay-network-detail').textContent = state.relay_network?.detail || '';
    }
    $('subtitle').textContent = inVault
      ? `${state.threshold} of ${state.total_members} · ${testnet ? 'Testnet' : 'Regtest'}`
      : 'One local profile, separate keys for each vault.';
    $('vault-network-detail').textContent = testnet
      ? `Zcash Testnet · vault starts at block ${state.birth_height}. This chain and block are part of the roster you compare.`
      : 'Local regtest vault.';
    $('receive-note').textContent = testnet
      ? `Zcash Testnet address. Fund it from a wallet that can send to the Ironwood pool. Scan begins at block ${state.birth_height}.`
      : 'Local regtest address. Fund it from the local test faucet or another regtest wallet.';
    const [kicker, headline] = steps[state.phase] || ['', ''];
    $('kicker').textContent = kicker;
    $('kicker').hidden = !kicker;
    $('headline').textContent = headline;
    const progress = progressLine(state);
    $('progress').textContent = progress;
    $('progress').hidden = !progress;
    /* A member whose app cannot reach the creator's courier is not waiting for
       people, it is waiting for a network. Say which. */
    $('transport-note').hidden = !state.transport_error;
    if (state.transport_error) {
      $('transport-note').textContent = state.transport_error.waiting
        ? `${state.transport_error.message} ${state.phase === 'active' ? 'Backup reports update' : 'Setup continues'} once it is reachable again.`
        : state.transport_error.message;
    }
    $('linked-account').hidden = !state.account_ak;
    if (state.account_ak) $('linked-account').textContent = `Proved Orchard account key: ${state.account_ak.slice(0, 16)}…`;
    if (state.phase === 'new_profile') $('new-profile').hidden = false;
    else if (state.phase === 'locked') $('locked').hidden = false;
    else if (state.phase === 'home') {
      $('home').hidden = false;
      vaultList(state.vaults);
    } else {
      $('connect-account').hidden = testnet || state.account_linked || state.transport === 'hosted';
      if (state.invites) {
        inviteRows(state);
        $('invites').hidden = state.phase !== 'waiting_for_members';
      }
      if (state.phase === 'compare_roster' || state.phase === 'creating_keys') {
        $('setup').hidden = false;
        rosterList(state);
        $('agree').hidden = state.phase === 'creating_keys';
        $('fingerprint').textContent = state.fingerprint;
      } else if (state.phase === 'back_up') $('backup').hidden = false;
      else if (state.phase === 'waiting_for_backups') {
        $('waiting').hidden = false;
        const hosted = state.transport === 'hosted';
        const arrived = state.backup_checks_received || 0;
        $('backup-progress').textContent = hosted
          ? 'Waiting for the other members’ backup checks. Setup continues automatically.'
          : `${arrived} of ${state.total_members} backup checks have arrived.`;
        $('activate').hidden = hosted;
        $('activate').querySelector('button').disabled = arrived < state.total_members;
      }
      else if (state.phase === 'final_backup') {
        $('final-backup').hidden = false;
        $('make-final-backup').hidden = !!state.final_card_created;
        $('download-final').hidden = !state.final_card_created;
        $('final-words-fallback').hidden = !state.final_card_needs_words;
        $('final-words-fallback').querySelector('input').required = !!state.final_card_needs_words;
      }
      else if (state.phase === 'active') {
        $('active').hidden = false;
        memberSlot = state.slot;
        const paymentAvailable = [[2, 3], [2, 4], [3, 4]].some(([t, n]) => t === state.threshold && n === state.total_members)
          && (state.transport !== 'hosted' || state.handoff === 'ready');
        memberCount = state.total_members;
        memberThreshold = state.threshold;
        const signerChoices = $('payment-signers');
        if (signerChoices.dataset.policy !== `${memberThreshold}-of-${memberCount}-${memberSlot}`) {
          signerChoices.replaceChildren();
          const letters = 'ABCD'.slice(0, memberCount);
          const pick = (start, chosen) => {
            if (chosen.length === memberThreshold) {
              const option = new Option(chosen.map(c => `Member ${letters.indexOf(c) + 1}`).join(', '), chosen.join(''));
              signerChoices.add(option);
              return;
            }
            for (let i = start; i < letters.length; i++) pick(i + 1, [...chosen, letters[i]]);
          };
          pick(0, []);
          signerChoices.value = [...signerChoices.options].find(option => option.value.includes(letters[memberSlot - 1]))?.value || '';
          signerChoices.dataset.policy = `${memberThreshold}-of-${memberCount}-${memberSlot}`;
        }
        $('relay-setup').hidden = !paymentAvailable || state.transport === 'hosted';
        $('payment-unavailable').hidden = paymentAvailable;
        $('show-address').hidden = !paymentAvailable;
        if (!paymentAvailable) $('address').textContent = 'Receive address is available after payment activation.';
        $('payment-draft').hidden = !paymentAvailable;
        $('refresh-payments').hidden = !paymentAvailable;
        $('payment-list').hidden = !paymentAvailable;
        const relayPhase = state.relay_setup?.phase;
        $('relay-note').textContent = state.relay_setup?.detail || '';
        $('relay-note').hidden = !state.relay_setup;
        relaySetupPhase = relayPhase;
        paymentsLive = paymentAvailable && (!state.relay_setup || relayPhase === 'ready');
        if (paymentAvailable && renderedPaymentVault !== selectedVault) await refreshPayments();
      }
      else if (state.phase === 'stopped') message('Setup stopped: ' + state.error + '. Start a fresh vault session.', true);
      if ((state.phase === 'final_backup' || state.phase === 'active') && state.backups?.length) {
        $('backup-status').querySelector('h2').textContent = state.transport === 'hosted' ? 'Backup checks' : 'Final backup reports';
        backupList(state);
        $('backup-status').hidden = false;
      }
    }
    if (state.error) message(state.error, true);
    else if (state.account_link_error) message(`${state.account_link_error}. Vault keys are unaffected.`, true);
    await refreshSignerRequests(!!state.profile);
  } catch (error) { if (!error.stale) message(error.message, true); }
}
action('profile-create', async (form) => { await api('profile-create', fields(form)); message('Profile created. You can now create or join vaults.'); });
action('account-create', async (form) => {
  ++refreshVersion;
  selectVault(null);
  await api('account-create', fields(form));
  message('Account created. This profile has its own vaults and key store.');
});
action('unlock', async (form) => { await api('unlock', fields(form)); message('Profile unlocked.'); });
action('create', async (form) => {
  const inputs = fields(form);
  const [threshold, members] = inputs.policy.split('-of-').map(Number);
  const value = await api('create', {name: inputs.name, threshold, members});
  selectVault(value.vault);
  message(`Vault draft created. Invite the other ${members - 1} members.`);
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
  message('Write down these words, then enter them below to check your copy. The final recovery card follows after the other members finish.');
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
$('download-final').addEventListener('click', () => downloadCard('final-card', 'loki-vault.card'));
action('check-backup', async (form) => {
  const value = fields(form);
  await api('verify', {vault: selectedVault, words: value.words});
  $('words').textContent = '';
  $('backup-made').hidden = true;
  message('Your words match this vault. Waiting for the other members before you save the final card.');
});
action('activate', async () => {
  await api('activate', {vault: selectedVault});
  message('The signed backup checks are complete. Save and check your final recovery card.');
});
action('make-final-backup', async (form) => {
  await api('finalize-backup', {vault: selectedVault, words: fields(form).words});
  message('Download the final card, then load the saved file to check it.');
});
action('check-final-backup', async (form) => {
  const value = fields(form);
  await api('verify-final-backup', {vault: selectedVault, words: value.words,
                                   card: await cardBase64(value.card)});
  message('Your final card checked. Ask every member to do the same before depositing.');
});
action('relay-provision', async (form) => {
  await api('relay-provision', {vault: selectedVault, bundle: fields(form).bundle});
  message('Your relay inboxes are provisioned. Prepare the encrypted files for the other members.');
});
action('relay-export', async () => {
  const vault = selectedVault;
  const {files} = await api('relay-export', {vault});
  if (selectedVault !== vault) return;
  const list = $('relay-downloads');
  list.replaceChildren();
  for (const file of files) {
    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = `Download encrypted file for member ${file.peer}`;
    button.addEventListener('click', () => {
      const bytes = Uint8Array.from(atob(file.data), c => c.charCodeAt(0));
      const link = document.createElement('a');
      link.href = URL.createObjectURL(new Blob([bytes], {type: 'application/octet-stream'}));
      link.download = file.name;
      link.click();
      setTimeout(() => URL.revokeObjectURL(link.href), 1000);
    });
    list.append(button);
  }
  message('Send each encrypted file only to the member named on its button. Ask them to import it in their own app.');
});
action('relay-import', async (form) => {
  const {file} = fields(form);
  const result = await api('relay-import', {vault: selectedVault,
                                             name: file.name, data: await cardBase64(file, 'Relay file')});
  message(`Member ${result.imported_from}'s relay config was checked and imported.`);
});
$('relay-check').addEventListener('click', async () => {
  const button = $('relay-check');
  button.disabled = true;
  try {
    const vault = selectedVault;
    const expectedPeers = memberCount - 1;
    const state = await api('relay-status', {vault});
    if (selectedVault !== vault) return;
    $('relay-state').textContent = !state.inboxes
      ? 'This member has no relay inboxes yet. Provision your relay kit.'
      : state.peers < expectedPeers
        ? `${state.peers} of ${expectedPeers} encrypted peer configs imported. Each other member must send you theirs.`
        : !state.configured
          ? 'Relay configs are present, but this member cannot route payments yet. Check the local kit and try again.'
        : state.live_relays < 2
          ? `${state.live_relays} of 3 relays responded. At least 2 must respond for approvals.`
          : 'All peer configs are present. This member’s inbox answered on at least 2 relays; delivery to peers is checked when sending.';
  } catch (error) { message(error.message, true); }
  finally { button.disabled = false; }
});
action('show-address', async () => {
  const value = await api('address', {vault: selectedVault});
  $('address').textContent = value.address;
});
$('refresh-balance').addEventListener('click', async () => {
  const button = $('refresh-balance');
  const vault = selectedVault;
  button.disabled = true;
  try {
    const value = await api('balance', {vault});
    if (selectedVault !== vault) return;
    $('balance').textContent = (value.network === 'testnet'
      ? `${zecFromZat(value.balance_zat)} ZEC · scanned block ${value.height} of ${value.chain_tip}`
        + (value.scan_ready ? ' · scan caught up' : ' · scan still catching up; balance may be incomplete')
      : `${zecFromZat(value.balance_zat)} ZEC · ${value.unspent_notes} unspent notes · block ${value.height}`)
      + (Number.isInteger(value.max_spendable_zat) ? ` · ${zecFromZat(value.max_spendable_zat)} ZEC spendable now` : '');
    if (value.network === 'testnet' && !$('payment-list').hidden) refreshPaymentsQuietly(true);
  } catch (error) {
    if (selectedVault === vault) $('balance').textContent = `Scan failed: ${error.message}. Balance unavailable.`;
  }
  finally { button.disabled = false; }
});
action('payment-draft', async (form) => {
  const vault = selectedVault;
  const value = fields(form);
  const amount_zat = zatFromZec(value.amount_zec);
  const draft = await api('payment-draft', {vault, recipient: value.recipient, memo: value.memo, amount_zat, pair: value.pair});
  if (selectedVault !== vault) return;
  $('draft-result').textContent = `DRAFT · no member has approved or sent this payment\n`
    + `Payment ID: ${draft.payment}\n`
    + `Amount: ${zecFromZat(amount_zat)} ZEC (${amount_zat} zat)\n`
    + `Signers: members ${draft.signers.join(', ')}`;
  $('draft-result').hidden = false;
  $('amount-zat').textContent = 'Up to 8 decimal places.';
  await api('payment-publish', {vault, attempt: draft.attempt});
  message('Proposal sent to the other members. You approve it below once the exact transaction is on screen.');
  await refreshPayments();
});
$('payment-draft').elements.amount_zec.addEventListener('input', amountEcho);
$('refresh-payments').addEventListener('click', async () => {
  if (!selectedVault) return;
  try {
    await api('payment-sync', {vault: selectedVault});
    await refreshPayments();
  } catch (error) {
    const detail = error.surface === 'payment-sync' && error.message === 'member_sealed'
      ? 'Payment relay configuration is unavailable for this vault. Complete relay setup or check the saved relay configuration. Receiving and balance checks are still available.'
      : `Payment updates failed: ${error.message}`;
    $('payment-updates').textContent = `${detail} Check for updates to retry.`;
    $('payment-updates').hidden = false;
  }
});
/* ── theme ──────────────────────────────────────────────────────────────────
   No stored choice means follow the system, which the stylesheet's media query
   already does; a stored choice pins data-theme on the root and wins.

   Storage throws rather than returning null in private browsing, in embedded
   webviews and under storage policy, so both sides fail quiet: a theme
   preference is not worth taking the page down for. */

const THEME_KEY = 'loki-theme';
const themeStore = {
  read() { try { return localStorage.getItem(THEME_KEY); } catch { return null; } },
  write(value) { try { localStorage.setItem(THEME_KEY, value); } catch { /* not fatal */ } },
};

function currentTheme() {
  return document.documentElement.dataset.theme
    || (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
}

function applyTheme(mode) {
  if (mode) document.documentElement.dataset.theme = mode;
  $('theme').textContent = currentTheme() === 'dark' ? 'Light' : 'Dark';  /* offers the other */
}

applyTheme(themeStore.read());
$('theme').addEventListener('click', () => {
  const next = currentTheme() === 'dark' ? 'light' : 'dark';
  themeStore.write(next);
  applyTheme(next);
});
matchMedia('(prefers-color-scheme: light)').addEventListener('change', () => {
  if (!themeStore.read()) applyTheme(null);
});
$('back').addEventListener('click', () => { selectVault(null); refresh(); });
$('lock').addEventListener('click', async () => {
  try { await api('lock', {}); selectVault(null); await refresh(); }
  catch (error) { message(error.message, true); }
});
$('setup-relays').addEventListener('click', async () => {
  $('setup-relays').disabled = true;
  try {
    await api('relay-setup-all', {});
    message('Local relays are running. All eligible vaults connect automatically as their signers unlock.');
    await refresh();
  } catch (error) { failure(error); }
  finally { $('setup-relays').disabled = false; }
});
refresh(); setInterval(refresh, 2000); setInterval(refreshPaymentsQuietly, 2000);
