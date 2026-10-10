'use strict';

const RELAY_NODES = [
  {id: 'member-alice', label: 'Alice', x: 80, y: 70},
  {id: 'member-bob', label: 'Bob', x: 80, y: 150},
  {id: 'member-carol', label: 'Carol', x: 80, y: 230},
  {id: 'relay-1', label: 'Relay 1', x: 460, y: 70},
  {id: 'relay-2', label: 'Relay 2', x: 460, y: 150},
  {id: 'relay-3', label: 'Relay 3 standby', x: 460, y: 230},
];

let relayEvents = [];
let relaySeen = new Set();
let relayCursor = 0;
let relayRun = null;
let relayMode = 'live';
let relaySpeed = 1;
let relayNetwork = null;
let relayFetches = 0;

const RELAY_FAILURES = new Set([
  'receipt_rejected', 'route_failure', 'quarantine', 'relay_failed', 'application_rejected',
]);

function relayNode(tag) {
  return document.createElementNS('http://www.w3.org/2000/svg', tag);
}

function relayText(tag, className, value) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  node.textContent = value;
  return node;
}

function memberName(member) {
  if (member === 1) return 'Alice';
  if (member === 2) return 'Bob';
  if (member === 3) return 'Carol';
  return 'A member';
}

function relayFilters() {
  const member = document.getElementById('relay-filter-member');
  const message = document.getElementById('relay-filter-message');
  const relay = document.getElementById('relay-filter-relay');
  const failure = document.getElementById('relay-filter-failure');
  return {
    member: member && member.value ? Number(member.value) : null,
    message: message && message.value ? message.value.trim() : '',
    relay: relay && relay.value ? relay.value.trim() : '',
    failure: Boolean(failure && failure.checked),
  };
}

function relayVisible(event) {
  const role = typeof memberRole === 'function' ? memberRole() : 'admin';
  if (!role || role === 'admin' || event.origin === 'controller') return true;
  const member = role === 'alice' ? 1 : role === 'bob' ? 2 : null;
  return event.actor_member === member || event.recipient_member === member;
}

function relayShown(event) {
  if (!relayVisible(event)) return false;
  const filters = relayFilters();
  if (filters.member && event.actor_member !== filters.member
      && event.recipient_member !== filters.member && event.member !== filters.member) {
    return false;
  }
  if (filters.message && !(typeof event.message_id === 'string' && event.message_id.startsWith(filters.message))) {
    return false;
  }
  if (filters.relay) {
    const pin = typeof event.relay_pin === 'string' ? event.relay_pin : '';
    const relay = event.relay == null ? '' : String(event.relay);
    if (!pin.startsWith(filters.relay) && relay !== filters.relay) return false;
  }
  if (filters.failure && !RELAY_FAILURES.has(event.event_type)) return false;
  return true;
}

function emptyPoll(event) {
  return event.event_type === 'request_end' && event.result_code === 'empty';
}

function showRelay() {
  if (typeof show === 'function') show('relay');
}

function resetRelay(runId) {
  relayEvents = [];
  relaySeen = new Set();
  relayCursor = 0;
  relayRun = runId;
}

function acceptRelayEvents(page) {
  const fresh = [];
  for (const event of page.events || []) {
    if (relaySeen.has(event.sequence)) continue;
    relaySeen.add(event.sequence);
    relayEvents.push(event);
    fresh.push(event);
  }
  if (typeof page.next === 'number') relayCursor = page.next;
  return fresh;
}

async function refreshRelay() {
  if (relayMode === 'replay') return;
  relayFetches += 1;
  try {
    const network = await api('/api/relay/state');
    if (relayRun && network.run_id !== relayRun) resetRelay(network.run_id);
    relayRun = network.run_id;
    relayNetwork = network;
    const page = await api(`/api/relay/events?after=${relayCursor}`);
    acceptRelayEvents(page);
    const error = document.getElementById('relay-error');
    if (error) error.textContent = '';
    renderRelay();
  } catch (error) {
    const node = document.getElementById('relay-error');
    if (node) node.textContent = error && error.message ? error.message : 'Relay view failed';
    const status = document.getElementById('relay-status');
    if (status) status.textContent = 'Error';
  }
}

function renderRelay() {
  const svg = document.getElementById('relay-svg');
  const milestones = document.getElementById('relay-milestones');
  const timeline = document.getElementById('relay-timeline');
  const mode = document.getElementById('relay-mode');
  const network = relayNetwork || {};
  if (!svg || !milestones || !timeline) return;
  while (svg.firstChild) svg.removeChild(svg.firstChild);
  for (const item of RELAY_NODES) {
    const group = relayNode('g');
    group.setAttribute('class', 'relay-node-group');
    const shape = relayNode('rect');
    shape.setAttribute('class', 'relay-node');
    shape.setAttribute('id', item.id);
    shape.setAttribute('x', String(item.x));
    shape.setAttribute('y', String(item.y));
    shape.setAttribute('width', '160');
    shape.setAttribute('height', '36');
    shape.setAttribute('rx', '8');
    const label = relayNode('text');
    label.setAttribute('x', String(item.x + 12));
    label.setAttribute('y', String(item.y + 23));
    label.textContent = nodeLabel(item, network);
    group.append(shape, label);
    if (item.id.startsWith('member-')) {
      const inbox = relayNode('text');
      inbox.setAttribute('class', 'relay-inbox');
      inbox.setAttribute('x', String(item.x + 12));
      inbox.setAttribute('y', String(item.y + 48));
      inbox.textContent = 'inbox';
      group.append(inbox);
    }
    svg.append(group);
  }
  for (const event of relayEvents.filter(relayShown)) {
    if (emptyPoll(event)) continue;
    if (event.event_type !== 'request_start' && event.event_type !== 'request_end') continue;
    const line = relayNode('line');
    line.setAttribute('class', event.event_type === 'request_start' ? 'relay-arrow request' : 'relay-arrow data');
    line.setAttribute('x1', event.event_type === 'request_start' ? '220' : '460');
    line.setAttribute('x2', event.event_type === 'request_start' ? '460' : '220');
    line.setAttribute('y1', '88');
    line.setAttribute('y2', '88');
    const caption = relayNode('text');
    caption.textContent = event.event_type === 'request_start' ? 'PUT toward relay' : 'data toward member';
    caption.setAttribute('x', '240');
    caption.setAttribute('y', '80');
    svg.append(line, caption);
  }
  const rows = [
    ['transport', `Transport saved ${network.saved || 0}, stored ${network.stored || 0}, received ${network.received || 0}`],
    ['application', `Application accepted ${network.application_accepted || 0}`],
    ['approval', `Approval ${network.approved || 0}`],
    ['chain', `Chain ${network.freshness || 'unknown'}`],
  ];
  milestones.replaceChildren();
  for (const [name, text] of rows) {
    const item = relayText('div', `relay-milestone milestone-${name}`, text);
    milestones.append(item);
  }
  timeline.replaceChildren();
  for (const item of collapsedTimeline(relayEvents.filter(relayShown))) {
    if (item.kind === 'empty') {
      timeline.append(relayText('li', 'relay-collapsed', `${item.count} empty polls collapsed`));
    } else {
      timeline.append(relayText('li', 'relay-event', relaySentence(item.event)));
    }
  }
  if (mode) mode.textContent = relayMode === 'replay' ? 'Replay' : 'Live';
  const status = document.getElementById('relay-status');
  if (status) status.textContent = relayStatusText();
  renderMessages(network);
  renderAdmin();
}

function nodeLabel(item, network) {
  if (item.id !== 'relay-3') return item.label;
  const relays = network.relays || {};
  const record = relays['3'] || relays[3];
  if (record && record.status === 'failed') return 'Relay 3 failed';
  if (record && record.status === 'offline') return 'Relay 3 offline';
  return 'Relay 3 standby';
}

function collapsedTimeline(events) {
  const items = [];
  let empty = 0;
  const flush = () => {
    if (!empty) return;
    items.push({kind: 'empty', count: empty});
    empty = 0;
  };
  for (const event of events) {
    if (emptyPoll(event)) {
      empty += 1;
      continue;
    }
    flush();
    items.push({kind: 'event', event});
  }
  flush();
  return items;
}

function relayStatusText() {
  if (!relayNetwork) return 'Loading';
  const network = relayNetwork;
  const parts = [];
  if (!relayEvents.length) parts.push('No relay events yet');
  if (network.freshness === 'stale') parts.push('Stale');
  else if (network.freshness === 'unknown') parts.push('Offline');
  else if (network.freshness) parts.push('Live evidence');
  if (network.gap) parts.push('Gap');
  for (const [id, relay] of Object.entries(network.relays || {})) {
    if (relay && relay.status === 'failed') parts.push(`Relay ${id} failed`);
    if (relay && relay.status === 'standby') parts.push(`Relay ${id} standby`);
  }
  for (const [id, member] of Object.entries(network.members || {})) {
    if (member && member.status === 'offline') parts.push(`Member ${id} offline`);
    if (member && member.status === 'paused') parts.push(`Member ${id} paused`);
  }
  const demo = typeof demoState === 'function' ? demoState() : null;
  if (demo && demo.substage) parts.push(`Preparation ${demo.substage}`);
  if (demo && demo.error) parts.push(String(demo.error));
  return parts.join('. ');
}

function renderMessages(network) {
  const list = document.getElementById('relay-messages');
  if (!list) return;
  list.replaceChildren();
  for (const id of network.messages || []) {
    if (typeof id !== 'string' || id.length !== 64) continue;
    const button = relayText('button', 'relay-message', id.slice(0, 8));
    button.setAttribute('type', 'button');
    button.addEventListener('click', () => inspectRelay(id, 0));
    list.append(button);
  }
}

function selectedNumber(id, allowed) {
  const node = document.getElementById(id);
  const value = Number(node && node.value);
  return allowed.includes(value) ? value : allowed[0];
}

async function relayAct(path, body) {
  try {
    if (typeof act === 'function') await act(path, body);
    else await api(path, body);
  } catch (error) {
    const node = document.getElementById('relay-error');
    if (node) node.textContent = error && error.message ? error.message : 'Relay action failed';
  }
}

function renderAdmin() {
  const host = document.getElementById('relay-admin');
  if (!host) return;
  const role = typeof memberRole === 'function' ? memberRole() : null;
  host.hidden = role !== 'admin';
  let actions = null;
  for (const child of host.children) {
    if (child.id === 'relay-admin-actions') actions = child;
  }
  if (!actions) {
    actions = document.createElement('div');
    actions.id = 'relay-admin-actions';
    host.append(actions);
  }
  actions.replaceChildren();
  if (role !== 'admin') return;
  const specs = [
    ['relay-admin-stop', 'Stop relay', () => relayAct('/api/relay/stop', {relay: selectedNumber('relay-admin-relay', [1, 2, 3])})],
    ['relay-admin-restart', 'Restart relay', () => relayAct('/api/relay/restart', {relay: selectedNumber('relay-admin-relay', [1, 2, 3])})],
    ['relay-admin-pause', 'Pause member', () => relayAct('/api/relay/member', {member: selectedNumber('relay-admin-member', [1, 2, 3]), action: 'pause'})],
    ['relay-admin-resume', 'Resume member', () => relayAct('/api/relay/member', {member: selectedNumber('relay-admin-member', [1, 2, 3]), action: 'resume'})],
    ['relay-admin-resend', 'Resend saved share', () => relayAct('/api/relay/resend', {member: selectedNumber('relay-admin-resend', [1, 2])})],
  ];
  for (const [className, label, run] of specs) {
    const button = relayText('button', className, label);
    button.setAttribute('type', 'button');
    button.addEventListener('click', run);
    actions.append(button);
  }
}

function relaySentence(event) {
  const actor = memberName(event.actor_member);
  if (event.event_type === 'request_start') return `${actor} sent a request toward a relay`;
  if (event.event_type === 'request_end') {
    const pin = typeof event.relay_pin === 'string' ? event.relay_pin.slice(0, 8) : 'a relay';
    return `${actor} fetched an object from relay ${pin}`;
  }
  if (event.event_type === 'application_accepted') return `${actor} accepted the signing message`;
  if (event.event_type === 'approved') return `${actor} approved the payment`;
  if (event.event_type === 'receipt_rejected') return `${actor} recorded a rejected receipt`;
  return `${actor} recorded ${event.event_type}`;
}

function relayObjectSentence(row) {
  const ordinal = row.object_ordinal == null ? '?' : row.object_ordinal;
  const bytes = typeof row.wire_bytes === 'number' ? row.wire_bytes : 0;
  let text = `outer copy for ${memberName(row.recipient_member)}, ordinal ${ordinal}, ${bytes} bytes`;
  if (typeof row.receipt_digest === 'string' && row.receipt_digest) {
    text += `, receipt ${row.receipt_digest.slice(0, 8)}`;
  }
  if (typeof row.relay_pin === 'string' && row.relay_pin) text += `, pin ${row.relay_pin.slice(0, 8)}`;
  return text;
}

function innerRecipients(messageId) {
  const found = [];
  for (const event of relayEvents) {
    if (event.message_id !== messageId) continue;
    if (event.event_type !== 'application_accepted' && event.event_type !== 'session_envelope_authenticated') continue;
    if ((event.recipient_member === 1 || event.recipient_member === 2 || event.recipient_member === 3)
        && !found.includes(event.recipient_member)) {
      found.push(event.recipient_member);
    }
  }
  return found;
}

async function inspectRelay(messageId, after) {
  const page = await api(`/api/relay/messages/${messageId}/objects?after=${after}&limit=100`);
  const inspector = document.getElementById('relay-inspector');
  if (!inspector) return page;
  const list = document.createElement('ol');
  let bytes = 0;
  for (const row of page.rows || []) {
    bytes += typeof row.wire_bytes === 'number' ? row.wire_bytes : 0;
    list.append(relayText('li', 'relay-object', relayObjectSentence(row)));
  }
  const inner = innerRecipients(messageId);
  const innerLine = relayText('p', 'relay-inner', inner.length
    ? `Inner recipients ${inner.map(memberName).join(', ')}`
    : 'Inner recipients none yet');
  const total = relayText('p', 'relay-bytes', `${bytes} bytes total`);
  inspector.replaceChildren(innerLine, total, list);
  if (!page.complete) {
    const more = relayText('button', 'relay-more', 'Next objects');
    more.addEventListener('click', () => inspectRelay(messageId, page.next));
    inspector.append(more);
  }
  return page;
}

function replayRelay() {
  relayMode = 'replay';
  const mode = document.getElementById('relay-mode');
  if (mode) mode.textContent = 'Replay';
  renderRelay();
}

function liveRelay() {
  relayMode = 'live';
  const mode = document.getElementById('relay-mode');
  if (mode) mode.textContent = 'Live';
}

document.getElementById('relay-replay')?.addEventListener('click', replayRelay);
document.getElementById('relay-live')?.addEventListener('click', () => { liveRelay(); refreshRelay(); });
document.getElementById('relay-speed')?.addEventListener('change', (event) => {
  relaySpeed = Number(event.target.value) || 1;
});
for (const id of ['relay-filter-member', 'relay-filter-message', 'relay-filter-relay', 'relay-filter-failure']) {
  document.getElementById(id)?.addEventListener('change', () => renderRelay());
}
