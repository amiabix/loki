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

function relayNode(tag) {
  return document.createElementNS('http://www.w3.org/2000/svg', tag);
}

function relayText(tag, className, value) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  node.textContent = value;
  return node;
}

function relayVisible(event) {
  const role = typeof memberRole === 'function' ? memberRole() : 'admin';
  if (!role || role === 'admin' || event.origin === 'controller') return true;
  const member = role === 'alice' ? 1 : role === 'bob' ? 2 : null;
  return event.actor_member === member || event.recipient_member === member;
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
  const network = await api('/api/relay/state');
  if (relayRun && network.run_id !== relayRun) resetRelay(network.run_id);
  relayRun = network.run_id;
  relayNetwork = network;
  const page = await api(`/api/relay/events?after=${relayCursor}`);
  acceptRelayEvents(page);
  renderRelay();
}

function renderRelay() {
  const svg = document.getElementById('relay-svg');
  const milestones = document.getElementById('relay-milestones');
  const timeline = document.getElementById('relay-timeline');
  const mode = document.getElementById('relay-mode');
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
    shape.setAttribute('width', '140');
    shape.setAttribute('height', '36');
    shape.setAttribute('rx', '8');
    const label = relayNode('text');
    label.setAttribute('x', String(item.x + 12));
    label.setAttribute('y', String(item.y + 23));
    label.textContent = item.label;
    group.append(shape, label);
    svg.append(group);
  }
  for (const event of relayEvents.filter(relayVisible)) {
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
  const network = relayNetwork || {};
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
  for (const event of relayEvents.filter(relayVisible)) {
    const item = relayText('li', 'relay-event', relaySentence(event));
    timeline.append(item);
  }
  if (mode) mode.textContent = relayMode === 'replay' ? 'Replay' : 'Live';
}

function relaySentence(event) {
  const actor = event.actor_member === 1 ? 'Alice' : event.actor_member === 2 ? 'Bob' : event.actor_member === 3 ? 'Carol' : 'A member';
  if (event.event_type === 'request_start') return `${actor} sent a request toward a relay`;
  if (event.event_type === 'request_end') {
    const pin = typeof event.relay_pin === 'string' ? event.relay_pin.slice(0, 8) : 'a relay';
    return `${actor} fetched an object from relay ${pin}`;
  }
  if (event.event_type === 'application_accepted') return `${actor} accepted the signing message`;
  if (event.event_type === 'approved') return `${actor} approved the payment`;
  return `${actor} recorded ${event.event_type}`;
}

async function inspectRelay(messageId, after) {
  const page = await api(`/api/relay/messages/${messageId}/objects?after=${after}&limit=100`);
  const inspector = document.getElementById('relay-inspector');
  if (!inspector) return page;
  const list = document.createElement('ol');
  for (const row of page.rows || []) {
    const item = relayText('li', 'relay-object', `object ${row.object_ordinal} for member ${row.recipient_member}`);
    list.append(item);
  }
  inspector.replaceChildren(list);
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
