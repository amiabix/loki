#!/usr/bin/env node
// UI fixture. This does not prove a relay payment.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const sourcePath = path.join(__dirname, 'static', 'relay.js');
const source = fs.readFileSync(sourcePath, 'utf8');
const page = fs.readFileSync(path.join(__dirname, 'static', 'member.html'), 'utf8');
const style = fs.readFileSync(path.join(__dirname, 'static', 'relay.css'), 'utf8');
assert.equal(source.includes('require('), false);
assert.equal(source.includes('module.exports'), false);
assert.equal(source.includes('innerHTML'), false);
assert.equal(source.includes('textContent'), true);
for (const id of [
  'relay-filter-member', 'relay-filter-message', 'relay-filter-relay', 'relay-filter-failure',
  'relay-admin', 'relay-admin-relay', 'relay-admin-member', 'relay-admin-resend',
  'relay-status', 'relay-error', 'relay-messages',
]) {
  assert.equal(page.includes(`id="${id}"`), true, id);
}
assert.equal(page.includes('<script src="/relay.js" defer></script>'), true);
assert.equal(style.includes('prefers-reduced-motion'), true);

class Element {
  constructor(tag) {
    this.tagName = tag;
    this.children = [];
    this.attributes = {};
    this.className = '';
    this.id = '';
    this.listeners = {};
    this._text = '';
    this.value = '';
    this.hidden = false;
    this.checked = false;
  }

  set textContent(value) {
    this._text = String(value);
  }

  get textContent() {
    return this._text + this.children.map((child) => child.textContent || '').join('');
  }

  setAttribute(name, value) {
    this.attributes[name] = String(value);
    if (name === 'id') this.id = String(value);
    if (name === 'class') this.className = String(value);
  }

  append(...children) {
    this.children.push(...children);
  }

  replaceChildren(...children) {
    this.children = children;
    this._text = '';
  }

  addEventListener(type, listener) {
    this.listeners[type] = listener;
  }

  get firstChild() {
    return this.children[0] || null;
  }

  removeChild(child) {
    const index = this.children.indexOf(child);
    if (index >= 0) this.children.splice(index, 1);
    return child;
  }
}

function count(node, className) {
  const classes = `${node.className || ''} ${node.attributes.class || ''}`.split(/\s+/);
  let total = classes.includes(className) ? 1 : 0;
  for (const child of node.children || []) total += count(child, className);
  return total;
}

function documentFor(ids) {
  const nodes = new Map();
  const document = {
    createElement: (tag) => new Element(tag),
    createElementNS: (_namespace, tag) => new Element(tag),
    getElementById: (id) => nodes.get(id) || null,
  };
  for (const id of ids) {
    const element = new Element('div');
    element.id = id;
    nodes.set(id, element);
  }
  return {document, nodes};
}

async function runOnce() {
  const {document, nodes} = documentFor([
    'relay-svg', 'relay-milestones', 'relay-timeline', 'relay-inspector',
    'relay-mode', 'relay-replay', 'relay-live', 'relay-speed',
    'relay-filter-member', 'relay-filter-message', 'relay-filter-relay', 'relay-filter-failure',
    'relay-admin', 'relay-admin-relay', 'relay-admin-member', 'relay-admin-resend',
    'relay-status', 'relay-error', 'relay-messages',
  ]);
  let calls = 0;
  const network = {
    saved: 1, stored: 2, received: 3, application_accepted: 4, approved: 5,
    freshness: 'live', run_id: 'demo-1',
  };
  const traffic = [
    {sequence: 1, event_type: 'request_start', actor_member: 1, origin: 'native'},
    {sequence: 2, event_type: 'request_end', actor_member: 2, recipient_member: 2,
     relay_pin: 'abcdef0123456789', origin: 'native'},
  ];
  const sandbox = {
    document,
    console,
    memberRole: () => 'admin',
    api: async (request) => {
      calls += 1;
      if (String(request).startsWith('/api/relay/state')) return network;
      if (String(request).startsWith('/api/relay/events')) return {events: traffic, next: 2};
      return {events: [], next: 0, run_id: 'demo-1'};
    },
  };
  vm.runInNewContext(source, sandbox, {filename: 'relay.js'});
  assert.equal(typeof sandbox.require, 'undefined');
  sandbox.renderRelay();
  assert.match(nodes.get('relay-status').textContent, /Loading/);
  await sandbox.refreshRelay();
  assert.equal(count(nodes.get('relay-svg'), 'relay-node'), 6);
  const milestoneText = nodes.get('relay-milestones').children.map((node) => node.textContent);
  assert.equal(milestoneText.length, 4);
  assert.match(milestoneText[0], /Transport/);
  assert.match(milestoneText[1], /Application/);
  assert.match(milestoneText[2], /Approval/);
  assert.match(milestoneText[3], /Chain/);
  const labels = [];
  (function walk(node) {
    if (node._text) labels.push(node._text);
    for (const child of node.children || []) walk(child);
  })(nodes.get('relay-svg'));
  assert.ok(labels.includes('Alice'));
  assert.equal(count(nodes.get('relay-svg'), 'relay-inbox'), 3);
  assert.equal(typeof nodes.get('relay-filter-member').listeners.change, 'function');
  assert.equal(typeof nodes.get('relay-filter-failure').listeners.change, 'function');

  sandbox.memberRole = () => 'alice';
  sandbox.renderRelay();
  const timeline = nodes.get('relay-timeline').textContent;
  assert.match(timeline, /Alice/);
  assert.equal(timeline.includes('Bob'), false);

  sandbox.acceptRelayEvents({
    events: [{sequence: 1, event_type: 'request_start', actor_member: 1, origin: 'native'}],
    next: 1,
  });
  sandbox.acceptRelayEvents({
    events: [
      {sequence: 1, event_type: 'request_start', actor_member: 1, origin: 'native'},
      {sequence: 3, event_type: 'approved', actor_member: 1, origin: 'native'},
    ],
    next: 3,
  });
  sandbox.memberRole = () => 'admin';
  sandbox.renderRelay();
  assert.equal(nodes.get('relay-timeline').children.length, 3);
  sandbox.acceptRelayEvents({
    events: [{sequence: 3, event_type: 'approved', actor_member: 1, origin: 'native'}],
    next: 3,
  });
  sandbox.renderRelay();
  assert.equal(nodes.get('relay-timeline').children.length, 3);

  const rows = Array.from({length: 120}, (_value, index) => ({
    object_ordinal: index + 1, recipient_member: 1,
  }));
  sandbox.api = async (request) => {
    calls += 1;
    const after = Number(new URL(request, 'http://127.0.0.1').searchParams.get('after'));
    const slice = rows.slice(after, after + 100);
    return {rows: slice, next: after + slice.length, complete: after + slice.length >= rows.length};
  };
  const first = await sandbox.inspectRelay('ab'.repeat(32), 0);
  assert.equal(first.rows.length, 100);
  assert.equal(first.complete, false);
  assert.equal(count(nodes.get('relay-inspector'), 'relay-object'), 100);
  const second = await sandbox.inspectRelay('ab'.repeat(32), first.next);
  assert.equal(second.rows.length, 20);
  assert.equal(second.complete, true);

  const before = calls;
  sandbox.replayRelay();
  await sandbox.refreshRelay();
  assert.equal(calls, before);
  assert.equal(nodes.get('relay-mode').textContent, 'Replay');

  sandbox.memberRole = () => 'admin';
  nodes.get('relay-filter-member').value = '2';
  sandbox.renderRelay();
  assert.match(nodes.get('relay-timeline').textContent, /Bob/);
  assert.equal(nodes.get('relay-timeline').textContent.includes('Alice sent'), false);
  nodes.get('relay-filter-member').value = '';
  nodes.get('relay-filter-relay').value = 'abcdef01';
  sandbox.renderRelay();
  assert.match(nodes.get('relay-timeline').textContent, /Bob/);
  assert.equal(nodes.get('relay-timeline').textContent.includes('Alice sent'), false);
  nodes.get('relay-filter-relay').value = '';
  nodes.get('relay-filter-message').value = 'ffff';
  sandbox.renderRelay();
  assert.equal(nodes.get('relay-timeline').children.length, 0);
  nodes.get('relay-filter-message').value = '';
  sandbox.acceptRelayEvents({
    events: [{sequence: 7, event_type: 'receipt_rejected', actor_member: 1, origin: 'native'}],
    next: 7,
  });
  nodes.get('relay-filter-failure').checked = true;
  sandbox.renderRelay();
  assert.match(nodes.get('relay-timeline').textContent, /rejected/);
  assert.equal(nodes.get('relay-timeline').textContent.includes('Alice sent'), false);
  nodes.get('relay-filter-failure').checked = false;

  sandbox.acceptRelayEvents({
    events: [4, 5, 6].map((sequence) => ({
      sequence, event_type: 'request_end', result_code: 'empty', actor_member: 1, origin: 'native',
    })),
    next: 6,
  });
  sandbox.renderRelay();
  assert.match(nodes.get('relay-timeline').textContent, /3 empty polls collapsed/);
  assert.match(nodes.get('relay-milestones').textContent, /Transport saved 1/);

  const message = 'ab'.repeat(32);
  sandbox.acceptRelayEvents({
    events: [
      {sequence: 50, event_type: 'application_accepted', message_id: message, recipient_member: 1, origin: 'native'},
      {sequence: 51, event_type: 'application_accepted', message_id: message, recipient_member: 2, origin: 'native'},
    ],
    next: 51,
  });
  sandbox.api = async () => ({
    rows: [1, 2, 3].map((member) => ({
      object_ordinal: 1,
      recipient_member: member,
      wire_bytes: 64,
      receipt_digest: 'bb'.repeat(32),
      relay_pin: 'cc'.repeat(32),
    })),
    next: 3,
    complete: true,
  });
  await sandbox.inspectRelay(message, 0);
  const inspector = nodes.get('relay-inspector');
  assert.equal(count(inspector, 'relay-object'), 3);
  assert.match(inspector.textContent, /ordinal 1/);
  assert.match(inspector.textContent, /64 bytes/);
  assert.match(inspector.textContent, /bbbbbbbb/);
  const inner = inspector.children.find((node) => String(node.className).includes('relay-inner'));
  assert.ok(inner);
  assert.match(inner.textContent, /Alice/);
  assert.match(inner.textContent, /Bob/);
  assert.equal(inner.textContent.includes('Carol'), false);
  assert.match(inspector.textContent, /192 bytes/);

  sandbox.memberRole = () => 'carol';
  sandbox.acceptRelayEvents({events: [
    {sequence: 60, event_type: 'approved', actor_member: 3, origin: 'native'},
    {sequence: 61, event_type: 'approved', actor_member: 1, origin: 'native'},
  ], next: 61});
  sandbox.renderRelay();
  assert.match(nodes.get('relay-timeline').textContent, /Carol approved/);
  assert.equal(nodes.get('relay-timeline').textContent.includes('Alice approved'), false);
  sandbox.memberRole = () => 'bob';
  sandbox.demoState = () => ({creator: 'bob', payment: {pair: ['bob', 'carol']}});

  const actions = [];
  sandbox.act = async (path, body) => {
    actions.push({path: String(path), body: JSON.parse(JSON.stringify(body))});
  };
  nodes.get('relay-admin-relay').value = '2';
  nodes.get('relay-admin-member').value = '1';
  nodes.get('relay-admin-resend').value = '3';
  sandbox.renderRelay();
  const adminButtons = [];
  (function walk(node) {
    if (String(node.className || '').startsWith('relay-admin-') && node.tagName === 'button') adminButtons.push(node);
    for (const child of node.children || []) walk(child);
  })(nodes.get('relay-admin'));
  const button = (name) => adminButtons.find((node) => node.className === name);
  await button('relay-admin-stop').listeners.click();
  await button('relay-admin-restart').listeners.click();
  await button('relay-admin-pause').listeners.click();
  await button('relay-admin-resume').listeners.click();
  await button('relay-admin-resend').listeners.click();
  assert.deepEqual(actions, [
    {path: '/api/relay/stop', body: {relay: 2}},
    {path: '/api/relay/restart', body: {relay: 2}},
    {path: '/api/relay/member', body: {member: 1, action: 'pause'}},
    {path: '/api/relay/member', body: {member: 1, action: 'resume'}},
    {path: '/api/relay/resend', body: {member: 3}},
  ]);
  sandbox.act = async () => {
    throw new Error('member 1 store is busy');
  };
  await button('relay-admin-pause').listeners.click();
  assert.match(nodes.get('relay-error').textContent, /busy/);
  sandbox.memberRole = () => 'alice';
  sandbox.renderRelay();
  const hiddenAdmin = [];
  (function walk(node) {
    if (String(node.className || '').startsWith('relay-admin-') && node.tagName === 'button') hiddenAdmin.push(node);
    for (const child of node.children || []) walk(child);
  })(nodes.get('relay-admin'));
  assert.equal(hiddenAdmin.length, 0);

  sandbox.liveRelay();
  sandbox.demoState = () => ({substage: 'funding', error: null});
  sandbox.api = async (request) => {
    if (String(request).startsWith('/api/relay/state')) {
      return {
        saved: 1, stored: 2, received: 3, application_accepted: 4, approved: 5,
        freshness: 'stale', gap: true, run_id: 'demo-1',
        relays: {1: {status: 'standby'}, 2: {status: 'standby'}, 3: {status: 'failed'}},
        members: {1: {status: 'offline'}},
        messages: [message],
      };
    }
    return {events: [], next: 51};
  };
  sandbox.memberRole = () => 'admin';
  await sandbox.refreshRelay();
  assert.match(nodes.get('relay-status').textContent, /Stale/);
  assert.match(nodes.get('relay-status').textContent, /Gap/);
  assert.match(nodes.get('relay-status').textContent, /Member 1 offline/);
  assert.match(nodes.get('relay-status').textContent, /funding/);
  const failedLabels = [];
  (function walk(node) {
    if (node._text) failedLabels.push(node._text);
    for (const child of node.children || []) walk(child);
  })(nodes.get('relay-svg'));
  assert.ok(failedLabels.includes('Relay 3 failed'));
  assert.equal(nodes.get('relay-messages').children.length, 1);

  sandbox.api = async () => {
    throw new Error('not authorized');
  };
  await sandbox.refreshRelay();
  assert.match(nodes.get('relay-error').textContent, /not authorized/);
  sandbox.resetRelay('demo-2');
  sandbox.renderRelay();
  assert.match(nodes.get('relay-status').textContent, /No relay events yet/);
  return 'relay-view-ok';
}

(async () => {
  const first = await runOnce();
  const second = await runOnce();
  assert.equal(first, second);
  console.log(first);
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
