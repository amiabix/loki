#!/usr/bin/env node
// UI fixture. This does not prove a relay payment.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const sourcePath = path.join(__dirname, 'static', 'relay.js');
const source = fs.readFileSync(sourcePath, 'utf8');
assert.equal(source.includes('require('), false);
assert.equal(source.includes('module.exports'), false);
assert.equal(source.includes('innerHTML'), false);
assert.equal(source.includes('textContent'), true);

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
