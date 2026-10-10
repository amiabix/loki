#!/usr/bin/env node
// Run against a fresh local member_demo.py instance; leaves its confirmed payment for inspection.
const assert = require('node:assert/strict');
const {chromium} = require('../g3/node_modules/playwright-core');

if (!process.env.LOKI_DEMO_URL) {
  throw new Error('set LOKI_DEMO_URL to the coordinator URL printed by member_demo.py');
}
const coordinator = new URL(process.env.LOKI_DEMO_URL);
if (coordinator.protocol !== 'http:' || coordinator.hostname !== '127.0.0.1' || !coordinator.hash) {
  throw new Error('set LOKI_DEMO_URL to the coordinator URL printed by member_demo.py');
}
const token = coordinator.hash.slice(1);
const base = coordinator.origin;

async function state(page, memberToken) {
  const response = await page.request.get(`${base}/api/state`, {
    headers: {'X-Loki-Token': memberToken},
  });
  assert.equal(response.status(), 200);
  return response.json();
}

(async () => {
  const browser = await chromium.launch({headless: true});
  const errors = [];
  try {
    const operator = await browser.newContext();
    const carol = await operator.newPage();
    carol.on('pageerror', error => errors.push(`Carol: ${error.message}`));
    await carol.goto(coordinator.href);
    assert.equal((await state(carol, token)).phase, 'idle', 'use a fresh demo instance');
    await carol.locator('#amount').fill('0.12');
    await carol.locator('#memo').fill('browser workflow check');
    await carol.locator('#start-form button').click();
    await carol.locator('#links-panel').waitFor({state: 'visible', timeout: 600000});
    const prepared = await state(carol, token);
    assert.equal(prepared.phase, 'waiting_for_reviews');
    const relay = await carol.request.get(`${base}/api/relay/state`, {
      headers: {'X-Loki-Token': token},
    });
    assert.equal(relay.status(), 200);
    const network = await relay.json();
    assert.equal(network.relays['3'].status === 'failed', false);
    await carol.locator('[data-view="relay"]').click();
    assert.equal(await carol.locator('#relay-svg .relay-node').count(), 6);
    assert.match(await carol.locator('#relay-milestones').innerText(), /Transport/);
    assert.match(await carol.locator('#relay-milestones').innerText(), /Application/);
    assert.match(await carol.locator('#relay-milestones').innerText(), /Approval/);
    assert.match(await carol.locator('#relay-milestones').innerText(), /Chain/);
    await carol.locator('[data-view="overview"]').click();
    assert.equal(prepared.payment.amount_zat, 12_000_000);
    assert.equal(prepared.payment.memo, 'browser workflow check');
    const links = await carol.locator('#member-links a').evaluateAll(anchors => anchors.map(a => a.href));
    assert.equal(links.length, 2);

    const opened = operator.waitForEvent('page');
    await carol.locator('#member-links a').first().click();
    const aliceWindow = await opened;
    await aliceWindow.locator('#side-role').filter({hasText: 'Alice'}).waitFor();
    assert.match(await carol.locator('#side-role').innerText(), /Carol/);
    await aliceWindow.close();

    const aliceProfile = await browser.newContext();
    const bobProfile = await browser.newContext();
    const alice = await aliceProfile.newPage();
    const bob = await bobProfile.newPage();
    for (const [name, page] of [['Alice', alice], ['Bob', bob]]) {
      page.on('pageerror', error => errors.push(`${name}: ${error.message}`));
    }
    await Promise.all([alice.goto(links[0]), bob.goto(links[1])]);
    await Promise.all([alice, bob].map(page => page.locator('#review-panel').waitFor({state: 'visible'})));
    assert.match(await alice.locator('#side-role').innerText(), /Alice/);
    assert.match(await bob.locator('#side-role').innerText(), /Bob/);
    const review = await alice.locator('#review-lines').innerText();
    assert.equal(review, await bob.locator('#review-lines').innerText());
    assert.match(review, /12000000 zat/);
    assert.match(review, /browser workflow check/);
    for (const [role, page, link] of [['alice', alice, links[0]], ['bob', bob, links[1]]]) {
      const member = await state(page, new URL(link).hash.slice(1));
      assert.equal(member.role, role);
      assert.equal(member.links, undefined);
    }

    await alice.locator('#approve').click();
    await carol.locator('[data-view="queue"]').click();
    await carol.waitForFunction(() => document.querySelector('#approval-total').textContent === '1 of 2');
    await bob.locator('#approve').click();
    await carol.locator('#finish-panel').waitFor({state: 'visible'});
    const ready = await state(carol, token);
    assert.equal(ready.phase, 'ready_to_send');
    assert.equal(ready.txid, null);
    assert.deepEqual(ready.signers, {alice: 'approved', bob: 'approved'});
    await carol.locator('#finish').click();
    await carol.locator('[data-view="history"]').click();
    await carol.locator('#history-item').waitFor({state: 'visible', timeout: 180000});
    const confirmed = await state(carol, token);
    assert.equal(confirmed.phase, 'confirmed');
    assert.match(confirmed.txid, /^[0-9a-f]{64}$/);
    assert.equal(await carol.locator('#history-txid').innerText(), confirmed.txid);
    assert.deepEqual(errors, []);
    console.log(`PASS: 2-of-3 payment confirmed, txid ${confirmed.txid}`);
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
