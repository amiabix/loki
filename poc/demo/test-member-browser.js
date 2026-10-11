#!/usr/bin/env node
// Run against a fresh local member_demo.py instance; leaves its confirmed payment for inspection.
const assert = require('node:assert/strict');
const {chromium} = require('../g3/node_modules/playwright-core');

const urls = Object.fromEntries(['alice', 'bob', 'carol'].map(role => {
  const raw = process.env[`LOKI_${role.toUpperCase()}_URL`];
  if (!raw) throw new Error(`set LOKI_${role.toUpperCase()}_URL from member_demo.py`);
  const url = new URL(raw);
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || !url.hash) {
    throw new Error(`LOKI_${role.toUpperCase()}_URL must be a loopback member link`);
  }
  return [role, url];
}));
assert.equal(new Set(Object.values(urls).map(url => url.origin)).size, 1);
const base = urls.alice.origin;

async function state(page, role) {
  const response = await page.request.get(`${base}/api/state`, {
    headers: {'X-Loki-Token': urls[role].hash.slice(1)},
  });
  assert.equal(response.status(), 200);
  return response.json();
}

(async () => {
  const browser = await chromium.launch({headless: true});
  const errors = [];
  try {
    const pages = {};
    for (const role of Object.keys(urls)) {
      const profile = await browser.newContext();
      const page = await profile.newPage();
      page.on('pageerror', error => errors.push(`${role}: ${error.message}`));
      await page.goto(urls[role].href);
      pages[role] = page;
    }
    const {alice, bob, carol} = pages;
    const initial = await state(bob, 'bob');
    assert.equal(initial.phase, 'idle', 'use a fresh demo instance');
    assert.equal(initial.payment, null);
    await Promise.all([alice, bob, carol].map(page =>
      page.locator('#create-panel').waitFor({state: 'visible'})));

    await bob.locator('#create-vault').click();
    await bob.locator('#fund-panel').waitFor({state: 'visible', timeout: 600000});
    const created = await state(bob, 'bob');
    assert.equal(created.creator, 'bob');
    assert.match(created.vaults.source, /^uregtest/);
    await bob.locator('#fund').click();
    await bob.locator('#start-panel').waitFor({state: 'visible', timeout: 180000});
    const funded = await state(bob, 'bob');
    const destination = funded.vaults.recipient;
    await bob.locator('#recipient').fill(destination);
    await bob.locator('#amount').fill('0.12');
    await bob.locator('#memo').fill('browser workflow check');
    await bob.locator('#pair').selectOption('BC');
    await bob.locator('#propose').click();
    await Promise.all([bob, carol].map(page =>
      page.locator('#review-panel').waitFor({state: 'visible', timeout: 600000})));
    const prepared = await state(bob, 'bob');
    assert.equal(prepared.phase, 'waiting_for_reviews');
    assert.equal(prepared.payment.proposer, 'bob');
    assert.deepEqual(prepared.payment.pair, ['bob', 'carol']);
    assert.equal(prepared.payment.recipient, destination);
    assert.equal(prepared.payment.amount_zat, 12_000_000);
    assert.equal(prepared.payment.memo, 'browser workflow check');
    const aliceState = await state(alice, 'alice');
    assert.equal(aliceState.own_status, 'not_requested');
    assert.equal(aliceState.review, null);
    assert.equal(await alice.locator('#review-panel').isVisible(), false);
    const review = await bob.locator('#review-lines').innerText();
    assert.equal(review, await carol.locator('#review-lines').innerText());
    assert.match(review, /12000000 zat/);
    assert.match(review, /browser workflow check/);
    for (const role of ['bob', 'carol']) {
      const member = await state(pages[role], role);
      assert.equal(member.signers, undefined);
      assert.equal(member.review, review);
    }

    await carol.locator('#approve').click();
    await alice.waitForFunction(() => document.querySelector('#approval-total').textContent === '1 of 2');
    await bob.locator('#approve').click();
    await alice.locator('#finish-panel').waitFor({state: 'visible'});
    const ready = await state(alice, 'alice');
    assert.equal(ready.phase, 'ready_to_send');
    assert.equal(ready.txid, null);
    assert.equal(ready.approvals_count, 2);
    await alice.locator('#finish').click();
    await alice.locator('[data-view="history"]').click();
    await alice.locator('#history-item').waitFor({state: 'visible', timeout: 180000});
    const confirmed = await state(alice, 'alice');
    assert.equal(confirmed.phase, 'confirmed');
    assert.equal(confirmed.payment.recipient_verified, true);
    assert.match(confirmed.txid, /^[0-9a-f]{64}$/);
    assert.equal(await alice.locator('#history-txid').innerText(), confirmed.txid);
    assert.equal(await alice.locator('#history-amount').innerText(), '0.12 ZEC sent');
    assert.equal(await alice.locator('#history-recipient').innerText(), `To ${destination}`);
    assert.match(await alice.locator('#history-memo').innerText(), /browser workflow check/);
    assert.deepEqual(errors, []);
    console.log(`PASS: Bob proposed, Bob and Carol approved, Alice finished ${confirmed.txid}`);
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
