#!/usr/bin/env node
// Run against a fresh local member_demo.py instance; leaves its confirmed payment for inspection.
const assert = require('node:assert/strict');
const {chromium} = require('../g3/node_modules/playwright-core');

if (!process.env.LOKI_DEMO_URL) {
  throw new Error('set LOKI_DEMO_URL to Carol’s URL printed by member_demo.py');
}
const carolUrl = new URL(process.env.LOKI_DEMO_URL);
if (carolUrl.protocol !== 'http:' || carolUrl.hostname !== '127.0.0.1' || !carolUrl.hash) {
  throw new Error('set LOKI_DEMO_URL to Carol’s URL printed by member_demo.py');
}
const token = carolUrl.hash.slice(1);
const base = carolUrl.origin;

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
    const carolProfile = await browser.newContext();
    const aliceProfile = await browser.newContext();
    const bobProfile = await browser.newContext();
    const carol = await carolProfile.newPage();
    const alice = await aliceProfile.newPage();
    const bob = await bobProfile.newPage();
    for (const [name, page] of [['Carol', carol], ['Alice', alice], ['Bob', bob]]) {
      page.on('pageerror', error => errors.push(`${name}: ${error.message}`));
    }
    await carol.goto(carolUrl.href);
    const initial = await state(carol, token);
    assert.equal(initial.phase, 'idle', 'use a fresh demo instance');
    assert.equal(initial.payment, null, 'a new vault must not inherit an old transaction');
    const links = initial.links;
    await Promise.all([alice.goto(links.alice), bob.goto(links.bob)]);
    await carol.locator('#create-panel').waitFor({state: 'visible'});
    assert.doesNotMatch(await carol.locator('body').innerText(), /regtest/i);
    assert.equal(await alice.locator('#payment-card').isVisible(), false);
    assert.equal(await bob.locator('#payment-card').isVisible(), false);
    assert.equal(await alice.locator('#create-panel').isVisible(), false);
    assert.equal(await bob.locator('#create-panel').isVisible(), false);
    assert.match(await alice.locator('#side-role').innerText(), /Alice/);
    assert.match(await bob.locator('#side-role').innerText(), /Bob/);
    assert.match(await carol.locator('#side-role').innerText(), /Carol/);

    await carol.locator('#create-vault').click();
    await carol.locator('#fund-panel').waitFor({state: 'visible', timeout: 600000});
    const created = await state(carol, token);
    assert.equal(created.phase, 'vault_ready');
    assert.match(created.vaults.source, /^uregtest/);
    assert.equal(created.payment, null);
    await carol.locator('#fund').click();
    await alice.locator('#start-panel').waitFor({state: 'visible', timeout: 180000});
    assert.equal((await state(carol, token)).phase, 'funded');
    assert.equal(await bob.locator('#start-panel').isVisible(), false);
    await alice.locator('#amount').fill('0.12');
    await alice.locator('#memo').fill('browser workflow check');
    await alice.locator('#propose').click();
    await Promise.all([alice, bob].map(page => page.locator('#review-panel').waitFor({state: 'visible', timeout: 600000})));
    const prepared = await state(carol, token);
    assert.equal(prepared.phase, 'waiting_for_reviews');
    assert.equal(prepared.payment.amount_zat, 12_000_000);
    assert.equal(prepared.payment.memo, 'browser workflow check');
    await carol.locator('[data-view="queue"]').click();
    assert.equal(await carol.locator('#review-panel').isVisible(), false);
    const review = await alice.locator('#review-lines').innerText();
    assert.equal(review, await bob.locator('#review-lines').innerText());
    assert.match(review, /12000000 zat/);
    assert.match(review, /browser workflow check/);
    for (const [role, page, link, other] of [
      ['alice', alice, links.alice, 'Bob'], ['bob', bob, links.bob, 'Alice'],
    ]) {
      const member = await state(page, new URL(link).hash.slice(1));
      assert.equal(member.role, role);
      assert.equal(member.links, undefined);
      assert.equal(member.signers, undefined);
      assert.equal(member.review, review);
      assert.doesNotMatch(await page.locator('#approvals').innerText(), new RegExp(other));
      assert.equal(await page.locator('#finish-panel').isVisible(), false);
    }

    await alice.locator('#approve').click();
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
    assert.equal(await carol.locator('#history-amount').innerText(), '0.12 ZEC sent');
    assert.equal(await carol.locator('#history-recipient').innerText(), `To ${confirmed.payment.recipient}`);
    assert.match(await carol.locator('#history-memo').innerText(), /browser workflow check/);
    assert.deepEqual(errors, []);
    console.log(`PASS: staged member payment confirmed, txid ${confirmed.txid}`);
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
