const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const {chromium} = require('../g3/node_modules/playwright-core');

// Overview shows a compact "Needs your approval" summary + Review payment.
// Review payment opens a focused view (amount, full recipient, fields, Approve,
// Back) that replaces the overview. Approve binds the review token.
async function run() {
  const browser = await chromium.launch({headless: true,
    ...(process.env.LOKI_BROWSER_EXECUTABLE ? {executablePath: process.env.LOKI_BROWSER_EXECUTABLE} : {})});
  try {
    const page = await browser.newPage();
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    const vault = 'a'.repeat(64);
    const attempt = 'b'.repeat(64);
    const recipient = 'uregtest1' + 'q'.repeat(90);
    let approveBody = null;
    await page.route('http://127.0.0.1:18801/**', async route => {
      const url = new URL(route.request().url());
      if (!url.pathname.startsWith('/api/')) {
        const file = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
        return route.fulfill({body: await fs.readFile(path.join(__dirname, file)),
          contentType: file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : file.endsWith('.woff2') ? 'font/woff2' : 'text/html'});
      }
      let result = {};
      if (url.pathname === '/api/status') result = url.searchParams.has('vault')
        ? {phase: 'active', name: 'Treasury', vault, slot: 1, threshold: 2, total_members: 3, profile: {name: 'Alice'}, account_linked: true}
        : {phase: 'home', profile: {name: 'Alice'}, vaults: [{name: 'Treasury', vault, slot: 1, threshold: 2, members: 3}]};
      else if (url.pathname === '/api/payments') result = {payments: [{attempt, payment: 'c'.repeat(64), pair: [1, 2], phase: 'package', ready_to_send: false}]};
      else if (url.pathname === '/api/payment-review') result = {recipient, amount_zat: '40000000',
        memo_utf8: 'rent', fee_zat: '10000', change_zat: '459990000', expiry_height: 1234, review_token: 'tok-1'};
      else if (url.pathname === '/api/payment-approve') { approveBody = JSON.parse(route.request().postData()); result = {ok: true}; }
      else if (url.pathname === '/api/payment-sync') result = {};
      else if (url.pathname === '/api/payment-advance') result = {did: []};
      else if (url.pathname === '/api/session/pending') result = {requests: []};
      else if (url.pathname === '/api/session/actions') result = {actions: []};
      return route.fulfill({json: result, status: 200});
    });
    await page.goto('http://127.0.0.1:18801/#test-token');
    await page.locator('.vault-row').filter({hasText: 'Treasury'}).click();

    // Overview: compact summary + Review payment button; Approve not yet shown.
    await page.getByRole('heading', {name: 'Needs your approval'}).waitFor();
    assert.match(await page.locator('#payment-list .pay-amount').textContent(), /^0\.40000000 ZEC$/);
    assert.ok((await page.locator('#payment-list .pay-addr').textContent()).includes(recipient), 'full recipient in overview');
    await page.getByRole('button', {name: 'Review payment'}).waitFor();
    assert.equal(await page.getByRole('button', {name: 'Approve this payment'}).isVisible(), false, 'approve hidden until the focused view opens');
    // Protocol stages are collapsed in the overview card.
    const stagesCollapsed = await page.evaluate(() => {
      const d = [...document.querySelectorAll('#payment-list details.aside')].find(x => /Payment details/.test(x.textContent));
      return d && !d.open;
    });
    assert.equal(stagesCollapsed, true, 'IDs and protocol stages collapsed in the overview');
    // Pending work precedes the new-payment form.
    assert.equal(await page.evaluate(() => {
      const list = document.querySelector('#payment-list'), form = document.querySelector('#payment-draft');
      return !!(list.compareDocumentPosition(form) & Node.DOCUMENT_POSITION_FOLLOWING);
    }), true, 'payment list precedes the new-payment form');

    // Open the focused review: overview is replaced.
    await page.getByRole('button', {name: 'Review payment'}).click();
    await page.locator('#review-view').waitFor({state: 'visible'});
    assert.equal(await page.locator('#active').isVisible(), false, 'overview hidden while reviewing');
    assert.match(await page.locator('#review-view .pay-amount').textContent(), /^0\.40000000 ZEC$/);
    assert.ok((await page.locator('#review-addr').textContent()).includes(recipient), 'full recipient in review');
    assert.ok((await page.locator('#review-fields').textContent()).includes('rent'), 'memo shown in review');
    await page.getByRole('button', {name: 'Approve this payment'}).waitFor();
    await page.getByRole('button', {name: '← Back to vault'}).waitFor();

    // Approve binds the exact review token.
    await page.getByRole('button', {name: 'Approve this payment'}).click();
    await page.waitForFunction(() => document.getElementById('review-view').hidden);
    assert.deepEqual(approveBody, {vault, attempt, review_token: 'tok-1'}, 'approve posts the exact review token');
    assert.equal(await page.locator('#active').isVisible(), true, 'returns to the overview after approving');

    assert.deepEqual(errors, []);
    console.log('PASS: compact summary → focused review → token-bound approve → back to overview');
  } finally { await browser.close(); }
}

run().catch(error => { console.error(error); process.exitCode = 1; });
