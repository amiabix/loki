const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const {chromium} = require('../g3/node_modules/playwright-core');

// The signer review reads like a transaction: "Needs your approval", a
// prominent amount, the full recipient, memo/fee/change/expiry, and an
// effect-named button. IDs and protocol stages live in a details disclosure.
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
      else if (url.pathname === '/api/payment-sync') result = {};
      else if (url.pathname === '/api/payment-advance') result = {did: []};
      else if (url.pathname === '/api/session/pending') result = {requests: []};
      else if (url.pathname === '/api/session/actions') result = {actions: []};
      return route.fulfill({json: result, status: 200});
    });
    await page.goto('http://127.0.0.1:18801/#test-token');
    await page.locator('.vault-row').filter({hasText: 'Treasury'}).click();

    // Headline + prominent amount + full recipient.
    await page.getByRole('heading', {name: 'Needs your approval'}).waitFor();
    assert.match(await page.locator('.pay-amount').textContent(), /^0\.40000000 ZEC$/);
    assert.ok((await page.locator('.pay-addr').textContent()).includes(recipient), 'full recipient shown, not truncated');

    // Effect-named approve button exists; protocol stages are tucked in a detail.
    await page.getByRole('button', {name: 'Approve this payment'}).waitFor();
    const stagesHidden = await page.evaluate(() => {
      const d = [...document.querySelectorAll('#payment-list details.aside')].find(x => /Payment details/.test(x.textContent));
      return d && !d.open;   // details present and collapsed by default
    });
    assert.equal(stagesHidden, true, 'IDs and protocol stages live in a collapsed details');

    // Payments appear above the New payment form (pending work first).
    const order = await page.evaluate(() => {
      const list = document.querySelector('#payment-list');
      const form = document.querySelector('#payment-draft');
      return !!(list.compareDocumentPosition(form) & Node.DOCUMENT_POSITION_FOLLOWING);
    });
    assert.equal(order, true, 'payment list precedes the new-payment form');

    assert.deepEqual(errors, []);
    console.log('PASS: review reads like a transaction; stages in details; pending work before the form');
  } finally { await browser.close(); }
}

run().catch(error => { console.error(error); process.exitCode = 1; });
