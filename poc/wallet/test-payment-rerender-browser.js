const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const {chromium} = require('../g3/node_modules/playwright-core');

async function run() {
  const browser = await chromium.launch({headless: true,
    ...(process.env.LOKI_BROWSER_EXECUTABLE ? {executablePath: process.env.LOKI_BROWSER_EXECUTABLE} : {})});
  try {
    const page = await browser.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    const vault = 'a'.repeat(64);
    const attempt = 'b'.repeat(64);
    let syncs = 0;
    let phase = 'package';
    await page.route('http://127.0.0.1:18801/**', async route => {
      const url = new URL(route.request().url());
      if (!url.pathname.startsWith('/api/')) {
        const file = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
        return route.fulfill({body: await fs.readFile(path.join(__dirname, file)),
          contentType: file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : file.endsWith('.woff2') ? 'font/woff2' : 'text/html'});
      }
      let result = {};
      if (url.pathname === '/api/status') {
        result = url.searchParams.has('vault')
          ? {phase: 'active', name: 'Gold', vault, slot: 1, threshold: 2, total_members: 3,
             profile: {name: 'Alice'}, account_linked: true}
          : {phase: 'home', profile: {name: 'Alice'}, vaults: [{name: 'Gold', vault, slot: 1, threshold: 2, members: 3}]};
      } else if (url.pathname === '/api/payments') {
        result = {payments: [{attempt, payment: 'c'.repeat(64), pair: [1, 2], phase, ready_to_send: false}]};
      } else if (url.pathname === '/api/payment-review') {
        result = {recipient: 'uregtest1xyz', amount_zat: '150000000', memo_utf8: 'lunch',
                  fee_zat: '10000', change_zat: '0', expiry_height: 500, review_token: 'tok-1'};
      } else if (url.pathname === '/api/payment-sync') { syncs++; result = {}; }
      else if (url.pathname === '/api/session/pending') result = {requests: []};
      else if (url.pathname === '/api/session/actions') result = {actions: []};
      return route.fulfill({json: result, status: result.error ? 400 : 200});
    });
    await page.goto('http://127.0.0.1:18801/#test-token');
    await page.locator('.vault-row').filter({hasText: 'Gold'}).click();
    const approve = page.getByRole('button', {name: 'Approve this exact transaction'});
    await approve.waitFor();
    await approve.evaluate(node => { node.dataset.probe = 'kept'; node.focus(); });
    // A manual sync followed by a read must preserve the approval control.
    const synced = page.waitForResponse(response => response.url().includes('/api/payment-sync'));
    const refreshed = page.waitForResponse(response => response.url().includes('/api/payments?'));
    await page.evaluate(() => document.getElementById('refresh-payments').dispatchEvent(new MouseEvent('click', {bubbles: true})));
    await synced;
    await refreshed;
    assert.equal(syncs, 1);
    assert.equal(await approve.getAttribute('data-probe'), 'kept',
      'Approve button DOM node must survive an unchanged payment read');
    assert.equal(await page.evaluate(() => document.activeElement?.dataset?.probe), 'kept',
      'focus must stay on the Approve button across a poll');
    phase = 'approved';
    await page.locator('#refresh-payments').click();
    await page.waitForFunction(() => document.querySelector('#payment-list')?.textContent.includes('your approval reached the relays'));
    assert.equal(await page.locator('#payment-list .card').count(), 1,
      'a changed payment replaces its previous card');
    assert.deepEqual(errors, []);
    console.log('PASS: payment cards persist across unchanged polls and replace changed cards once');
  } finally { await browser.close(); }
}

run().catch(error => { console.error(error); process.exitCode = 1; });
