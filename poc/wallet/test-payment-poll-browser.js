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
    const address = 'utest1' + 'q'.repeat(105);
    let relayFailure = true;
    let paymentReady = false;
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
          ? {phase: 'active', network: 'testnet', birth_height: 4500000,
             name: 'Gold', vault, slot: 1, threshold: 2, total_members: 3,
             profile: {name: 'Alice'}, account_linked: true}
          : {phase: 'home', network: 'testnet', profile: {name: 'Alice'}, vaults: [{name: 'Gold', vault, slot: 1, threshold: 2, members: 3}]};
      } else if (url.pathname === '/api/payments') result = paymentReady
        ? {payments: [{attempt: 'b'.repeat(64), payment: 'c'.repeat(64),
            signers: [2, 3], phase: 'received', ready_to_send: true}],
           readiness: {relay_ready: true, relay_detail: 'Relay reachable.', scan_height: 104}}
        : {payments: []};
      else if (url.pathname === '/api/session/pending') result = {requests: []};
      else if (url.pathname === '/api/session/actions') result = {actions: []};
      else if (url.pathname === '/api/address') result = {address};
      else if (url.pathname === '/api/payment-sync' && relayFailure) result = {error: 'member_sealed', surface: 'payment-sync', retry: false};
      return route.fulfill({json: result, status: result.error ? 400 : 200});
    });
    await page.goto('http://127.0.0.1:18801/#test-token');
    await page.getByText('Join a vault', {exact: true}).click();
    assert.equal(await page.locator('#join textarea').isVisible(), true);
    await page.locator('.vault-row').filter({hasText: 'Gold'}).click();
    await page.locator('#active').waitFor({state: 'visible'});
    assert.equal(await page.locator('#network-chip').textContent(), 'ZCASH TESTNET');
    assert.match(await page.locator('#receive-note').textContent(), /block 4500000/);
    assert.equal(await page.locator('#connect-account').isVisible(), false);
    assert.doesNotMatch(await page.locator('#build-note').textContent(), /regtest/i);
    await page.getByRole('button', {name: 'Show receive address'}).click();
    await page.waitForFunction(value => document.getElementById('address').textContent === value, address);
    await page.getByRole('button', {name: 'Check for updates'}).click();
    await page.waitForFunction(() => pumpPaused);
    assert.equal(await page.locator('#message.error').isVisible(), false,
      'payment polling failure must not appear as a page-wide receive-address error');
    const status = page.locator('#payment-updates');
    assert.equal(await status.isVisible(), true);
    assert.match(await status.textContent(), /relay configuration/i);
    assert.doesNotMatch(await status.textContent(), /member_sealed/);
    assert.equal(await page.locator('#address').textContent(), address);
    relayFailure = false;
    await page.getByRole('button', {name: 'Check for updates'}).click();
    await page.waitForFunction(() => !pumping);
    assert.equal(await status.isVisible(), false, 'successful retry clears the payment error');
    paymentReady = true;
    await page.getByRole('button', {name: 'Check for updates'}).click();
    await page.getByRole('button', {name: 'Send this payment'}).waitFor();
    assert.deepEqual(errors, []);
    console.log('PASS: payment relay errors stay beside payments; receiving and retry remain available');
  } finally { await browser.close(); }
}

run().catch(error => { console.error(error); process.exitCode = 1; });
