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
    const address = 'uregtest1' + 'q'.repeat(105);
    let relayFailure = true;
    let paymentReady = false;
    let selectedPair = null;
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
      } else if (url.pathname === '/api/payments') result = paymentReady
        ? {payments: [{attempt: 'b'.repeat(64), payment: 'c'.repeat(64),
            pair: [2, 3], phase: 'received', ready_to_send: true}],
           readiness: {relay_ready: true, relay_detail: 'Relay reachable.', scan_height: 104}}
        : {payments: []};
      else if (url.pathname === '/api/session/pending') result = {requests: []};
      else if (url.pathname === '/api/session/actions') result = {actions: []};
      else if (url.pathname === '/api/address') result = {address};
      else if (url.pathname === '/api/payment-draft') {
        selectedPair = route.request().postDataJSON().pair;
        result = {payment: 'c'.repeat(64), attempt: 'b'.repeat(64), pair: [2, 3]};
      }
      else if (url.pathname === '/api/payment-sync' && relayFailure) result = {error: 'member_sealed', surface: 'payment-sync', retry: false};
      return route.fulfill({json: result, status: result.error ? 400 : 200});
    });
    await page.goto('http://127.0.0.1:18801/#test-token');
    await page.locator('.vault-row').filter({hasText: 'Gold'}).click();
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
    await page.locator('#payment-draft input[name="recipient"]').fill(address);
    await page.locator('#payment-draft input[name="amount_zec"]').fill('0.5');
    await page.locator('#payment-draft textarea[name="memo"]').fill('Payment');
    assert.equal(await page.locator('#payment-draft option[value="AD"]').evaluate(option => option.disabled), true);
    await page.locator('#payment-draft select[name="pair"]').selectOption('BC');
    await page.getByRole('button', {name: 'Propose payment'}).click();
    await page.waitForFunction(() => document.getElementById('draft-result').textContent.includes('Signers: members 2 and 3'));
    assert.equal(selectedPair, 'BC');
    relayFailure = false;
    await page.getByRole('button', {name: 'Check for updates'}).click();
    await page.waitForFunction(() => !pumping);
    assert.equal(await status.isVisible(), false, 'successful retry clears the payment error');
    paymentReady = true;
    await page.getByRole('button', {name: 'Check for updates'}).click();
    await page.getByRole('button', {name: 'Send this payment'}).waitFor();
    assert.deepEqual(errors, []);
    console.log('PASS: payment retry, receiving, and chosen signer pair remain available');
  } finally { await browser.close(); }
}

run().catch(error => { console.error(error); process.exitCode = 1; });
