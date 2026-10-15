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
    let setupRequested;
    let finishSetup;
    let actionRequests = 0;
    let ready = false;
    let funding = {available: true, phase: 'idle'};
    const fundingRequests = [];
    await page.addInitScript(() => sessionStorage.setItem('lokiSignerSession', 'approved-test-session'));
    await page.route('http://127.0.0.1:18801/**', async route => {
      const url = new URL(route.request().url());
      if (url.pathname === '/api/session/vaults') {
        return route.fulfill({json: {profile: 'Alice', relay_network: {enabled: ready, detail: ready ? 'Automatic relay connection is enabled.' : 'Set up local relays once.'}, vaults: [
          {vault, name: 'Gold', slot: 1, phase: 'active', funding, relay_setup: {
            phase: ready ? 'ready' : 'not_configured', available: true,
            detail: ready ? 'Local test relays are configured.' : 'Set up local test relays in each member’s app.'}},
          {vault: 'b'.repeat(64), name: 'New vault', slot: 1, phase: 'back_up', funding: {available: false, phase: 'idle'},
            relay_setup: {phase: 'not_configured', available: false, detail: 'Available after final backup.'}}
        ]}});
      }
      if (url.pathname === '/api/session/fund') {
        const request = route.request().postDataJSON();
        fundingRequests.push(request);
        if (fundingRequests.length === 1) {
          funding = {available: true, phase: 'failed', request_id: request.request_id, detail: 'Retry funding to check the same request.'};
          return route.fulfill({status: 500, json: {error: 'Confirmation response lost'}});
        }
        funding = {available: true, phase: 'confirmed', request_id: request.request_id, detail: '5 test ZEC confirmed.'};
        return route.fulfill({json: {status: 'confirmed', amount_zatoshi: 500000000, txid: 'c'.repeat(64)}});
      }
      if (url.pathname === '/api/session/relay-setup-all') {
        setupRequested = route.request().postDataJSON();
        await new Promise(resolve => { finishSetup = resolve; });
        ready = true;
        return route.fulfill({json: {relay_setup: true}});
      }
      if (url.pathname.startsWith('/api/session/action')) {
        actionRequests++;
        return route.fulfill({status: 400, json: {error: 'Relay setup should run directly'}});
      }
      const file = url.pathname === '/' ? 'dashboard.html' : url.pathname.slice(1);
      let body = await fs.readFile(path.join(__dirname, file));
      if (file === 'dashboard.html') body = Buffer.from(body.toString().replace('{{SIGNER_ORIGIN}}', 'http://127.0.0.1:18801'));
      return route.fulfill({body, contentType: file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : file.endsWith('.woff2') ? 'font/woff2' : 'text/html'});
    });
    await page.goto('http://127.0.0.1:18801/');
    assert.equal(await page.locator('#vault-list button').count(), 2);
    assert.equal(await page.getByRole('button', {name: 'Fund Vault for New vault'}).isDisabled(), true);
    assert.equal(await page.getByRole('button', {name: 'Set up relays', exact: true}).count(), 1);
    const setupRequest = page.waitForRequest(/\/api\/session\/relay-setup-all$/);
    await page.getByRole('button', {name: 'Set up relays', exact: true}).click();
    await page.waitForFunction(() => document.getElementById('relay-network-detail').textContent.includes('Starting local relays'));
    assert.equal(await page.locator('#setup-relays').isDisabled(), true);
    await setupRequest;
    assert.deepEqual(setupRequested, {});
    assert.equal(actionRequests, 0);
    finishSetup();
    await page.getByRole('button', {name: 'Retry connections'}).waitFor();
    assert.match(await page.locator('#message').textContent(), /Local relays are running/);
    assert.match(await page.locator('#vault-list').textContent(), /Local test relays are configured/);
    await page.getByRole('button', {name: 'Fund Vault for Gold'}).click();
    await page.getByRole('button', {name: 'Retry funding for Gold'}).waitFor();
    assert.equal(fundingRequests[0].vault, vault);
    assert.match(fundingRequests[0].request_id, /^[0-9a-f]{32}$/);
    await page.getByRole('button', {name: 'Retry funding for Gold'}).click();
    await page.waitForFunction(() => document.getElementById('message').textContent.includes('with 5 local test ZEC'));
    assert.deepEqual(fundingRequests[1], fundingRequests[0]);
    assert.match(await page.locator('#vault-list').textContent(), /5 test ZEC confirmed/);
    await page.evaluate(({vault, request}) => sessionStorage.setItem(`lokiFundingRequest:${vault}`, request),
      {vault, request: fundingRequests[1].request_id});
    await page.reload();
    await page.getByRole('button', {name: 'Fund Vault for Gold'}).waitFor();
    assert.equal(await page.evaluate(vault => sessionStorage.getItem(`lokiFundingRequest:${vault}`), vault), null);
    await page.getByRole('button', {name: 'Fund Vault for Gold'}).click();
    await page.waitForFunction(() => document.getElementById('message').textContent.includes('with 5 local test ZEC'));
    assert.notEqual(fundingRequests[2].request_id, fundingRequests[1].request_id);
    await page.setViewportSize({width: 375, height: 900});
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    assert.deepEqual(errors, []);
    console.log('PASS: single relay setup, per-vault funding, same-request funding retry, progress refresh, and mobile layout');
  } finally { await browser.close(); }
}
run().catch(error => { console.error(error); process.exitCode = 1; });
