const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const {chromium} = require('../g3/node_modules/playwright-core');

// Home leads with Create/Join; relay + restore are collapsed disclosures below;
// the fake one-option policy selector is gone (API still gets members=3).
async function run() {
  const browser = await chromium.launch({headless: true,
    ...(process.env.LOKI_BROWSER_EXECUTABLE ? {executablePath: process.env.LOKI_BROWSER_EXECUTABLE} : {})});
  try {
    const page = await browser.newPage();
    await page.route('http://127.0.0.1:18801/**', async route => {
      const url = new URL(route.request().url());
      if (!url.pathname.startsWith('/api/')) {
        const file = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
        return route.fulfill({body: await fs.readFile(path.join(__dirname, file)),
          contentType: file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : file.endsWith('.woff2') ? 'font/woff2' : 'text/html'});
      }
      const result = url.pathname === '/api/status' ? {phase: 'home', profile: {name: 'Alice'}, vaults: []}
        : url.pathname === '/api/session/pending' ? {requests: []}
        : url.pathname === '/api/session/actions' ? {actions: []} : {};
      return route.fulfill({json: result, status: 200});
    });
    await page.goto('http://127.0.0.1:18801/#test-token');
    await page.locator('#home').waitFor({state: 'visible'});

    // Create comes before the relay diagnostics in document order.
    const order = await page.evaluate(() => {
      const create = document.querySelector('#create');
      const relay = document.querySelector('#relay-disclosure');
      return !!(create.compareDocumentPosition(relay) & Node.DOCUMENT_POSITION_FOLLOWING);
    });
    assert.equal(order, true, 'Create must appear before relay diagnostics');

    // The fake one-option policy selector is gone; members=3 still sent.
    assert.equal(await page.locator('#create select[name="members"]').count(), 0, 'policy selector must be removed');
    assert.equal(await page.locator('#create input[name="members"]').getAttribute('value'), '3');

    // Relay + restore are collapsed disclosures, not prominent cards.
    for (const id of ['#relay-disclosure', '#restore-disclosure']) {
      assert.equal(await page.locator(id).evaluate(e => e.tagName.toLowerCase()), 'details', `${id} is a details`);
      assert.equal(await page.locator(id).evaluate(e => e.open), false, `${id} starts collapsed`);
    }

    // Create is primary; Join is secondary.
    assert.equal(await page.locator('#create button').evaluate(b => b.classList.contains('secondary')), false);
    assert.equal(await page.locator('#join button').evaluate(b => b.classList.contains('secondary')), true);

    // Empty state copy.
    assert.match(await page.locator('#vault-list').textContent(), /No vaults on this device/);
    console.log('PASS: home leads with create/join; relay+restore collapsed; no fake policy selector');
  } finally { await browser.close(); }
}

run().catch(error => { console.error(error); process.exitCode = 1; });
