const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const {chromium} = require('../g3/node_modules/playwright-core');

// Locks the premium-refresh intent: rounded cards/buttons, a real focus ring,
// and no all-caps shouting in the footer. A future edit that reverts to the
// beveled/uppercase HUD skin fails here.
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
      // Fresh install: the create-profile screen.
      const result = url.pathname === '/api/status' ? {phase: 'new_profile', network: 'regtest'} : {};
      return route.fulfill({json: result, status: 200});
    });
    await page.goto('http://127.0.0.1:18801/#test-token');
    await page.locator('#new-profile').waitFor({state: 'visible'});

    const radius = (sel) => page.evaluate(s => parseFloat(getComputedStyle(document.querySelector(s)).borderTopLeftRadius) || 0, sel);
    assert.ok(await radius('#new-profile') >= 12, 'cards must be rounded (>=12px), not beveled');

    const button = page.getByRole('button', {name: 'Create profile'});
    await button.waitFor();
    assert.ok(await button.evaluate(b => parseFloat(getComputedStyle(b).borderTopLeftRadius) || 0) >= 8,
      'primary button must be rounded (>=8px)');

    // Focus ring: focusing the name input must produce a non-none box-shadow.
    await page.locator('#profile-create input[name="name"]').focus();
    const ring = await page.locator('#profile-create input[name="name"]').evaluate(el => getComputedStyle(el).boxShadow);
    assert.notEqual(ring, 'none', 'inputs must show a focus ring');

    // No all-caps shouting in the footer.
    const footerTransform = await page.evaluate(() => {
      const el = document.querySelector('main > p.muted:last-child');
      return el ? getComputedStyle(el).textTransform : 'MISSING';
    });
    assert.equal(footerTransform, 'none', 'footer must not be uppercased');

    console.log('PASS: rounded cards + buttons, focus ring present, footer not shouting');
  } finally { await browser.close(); }
}

run().catch(error => { console.error(error); process.exitCode = 1; });
