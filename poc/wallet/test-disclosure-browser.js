const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const {chromium} = require('../g3/node_modules/playwright-core');

async function run() {
  const browser = await chromium.launch({headless: true,
    ...(process.env.LOKI_BROWSER_EXECUTABLE ? {executablePath: process.env.LOKI_BROWSER_EXECUTABLE} : {})});
  try {
    const page = await browser.newPage();
    const vault = 'a'.repeat(64);
    await page.route('http://127.0.0.1:18801/**', async route => {
      const url = new URL(route.request().url());
      if (!url.pathname.startsWith('/api/')) {
        const file = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
        return route.fulfill({body: await fs.readFile(path.join(__dirname, file)),
          contentType: file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : file.endsWith('.woff2') ? 'font/woff2' : 'text/html'});
      }
      let result = {};
      if (url.pathname === '/api/status') result = {phase: 'home', profile: {name: 'Alice'},
        vaults: [{name: 'Gold', vault, slot: 1, threshold: 2, members: 3}]};
      else if (url.pathname === '/api/session/pending') result = {requests: []};
      else if (url.pathname === '/api/session/actions') result = {actions: []};
      return route.fulfill({json: result, status: 200});
    });
    await page.goto('http://127.0.0.1:18801/#test-token');
    await page.locator('#home').waitFor({state: 'visible'});
    // The "Join a vault" explanation is collapsed behind a disclosure by default.
    // (The details sits in the card section, a sibling of #join, so locate it by content.)
    const joinAside = page.locator('details.aside').filter({hasText: 'Paste the invite'});
    assert.equal(await joinAside.count(), 1, 'join explanation must be wrapped in details.aside');
    const joinBody = joinAside.locator('p');
    assert.equal(await joinBody.isVisible(), false, 'educational prose must be hidden until expanded');
    assert.equal(await joinAside.locator('summary').isVisible(), true, 'the disclosure summary is visible');
    // Opening it reveals the prose.
    await joinAside.locator('summary').click();
    assert.equal(await joinBody.isVisible(), true, 'expanding shows the prose');
    // A short instruction we did NOT collapse stays plainly visible.
    assert.equal(await page.getByText('2 of 3 members must approve a payment.').isVisible(), true,
      'short instructions must not be collapsed');
    console.log('PASS: educational asides collapse by default; instructions stay visible');
  } finally { await browser.close(); }
}

run().catch(error => { console.error(error); process.exitCode = 1; });
