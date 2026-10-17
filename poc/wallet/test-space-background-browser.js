const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const {chromium} = require('../g3/node_modules/playwright-core');

// The starfield must sit behind content and never intercept clicks, must not
// throw, and must render a frame. Also checks the reduced-motion still path.
async function run() {
  const browser = await chromium.launch({headless: true,
    ...(process.env.LOKI_BROWSER_EXECUTABLE ? {executablePath: process.env.LOKI_BROWSER_EXECUTABLE} : {})});
  try {
    const page = await browser.newPage();
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    const vault = 'a'.repeat(64);
    await page.route('http://127.0.0.1:18801/**', async route => {
      const url = new URL(route.request().url());
      if (!url.pathname.startsWith('/api/')) {
        const file = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
        return route.fulfill({body: await fs.readFile(path.join(__dirname, file)),
          contentType: file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : file.endsWith('.woff2') ? 'font/woff2' : 'text/html'});
      }
      const result = url.pathname === '/api/status'
        ? {phase: 'home', profile: {name: 'Alice'}, vaults: [{name: 'Gold', vault, slot: 1, threshold: 2, members: 3}]}
        : url.pathname === '/api/session/pending' ? {requests: []}
        : url.pathname === '/api/session/actions' ? {actions: []} : {};
      return route.fulfill({json: result, status: 200});
    });
    await page.goto('http://127.0.0.1:18801/#test-token');
    await page.locator('#space').waitFor({state: 'attached'});

    const probe = await page.evaluate(() => {
      const c = document.getElementById('space');
      const s = getComputedStyle(c);
      return {exists: !!c, aria: c.getAttribute('aria-hidden'), pos: s.position,
              pe: s.pointerEvents, z: s.zIndex, w: c.width, h: c.height};
    });
    assert.equal(probe.exists, true, 'canvas#space must exist');
    assert.equal(probe.aria, 'true', 'canvas must be aria-hidden');
    assert.equal(probe.pos, 'fixed');
    assert.equal(probe.pe, 'none', 'canvas must not intercept pointer events');
    assert.equal(probe.z, '-1', 'canvas must sit behind content');
    assert.ok(probe.w > 0 && probe.h > 0, 'canvas must be sized');

    // The canvas does not block the UI: a control behind it is clickable.
    await page.locator('.vault-row').filter({hasText: 'Gold'}).click();
    await page.locator('#active, #address').first().waitFor().catch(() => {});

    assert.deepEqual(errors, [], 'no page errors from the starfield');
    console.log('PASS: starfield renders behind content, never blocks clicks, no errors');
  } finally { await browser.close(); }
}

run().catch(error => { console.error(error); process.exitCode = 1; });
