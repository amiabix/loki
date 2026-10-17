const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const {chromium} = require('../g3/node_modules/playwright-core');

// The word-entry form appears only after the words are revealed, so the backup
// step shows one action at a time.
async function run() {
  const browser = await chromium.launch({headless: true,
    ...(process.env.LOKI_BROWSER_EXECUTABLE ? {executablePath: process.env.LOKI_BROWSER_EXECUTABLE} : {})});
  try {
    const page = await browser.newPage();
    const vault = 'a'.repeat(64);
    const words = Array.from({length: 24}, (_, i) => `word${i + 1}`).join(' ');
    await page.route('http://127.0.0.1:18801/**', async route => {
      const url = new URL(route.request().url());
      if (!url.pathname.startsWith('/api/')) {
        const file = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
        return route.fulfill({body: await fs.readFile(path.join(__dirname, file)),
          contentType: file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : file.endsWith('.woff2') ? 'font/woff2' : 'text/html'});
      }
      let result = {};
      if (url.pathname === '/api/status') result = url.searchParams.has('vault')
        ? {phase: 'back_up', name: 'Gold', vault, slot: 1, threshold: 2, total_members: 3, profile: {name: 'Alice'}}
        : {phase: 'home', profile: {name: 'Alice'}, vaults: [{name: 'Gold', vault, slot: 1, threshold: 2, members: 3}]};
      else if (url.pathname === '/api/backup') result = {words};
      else if (url.pathname === '/api/session/pending') result = {requests: []};
      else if (url.pathname === '/api/session/actions') result = {actions: []};
      return route.fulfill({json: result, status: 200});
    });
    await page.goto('http://127.0.0.1:18801/#test-token');
    await page.locator('.vault-row').filter({hasText: 'Gold'}).click();
    await page.locator('#backup').waitFor({state: 'visible'});

    // Before reveal: the check form is hidden.
    assert.equal(await page.locator('#check-backup').isVisible(), false, 'word-entry hidden until reveal');
    assert.equal(await page.locator('#backup-made').isVisible(), false, 'words hidden until reveal');

    await page.getByRole('button', {name: 'Show 24 words'}).click();
    await page.locator('#backup-made').waitFor({state: 'visible'});
    assert.ok((await page.locator('#words').textContent()).includes('word1'), 'words revealed');
    assert.equal(await page.locator('#check-backup').isVisible(), true, 'word-entry appears after reveal');
    console.log('PASS: backup reveals words first, then the check form');
  } finally { await browser.close(); }
}

run().catch(error => { console.error(error); process.exitCode = 1; });
