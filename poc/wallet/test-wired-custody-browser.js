const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const {chromium} = require('../g3/node_modules/playwright-core');

async function main() {
  const browser = await chromium.launch({headless: true});
  const page = await browser.newPage({acceptDownloads: true});
  page.setDefaultTimeout(3000);
  const vault = 'a'.repeat(64);
  const fingerprint = 'b'.repeat(64);
  const posts = [];
  let phase = 'compare_roster';
  let finalCardCreated = false;
  const finalCard = Buffer.from('LOKISEAL\x01test card');
  try {
    await page.route('http://127.0.0.1:18801/**', async route => {
      const request = route.request();
      const url = new URL(request.url());
      if (!url.pathname.startsWith('/api/')) {
        const file = url.pathname === '/ui' ? 'ui.html'
          : url.pathname.startsWith('/ui/') ? `design/${url.pathname.slice(4)}`
          : url.pathname.slice(1);
        const body = await fs.readFile(path.join(__dirname, file));
        return route.fulfill({body, contentType: file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : 'text/html'});
      }
      if (request.method() === 'POST') posts.push({path: url.pathname, body: request.postDataJSON()});
      let result = {};
      if (url.pathname === '/api/status') result = url.searchParams.has('vault')
        ? {phase, vault, name: 'Treasury', slot: 1, threshold: 2, total_members: 3,
           fingerprint, confirmations: [], final_card_created: finalCardCreated,
           final_card_needs_words: false, profile: {name: 'Alice'}}
        : {phase: 'home', profile: {name: 'Alice'}, vaults: [{vault, name: 'Treasury', slot: 1, threshold: 2, members: 3}]};
      else if (url.pathname === '/api/finalize-backup') {
        finalCardCreated = true;
        result = {created: true};
      } else if (url.pathname === '/api/final-card') result = {card: finalCard.toString('base64')};
      else if (url.pathname === '/api/verify-final-backup') result = {verified: true};
      return route.fulfill({json: result});
    });
    await page.goto('http://127.0.0.1:18801/ui#test-token');

    await page.locator('[data-go="create"]').click();
    assert.deepEqual(await page.locator('#n-sel option').allTextContents(), ['3', '4']);
    assert.deepEqual(await page.locator('#t-sel option').allTextContents(), ['2']);
    await page.locator('#n-sel').selectOption('4');
    assert.deepEqual(await page.locator('#t-sel option').allTextContents(), ['2', '3']);

    await page.locator('[data-go="setup"]').click();
    await page.waitForFunction(() => document.getElementById('setup-code').textContent.includes('BBBB'));
    await page.locator('#setup-agree').click();
    await page.waitForFunction(() => document.getElementById('setup-agree-out').textContent.includes('Type the full fingerprint'));
    assert.equal(posts.filter(p => p.path === '/api/agree').length, 0, 'empty confirmation must not start DKG');
    await page.locator('#setup-agree-out').evaluate(el => { el.textContent = ''; });
    await page.locator('#setup-fingerprint').fill('c'.repeat(64));
    await page.locator('#setup-agree').click();
    await page.waitForFunction(() => document.getElementById('setup-agree-out').textContent.includes('Type the full fingerprint'));
    assert.equal(posts.filter(p => p.path === '/api/agree').length, 0, 'wrong fingerprint must not start DKG');
    await page.locator('#setup-fingerprint').fill(fingerprint);
    await page.locator('#setup-agree').click();
    await page.waitForFunction(() => document.getElementById('setup-agree-out').textContent.includes('Roster confirmed'));
    assert.deepEqual(posts.filter(p => p.path === '/api/agree').map(p => p.body), [{vault, fingerprint}]);

    phase = 'final_backup';
    await page.locator('[data-go="setup"]').click();
    await page.locator('#setup-finalize').click();
    await page.waitForFunction(() => !document.getElementById('setup-download-final').disabled);
    assert.deepEqual(posts.filter(p => p.path === '/api/finalize-backup').map(p => p.body), [{vault}]);
    await page.locator('#setup-verify-final').click();
    assert.equal(posts.filter(p => p.path === '/api/verify-final-backup').length, 0,
      'verification needs words and a card loaded from disk');
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      page.locator('#setup-download-final').click(),
    ]);
    assert.equal(download.suggestedFilename(), 'loki-vault.card');
    assert.deepEqual(await fs.readFile(await download.path()), finalCard);
    await page.locator('#setup-final-words').fill('valid private recovery words');
    await page.locator('#setup-final-card').setInputFiles({name: 'loki-vault.card', mimeType: 'application/octet-stream', buffer: finalCard});
    await page.locator('[data-go="vaults"]').click();
    assert.equal(await page.locator('#setup-final-words').inputValue(), '', 'leaving setup clears recovery words');
    assert.equal(await page.locator('#setup-final-card').inputValue(), '', 'leaving setup clears the selected card');
    await page.locator('[data-go="setup"]').click();
    await page.locator('#setup-final-words').fill('valid private recovery words');
    await page.locator('#setup-final-card').setInputFiles({name: 'loki-vault.card', mimeType: 'application/octet-stream', buffer: finalCard});
    await page.locator('#setup-verify-final').click();
    await page.waitForFunction(() => document.getElementById('setup-final-out').textContent.includes('Final recovery card checked'));
    assert.deepEqual(posts.filter(p => p.path === '/api/verify-final-backup').map(p => p.body),
      [{vault, words: 'valid private recovery words', card: finalCard.toString('base64')}]);
  } finally {
    await browser.close();
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
