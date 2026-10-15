const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const {chromium} = require('../g3/node_modules/playwright-core');

async function run() {
  const browser = await chromium.launch({headless: true,
    ...(process.env.LOKI_BROWSER_EXECUTABLE ? {executablePath: process.env.LOKI_BROWSER_EXECUTABLE} : {})});
  try {
    for (const count of [3, 4]) {
      const page = await browser.newPage();
      const errors = [];
      page.on('pageerror', error => errors.push(error.message));
      const vault = String(count).repeat(64);
      let phase = 'connecting_relays';
      const state = () => ({phase, name: 'Hosted Treasury', vault, slot: 1, threshold: 2, total_members: count,
        transport: 'hosted', handoff: phase === 'active' ? 'ready' : 'pending', missing_slots: phase === 'active' ? [] : [count],
        profile: {name: 'Alice'}, relay_setup: {phase: phase === 'active' ? 'ready' : 'waiting',
          detail: 'Hosted relays connect automatically.'}, funding: {available: false, phase: 'unavailable'}, invites: []});
      await page.route('http://127.0.0.1:18801/**', async route => {
        const url = new URL(route.request().url());
        if (!url.pathname.startsWith('/api/')) {
          const file = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
          return route.fulfill({body: await fs.readFile(path.join(__dirname, file)),
            contentType: file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : 'text/html'});
        }
        let result = {};
        if (url.pathname === '/api/status') result = url.searchParams.has('vault') ? state()
          : {phase: 'home', profile: {name: 'Alice'}, vaults: [{name: 'Hosted Treasury', vault, slot: 1, threshold: 2, members: count}],
             relay_network: {transport: 'hosted', enabled: true, detail: 'Connecting automatically.'}};
        else if (url.pathname === '/api/payments') result = {payments: []};
        else if (url.pathname === '/api/session/pending') result = {requests: []};
        else if (url.pathname === '/api/session/actions') result = {actions: []};
        return route.fulfill({json: result});
      });
      await page.goto('http://127.0.0.1:18801/#test-token');
      assert.equal(await page.locator('#setup-relays').isHidden(), true);
      await page.locator('.vault-row').filter({hasText: 'Hosted Treasury'}).click();
      await page.waitForFunction(() => document.getElementById('headline').textContent === 'Connecting payment relays');
      assert.match(await page.locator('#progress').textContent(), new RegExp(`member ${count}`));
      assert.equal(await page.locator('#show-address').isVisible(), false);
      assert.equal(await page.locator('#connect-account').isVisible(), false);
      phase = 'active';
      await page.waitForFunction(() => !document.getElementById('active').hidden);
      assert.equal(await page.locator('#payment-draft').isVisible(), true);
      assert.equal(await page.locator('#show-address').isVisible(), true);
      assert.equal(await page.locator('#payment-unavailable').isHidden(), true);
      assert.equal(await page.locator('#relay-setup').isHidden(), true);
      await page.reload();
      await page.waitForFunction(() => !document.getElementById('active').hidden);
      assert.deepEqual(errors, []);
      await page.close();
    }
    const operator = await browser.newPage();
    const localVault = 'a'.repeat(64);
    let peerCount = 2;
    let checked = false;
    await operator.route('http://127.0.0.1:18801/**', async route => {
      const url = new URL(route.request().url());
      if (!url.pathname.startsWith('/api/')) {
        const file = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
        return route.fulfill({body: await fs.readFile(path.join(__dirname, file)),
          contentType: file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : 'text/html'});
      }
      let result = {};
      if (url.pathname === '/api/status') result = url.searchParams.has('vault')
        ? {phase: 'active', name: 'Operator vault', vault: localVault, slot: 1, threshold: 2,
           total_members: 4, profile: {name: 'Alice'}, relay_setup: {phase: checked ? 'ready' : 'waiting'}}
        : {phase: 'home', profile: {name: 'Alice'}, vaults: [{name: 'Operator vault', vault: localVault, slot: 1, members: 4}]};
      else if (url.pathname === '/api/relay-status') {
        checked = peerCount === 3;
        result = {configured: checked, reachable: checked, inboxes: 3, peers: peerCount, live_relays: 2};
      } else if (url.pathname === '/api/payments') result = {payments: []};
      else if (url.pathname === '/api/session/pending') result = {requests: []};
      else if (url.pathname === '/api/session/actions') result = {actions: []};
      return route.fulfill({json: result});
    });
    await operator.goto('http://127.0.0.1:18801/#test-token');
    await operator.locator('.vault-row').filter({hasText: 'Operator vault'}).click();
    await operator.locator('#relay-setup summary').click();
    await operator.locator('#relay-check').click();
    await operator.waitForFunction(() => document.getElementById('relay-state').textContent.includes('2 of 3 encrypted peer configs'));
    peerCount = 3;
    await operator.locator('#relay-check').click();
    await operator.waitForFunction(() => document.getElementById('relay-state').textContent.includes('All peer configs are present'));
    assert.equal(await operator.locator('#payment-draft').isVisible(), true);
    await operator.close();
    const dashboard = await browser.newPage();
    await dashboard.addInitScript(() => sessionStorage.setItem('lokiSignerSession', 'hosted-session'));
    await dashboard.route('http://127.0.0.1:18801/**', async route => {
      const url = new URL(route.request().url());
      if (url.pathname === '/api/session/vaults') return route.fulfill({json: {profile: 'Alice',
        relay_network: {transport: 'hosted', enabled: true, detail: 'Connecting automatically.'},
        vaults: [{vault: '4'.repeat(64), name: 'Hosted Treasury', slot: 4, total_members: 4,
          transport: 'hosted', phase: 'connecting_relays', handoff: 'pending', missing_slots: [3],
          funding: {available: false, phase: 'unavailable'}, relay_setup: {detail: 'Connecting automatically.'}}]}});
      const file = url.pathname === '/' ? 'dashboard.html' : url.pathname.slice(1);
      let body = await fs.readFile(path.join(__dirname, file));
      if (file === 'dashboard.html') body = Buffer.from(body.toString().replace('{{SIGNER_ORIGIN}}', 'http://127.0.0.1:18801'));
      return route.fulfill({body, contentType: file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : 'text/html'});
    });
    await dashboard.goto('http://127.0.0.1:18801/');
    await dashboard.waitForFunction(() => document.getElementById('vault-list').textContent.includes('Hosted Treasury'));
    assert.equal(await dashboard.locator('#setup-relays').isVisible(), false);
    assert.equal(await dashboard.getByRole('button', {name: /Fund Vault/}).count(), 0);
    assert.match(await dashboard.locator('#vault-list').textContent(), /2 of 4/);
    assert.match(await dashboard.locator('#vault-list').textContent(), /Waiting for members 3/);
    console.log('PASS: both hosted policies, pending member, automatic activation, reopening, and no local controls');
  } finally { await browser.close(); }
}
run().catch(error => { console.error(error); process.exitCode = 1; });
