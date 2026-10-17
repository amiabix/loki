const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const {chromium} = require('../g3/node_modules/playwright-core');

const [stage, configPath] = process.argv.slice(2);

async function wait(page, selector, timeout = 120000) {
  await page.locator(selector).waitFor({state: 'visible', timeout});
  const error = page.locator('#message.error:visible, .form-error:visible');
  assert.equal(await error.count(), 0, JSON.stringify(await error.allTextContents()));
}

async function open(browser, url) {
  const context = await browser.newContext({acceptDownloads: true});
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(url);
  return {context, page, errors};
}

// The current signer is a local Rust process. Its one-use FROST nonce material
// must not migrate into browser storage or payment API traffic as the UI evolves.
function watchBrowserNonceBoundary(page) {
  const bodies = [];
  page.on('request', request => {
    if (new URL(request.url()).pathname.startsWith('/api/'))
      bodies.push(Promise.resolve(request.postData() || ''));
  });
  page.on('response', response => {
    if (new URL(response.url()).pathname.startsWith('/api/'))
      bodies.push(response.text().catch(() => ''));
  });
  return async () => {
    const databases = await page.evaluate(() => indexedDB.databases());
    assert.deepEqual(databases, [], 'payment page created browser IndexedDB state');
    const browserStorage = await page.evaluate(() =>
      JSON.stringify({local: {...localStorage}, session: {...sessionStorage}}));
    for (const body of [...await Promise.all(bodies), browserStorage]) {
      assert.doesNotMatch(body, /"(?:nonce|nonces|nonce_secret|signing_nonces|secret|signing_share|key_package)"\s*:/i,
        'payment page received or stored signer secret material');
    }
  };
}

async function setup(browser, config) {
  const members = await Promise.all(config.urls.map(url => open(browser, url)));
  try {
    for (let i = 0; i < members.length; i++) {
      const page = members[i].page;
      await wait(page, '#new-profile');
      await page.locator('#profile-create input[name=name]').fill(`Member ${i + 1}`);
      await page.locator('#profile-create input[name=passphrase]').fill(config.passphrases[i]);
      await page.locator('#profile-create button').click();
      await wait(page, '#home');
    }
    const creator = members[0].page;
    await creator.locator('#create input[name=name]').fill('Browser treasury');
    await creator.locator('#create button').click();
    await wait(creator, '#invites');
    for (let i = 1; i < members.length; i++) {
      const row = creator.locator('.invite-row').nth(i - 1);
      await row.getByRole('button', {name: 'Show code'}).click();
      const code = await row.locator('.invite-code').textContent();
      const page = members[i].page;
      await page.getByText('Join a vault', {exact: true}).click();
      await page.locator('#join textarea[name=invite]').fill(code.trim());
      await page.locator('#join button').click();
    }
    const fingerprints = [];
    for (const {page} of members) {
      await wait(page, '#setup');
      fingerprints.push((await page.locator('#fingerprint').textContent()).trim());
    }
    assert.equal(new Set(fingerprints).size, 1, 'member apps disagree on the roster');
    for (const {page} of members) {
      await page.locator('#agree input[name=fingerprint]').fill(fingerprints[0]);
      await page.locator('#agree button').click();
    }
    for (const {page} of members) await wait(page, '#backup', 180000);
    const words = [];
    for (const {page} of members) {
      await page.locator('#make-backup button').click();
      await wait(page, '#backup-made');
      words.push((await page.locator('#words').textContent()).trim());
    }
    for (let i = 0; i < members.length; i++) {
      const page = members[i].page;
      await page.locator('#check-backup input[name=words]').fill(words[i]);
      await page.locator('#check-backup button').click();
      await wait(page, '#waiting');
      if (i === 0) assert.equal(await page.locator('#activate button').isDisabled(), true,
        'final backup must wait for the other members’ checks');
    }
    for (const {page} of members) {
      await page.waitForFunction(() => !document.querySelector('#activate button').disabled,
        null, {timeout: 120000});
    }
    for (const {page} of members) await page.locator('#activate button').click();
    for (const {page} of members) await wait(page, '#final-backup');
    const addresses = [];
    for (let i = 0; i < members.length; i++) {
      const page = members[i].page;
      await page.locator('#make-final-backup button').click();
      await wait(page, '#download-final');
      const downloadPromise = page.waitForEvent('download');
      await page.locator('#download-final').click();
      const download = await downloadPromise;
      const card = path.join(config.privateRoot, `member-${i + 1}.card`);
      await download.saveAs(card);
      await fs.chmod(card, 0o600);
      await page.locator('#check-final-backup input[name=words]').fill(words[i]);
      await page.locator('#check-final-backup input[name=card]').setInputFiles(card);
      await page.locator('#check-final-backup button').click();
      await wait(page, '#active');
      await page.locator('#show-address button').click();
      await page.waitForFunction(() => document.querySelector('#address').textContent.startsWith('uregtest1'));
      addresses.push((await page.locator('#address').textContent()).trim());
    }
    assert.equal(new Set(addresses).size, 1, 'member apps show different receive addresses');
    for (const member of members) assert.deepEqual(member.errors, []);
    return {address: addresses[0], fingerprint: fingerprints[0]};
  } finally {
    for (const member of members) await member.context.close();
  }
}

async function relay(browser, config) {
  const members = await Promise.all(config.urls.map(url => open(browser, url)));
  try {
    for (let i = 0; i < members.length; i++) {
      const page = members[i].page;
      await wait(page, '#home');
      await page.locator('.vault-row').click();
      await wait(page, '#active');
      await page.locator('#relay-setup summary').click();
      await page.locator('#relay-provision input[name=bundle]').fill(config.kits[i]);
      await page.locator('#relay-provision button').click();
      await page.locator('#message').getByText('inboxes are provisioned').waitFor();
    }
    const files = [];
    for (let i = 0; i < members.length; i++) {
      const page = members[i].page;
      await page.locator('#relay-export button').click();
      await page.locator('#relay-downloads button').first().waitFor();
      for (let j = 0; j < 2; j++) {
        const downloadPromise = page.waitForEvent('download');
        await page.locator('#relay-downloads button').nth(j).click();
        const download = await downloadPromise;
        const destination = path.join(config.privateRoot, download.suggestedFilename());
        await download.saveAs(destination);
        await fs.chmod(destination, 0o600);
        const peer = Number((await page.locator('#relay-downloads button').nth(j).textContent()).match(/member (\d+)/)[1]);
        files.push({peer, destination});
      }
    }
    for (const {peer, destination} of files) {
      const page = members[peer - 1].page;
      await page.locator('#relay-import input[name=file]').setInputFiles(destination);
      await page.locator('#relay-import button').click();
      await page.locator('#message').getByText('checked and imported').waitFor();
    }
    for (const {page} of members) {
      await page.locator('#relay-check').click();
      await page.waitForFunction(() => document.querySelector('#relay-state').textContent.includes('All peer configs are present'));
    }
    for (const member of members) assert.deepEqual(member.errors, []);
    return {relays: 'connected'};
  } finally {
    for (const member of members) await member.context.close();
  }
}

async function payment(browser, config) {
  const members = await Promise.all(config.urls.slice(0, 2).map(url => open(browser, url)));
  try {
    const checkNonceBoundaries = members.map(({page}) => watchBrowserNonceBoundary(page));
    for (const {page} of members) {
      await wait(page, '#home');
      await page.locator('.vault-row').click();
      await wait(page, '#active');
      await page.locator('#refresh-balance').click();
      await page.waitForFunction(() => document.querySelector('#balance').textContent.includes('ZEC ·'));
    }
    const creator = members[0].page;
    await creator.locator('#payment-draft input[name=recipient]').fill(config.recipient);
    await creator.locator('#payment-draft input[name=amount_zec]').fill('0.4');
    await creator.locator('#payment-draft textarea[name=memo]').fill('browser payment journey');
    await creator.locator('#payment-draft button').click();
    await creator.locator('#draft-result').waitFor({state: 'visible'});
    const reviewedRecipients = [];
    for (const [index, {page}] of members.entries()) {
      try {
        await page.getByRole('button', {name: 'Approve this exact transaction'}).waitFor({timeout: 180000});
      } catch (error) {
        await checkNonceBoundaries[index]();
        const updates = await page.locator('#payment-updates').textContent();
        const status = await page.locator('#payment-list').textContent();
        throw new Error(`approval unavailable: ${updates} | ${status}`, {cause: error});
      }
      const summary = await page.locator('#payment-list pre').textContent();
      const reviewed = summary.match(/^Recipient: (uregtest1\S+)/m)?.[1];
      assert.ok(reviewed, 'review lacks a shielded recipient');
      reviewedRecipients.push(reviewed);
      assert.ok(summary.includes('0.40000000 ZEC'), 'review lacks exact amount');
      assert.ok(summary.includes('browser payment journey'), 'review lacks memo');
      assert.ok(summary.includes('Network fee:'), 'review lacks fee');
      assert.ok(summary.includes('Change back to the vault:'), 'review lacks change');
      await page.getByRole('button', {name: 'Approve this exact transaction'}).click();
      await page.waitForFunction(() => document.querySelector('#message').textContent.includes('Approved. Your approval is on its way'), null, {timeout: 180000});
      await page.waitForFunction(() => {
        const status = document.querySelector('#payment-list').textContent;
        return status.includes('your approval reached the relays')
          || status.includes('2 approvals verified; ready to send');
      }, null, {timeout: 180000});
    }
    assert.equal(new Set(reviewedRecipients).size, 1, 'the two signers reviewed different recipients');
    for (const check of checkNonceBoundaries) await check();
    for (const member of members) {
      assert.deepEqual(member.errors, []);
      await member.context.close();
    }
    const finisher = await open(browser, config.urls[2]);
    try {
      await wait(finisher.page, '#home');
      await finisher.page.locator('.vault-row').click();
      await wait(finisher.page, '#active');
      await finisher.page.getByRole('button', {name: 'Send this payment'}).waitFor({timeout: 180000});
      await finisher.page.getByRole('button', {name: 'Send this payment'}).click();
      await finisher.page.waitForFunction(() => document.querySelector('#payment-list').textContent.includes('sent — waiting for a confirmation'), null, {timeout: 180000});
      assert.deepEqual(finisher.errors, []);
      return {broadcast: true};
    } finally { await finisher.context.close(); }
  } finally {
    for (const member of members) await member.context.close().catch(() => {});
  }
}

async function confirmed(browser, config) {
  const members = await Promise.all(config.urls.map(url => open(browser, url)));
  try {
    for (const {page} of members) {
      await wait(page, '#home');
      await page.locator('.vault-row').click();
      await wait(page, '#active');
      await page.getByRole('button', {name: 'Check for updates'}).click();
      await page.waitForFunction(() => document.querySelector('#payment-list').textContent.includes('confirmed on chain'), null, {timeout: 120000});
      await page.locator('#refresh-balance').click();
      await page.waitForFunction(() => document.querySelector('#balance').textContent.includes('ZEC ·'));
    }
    for (const member of members) assert.deepEqual(member.errors, []);
    return {membersConfirmed: members.length};
  } finally {
    for (const member of members) await member.context.close();
  }
}

async function main() {
  const config = JSON.parse(await fs.readFile(configPath, 'utf8'));
  const browser = await chromium.launch({headless: true,
    ...(process.env.LOKI_BROWSER_EXECUTABLE ? {executablePath: process.env.LOKI_BROWSER_EXECUTABLE} : {})});
  try {
    const result = await {setup, relay, payment, confirmed}[stage](browser, config);
    process.stdout.write(JSON.stringify(result) + '\n');
  } finally { await browser.close(); }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
