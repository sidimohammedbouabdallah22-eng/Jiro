// Full Chromium asset/session workloads through an owned source-bound HTTP proxy.
const { chromium } = require('../ui-check/node_modules/playwright');
const fs = require('node:fs/promises');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');

function waveDelay(epoch, intervalMs, wave, now) {
  return Math.max(0, epoch + wave * intervalMs - now);
}

async function saveFailureArtifacts(page, directory, prefix, clean) {
  const errors = {};
  try {
    await page.screenshot({ path: directory + '/' + prefix + '.png', timeout: 5000 });
  } catch (error) {
    errors.screenshot = clean(error.message).slice(0, 800);
  }
  try {
    const content = await page.content();
    await fs.writeFile(directory + '/' + prefix + '.private.html', content);
  } catch (error) {
    errors.html = clean(error.message).slice(0, 800);
  }
  return errors;
}

async function main() {
  const [privatePath, outputPath] = process.argv.slice(2);
  const f = JSON.parse(await fs.readFile(privatePath, 'utf8'));
  const report = { passed: false, profile: f.profile, waves: [], responses: [], failures: [], blockedExternal: [] };
  const secrets = [f.erpPassword, f.shopPassword, f.apiKey];
  const clean = value => secrets.reduce((text, secret) => text.split(secret).join('[REDACTED]'), String(value));
  const allowed = new Set(['erp.joint.test', 'shop.joint.test']);
  const browser = await chromium.launch({
    executablePath: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', headless: true,
    args: ['--disable-background-networking', '--proxy-bypass-list=<-loopback>'],
  });
  report.browser_version = browser.version();
  const bytes = await fs.readFile(f.uploadFixture);
  const hash = data => createHash('sha256').update(data).digest('hex');
  const users = [
    { app: 'dolibarr', login: 'lab-admin', id: f.erpUsers['lab-admin'] },
    { app: 'dolibarr', login: 'lab-reader', id: f.erpUsers['lab-reader'] },
    { app: 'prestashop', login: 'customer@example.invalid' },
    { app: 'prestashop', login: f.natEmail },
  ];
  async function uploadPair(context, wave) {
    return Promise.all([0, 1].map(async index => {
      const filename = `fair-${f.tag}-${f.profile}-${wave}-${index}.csv`;
      const body = { filename, modulepart: 'invoice', ref: f.invoiceRef,
        filecontent: bytes.toString('base64'), fileencoding: 'base64', overwriteifexists: 0 };
      const start = performance.now();
      const flow = { name: filename, ref: f.invoiceRef, kind: 'api', bytes: bytes.length,
        sha256: hash(bytes), committed: false, exact: false };
      try {
        const response = await context.request.post(f.erpOrigin + '/api/index.php/documents/upload', {
          data: body, headers: { DOLAPIKEY: f.apiKey }, timeout: 45000,
        });
        flow.upload_status = response.status();
        flow.committed = response.status() === 200;
        if (response.status() >= 500) {
          const detail = await response.text();
          const admissionRefusal = response.status() === 503 && [
            'Application admission share exhausted\n', 'Client buffer share exhausted\n',
            'Client concurrency share exhausted\n', 'Process inspection capacity exhausted\n',
          ].includes(detail);
          flow.commit_unknown = !admissionRefusal;
        }
        if (flow.committed) {
          const download = await context.request.get(f.erpOrigin + '/api/index.php/documents/download?modulepart=invoice&original_file=' +
            encodeURIComponent(f.invoiceRef + '/' + filename), { headers: { DOLAPIKEY: f.apiKey }, timeout: 45000 });
          flow.download_status = download.status();
          if (flow.download_status === 200) flow.exact = Buffer.from((await download.json()).content, 'base64').equals(bytes);
        }
      } catch (error) {
        flow.error = clean(error.message).slice(0, 800);
        flow.commit_unknown = flow.commit_unknown || flow.upload_status === undefined;
      }
      flow.elapsed_ms = performance.now() - start;
      return flow;
    }));
  }
  async function session(user, wave) {
    const index = users.indexOf(user);
    const proxy = f.sharedNat ? f.proxies[0] : f.proxies[index];
    const context = await browser.newContext({ proxy: { server: proxy, bypass: '<-loopback>' } });
    const page = await context.newPage();
    const cdp = await context.newCDPSession(page);
    await cdp.send('Network.enable');
    page.setDefaultTimeout(15000);
    page.setDefaultNavigationTimeout(30000);
    const facts = { app: user.app, user: user.login, wave, passed: false, navigations: [], uploads: [] };
    facts.cache_hits = 0;
    cdp.on('Network.requestServedFromCache', () => facts.cache_hits++);
    page.on('response', response => {
      const url = new URL(response.url());
      if (!allowed.has(url.hostname)) {
        if (['localhost', '127.0.0.1'].includes(url.hostname)) report.failures.push({ error: 'uncanonical-local-origin', path: url.pathname });
        return;
      }
      report.responses.push({ wave, user: user.login, app: user.app, path: url.pathname,
        type: response.request().resourceType(), status: response.status(),
        fromServiceWorker: response.fromServiceWorker() });
    });
    page.on('requestfailed', request => {
      const url = new URL(request.url());
      const row = { wave, user: user.login, app: user.app, path: url.pathname,
        type: request.resourceType(), error: request.failure()?.errorText };
      (allowed.has(url.hostname) || ['localhost', '127.0.0.1'].includes(url.hostname) ? report.failures : report.blockedExternal).push(row);
    });
    async function navigate(url, label) {
      const start = performance.now();
      const response = await page.goto(url, { waitUntil: 'networkidle' });
      assert.equal(response.status(), 200);
      facts.navigations.push({ label, elapsed_ms: performance.now() - start });
    }
    try {
      const origin = user.app === 'dolibarr' ? f.erpOrigin : f.shopOrigin;
      await navigate(user.app === 'dolibarr' ? origin + '/index.php' : f.routes.login, 'cold-login-page');
      if (user.app === 'dolibarr') {
        await page.locator('input[name=username]').fill(user.login);
        await page.locator('input[name=password]').fill(f.erpPassword);
        await page.locator('input[type=submit], button[type=submit]').first().click();
        await page.waitForLoadState('networkidle');
        assert.ok(await page.locator('a[href*="logout.php"]').count(), 'ERP authentication missing');
        const self = await page.locator('a[href*="user/card.php?id="]').first().getAttribute('href');
        assert.equal(Number(new URL(self, origin).searchParams.get('id')), user.id);
        facts.authenticated_id = user.id;
        await navigate(origin + '/societe/list.php', 'customer-list');
        await navigate(origin + '/societe/list.php', 'warm-customer-list');
      } else {
        await page.locator('#login-form input[name=email]').fill(user.login);
        await page.locator('#login-form input[name=password]').fill(f.shopPassword);
        await page.locator('#submit-login').click();
        await page.waitForLoadState('networkidle');
        assert.ok(await page.locator('a.logout, a[href*="mylogout"]').count(), 'storefront authentication missing');
        await navigate(f.routes.addresses, 'saved-address');
        assert.ok((await page.locator('body').innerText()).includes('12 Example Street'));
        await navigate(origin + '/index.php?controller=identity', 'account-identity');
        assert.equal(await page.locator('#field-email').inputValue(), user.login);
        facts.authenticated_email = user.login;
        const category = await page.locator('a[data-ps-ref="desktop-menu-link"]').first().getAttribute('href');
        assert.equal(new URL(category).origin, origin);
        await navigate(category, 'catalog-category');
        await navigate(f.routes.product, 'product');
        assert.ok((await page.locator('body').innerText()).includes('OpenWAF Qualification Product'));
        await navigate(f.routes.product, 'warm-product');
      }
      const cookies = await context.cookies(origin);
      facts.cookie_fingerprints = cookies.map(cookie => ({ name: cookie.name, sha256: hash(Buffer.from(cookie.value)) }));
      if (user.login === 'lab-admin' && f.uploads) {
        facts.uploads = await uploadPair(context, wave);
        assert.ok(facts.uploads.every(upload => upload.exact), 'parallel file round trip failed');
      }
      facts.passed = true;
    } catch (error) {
      facts.error = clean(error.message).slice(0, 800);
      const prefix = `${f.profile}-${wave}-${users.indexOf(user)}`;
      facts.diagnostic_errors = await saveFailureArtifacts(page, f.outputDirectory, prefix, clean);
    } finally {
      await context.close();
    }
    return facts;
  }
  try {
    const epoch = performance.now();
    report.schedule_version = 2;
    report.interval_ms = f.intervalMs;
    const apiContext = await browser.newContext({ proxy: { server: f.proxies[0], bypass: '<-loopback>' } });
    try { report.initial_uploads = await uploadPair(apiContext, 'api'); } finally { await apiContext.close(); }
    for (let wave = 0; wave < f.waves; wave++) {
      let delay = waveDelay(epoch, f.intervalMs, wave, performance.now());
      while (delay > 0) {
        await new Promise(resolve => setTimeout(resolve, Math.ceil(delay)));
        delay = waveDelay(epoch, f.intervalMs, wave, performance.now());
      }
      const start = performance.now();
      const results = [];
      if (f.sequential) {
        for (const user of users) results.push(await session(user, wave));
      } else {
        results.push(...await Promise.all(users.map(user => session(user, wave))));
      }
      const scheduledStart = wave * f.intervalMs;
      report.waves.push({ wave, sessions: results, elapsed_ms: performance.now() - start,
        scheduled_start_ms: scheduledStart, started_ms: start - epoch,
        start_delay_ms: Math.max(0, start - epoch - scheduledStart) });
      await fs.writeFile(outputPath, JSON.stringify(report, null, 2));
    }
    report.work_elapsed_ms = performance.now() - epoch;
    report.passed = report.waves.every(wave => wave.sessions.every(session => session.passed)) &&
      report.responses.every(response => response.status < 400) && report.failures.length === 0 &&
      report.initial_uploads.every(upload => upload.exact);
  } catch (error) {
    report.harness_error = clean(error.message).slice(0, 2400);
    throw error;
  } finally {
    await browser.close();
    await fs.writeFile(outputPath, JSON.stringify(report, null, 2));
  }
}
module.exports = { waveDelay, saveFailureArtifacts };
if (require.main === module) {
  main().catch(error => { console.error(error.name); process.exitCode = 1; });
}
