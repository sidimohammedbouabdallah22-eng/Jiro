// Real, synthetic business workflows in the owned loopback-only lab.
const { chromium, request } = require('../ui-check/node_modules/playwright');
const fs = require('node:fs/promises');
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');

async function main() {
  const [privatePath, resultPath] = process.argv.slice(2);
  const f = JSON.parse(await fs.readFile(privatePath, 'utf8'));
  const origin = new URL(f.origin);
  assert.equal(origin.protocol, 'http:'); assert.equal(origin.hostname, 'localhost');
  const report = { passed: false, app: f.app, package_sha256: f.package_sha256,
    coverage: f.app==='dolibarr' ? 'business-v3-native' : 'business-v2-cart',
    server_sha256: f['waf-server_sha256'], image: f.image, started: new Date().toISOString(), cases: [] };
  const save = () => fs.writeFile(resultPath, JSON.stringify(report, null, 2));
  async function test(name, fn) {
    try { const facts = await fn(); report.cases.push({ name, passed: true, ...facts }); }
    catch (e) { report.cases.push({ name, passed: false, error: e.message }); throw e; }
    finally { await save(); }
  }
  const http = await request.newContext({ baseURL: f.origin, timeout: 30000 });
  const browser = await chromium.launch({ executablePath: process.env.CHROME_PATH || 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', headless: true });
  const context = await browser.newContext(); const page = await context.newPage();
  const unexpectedBrowserRefusals = [];
  page.on('response', response => {
    if ([403,413,421,429,502,503].includes(response.status())) {
      unexpectedBrowserRefusals.push({status:response.status(),path:new URL(response.url()).pathname});
    }
  });
  await context.route('**/*', route => {
    const url = new URL(route.request().url());
    return ['localhost','127.0.0.1'].includes(url.hostname) ? route.continue() : route.abort();
  });
  const id = randomUUID().slice(0, 8);
  async function api(method, path, data, expected = [200], key = f.api_key) {
    const res = await http.fetch('/api/index.php/' + path, {
      method, data, headers: key ? { DOLAPIKEY: key } : {}, failOnStatusCode: false,
    });
    if (!expected.includes(res.status())) {
      let detail='';
      try { detail=(await res.json()).error?.message || ''; } catch {}
      for (const value of [f.api_key,f.password,f.token,f.reader_api_key].filter(Boolean)) detail=detail.split(value).join('[REDACTED]');
      assert.fail(`${method} ${path.split('?')[0]}: expected ${expected}, received ${res.status()} ${detail.slice(0,200)}`);
    }
    if ([401, 403].includes(res.status())) return res;
    return res.json();
  }
  async function admin(endpoint, data) {
    const res = await http.fetch('http://127.0.0.1:' + f.ports.admin + '/api/v1/' + endpoint,
      { method: data ? 'POST' : 'GET', data, headers: { Authorization: 'Bearer ' + f.token } });
    assert.equal(res.status(), 200); return res.json();
  }
  try {
    const beforeStatus = await admin('status');
    report.before_status = beforeStatus;
    const allEvents=require('./event-oracle.cjs');
    const baseline = await allEvents(admin);
    assert.equal(baseline.items.length,beforeStatus.storage.stored);
    report.before_event_ids=baseline.items.map(x=>x.id);
    report.before_event_pages=baseline.pages;
    if (f.app === 'prestashop') {
      await require('./prestashop.cjs')({ f, http, page, test, report });
    } else {
    assert.equal(f.app, 'dolibarr');
    await test('browser password login through enforcing WAF', async () => {
      await page.goto(f.origin + '/index.php');
      await page.locator('input[name=username]').fill('lab-admin');
      await page.locator('input[name=password]').fill(f.password);
      await page.locator('input[type=submit], button[type=submit]').first().click();
      await page.waitForLoadState('domcontentloaded');
      assert.ok(await page.locator('a[href*="logout.php"]').count(), 'authenticated logout link absent');
      return { authenticated: true };
    });
    await test('application API rejects missing and invalid credentials', async () => {
      await api('GET', 'thirdparties', undefined, [401], '');
      await api('GET', 'thirdparties', undefined, [401], 'invalid-' + id);
      return { missing_key: 401, invalid_key: 401 };
    });
    await test('reviewed route and method tuning preserves inspection', async () => {
      let config = await admin('config'); config.applications[0].policy.custom_rules = '';
      await admin('config/apply', { config, reason: 'Reset isolated Dolibarr baseline before method qualification' });
      await api('PUT', 'thirdparties/0', { name: 'Method probe' }, [403]);
      config = await admin('config');
      config.applications[0].policy.custom_rules =
        'SecRule REQUEST_URI "@rx ^/api/index[.]php/thirdparties/[0-9]+(?:[?]|$)" "id:100191,phase:1,pass,nolog,t:none,chain"\n' +
        'SecRule REQUEST_METHOD "@streq PUT" "t:none,setvar:\'tx.allowed_methods=GET HEAD POST OPTIONS PUT\'"\n' +
        'SecRule REQUEST_URI "@rx ^/api/index[.]php/documents/builddoc(?:[?]|$)" "id:100192,phase:1,pass,nolog,t:none,chain"\n' +
        'SecRule REQUEST_METHOD "@streq PUT" "t:none,setvar:\'tx.allowed_methods=GET HEAD POST OPTIONS PUT\'"';
      await admin('config/apply', { config, reason: 'Permit PUT only for reviewed numeric customer update and document build routes' });
      await api('PUT', 'invoices/0', {}, [403]);
      await api('PUT', 'thirdparties/0/extra', {}, [403]);
      await api('PATCH', 'thirdparties/0', {}, [403]);
      await api('DELETE', 'thirdparties/0', undefined, [403]);
      await api('PUT', 'thirdparties/0', { name: '<script>alert(1)</script>' }, [403]);
      report.policy = config;
      return { baseline_rule: 911100, exception_routes: 2, negative_checks: 5 };
    });
    let customer, quote, invoice, invoiceRef;
    const name = `O'Reilly & Sons — الجزائر ${id}`;
    await test('create, read and edit Unicode customer', async () => {
      customer = await api('POST', 'thirdparties', { name, client: 1, code_client: '-1', country_id: 1,
        email: 'customer-' + id + '@example.invalid', address: '12 Example Street', zip: '75001', town: 'Paris' });
      assert.ok(Number(customer) > 0);
      let value = await api('GET', 'thirdparties/' + customer); assert.equal(value.name, name);
      await api('PUT', 'thirdparties/' + customer, { name, note_public: 'Annual support & maintenance — السنة' });
      value = await api('GET', 'thirdparties/' + customer);
      assert.ok(value.note_public.includes('Annual support')); return { customer_id: Number(customer), persisted: true };
    });
    await test('browser finds the committed customer', async () => {
      await page.goto(f.origin + '/societe/list.php?search_nom=' + encodeURIComponent(id));
      assert.ok((await page.locator('body').innerText()).includes(name));
      return { browser_verified: true };
    });
    await test('create, price and validate quote', async () => {
      quote = await api('POST', 'proposals', { socid: Number(customer), date: Math.floor(Date.now()/1000),
        fin_validite: Math.floor(Date.now()/1000) + 86400 * 30 });
      assert.ok(Number(quote) > 0);
      await api('POST', `proposals/${quote}/line`, { desc: 'Managed support — maintenance', qty: 2,
        subprice: 125, tva_tx: 0, product_type: 1 });
      let value = await api('GET', 'proposals/' + quote);
      assert.equal(Number(value.total_ht), 250); assert.equal(value.lines.length, 1);
      await api('POST', `proposals/${quote}/validate`, { notrigger: 0 });
      value = await api('GET', 'proposals/' + quote); assert.equal(Number(value.statut), 1);
      return { quote_id: Number(quote), total_ht: 250, validated: true };
    });
    await test('create, price and validate invoice', async () => {
      invoice = await api('POST', 'invoices', { socid: Number(customer), type: 0, date: Math.floor(Date.now()/1000) });
      assert.ok(Number(invoice) > 0);
      await api('POST', `invoices/${invoice}/lines`, { desc: 'Support contract — خدمة', qty: 2,
        subprice: 125, tva_tx: 0, product_type: 1 });
      let value = await api('GET', 'invoices/' + invoice);
      assert.equal(Number(value.total_ht), 250);
      await api('POST', `invoices/${invoice}/validate`, { force_number: '', idwarehouse: 0, notrigger: 0 });
      value = await api('GET', 'invoices/' + invoice); assert.equal(Number(value.statut), 1);
      invoiceRef = value.ref;
      return { invoice_id: Number(invoice), total_ht: 250, validated: true };
    });
    await test('build and download invoice PDF', async () => {
      await api('PUT', 'documents/builddoc', { modulepart: 'invoice', original_file: invoiceRef, doctemplate: 'sponge', langcode: 'en_US' });
      const doc = await api('GET', 'documents/download?modulepart=invoice&original_file=' + encodeURIComponent(invoiceRef + '/' + invoiceRef + '.pdf'));
      const bytes = Buffer.from(doc.content, doc.encoding === 'base64' ? 'base64' : 'utf8');
      assert.equal(bytes.subarray(0,5).toString(), '%PDF-'); assert.ok(bytes.length > 1000);
      return { bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') };
    });
    await test('upload and download exact invoice attachment', async () => {
      const content = Buffer.from('contract_id,description\n' + id + ',Maintenance الجزائر\n');
      const filename = 'contract-' + id + '.csv';
      await api('POST', 'documents/upload', { filename, modulepart: 'invoice', ref: invoiceRef,
        filecontent: content.toString('base64'), fileencoding: 'base64', overwriteifexists: 0 });
      const doc = await api('GET', 'documents/download?modulepart=invoice&original_file=' + encodeURIComponent(invoiceRef + '/' + filename));
      assert.deepEqual(Buffer.from(doc.content, 'base64'), content);
      return { bytes: content.length, sha256: createHash('sha256').update(content).digest('hex') };
    });
    await require('./dolibarr-access.cjs')({f,page,context,api,test,customer,invoice,invoiceRef,id});
    await require('./dolibarr-workflows.cjs')({f,page,context,api,test,customer,id});
    await test('SQL injection and XSS blocked with direct application controls', async () => {
      const direct = await request.newContext({ baseURL: 'http://127.0.0.1:' + f.ports.app, timeout: 30000 });
      try {
        for (const payload of ["1 UNION SELECT NULL,NULL,NULL-- -", '<script>alert(1)</script>']) {
          const path = '/api/index.php/thirdparties?sortfield=' + encodeURIComponent(payload);
          const backend = await direct.get(path, { headers: { DOLAPIKEY: f.api_key } });
          const filtered = await http.get(path, { headers: { DOLAPIKEY: f.api_key } });
          assert.equal(filtered.status(), 403); assert.notEqual(await filtered.text(), await backend.text());
        }
      } finally { await direct.dispose(); }
      return { attack_pairs: 2 };
    });
    }
    await test('wrong hostname and oversized JSON refused', async () => {
      const wrong = await http.get('/', { headers: { Host: 'unassigned.invalid' } });
      assert.equal(wrong.status(), 421);
      const large = await http.post(f.app === 'dolibarr' ? '/api/index.php/thirdparties' : '/index.php', { headers: { DOLAPIKEY: f.api_key },
        data: { name: 'x'.repeat(1048577), client: 1 } });
      assert.equal(large.status(), 413); return { wrong_host: 421, oversized_body: 413 };
    });
    // Wait for durable security export, including periodic aggregation flushes.
    report.policy = await admin('config');
    // Finish all browser activity before taking the durable delivery oracle.
    await context.close();
    const monitorClient = await request.newContext({ baseURL: 'http://127.0.0.1:' + f.ports.admin,
      extraHTTPHeaders: { Authorization: 'Bearer ' + f.token } });
    const deadline = Date.now() + 30000;
    let stable=0, previous='';
    try {
      while (true) {
        const response = await monitorClient.get('/api/v1/status'); assert.equal(response.status(), 200);
        const status = await response.json();
        const all=await allEvents(admin);
        const ids=new Set(report.before_event_ids);
        const fresh=all.items.filter(x=>!ids.has(x.id));
        const verdicts={}; let total=0;
        for(const event of fresh) {
          const n=Math.max(1,event.occurrences || 1); total+=n;
          if([403,413,421].includes(event.status)) verdicts[event.status]=(verdicts[event.status] || 0)+n;
          else assert.ok([200,499].includes(event.status) && event.matches.length===0 &&
            ['Client or gateway cancelled response delivery','Client cancelled request'].includes(event.reason),
            'unexpected additional security event');
        }
        const expected403=f.app==='dolibarr'?9:2;
        const expected413=f.app==='dolibarr'?2:1;
        const complete=verdicts[403]===expected403 && verdicts[413]===expected413 && verdicts[421]===1 &&
          status.storage.committed_occurrences===beforeStatus.storage.committed_occurrences+total &&
          status.storage.export.acked_occurrences===status.storage.committed_occurrences &&
          status.storage.export.acked_records===all.items.length && status.storage.stored===all.items.length &&
          status.storage.pending_writes===0 && status.storage.export.pending_records===0;
        const signature=JSON.stringify(fresh.map(x=>[x.id,x.occurrences]));
        stable=complete && signature===previous?stable+1:0; previous=signature;
        if (stable>=2) {
          report.final_status=status; report.attempt_event_ids=fresh.map(x=>x.id);
          report.final_event_pages=all.pages;
          report.attempt_status_occurrences=verdicts; report.browser_cancellation_occurrences=total-expected403-expected413-1;
          break;
        }
        assert.ok(Date.now() < deadline, 'event export did not drain');
        await new Promise(r => setTimeout(r, 500));
      }
    } finally { await monitorClient.dispose(); }
    report.browser_refusals = unexpectedBrowserRefusals;
    assert.deepEqual(unexpectedBrowserRefusals, [], 'unexpected browser resource refusals');
    report.functional_passed = true;
  } finally {
    report.finished = new Date().toISOString(); await save();
    await context.close(); await browser.close(); await http.dispose();
  }
}
main().catch(e => { console.error(e.message); process.exitCode = 1; });
