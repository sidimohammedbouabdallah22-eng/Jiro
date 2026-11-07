// Exercise the body-byte controls through the normal administrator console.
const { chromium } = require('playwright');
const { createServer } = require('node:http');
const { spawn } = require('node:child_process');
const { randomBytes, createHash } = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const assert = require('node:assert/strict');

async function listen(server) {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return server.address().port;
}
async function port() {
  const server = createServer();
  const value = await listen(server);
  await new Promise(resolve => server.close(resolve));
  return value;
}

(async () => {
  const binary = path.resolve(process.argv[2]);
  const directory = path.resolve(process.argv[3]);
  await fs.mkdir(directory);
  const token = randomBytes(32).toString('hex');
  const backend = createServer((request,response) => response.end('owned fixture'));
  const upstream = await listen(backend);
  const admin = await port(), proxy = await port();
  const config = path.join(directory,'policy.json');
  await fs.writeFile(config,JSON.stringify({schema_version:2,revision:1,applications:[{
    application_id:'shop',name:'Owned shop',hosts:['shop.test'],upstream:`http://127.0.0.1:${upstream}`,
    policy:{mode:'enforcing',paranoia:1,inbound_threshold:5,outbound_threshold:4,
      request_limit:1048576,response_limit:1048576,inspect_response:false,exclusions:[],custom_rules:'',scoped_exceptions:[]},
    traffic_controls:{requests_per_second:0,burst:0,client_requests_per_second:0,client_burst:0,
      max_concurrent:32,max_client_concurrent:0,max_client_buffer_mib:12,admission_wait_ms:1000},
  }]}));
  const child = spawn(binary,['-config',config,'-admin',`127.0.0.1:${admin}`,'-listen',`127.0.0.1:${proxy}`],
    {env:{...process.env,OPENWAF_ADMIN_TOKEN:token},windowsHide:true,stdio:'ignore'});
  let browser;
  const report = {passed:false,server_sha256:createHash('sha256').update(await fs.readFile(binary)).digest('hex')};
  try {
    const origin = `http://127.0.0.1:${admin}`;
    let ready = false;
    for (let attempt=0; attempt<120; attempt++) {
      try { ready = (await fetch(origin+'/')).ok; } catch {}
      if (ready) break;
      await new Promise(resolve => setTimeout(resolve,250));
    }
    assert.ok(ready,'owned console did not start');
    browser = await chromium.launch({executablePath:'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',headless:true});
    const page = await browser.newPage({viewport:{width:1440,height:1050}});
    await page.goto(origin);
    await page.locator('#token').fill(token);
    await page.getByRole('button',{name:'Open security console'}).click();
    await page.locator('#shell').waitFor({state:'visible'});
    await page.locator('[data-view="policy"]').click();
    for (const [rate,burst] of [[128,4096],[0,0]]) {
      await page.locator('[name="traffic_client_body_kib_per_second"]').fill(String(rate));
      await page.locator('[name="traffic_client_body_burst_kib"]').fill(String(burst));
      await page.locator('#change-reason').fill('Owned browser body-budget regression');
      await page.getByRole('button',{name:'Save & apply',exact:true}).click();
      await page.getByRole('status').filter({hasText:'Policy saved and applied'}).waitFor();
      const stored = JSON.parse(await fs.readFile(config));
      assert.equal(stored.applications[0].traffic_controls.client_body_kib_per_second || 0,rate);
      assert.equal(stored.applications[0].traffic_controls.client_body_burst_kib || 0,burst);
      await page.reload();
      await page.locator('[data-view="policy"]').click();
      assert.equal(await page.locator('[name="traffic_client_body_kib_per_second"]').inputValue(),String(rate));
      assert.equal(await page.locator('[name="traffic_client_body_burst_kib"]').inputValue(),String(burst));
      if (rate) await page.screenshot({path:path.join(directory,'body-budget.png'),fullPage:true});
    }
    report.passed = true;
  } catch (error) {
    report.error = String(error.message).split(token).join('[REDACTED]').slice(0,2000);
    throw error;
  } finally {
    if (browser) await browser.close();
    child.kill();
    await new Promise(resolve => child.exitCode!==null ? resolve() : child.once('exit',resolve));
    await new Promise(resolve => backend.close(resolve));
    await fs.writeFile(path.join(directory,'result.json'),JSON.stringify(report,null,2));
  }
  console.log('Body-budget console save, reload and disable passed');
})().catch(error => { console.error(error.name); process.exitCode=1; });
