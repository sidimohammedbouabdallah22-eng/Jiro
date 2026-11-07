// Real-browser smoke check. Run after: go build -o bin/openwaf.exe ./cmd/waf-server
const { chromium } = require("playwright");
const { createServer, request: httpRequest } = require("node:http");
const net = require("node:net");
const { spawn } = require("node:child_process");
const { randomBytes, createHmac, generateKeyPairSync, createHash, createPrivateKey, sign, verify } = require("node:crypto");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const assert = require("node:assert/strict");
const root = path.resolve(__dirname, "../..");
function authenticatorCode(secret, offset = 0) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const character of secret) bits += alphabet.indexOf(character).toString(2).padStart(5, "0");
  const bytes = [];
  for (let index = 0; index + 8 <= bits.length; index += 8) bytes.push(parseInt(bits.slice(index, index + 8), 2));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000) + offset));
  const digest = createHmac("sha1", Buffer.from(bytes)).update(counter).digest();
  const position = digest[digest.length - 1] & 15;
  return String((digest.readUInt32BE(position) & 0x7fffffff) % 1000000).padStart(6, "0");
}
const listen = (server) =>
  new Promise((resolve) =>
    server.listen(0, "127.0.0.1", () => resolve(server.address().port)),
  );
const freePort = async () => {
  const s = net.createServer();
  const p = await listen(s);
  await new Promise((r) => s.close(r));
  return p;
};
(async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "openwaf-ui-"));
  const token = randomBytes(32).toString("hex");
  const upstream = createServer((req, res) => {
    res.setHeader("Content-Type", "text/plain");
    res.end("Healthy test upstream");
  });
  const secondaryUpstream = createServer((request,response) => { response.setHeader("Content-Type","text/plain"); response.end("Healthy secondary upstream"); });
  const secondaryPort = await listen(secondaryUpstream);
  const up = await listen(upstream),
    admin = await freePort(),
    proxy = await freePort();
  const origin = `http://localhost:${admin}`;
  const providerKey = generateKeyPairSync("rsa", {modulusLength:2048});
  const providerFlows = new Map();
  let providerURL = "";
  const provider = createServer(async (request, response) => {
    const url = new URL(request.url, providerURL || "http://127.0.0.1");
    response.setHeader("Content-Type", "application/json");
    if (url.pathname === "/.well-known/openid-configuration") {
      response.end(JSON.stringify({issuer:providerURL,authorization_endpoint:providerURL+"/authorize",token_endpoint:providerURL+"/token",jwks_uri:providerURL+"/keys",id_token_signing_alg_values_supported:["RS256"]}));
    } else if (url.pathname === "/keys") {
      response.end(JSON.stringify({keys:[{...providerKey.publicKey.export({format:"jwk"}),kid:"browser-fixture",alg:"RS256",use:"sig"}]}));
    } else if (url.pathname === "/authorize") {
      const code = randomBytes(24).toString("hex");
      providerFlows.set(code, url.searchParams);
      response.writeHead(303, {Location:url.searchParams.get("redirect_uri")+"?"+new URLSearchParams({code,state:url.searchParams.get("state")})});
      response.end();
    } else if (url.pathname === "/token") {
      let body = "";
      for await (const chunk of request) { body += chunk; if (body.length > 65536) { request.destroy(); return; } }
      const values = new URLSearchParams(body), flow = providerFlows.get(values.get("code"));
      providerFlows.delete(values.get("code"));
      if (!flow || createHash("sha256").update(values.get("code_verifier") || "").digest("base64url") !== flow.get("code_challenge")) { response.writeHead(400); response.end(JSON.stringify({error:"invalid_grant"})); return; }
      const header = Buffer.from(JSON.stringify({alg:"RS256",kid:"browser-fixture"})).toString("base64url");
      const payload = Buffer.from(JSON.stringify({iss:providerURL,sub:"browser-subject",aud:"browser-client",iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+3600,auth_time:Math.floor(Date.now()/1000),acr:"browser-mfa",nonce:flow.get("nonce"),roles:["administrator"]})).toString("base64url");
      const input = header+"."+payload;
      response.end(JSON.stringify({token_type:"Bearer",access_token:"fixture-access",id_token:input+"."+sign("RSA-SHA256",Buffer.from(input),providerKey.privateKey).toString("base64url")}));
    } else { response.writeHead(404); response.end("{}"); }
  });
  providerURL = `http://127.0.0.1:${await listen(provider)}`;
  const authConfigPath = path.join(dir, "authentication.json");
  await fs.writeFile(authConfigPath, JSON.stringify({origin,passkey_rp_id:"localhost",oidc:{issuer:providerURL,client_id:"browser-client",required_acr:"browser-mfa"}}));
  const proxyFetch = (pathname, host = "application.test") =>
    new Promise((resolve, reject) => {
      const req = httpRequest(
        {
          hostname: "127.0.0.1",
          port: proxy,
          path: pathname,
          headers: {
            Host: host,
            "User-Agent": "OpenWAF UI test",
          },
        },
        (res) => {
          res.resume();
          res.on("end", () => resolve({ status: res.statusCode }));
        },
      );
      req.on("error", reject);
      req.end();
    });
  const configPath = path.join(dir, "policy.json");
  await fs.writeFile(
    configPath,
    JSON.stringify({
      revision: 1,
      name: "Integration application",
      upstream: `http://127.0.0.1:${up}`,
      mode: "enforcing",
      paranoia: 1,
      inbound_threshold: 5,
      outbound_threshold: 4,
      request_limit: 10485760,
      response_limit: 1048576,
      inspect_response: false,
      exclusions: [],
      custom_rules: "",
    }),
  );
  let child,
    browser,
    log = "";
  function start() {
    child = spawn(
      process.env.OPENWAF_TEST_BINARY ||
        path.join(
          root,
          "bin",
          process.platform === "win32" ? "openwaf.exe" : "openwaf",
        ),
      [
        "-config",
        configPath,
        "-auth-config",
        authConfigPath,
        "-admin",
        `127.0.0.1:${admin}`,
        "-listen",
        `127.0.0.1:${proxy}`,
      ],
      {
        env: { ...process.env, OPENWAF_ADMIN_TOKEN: token },
        windowsHide: true,
      },
    );
    child.stderr.on("data", (b) => (log += b));
  }
  async function ready() {
    for (let i = 0; i < 100; i++) {
      try {
        const r = await fetch(`http://127.0.0.1:${admin}/`);
        if (r.ok) return;
      } catch {}
      await new Promise((r) => setTimeout(r, 100));
    }
    throw new Error("Server failed to start: " + log);
  }
  async function stop() {
    if (child && child.exitCode === null) {
      const done = new Promise((r) => child.once("exit", r));
      child.kill();
      await done;
    }
  }
  try {
    start();
    await ready();
    for (const endpoint of ["health", "metrics"]) {
      const response = await fetch(
        `http://127.0.0.1:${admin}/api/v1/${endpoint}`,
      );
      assert.equal(response.status, 401);
    }
    const healthResponse = await fetch(
      `http://127.0.0.1:${admin}/api/v1/health`,
      { headers: { Authorization: "Bearer " + token } },
    );
    assert.equal(healthResponse.status, 200);
    const health = await healthResponse.json();
    assert.equal(health.ready, true);
    assert.equal(health.healthy, true);
    for (let i = 0; i < 20; i++) {
      const r = await proxyFetch("/hello");
      assert.equal(r.status, 200);
    }
    for (let i = 0; i < 3; i++) {
      const r = await proxyFetch(
        `/?id=${encodeURIComponent("1' UNION SELECT username,password FROM users--")}`,
      );
      assert.equal(r.status, 403);
    }
    const metricsResponse = await fetch(
      `http://127.0.0.1:${admin}/api/v1/metrics`,
      { headers: { Authorization: "Bearer " + token } },
    );
    assert.equal(metricsResponse.status, 200);
    assert.match(
      metricsResponse.headers.get("content-type"),
      /version=0\.0\.4/,
    );
    const metrics = await metricsResponse.text();
    assert.match(metrics, /^openwaf_requests_total 23$/m);
    assert.match(metrics, /^openwaf_blocked_requests_total 3$/m);
    assert.equal(metrics.includes(token), false);
    assert.equal(metrics.includes("UNION"), false);
    await fs.mkdir(path.join(root, "artifacts"), { recursive: true });
    await fs.writeFile(
      path.join(root, "artifacts/monitoring-metrics.txt"),
      metrics,
    );
    const executablePath =
      process.env.CHROME_PATH ||
      (process.platform === "win32"
        ? "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
        : undefined);
    browser = await chromium.launch({ executablePath, headless: true });
    const page = await browser.newPage({
        viewport: { width: 1440, height: 1050 },
      }),
      errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    page.on("console", (m) => {
      if (
        m.type() === "error" &&
        !/status of (400|401|403|404|409|429)/.test(m.text())
      )
        errors.push(m.text());
    });
    await page.goto(origin);
    await page.locator("#token").fill(token);
    await page.getByRole("button", { name: "Open security console" }).click();
    await page.locator("#shell").waitFor({ state: "visible" });
    await page.waitForFunction(
      () => document.querySelector("#metric-requests").textContent === "23",
    );
    assert.equal(await page.locator("#metric-blocked").textContent(), "3");
    assert.equal(await page.locator("#metric-detected").textContent(), "0");
    await page.screenshot({
      path: path.join(root, "artifacts/dashboard.png"),
      fullPage: true,
    });
    await page.locator('[data-view="application"]').click();
    await page.locator('[name="name"]').fill("Saved through the console");
    await page
      .getByRole("button", { name: "Validate policy", exact: true })
      .click();
    await page
      .getByRole("status")
      .filter({ hasText: "Policy compiled successfully" })
      .waitFor();
    const unchanged = JSON.parse(await fs.readFile(configPath));
    assert.equal(unchanged.revision, 1);
    await page.locator("#change-reason").fill("Name test application");
    await page
      .getByRole("button", { name: "Save & apply", exact: true })
      .click();
    await page
      .getByRole("status")
      .filter({ hasText: "Policy saved and applied" })
      .waitFor();
    assert.equal(
      JSON.parse(await fs.readFile(configPath)).name,
      "Saved through the console",
    );
    await page.locator('[data-view="policy"]').click();
    await page.locator('[name="mode"]').selectOption("detection");
    await page.locator("#change-reason").fill("Enable detection for testing");
    await page
      .getByRole("button", { name: "Save & apply", exact: true })
      .click();
    await page
      .getByRole("status")
      .filter({ hasText: "Policy saved and applied" })
      .waitFor();
    const attack = await proxyFetch(
      `/?q=${encodeURIComponent("<script>alert(1)</script>")}`,
    );
    assert.equal(attack.status, 200);
    await page.screenshot({
      path: path.join(root, "artifacts/policy.png"),
      fullPage: true,
    });
    await page.locator('[data-view="rules"]').click();
    await page
      .locator('[name="custom_rules"]')
      .fill("SecRule NOT_VALID broken");
    await page
      .getByRole("button", { name: "Validate policy", exact: true })
      .click();
    await page.locator("#notice.error").waitFor();
    assert.equal(JSON.parse(await fs.readFile(configPath)).custom_rules, "");
    page.on("dialog", (d) => d.accept());
    await page
      .getByRole("button", { name: "Discard changes", exact: true })
      .click();
    await page
      .getByRole("status")
      .filter({ hasText: "Active configuration reloaded" })
      .waitFor();
    await page.locator('[data-view="policy"]').click();
    await page.locator('[name="mode"]').selectOption("enforcing");
    await page.locator('[name="paranoia"]').selectOption("2");
    await page
      .locator("#change-reason")
      .fill("Exercise scoped exceptions at PL2");
    await page
      .getByRole("button", { name: "Save & apply", exact: true })
      .click();
    await page
      .getByRole("status")
      .filter({ hasText: "Policy saved and applied" })
      .waitFor();
    const price = "price < 100";
    assert.equal(
      (await proxyFetch("/search?q=" + encodeURIComponent(price))).status,
      403,
    );
    await page.locator('[data-view="rules"]').click();
    await page.locator("#add-exception").click();
    await page.locator("#exception-id").fill("price-search");
    await page.locator("#exception-path").fill("/search");
    await page.locator("#exception-parameter").fill("q");
    await page.locator("#exception-rules").fill("942131");
    await page.locator("#exception-owner").fill("Application team");
    await page
      .locator("#exception-reason")
      .fill("Legitimate price comparison in search");
    await page
      .getByRole("button", { name: "Add to draft", exact: true })
      .click();
    await page
      .locator("#change-reason")
      .fill("Add narrowly scoped search exception");
    await page
      .getByRole("button", { name: "Save & apply", exact: true })
      .click();
    await page
      .getByRole("status")
      .filter({ hasText: "Policy saved and applied" })
      .waitFor();
    assert.equal(
      (await proxyFetch("/search?q=" + encodeURIComponent(price))).status,
      200,
    );
    assert.equal(
      (await proxyFetch("/other?q=" + encodeURIComponent(price))).status,
      403,
    );
    assert.equal(
      (await proxyFetch("/search?other=" + encodeURIComponent(price))).status,
      403,
    );
    await page.screenshot({
      path: path.join(root, "artifacts/scoped-exceptions.png"),
      fullPage: true,
    });
    await page.locator('[data-view="history"]').click();
    const detectionRevision = page
      .locator("#policy-history tr")
      .filter({ hasText: "Enable detection for testing" });
    await detectionRevision.getByRole("button", { name: "Compare" }).click();
    await page
      .locator("#rollback-reason")
      .fill("Restore the earlier detection policy");
    await page
      .getByRole("button", { name: "Restore as new revision", exact: true })
      .click();
    await page
      .getByRole("status")
      .filter({ hasText: "Previous settings restored" })
      .waitFor();
    assert.equal(JSON.parse(await fs.readFile(configPath)).mode, "detection");
    assert.equal(
      JSON.parse(await fs.readFile(configPath)).scoped_exceptions.length,
      0,
    );
    await page.screenshot({
      path: path.join(root, "artifacts/policy-history.png"),
      fullPage: true,
    });
    await page.locator('[data-view="events"]').click();
    await page.locator("#refresh").click();
    await page.locator("#event-search").fill("941100");
    assert.ok(await page.locator("#all-events").textContent());
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({
      path: path.join(root, "artifacts/mobile.png"),
      fullPage: true,
    });
    assert.equal(
      await page.evaluate(
        () => document.documentElement.scrollWidth > window.innerWidth,
      ),
      false,
      "page overflows on mobile",
    );
    await page.setViewportSize({ width: 1440, height: 1050 });
    await page.locator('[data-view="system"]').click();
    await page.locator("#audit-entries tr").first().waitFor();
    assert.match(await page.locator("#audit-health").textContent(), /Healthy/);
    assert.match(await page.locator("#audit-export-health").textContent(), /Disabled/);
    assert.equal(await page.locator("#reload-certificate").isDisabled(), true);
    assert.match(
      await page.locator("#certificate-health").textContent(),
      /TLS is not configured/,
    );
    assert.match(
      await page.locator("#proxy-identity").textContent(),
      /Direct connection identity/,
    );
    await page.locator('[data-page="system"]').waitFor({ state: "visible" });
    assert.equal(
      await page.locator("#export-health").textContent(),
      "Disabled",
    );
    assert.match(
      await page.locator("#event-accounting").textContent(),
      /committed occurrences/,
    );
    assert.match(
      await page.locator("#storage-health").textContent(),
      /Healthy.*retained.*pending/,
    );
    assert.match(
      await page.locator("#resource-health").textContent(),
      /64 active.*256 MiB/,
    );
    await page.screenshot({
      path: path.join(root, "artifacts/system.png"),
      fullPage: true,
    });
    await page.getByRole("button", { name: "Sign out" }).click();
    await page.locator("#login").waitFor({ state: "visible" });
    await page.goto("about:blank");
    await stop();
    start();
    await ready();
    const response = await fetch(`http://127.0.0.1:${admin}/api/v1/config`, {
      headers: { Authorization: "Bearer " + token },
    });
    const restored = await response.json();
    assert.equal(restored.mode, "detection");
    assert.equal(restored.name, "Saved through the console");
    const historyResponse = await fetch(
      `http://127.0.0.1:${admin}/api/v1/events/search?limit=1&q=941100`,
      { headers: { Authorization: "Bearer " + token } },
    );
    assert.equal(historyResponse.status, 200);
    const persistedEvents = await historyResponse.json();
    assert.equal(
      persistedEvents.items.length,
      1,
      "security events missing after restart",
    );
    assert.ok(persistedEvents.items[0].sequence > 0);
    if (persistedEvents.has_more) {
      const older = await (
        await fetch(
          `http://127.0.0.1:${admin}/api/v1/events/search?limit=1&q=941100&before=${persistedEvents.next_before}`,
          { headers: { Authorization: "Bearer " + token } },
        )
      ).json();
      assert.equal(older.items.length, 1);
      assert.ok(older.items[0].sequence < persistedEvents.items[0].sequence);
    }
    // Exercise explicit migration and application administration through the UI.
    await page.goto(origin);
    await page.locator("#token").fill(token);
    await page.getByRole("button", { name: "Open security console" }).click();
    await page.locator("#shell").waitFor({ state: "visible" });
    await page.locator('[data-view="application"]').click();
    assert.equal(await page.locator("#new-application").isDisabled(), true);
    await page.locator('[name="hostnames"]').fill("application.test");
    await page
      .locator("#change-reason")
      .fill("Migrate to explicit hostname routing");
    await page.locator("#save").click();
    await page
      .getByRole("status")
      .filter({ hasText: "Policy saved and applied" })
      .waitFor();
    assert.equal(JSON.parse(await fs.readFile(configPath)).schema_version, 2);
    assert.equal((await proxyFetch("/", "unassigned.test")).status, 421);
    await page.locator("#new-application").click();
    await page.locator("#new-application-id").fill("portal");
    await page.locator("#new-application-name").fill("Customer portal");
    await page.locator("#new-application-hosts").fill("portal.test");
    await page
      .locator("#new-application-upstream")
      .fill(`http://127.0.0.1:${up}`);
    await page
      .locator("#new-application-reason")
      .fill("Add isolated customer portal");
    await page.locator("#create-application").click();
    await page.locator("#application-dialog").waitFor({ state: "hidden" });
    assert.equal(
      await page.locator("#application-selector").inputValue(),
      "portal",
    );
    assert.equal(await page.locator('[name="mode"]').inputValue(), "detection");
    await page.locator('[data-view="rules"]').click();
    await page
      .locator('[name="custom_rules"]')
      .fill(
        'SecRule REQUEST_URI "@streq /portal-only" "id:10001,phase:1,deny,status:403,log,msg:\'Portal route\'"',
      );
    await page.locator('[data-view="policy"]').click();
    await page.locator('[name="mode"]').selectOption("enforcing");
    await page.locator("#change-reason").fill("Enforce portal-only rule");
    await page.locator("#save").click();
    await page
      .getByRole("status")
      .filter({ hasText: "Policy saved and applied" })
      .waitFor();
    assert.equal((await proxyFetch("/portal-only", "portal.test")).status, 403);
    assert.equal((await proxyFetch("/portal-only")).status, 200);
    await page.locator('[data-view="events"]').click();
    await page.locator("#event-search").fill("");
    await page.locator("#event-application").fill("portal");
    await page.locator("#event-application").dispatchEvent("change");
    await page.waitForFunction(() =>
      document
        .querySelector("#all-events")
        .textContent.includes("portal · GET /portal-only"),
    );
    await page.screenshot({
      path: path.join(root, "artifacts/applications-events.png"),
      fullPage: true,
    });
    await page.locator('[data-view="application"]').click();
    await page
      .locator('[data-page="application"]')
      .waitFor({ state: "visible" });
    await page.screenshot({
      path: path.join(root, "artifacts/applications-console.png"),
      fullPage: true,
    });
    await page.locator("#application-selector").selectOption("primary");
    assert.equal(await page.locator('[name="mode"]').inputValue(), "detection");
    await page.locator("#application-selector").selectOption("portal");
    await page.locator("#remove-application").click();
    await page
      .locator("#remove-application-reason")
      .fill("Retire customer portal");
    await page.locator("#delete-application").click();
    await page
      .locator("#application-remove-dialog")
      .waitFor({ state: "hidden" });
    assert.equal((await proxyFetch("/", "portal.test")).status, 421);
    assert.equal(await page.locator("#remove-application").isDisabled(), true);
    await page.goto("about:blank");
    await stop();
    start();
    await ready();
    const applicationConfig = await (
      await fetch(`http://127.0.0.1:${admin}/api/v1/config`, {
        headers: { Authorization: "Bearer " + token },
      })
    ).json();
    assert.equal(applicationConfig.schema_version, 2);
    assert.equal(applicationConfig.applications.length, 1);
    assert.equal((await proxyFetch("/")).status, 200);
    assert.equal((await proxyFetch("/", "portal.test")).status, 421);
    const retiredEvents = await (
      await fetch(
        `http://127.0.0.1:${admin}/api/v1/events/search?application=portal`,
        { headers: { Authorization: "Bearer " + token } },
      )
    ).json();
    assert.ok(retiredEvents.items.length > 0);
    assert.ok(
      retiredEvents.items.every((event) => event.application_id === "portal"),
    );
    // Configure bounded controls and exercise all local roles in real Chrome.
    await page.goto(origin);
    await page.locator("#token").fill(token);
    await page.getByRole("button", { name: "Open security console" }).click();
    await page.locator("#shell").waitFor({ state: "visible" });
    await page.locator('[data-view="policy"]').click();
    await page.locator('[name="traffic_requests_per_second"]').fill("1");
    await page.locator('[name="traffic_burst"]').fill("1");
    await page.locator('[name="traffic_max_client_concurrent"]').fill("2");
    await page.locator("#change-reason").fill("Bound application traffic");
    await page.locator("#save").click();
    await page
      .getByRole("status")
      .filter({ hasText: "Policy saved and applied" })
      .waitFor();
    assert.equal((await proxyFetch("/")).status, 200);
    assert.equal((await proxyFetch("/")).status, 429);
    await page.screenshot({
      path: path.join(root, "artifacts/traffic-controls.png"),
      fullPage: true,
    });
    const accountPassword = "local account test password long enough";
    await page.locator('[data-view="access"]').click();
    await page.locator("#accounts-panel").waitFor({ state: "visible" });
    for (const role of ["administrator", "operator", "viewer"]) {
      await page.locator("#account-selector").selectOption("");
      await page.locator("#account-username").fill(role);
      await page.locator("#account-role").selectOption(role);
      await page.locator("#account-password").fill(accountPassword);
      await page.locator("#account-reason").fill("Create local " + role);
      await page.locator("#save-account").click();
      await page
        .locator("#account-selector option[value='" + role + "']")
        .waitFor({ state: "attached" });
      await page
        .getByRole("status")
        .filter({ hasText: "Account saved" })
        .waitFor();
      assert.equal(await page.locator("#account-error").textContent(), "");
    }
    await page.screenshot({
      path: path.join(root, "artifacts/local-accounts.png"),
      fullPage: true,
    });
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(
      await page.evaluate(
        () => document.documentElement.scrollWidth > innerWidth,
      ),
      false,
      "account page overflows on mobile",
    );
    await page.screenshot({
      path: path.join(root, "artifacts/accounts-mobile.png"),
      fullPage: true,
    });
    await page.setViewportSize({ width: 1440, height: 1050 });
    await page.locator("#automation-owner").selectOption("viewer");
    await page.locator("#automation-name").fill("Browser monitoring integration");
    await page.locator("#automation-reason").fill("Exercise scoped credential workflow");
    await page.locator('#automation-scopes input[value="monitoring:read"]').check();
    await page.locator("#token-form button").click();
    await page.locator("#issued-token-panel").waitFor({ state: "visible" });
    const automationSecret = await page.locator("#issued-token").textContent();
    assert.match(automationSecret, /^owaf_[a-f0-9]{32}\.[a-f0-9]{64}$/);
    const automationFetch = (endpoint) => fetch(`http://127.0.0.1:${admin}/api/v1/${endpoint}`, { headers: { Authorization: "Bearer " + automationSecret } });
    assert.equal((await automationFetch("health")).status, 200);
    assert.equal((await automationFetch("config")).status, 403);
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, "token page overflows on mobile");
    await page.locator("#clear-issued-token").click();
    await page.screenshot({ path: path.join(root, "artifacts/m3-automation-mobile.png"), fullPage: true });
    await page.setViewportSize({ width: 1440, height: 1050 });
    await page.locator("#automation-rows button").click();
    await page.getByRole("status").filter({ hasText: "Automation token revoked" }).waitFor();
    assert.equal((await automationFetch("health")).status, 401);
    async function localSignIn(username, password = accountPassword, code = "") {
      await page.locator("#login-method").selectOption("account");
      await page.locator("#login-username").fill(username);
      await page.locator("#login-password").fill(password);
      await page.locator("#login-code").fill(code);
      await page.getByRole("button", { name: "Open security console" }).click();
      await page.locator("#shell").waitFor({ state: "visible" });
    }
    await page.locator("#logout").click();
    await page.locator("#login").waitFor({ state: "visible" });
    await localSignIn("viewer");
    await page.locator('[data-view="policy"]').click();
    assert.equal(await page.locator("#save").isDisabled(), true);
    assert.equal(await page.locator('[name="mode"]').isDisabled(), true);
    const denied = await page.evaluate(
      async () =>
        (
          await fetch("/api/v1/config/apply", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: "{}",
          })
        ).status,
    );
    assert.equal(denied, 403);
    await page.locator('[data-view="access"]').click();
    assert.equal(await page.locator("#accounts-panel").isHidden(), true);
    await page.locator("#logout").click();
    await page.locator("#login").waitFor({ state: "visible" });
    await localSignIn("operator");
    await page.locator('[data-view="application"]').click();
    assert.equal(await page.locator("#save").isDisabled(), false);
    await page.locator('[name="name"]').fill("Operator-managed application");
    await page.locator("#change-reason").fill("Named operator policy change");
    await page.locator("#save").click();
    await page
      .getByRole("status")
      .filter({ hasText: "Policy saved and applied" })
      .waitFor();
    const authHeaders = {
      Authorization: "Bearer " + token,
      "Content-Type": "application/json",
    };
    const directory = await (
      await fetch(`http://127.0.0.1:${admin}/api/v1/accounts`, {
        headers: authHeaders,
      })
    ).json();
    const disable = await fetch(`http://127.0.0.1:${admin}/api/v1/accounts`, {
      method: "POST",
      headers: authHeaders,
      body: JSON.stringify({
        revision: directory.revision,
        username: "operator",
        role: "operator",
        disabled: true,
        reason: "Revoke operator access",
      }),
    });
    assert.equal(disable.status, 200);
    await page.locator("#refresh").click();
    await page.locator("#login").waitFor({ state: "visible" });
    await page.goto("about:blank");
    await stop();
    start();
    await ready();
    await page.goto(origin);
    await localSignIn("viewer");
    await page.locator('[data-view="access"]').click();
    await page.locator("#password-panel").waitFor({ state: "visible" });
    await page.locator("#current-password").fill(accountPassword);
    await page
      .locator("#self-new-password")
      .fill("a changed viewer password for testing");
    await page.locator("#password-form button").click();
    await page.locator("#login").waitFor({ state: "visible" });
    await localSignIn("viewer", "a changed viewer password for testing");
    assert.match(await page.locator("#identity-label").textContent(), /viewer/);
    await page.locator("#logout").click();
    await page.locator("#login").waitFor({ state: "visible" });
    await localSignIn("administrator");
    await page.locator('[data-view="access"]').click();
    await page.locator("#mfa-password").fill(accountPassword);
    await page.locator("#mfa-setup").click();
    await page.locator("#mfa-enrollment").waitFor({ state: "visible" });
    const mfaSecret = await page.locator("#mfa-secret").textContent();
    await page.locator("#mfa-password").fill(accountPassword);
    await page.locator("#mfa-code").fill(authenticatorCode(mfaSecret, -1));
    await page.locator("#mfa-enable").click();
    await page.locator("#login").waitFor({ state: "visible" });
    assert.equal(await page.locator("#mfa-secret").textContent(), "");
    await page.locator("#login-method").selectOption("account");
    await page.locator("#login-username").fill("administrator");
    await page.locator("#login-password").fill(accountPassword);
    await page.getByRole("button", { name: "Open security console" }).click();
    await page.locator("#login-error").filter({ hasText: "Invalid sign-in credentials" }).waitFor();
    await localSignIn("administrator", accountPassword, authenticatorCode(mfaSecret));
    await page.locator('[data-view="access"]').click();
    await page.locator("#mfa-disable").waitFor({ state: "visible" });
    assert.match(await page.locator("#mfa-status").textContent(), /enabled/);
    await page.screenshot({ path: path.join(root, "artifacts/m3-authenticator.png"), fullPage: true });
    await page.locator("#mfa-password").fill(accountPassword);
    await page.locator("#mfa-code").fill(authenticatorCode(mfaSecret, 1));
    await page.locator("#mfa-disable").click();
    await page.locator("#login").waitFor({ state: "visible" });
    await localSignIn("administrator");
    // Re-enroll to exercise administrator enforcement through the console.
    await page.locator('[data-view="access"]').click();
    await page.locator("#mfa-password").fill(accountPassword);
    await page.locator("#mfa-setup").click();
    await page.locator("#mfa-enrollment").waitFor({ state: "visible" });
    const policySecret = await page.locator("#mfa-secret").textContent();
    await page.locator("#mfa-password").fill(accountPassword);
    await page.locator("#mfa-code").fill(authenticatorCode(policySecret, -1));
    await page.locator("#mfa-enable").click();
    await page.locator("#login").waitFor({ state: "visible" });
    await localSignIn("administrator", accountPassword, authenticatorCode(policySecret));
    await page.locator('[data-view="access"]').click();
    await page.locator("#account-selector").selectOption("");
    await page.locator("#account-username").fill("enrollment-admin");
    await page.locator("#account-role").selectOption("administrator");
    await page.locator("#account-password").fill(accountPassword);
    await page.locator("#account-reason").fill("Add administrator pending MFA");
    await page.locator("#save-account").click();
    await page.locator('#account-selector option[value="enrollment-admin"]').waitFor({ state: "attached" });
    await page.locator("#require-admin-mfa").check();
    await page.locator("#mfa-policy-password").fill(accountPassword);
    await page.locator("#mfa-policy-code").fill(authenticatorCode(policySecret, 1));
    await page.locator("#mfa-policy-reason").fill("Require MFA for named administrators");
    await page.locator("#mfa-policy-form button").click();
    await page.getByRole("status").filter({ hasText: "Administrator authentication policy saved" }).waitFor();
    await page.locator("#logout").click();
    await page.locator("#login").waitFor({ state: "visible" });
    await localSignIn("enrollment-admin");
    await page.locator("#enrollment-required-panel").waitFor({ state: "visible" });
    assert.equal(await page.locator("#accounts-panel").isHidden(), true);
    assert.equal(await page.locator('[data-view="overview"]').isHidden(), true);
    assert.equal(await page.locator("#password-panel").isHidden(), true);
    await page.screenshot({ path: path.join(root, "artifacts/m3-enrollment-required.png"), fullPage: true });
    await page.locator("#mfa-password").fill(accountPassword);
    await page.locator("#mfa-setup").click();
    await page.locator("#mfa-enrollment").waitFor({ state: "visible" });
    const enrollmentSecret = await page.locator("#mfa-secret").textContent();
    await page.locator("#mfa-password").fill(accountPassword);
    await page.locator("#mfa-code").fill(authenticatorCode(enrollmentSecret, -1));
    await page.locator("#mfa-enable").click();
    await page.locator("#login").waitFor({ state: "visible" });
    await localSignIn("enrollment-admin", accountPassword, authenticatorCode(enrollmentSecret));
    await page.locator('[data-view="access"]').click();
    await page.locator("#accounts-panel").waitFor({ state: "visible" });
    await page.locator("#mfa-password").fill(accountPassword);
    await page.locator("#mfa-code").fill(authenticatorCode(enrollmentSecret, 1));
    await page.locator("#mfa-disable").click();
    await page.locator("#mfa-error").filter({ hasText: "required by deployment policy" }).waitFor();
    async function bootstrapSignIn() {
      await page.locator("#logout").click();
      await page.locator("#login").waitFor({ state: "visible" });
      await page.locator("#login-method").selectOption("token");
      await page.locator("#token").fill(token);
      await page.getByRole("button", { name: "Open security console" }).click();
      await page.locator("#shell").waitFor({ state: "visible" });
      await page.locator('[data-view="access"]').click();
      await page.locator("#accounts-panel").waitFor({ state: "visible" });
    }
    await bootstrapSignIn();
    await page.locator("#account-selector").selectOption("enrollment-admin");
    await page.locator("#account-reason").fill("Recover lost administrator authenticator");
    await page.locator("#reset-mfa").click();
    await page.getByRole("status").filter({ hasText: "Authenticator recovered" }).waitFor();
    assert.equal(await page.locator("#require-admin-mfa").isChecked(), true);
    await page.locator("#logout").click();
    await page.locator("#login").waitFor({ state: "visible" });
    await localSignIn("enrollment-admin");
    await page.locator("#enrollment-required-panel").waitFor({ state: "visible" });
    await bootstrapSignIn();
    await page.locator("#require-admin-mfa").uncheck();
    await page.locator("#mfa-policy-reason").fill("Explicit bootstrap policy override for test completion");
    await page.locator("#mfa-policy-form button").click();
    await page.getByRole("status").filter({ hasText: "Administrator authentication policy saved" }).waitFor();
    const fullConfig = await (await fetch(`http://127.0.0.1:${admin}/api/v1/config`, { headers: authHeaders })).json();
    const privateApplication = await fetch(`http://127.0.0.1:${admin}/api/v1/applications`, {
      method: "POST", headers: authHeaders,
      body: JSON.stringify({ revision: fullConfig.revision, application_id: "private", name: "Private application", hosts: ["private.test"], upstream: `http://127.0.0.1:${up}`, reason: "Application authorization fixture" }),
    });
    assert.equal(privateApplication.status, 200);
    await page.reload();
    await page.locator("#accounts-panel").waitFor({ state: "visible" });
    await page.locator("#account-selector").selectOption("");
    await page.locator("#account-username").fill("assigned");
    await page.locator("#account-role").selectOption("operator");
    await page.locator("#account-password").fill(accountPassword);
    await page.locator("#account-access-mode").selectOption("assigned");
    await page.locator('#account-applications input[value="primary"]').check();
    await page.locator("#account-reason").fill("Assign primary application only");
    await page.locator("#save-account").click();
    await page.locator('#account-selector option[value="assigned"]').waitFor({ state: "attached" });
    await page.locator("#automation-owner").selectOption("assigned");
    assert.equal(await page.locator('#automation-scopes input[value="monitoring:read"]').isDisabled(), true);
    await page.locator("#logout").click();
    await page.locator("#login").waitFor({ state: "visible" });
    await localSignIn("assigned");
    assert.equal(await page.locator('[data-view="system"]').isHidden(), true);
    assert.equal(await page.locator('[data-view="history"]').isHidden(), true);
    await page.locator('[data-view="application"]').click();
    assert.equal(await page.locator("#application-selector option").count(), 1);
    assert.equal(await page.locator('[name="upstream"]').isDisabled(), true);
    assert.equal(await page.locator("#new-application").isDisabled(), true);
    await page.locator('[name="name"]').fill("Assigned operator updated primary");
    await page.locator("#change-reason").fill("Scoped policy merge through console");
    await page.locator("#save").click();
    await page.getByRole("status").filter({ hasText: "Policy saved and applied" }).waitFor();
    const afterScope = await (await fetch(`http://127.0.0.1:${admin}/api/v1/config`, { headers: authHeaders })).json();
    assert.equal(afterScope.applications.length, 2);
    assert.equal(afterScope.applications.find((application) => application.application_id === "private").name, "Private application");
    await page.locator('[data-view="events"]').click();
    await page.locator("#refresh").click();
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, "assigned console overflows on mobile");
    await page.screenshot({ path: path.join(root, "artifacts/m3-assigned-mobile.png"), fullPage: true });
    await page.setViewportSize({width:1440,height:1050});
    await bootstrapSignIn();
    await page.locator('[data-view="application"]').click();
    await page.locator("#application-selector").selectOption("primary");
    await page.locator("#pool-enabled").check();
    await page.locator("#add-pool-backend").click();
    await page.locator('.pool-backend').nth(1).locator('[data-backend-field="url"]').fill(`http://127.0.0.1:${secondaryPort}`);
    await page.locator('[data-view="policy"]').click();
    await page.locator('[name="traffic_requests_per_second"]').fill("0");
    await page.locator('[name="traffic_burst"]').fill("0");
    await page.locator('[name="mode"]').selectOption("enforcing");
    await page.locator("#change-reason").fill("Activate inspected upstream pool");
    await page.locator("#save").click();
    await page.getByRole("status").filter({hasText:"Policy saved and applied"}).waitFor();
    assert.equal((await proxyFetch("/pool-one")).status,200);
    assert.equal((await proxyFetch("/pool-two")).status,200);
    assert.equal((await proxyFetch("/?q=%3Cscript%3Ealert(1)%3C/script%3E")).status,403);
    await page.locator("#refresh").click();
    await page.locator('[data-view="application"]').click();
    await page.locator("#pool-observations").filter({hasText:"observed healthy"}).waitFor();
    await page.screenshot({path:path.join(root,"artifacts/m3-upstream-pools.png"),fullPage:true});
    await page.locator('[data-view="access"]').click();
    await page.locator("#oidc-binding-user").selectOption("viewer");
    await page.locator("#oidc-binding-subject").fill("browser-subject");
    await page.locator("#oidc-binding-reason").fill("Map organization identity to local viewer");
    await page.locator("#oidc-binding-form button").click();
    await page.getByRole("status").filter({hasText:"Organization identity binding saved"}).waitFor();
    await page.locator("#logout").click();
    await page.locator("#login").waitFor({state:"visible"});
    await page.locator("#oidc-signin").click();
    await page.locator("#shell").waitFor({state:"visible"});
    assert.match(await page.locator("#identity-label").textContent(),/viewer/);
    await page.locator('[data-view="policy"]').click();
    assert.equal(await page.locator("#save").isDisabled(),true,"provider role claim escalated local viewer");
    await bootstrapSignIn();
    await page.locator("#account-selector").selectOption("");
    await page.locator("#account-username").fill("passkey-admin");
    await page.locator("#account-role").selectOption("administrator");
    await page.locator("#account-password").fill(accountPassword);
    await page.locator("#account-reason").fill("Passkey administrator fixture");
    await page.locator("#save-account").click();
    await page.locator('#account-selector option[value="passkey-admin"]').waitFor({state:"attached"});
    await page.locator("#logout").click();
    await page.locator("#login").waitFor({state:"visible"});
    await localSignIn("passkey-admin");
    await page.locator('[data-view="access"]').click();
    const authenticator = await page.context().newCDPSession(page);
    await authenticator.send("WebAuthn.enable");
    const {authenticatorId} = await authenticator.send("WebAuthn.addVirtualAuthenticator",{options:{protocol:"ctap2",transport:"internal",hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
    await page.locator("#passkey-name").fill("Verified browser test key");
    await page.locator("#passkey-password").fill(accountPassword);
    await page.locator("#passkey-enrollment-form button").click();
    await page.locator("#login").waitFor({state:"visible"});
    async function keySignIn(){
      await page.locator("#login-method").selectOption("account");
      await page.locator("#login-username").fill("passkey-admin");
      await page.locator("#passkey-signin").click();
      await page.locator("#shell").waitFor({state:"visible"});
    }
    await keySignIn();
    await page.locator('[data-view="access"]').click();
    await page.locator("#passkey-list").filter({hasText:"Verified browser test key"}).waitFor();
    await page.locator("#require-admin-mfa").check();
    await page.locator("#mfa-policy-reason").fill("Passkey-verified administrator policy change");
    await page.locator("#mfa-policy-form button").click();
    await page.getByRole("status").filter({hasText:"Administrator authentication policy saved"}).waitFor();
    await page.locator("#logout").click();
    await page.locator("#login").waitFor({state:"visible"});
    await localSignIn("passkey-admin");
    await page.locator("#enrollment-required-panel").waitFor({state:"visible"});
    await page.locator("#verify-passkey").click();
    await page.locator("#accounts-panel").waitFor({state:"visible"});
    await page.screenshot({path:path.join(root,"artifacts/m3-passkeys.png"),fullPage:true});
    await page.locator("#logout").click();
    await page.locator("#login").waitFor({state:"visible"});
    await page.route("**/api/v1/login/passkey/finish",async(route)=>{
      const body=route.request().postDataJSON();
      const clientData=JSON.parse(Buffer.from(body.response.response.clientDataJSON,"base64url").toString());
      clientData.origin="http://localhost:1";
      body.response.response.clientDataJSON=Buffer.from(JSON.stringify(clientData)).toString("base64url");
      // Keep a valid signature so this exercises origin validation independently.
      const {credentials} = await authenticator.send("WebAuthn.getCredentials",{authenticatorId});
      assert.equal(credentials.length,1);
      assert.deepEqual(Buffer.from(credentials[0].credentialId,"base64"),Buffer.from(body.response.id,"base64url"));
      const privateKey=createPrivateKey({key:Buffer.from(credentials[0].privateKey,"base64"),format:"der",type:"pkcs8"});
      const signedData=Buffer.concat([Buffer.from(body.response.response.authenticatorData,"base64url"),createHash("sha256").update(Buffer.from(body.response.response.clientDataJSON,"base64url")).digest()]);
      const signature=sign("sha256",signedData,privateKey);
      assert.ok(verify("sha256",signedData,privateKey,signature));
      body.response.response.signature=signature.toString("base64url");
      await route.continue({postData:JSON.stringify(body)});
    },{times:1});
    await page.locator("#login-method").selectOption("account");
    await page.locator("#login-username").fill("passkey-admin");
    await page.locator("#passkey-signin").click();
    await page.locator("#login-error").filter({hasText:"verification failed"}).waitFor();
    await keySignIn();
    await bootstrapSignIn();
    await page.locator("#account-selector").selectOption("passkey-admin");
    await page.locator("#account-reason").fill("Recover lost passkey without weakening MFA policy");
    await page.locator("#reset-passkeys").click();
    await page.getByRole("status").filter({hasText:"Passkeys recovered"}).waitFor();
    assert.equal(await page.locator("#require-admin-mfa").isChecked(),true);
    await page.setViewportSize({width:390,height:844});
    for (const [view,screenshot] of [["application","m3-mobile-pools.png"],["access","m3-mobile-authentication.png"]]) {
      await page.locator(`[data-view="${view}"]`).click();
      await page.locator(`[data-page="${view}"]`).waitFor({state:"visible"});
      await page.screenshot({path:path.join(root,"artifacts",screenshot),fullPage:true});
      const overflow = await page.evaluate(()=>({
        present:document.documentElement.scrollWidth>window.innerWidth,
        elements:[...document.querySelectorAll("main *")].filter(element=>element.getBoundingClientRect().right>window.innerWidth).slice(0,20).map(element=>({tag:element.tagName,id:element.id,class:element.className,right:element.getBoundingClientRect().right}))
      }));
      assert.equal(overflow.present,false,`${view} mobile overflow ${JSON.stringify(overflow.elements)}`);
    }
    assert.deepEqual(errors, []);
    console.log(
      "PASS: console workflows, application migration/isolation, durable events, rate controls, accounts/RBAC, revocation and restart persistence, scoped automation, TOTP and administrator MFA enforcement/recovery, application assignments, upstream pools and health, OIDC local-role isolation, passkey enrollment/sign-in/step-up/recovery and valid-signature wrong-origin rejection. Screenshots: artifacts/",
    );
  } finally {
    if (browser) await browser.close();
    await stop();
    await new Promise((r) => upstream.close(r));
    await new Promise((r) => secondaryUpstream.close(r));
    await new Promise((r) => provider.close(r));
    await fs.rm(dir, { recursive: true, force: true });
  }
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
