// Controlled application workflows against pinned products in the owned M4 lab.
const { chromium, request } = require("../ui-check/node_modules/playwright");
const { createHmac, createHash, randomUUID } = require("node:crypto");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs/promises");
const path = require("node:path");
const assert = require("node:assert/strict");

function otp(secret, step) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const value = createHmac("sha1", secret).update(counter).digest();
  return ((value.readUInt32BE(value[19] & 15) & 0x7fffffff) % 1000000)
    .toString()
    .padStart(6, "0");
}

async function main() {
  const fixturePath = process.argv[2];
  const fixture = JSON.parse(await fs.readFile(fixturePath, "utf8"));
  for (const value of [
    fixture.admin_origin,
    fixture.wordpress_origin,
    fixture.dvwa_origin,
    fixture.idp_origin,
  ]) {
    const url = new URL(value);
    assert.ok(
      url.protocol === "http:" &&
        ["localhost", "127.0.0.1"].includes(url.hostname),
      "lab targets must use loopback",
    );
  }
  const out = path.dirname(fixturePath);
  const resultPath = path.join(out, "results.json");
  const report = {
    started: new Date().toISOString(),
    passed: false,
    fixture: fixture.tag,
    package_sha256: fixture.package_sha256,
    server_sha256: fixture.server_sha256,
    images: fixture.images,
    profile:
      "isolated products on loopback; DVWA low security; CRS PL1 enforcement; Keycloak LoA2 with OTP",
    cases: [],
  };
  report.source_sha256 = {};
  for (const file of [
    "tools/application-check/check.cjs",
    "tools/application-check/images.lock.json",
    "scripts/m4_guest.py",
    "scripts/m4_idp.py",
    "scripts/qualify-applications.py",
    "scripts/pilot.py",
  ]) {
    report.source_sha256[file] = createHash("sha256")
      .update(await fs.readFile(path.resolve(__dirname, "../..", file)))
      .digest("hex");
  }
  const save = () =>
    fs.writeFile(resultPath, JSON.stringify(report, null, 2) + "\n");
  async function test(name, category, operation) {
    try {
      const detail = await operation();
      report.cases.push({ name, category, passed: true, ...detail });
      console.log("PASS " + name);
      await save();
      return true;
    } catch (error) {
      report.cases.push({
        name,
        category,
        passed: false,
        error: error.message.slice(0, 1000),
      });
      console.log("FAIL " + name);
      await save();
      return false;
    }
  }
  async function admin(endpoint, body) {
    const response = await fetch(fixture.admin_origin + "/api/v1/" + endpoint, {
      method: body ? "POST" : "GET",
      headers: {
        Authorization: "Bearer " + fixture.token,
        "Content-Type": "application/json",
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    assert.ok(
      response.ok,
      "administration " + endpoint + " returned " + response.status,
    );
    return response.json();
  }
  async function apply(change, reason) {
    const config = await admin("config");
    change(config);
    await admin("config/apply", { config, reason });
  }
  let browser;
  const contexts = [];
  try {
    await save();
    let available = false;
    for (let attempt = 0; attempt < 60; attempt++) {
      try {
        const health = await admin("health");
        if (health.ready) {
          available = true;
          break;
        }
      } catch {}
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
    assert.ok(available, "lab gateway did not become ready");
    await apply((config) => {
      config.applications.find(
        (app) => app.application_id === "wordpress",
      ).policy.custom_rules = "";
    }, "Reset isolated WordPress method policy to the CRS baseline");
    // Prepare DVWA over its direct loopback fixture endpoint.
    const dvwa = await request.newContext({
      baseURL: "http://127.0.0.1:" + fixture.ports.dvwa,
      timeout: 15000,
    });
    contexts.push(dvwa);
    const setup = await dvwa.get("/setup.php");
    const token = (await setup.text()).match(
      /name=['"]user_token['"]\s+value=['"]([^'"]+)/,
    )?.[1];
    assert.ok(token, "DVWA setup token unavailable");
    await dvwa.post("/setup.php", {
      form: { create_db: "Create / Reset Database", user_token: token },
    });
    const login = await dvwa.get("/login.php");
    const loginToken = (await login.text()).match(
      /name=['"]user_token['"]\s+value=['"]([^'"]+)/,
    )?.[1];
    const logged = await dvwa.post("/login.php", {
      form: {
        username: "admin",
        password: "password",
        Login: "Login",
        user_token: loginToken,
      },
    });
    assert.match(
      await logged.text(),
      /Welcome to Damn Vulnerable Web Application/,
    );
    const state = await dvwa.storageState();
    state.cookies = state.cookies.filter(
      (cookie) => cookie.name !== "security",
    );
    state.cookies.push({
      name: "security",
      value: "low",
      domain: "127.0.0.1",
      path: "/",
      expires: -1,
      httpOnly: false,
      secure: false,
      sameSite: "Lax",
    });
    const protectedDVWA = await request.newContext({
      baseURL: fixture.dvwa_origin,
      storageState: state,
      timeout: 15000,
    });
    contexts.push(protectedDVWA);
    await test("DVWA benign authenticated lookup", "benign", async () => {
      const response = await protectedDVWA.get(
        "/vulnerabilities/sqli/?id=1&Submit=Submit",
      );
      assert.equal(response.status(), 200);
      assert.match(await response.text(), /First name: admin/);
      return { status: response.status() };
    });
    await test(
      "DVWA SQL injection direct exploit and WAF block",
      "attack",
      async () => {
        const target =
          "/vulnerabilities/sqli/?" +
          new URLSearchParams({ id: "1' OR '1'='1' -- ", Submit: "Submit" });
        const direct = await dvwa.get(target);
        const body = await direct.text();
        const rows = (body.match(/First name:/g) || []).length;
        assert.ok(
          rows > 1,
          "direct SQL injection did not return multiple users",
        );
        const blocked = await protectedDVWA.get(target);
        assert.equal(blocked.status(), 403);
        return { baseline_rows: rows, protected_status: blocked.status() };
      },
    );
    await test(
      "DVWA reflected XSS direct exploit and WAF block",
      "attack",
      async () => {
        const target =
          "/vulnerabilities/xss_r/?" +
          new URLSearchParams({ name: "<script>window.owaf_xss=1</script>" });
        const direct = await dvwa.get(target);
        assert.ok(
          (await direct.text()).includes("<script>window.owaf_xss=1</script>"),
          "direct response did not contain executable script",
        );
        const blocked = await protectedDVWA.get(target);
        assert.equal(blocked.status(), 403);
        return { baseline_executable_markup: true, protected_status: 403 };
      },
    );
    await test(
      "DVWA command injection direct execution and WAF block",
      "attack",
      async () => {
        const form = {
          ip: "127.0.0.1; printf OWAF_COMMAND_EXECUTED",
          Submit: "Submit",
        };
        const direct = await dvwa.post("/vulnerabilities/exec/", { form });
        assert.match(await direct.text(), /OWAF_COMMAND_EXECUTED/);
        const blocked = await protectedDVWA.post("/vulnerabilities/exec/", {
          form,
        });
        assert.equal(blocked.status(), 403);
        return { baseline_marker: true, protected_status: 403 };
      },
    );
    await test(
      "DVWA executable upload baseline and WAF verdict",
      "attack",
      async () => {
        const name = "owaf-" + randomUUID() + ".php";
        const multipart = {
          MAX_FILE_SIZE: "100000",
          Upload: "Upload",
          uploaded: {
            name,
            mimeType: "application/x-php",
            buffer: Buffer.from("<?php echo 'OWAF_UPLOAD_EXECUTED'; ?>"),
          },
        };
        const direct = await dvwa.post("/vulnerabilities/upload/", {
          multipart,
        });
        assert.match(await direct.text(), /succesfully uploaded/i);
        const execution = await dvwa.get("/hackable/uploads/" + name);
        assert.equal((await execution.text()).trim(), "OWAF_UPLOAD_EXECUTED");
        multipart.uploaded.name = "protected-" + name;
        const blocked = await protectedDVWA.post("/vulnerabilities/upload/", {
          multipart,
        });
        assert.equal(
          blocked.status(),
          403,
          "executable upload reached the vulnerable application",
        );
        return { baseline_execution: true, protected_status: 403 };
      },
    );
    await test("DVWA harmless text upload", "benign", async () => {
      const response = await protectedDVWA.post("/vulnerabilities/upload/", {
        multipart: {
          MAX_FILE_SIZE: "100000",
          Upload: "Upload",
          uploaded: {
            name: "notes-" + randomUUID() + ".txt",
            mimeType: "text/plain",
            buffer: Buffer.from("Invoice notes and project milestones"),
          },
        },
      });
      assert.equal(response.status(), 200);
      assert.match(await response.text(), /succesfully uploaded/i);
      return { status: 200 };
    });

    const wordpress = await request.newContext({
      baseURL: fixture.wordpress_origin,
      timeout: 15000,
      extraHTTPHeaders: {
        Authorization:
          "Basic " +
          Buffer.from("site-admin:" + fixture.wordpress_app_password).toString(
            "base64",
          ),
      },
    });
    contexts.push(wordpress);
    let postID;
    await test(
      "WordPress authenticated REST publish with rich text",
      "benign",
      async () => {
        const response = await wordpress.post("/wp-json/wp/v2/posts", {
          data: {
            title: "Quarterly review — O'Reilly",
            content:
              "<p>Invoice total &amp; customer notes.</p><pre>SELECT customer FROM invoices</pre>",
            status: "publish",
          },
        });
        assert.equal(
          response.status(),
          201,
          "rich-text publishing was blocked or rejected",
        );
        const body = await response.json();
        postID = body.id;
        assert.equal(body.status, "publish");
        return { status: 201 };
      },
    );
    await test(
      "WordPress search and multilingual punctuation",
      "benign",
      async () => {
        const response = await wordpress.get(
          "/wp-json/wp/v2/posts?" +
            new URLSearchParams({ search: "O'Reilly فاتورة café & quarterly" }),
        );
        assert.equal(response.status(), 200);
        assert.ok(Array.isArray(await response.json()));
        return { status: 200 };
      },
    );
    await test("WordPress multipart media upload", "benign", async () => {
      const png = Buffer.from(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a1ZkAAAAASUVORK5CYII=",
        "base64",
      );
      const response = await wordpress.post("/wp-json/wp/v2/media", {
        multipart: {
          file: {
            name: "pixel-" + randomUUID() + ".png",
            mimeType: "image/png",
            buffer: png,
          },
        },
      });
      assert.equal(response.status(), 201);
      const body = await response.json();
      const downloaded = await wordpress.get(body.source_url);
      assert.equal(downloaded.status(), 200);
      assert.deepEqual(await downloaded.body(), png);
      return { status: 201, download_sha_verified: true };
    });
    await test(
      "WordPress REST deletion requires explicit method policy",
      "tuning",
      async () => {
        assert.ok(postID, "publishing prerequisite failed");
        const response = await wordpress.delete(
          "/wp-json/wp/v2/posts/" + postID + "?force=true",
        );
        assert.equal(response.status(), 403);
        return {
          baseline_status: 403,
          finding: "CRS 911100 rejects DELETE by default",
        };
      },
    );
    await apply((config) => {
      config.applications.find(
        (app) => app.application_id === "wordpress",
      ).policy.custom_rules =
        'SecRule REQUEST_URI "@rx ^/wp-json/wp/v2/posts/[0-9]+(?:[?]|$)" "id:100090,phase:1,pass,nolog,t:none,chain"\n' +
        'SecRule REQUEST_METHOD "@streq DELETE" "t:none,setvar:\'tx.allowed_methods=GET HEAD POST OPTIONS DELETE\'"';
    }, "Permit WordPress post DELETE only on the reviewed numeric REST resource route");
    await test(
      "WordPress REST update and deletion after scoped method tuning",
      "benign",
      async () => {
        assert.ok(postID, "publishing prerequisite failed");
        const edited = await wordpress.post("/wp-json/wp/v2/posts/" + postID, {
          data: {
            title: "Reviewed customer invoice",
            content: "<p>Approved quotation and shipping address.</p>",
          },
        });
        assert.equal(edited.status(), 200, "REST update failed");
        const deleted = await wordpress.delete(
          "/wp-json/wp/v2/posts/" + postID + "?force=true",
        );
        assert.equal(deleted.status(), 200, "REST deletion failed");
        assert.equal((await deleted.json()).deleted, true);
        return { updated: true, deleted: true };
      },
    );
    await test(
      "WordPress method tuning preserves other route and payload checks",
      "attack",
      async () => {
        assert.equal(
          (await wordpress.delete("/wp-json/wp/v2/users/1")).status(),
          403,
        );
        assert.equal(
          (
            await wordpress.delete(
              "/wp-json/wp/v2/posts/999999?" +
                new URLSearchParams({ s: "<script>alert(1)</script>" }),
            )
          ).status(),
          403,
        );
        return {
          unrelated_delete_blocked: true,
          allowed_route_xss_blocked: true,
        };
      },
    );
    await test(
      "WordPress attack outside an editing workflow",
      "attack",
      async () => {
        const response = await wordpress.get(
          "/?" + new URLSearchParams({ s: "<script>alert(1)</script>" }),
        );
        assert.equal(response.status(), 403);
        return { status: 403 };
      },
    );

    let directory = await admin("accounts");
    if (!directory.accounts.length) {
      await admin("accounts", {
        revision: directory.revision,
        username: "qualification-admin",
        role: "administrator",
        disabled: false,
        password: fixture.password,
        reason:
          "Establish the required local recovery administrator in the isolated lab",
      });
      directory = await admin("accounts");
    }
    let account = directory.accounts.find(
      (value) => value.username === "organization-viewer",
    );
    if (!account) {
      await admin("accounts", {
        revision: directory.revision,
        username: "organization-viewer",
        role: "viewer",
        disabled: false,
        password: fixture.password,
        reason: "Bind real Keycloak qualification identity",
        access: { application_ids: ["wordpress"] },
      });
      const updated = await admin("accounts");
      await admin("accounts/oidc", {
        revision: updated.revision,
        username: "organization-viewer",
        subject: fixture.subject,
        reason: "Explicit Keycloak subject binding",
      });
    }
    browser = await chromium.launch({
      executablePath:
        process.env.CHROME_PATH ||
        (process.platform === "win32"
          ? "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
          : undefined),
      headless: true,
    });
    function provider(operation) {
      const run = spawnSync(
        process.platform === "win32" ? "python" : "python3",
        [
          path.resolve(__dirname, "../../scripts/m4_idp.py"),
          operation,
          "--fixture",
          fixturePath,
        ],
        { encoding: "utf8", timeout: 230000 },
      );
      assert.equal(
        run.status,
        0,
        "owned provider control failed: " + operation,
      );
      return JSON.parse(run.stdout);
    }
    async function organizationLogin(
      acr = "2",
      expectSuccess = true,
      options = {},
    ) {
      const context = await browser.newContext();
      const page = await context.newPage();
      await page.goto(fixture.admin_origin);
      const started = await page.evaluate(async () => {
        const response = await fetch("/api/v1/login/oidc", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: "{}",
        });
        if (!response.ok)
          throw new Error("SSO initiation returned " + response.status);
        return response.json();
      });
      const auth = new URL(started.url);
      assert.equal(auth.searchParams.get("code_challenge_method"), "S256");
      auth.searchParams.set("acr_values", acr);
      let heldCallback;
      if (options.holdCallback) {
        await context.route("**/*", async (route) => {
          const request = route.request();
          if (
            request.method() !== "POST" ||
            new URL(request.url()).origin !== fixture.idp_origin
          ) {
            await route.continue();
            return;
          }
          // Intercept the provider's form response before the browser follows
          // its redirect. Redirect targets themselves can bypass route matching.
          const response = await route.fetch({
            maxRedirects: 0,
            timeout: 15000,
          });
          const location = response.headers().location;
          const target = location && new URL(location, fixture.idp_origin);
          if (
            target &&
            target.origin === fixture.admin_origin &&
            target.pathname === "/auth/oidc/callback"
          ) {
            heldCallback = target.toString();
            await route.fulfill({
              status: 200,
              contentType: "text/html",
              body: "Callback held in isolated qualification runner",
            });
          } else {
            await route.fulfill({ response });
          }
        });
      }
      await page.goto(auth.toString());
      const callback =
        options.providerDenied || options.holdCallback
          ? null
          : page.waitForResponse(
              (response) => {
                const target = new URL(response.url());
                return (
                  target.origin === fixture.admin_origin &&
                  target.pathname === "/auth/oidc/callback"
                );
              },
              { timeout: 60000 },
            );
      await page.locator("#username").fill("organization-user");
      await page.locator("#password").fill(fixture.password);
      await page.locator("#kc-login").click();
      if (options.providerDenied) {
        await page.waitForFunction(() =>
          /invalid username|account is disabled/i.test(
            document.body?.textContent || "",
          ),
        );
        assert.equal(new URL(page.url()).origin, fixture.idp_origin);
        assert.equal(
          (
            await context.request.get(fixture.admin_origin + "/api/v1/me")
          ).status(),
          401,
        );
        await context.close();
        return;
      }
      if (acr === "2") {
        await page.locator("#otp").waitFor();
        const current = Math.floor(Date.now() / 30000);
        if (current <= Number(fixture.last_otp_step || 0))
          await new Promise((resolve) =>
            setTimeout(
              resolve,
              (fixture.last_otp_step + 1) * 30000 - Date.now() + 100,
            ),
          );
        const step = Math.floor(Date.now() / 30000);
        await page
          .locator("#otp")
          .fill(otp(Buffer.from(fixture.otp_secret), step));
        fixture.last_otp_step = step;
        await fs.writeFile(
          fixturePath,
          JSON.stringify(fixture, null, 2) + "\n",
        );
        await page.locator("#kc-login").click();
      }
      if (options.holdCallback) {
        for (let attempt = 0; !heldCallback && attempt < 100; attempt++)
          await new Promise((resolve) => setTimeout(resolve, 100));
        assert.ok(heldCallback);
        return { context, page, callbackURL: heldCallback };
      }
      await page.waitForURL((url) => url.origin === fixture.admin_origin, {
        timeout: 20000,
      });
      if (expectSuccess) {
        assert.equal((await callback).status(), 303);
        await page.locator("#shell").waitFor({ state: "visible" });
        const identity = await page.evaluate(async () => {
          const response = await fetch("/api/v1/me");
          return { status: response.status, body: await response.json() };
        });
        await page.screenshot({
          path: path.join(out, "keycloak-login.png"),
          fullPage: true,
        });
        return { context, page, identity };
      }
      const text = await page.locator("body").textContent();
      assert.equal((await callback).status(), 401);
      assert.match(text, /Required identity assurance was not verified/);
      await context.close();
    }
    await test(
      "Keycloak password plus OTP, LoA2 and local application grants",
      "identity",
      async () => {
        const login = await organizationLogin();
        assert.equal(login.identity.status, 200);
        assert.equal(login.identity.body.role, "viewer");
        assert.equal(login.identity.body.strong_authentication, true);
        assert.equal(login.identity.body.authentication_method, "oidc");
        assert.deepEqual(login.identity.body.access.application_ids, [
          "wordpress",
        ]);
        const config = await login.page.evaluate(async () => {
          const response = await fetch("/api/v1/config");
          return response.json();
        });
        assert.deepEqual(
          config.applications.map((value) => value.application_id),
          ["wordpress"],
        );
        const forbidden = await login.page.evaluate(async () => {
          const response = await fetch("/api/v1/accounts");
          return response.status;
        });
        assert.equal(forbidden, 403);
        await login.context.close();
        return {
          provider_mfa: true,
          acr: "2",
          local_role: "viewer",
          application_isolation: true,
        };
      },
    );
    await test(
      "Keycloak genuine password-only LoA1 rejected for required LoA2",
      "identity",
      async () => {
        await organizationLogin("1", false);
        return { weaker_provider_assurance_rejected: true };
      },
    );
    await test(
      "Local unlink revokes a real Keycloak session",
      "identity",
      async () => {
        const login = await organizationLogin();
        const directory = await admin("accounts");
        await admin("accounts/oidc", {
          revision: directory.revision,
          username: "organization-viewer",
          subject: fixture.subject,
          remove: true,
          reason: "Qualification session revocation",
        });
        const status = await login.page.evaluate(async () => {
          const response = await fetch("/api/v1/me");
          return response.status;
        });
        assert.equal(status, 401);
        await login.context.close();
        const latest = await admin("accounts");
        await admin("accounts/oidc", {
          revision: latest.revision,
          username: "organization-viewer",
          subject: fixture.subject,
          reason: "Restore qualification identity binding",
        });
        return { session_revoked: true };
      },
    );
    await test(
      "Real Keycloak signing-key rotation refreshes verification keys",
      "identity-lifecycle",
      async () => {
        const change = provider("rotate");
        assert.notEqual(change.before_kid, change.after_kid);
        const login = await organizationLogin();
        assert.equal(login.identity.body.strong_authentication, true);
        await login.context.close();
        return change;
      },
    );
    await test(
      "Real provider token expiry bounds the OpenWAF session",
      "identity-lifecycle",
      async () => {
        provider("short-ttl");
        let login;
        try {
          login = await organizationLogin();
          const cookie = (await login.context.cookies()).find(
            (item) => item.name === "openwaf_session",
          );
          const remaining = cookie.expires * 1000 - Date.now();
          assert.ok(
            remaining > 0 && remaining <= 31000,
            "provider TTL did not bound the session",
          );
          await new Promise((resolve) => setTimeout(resolve, remaining + 1200));
          const replay = await login.context.request.get(
            fixture.admin_origin + "/api/v1/me",
            {
              headers: { Cookie: "openwaf_session=" + cookie.value },
            },
          );
          assert.equal(
            replay.status(),
            401,
            "server accepted the expired session cookie",
          );
          assert.equal(
            (
              await login.context.request.get(
                fixture.admin_origin + "/api/v1/me",
              )
            ).status(),
            401,
          );
          return {
            real_time_expiry_observed: true,
            token_lifespan_seconds: 30,
          };
        } finally {
          if (login) await login.context.close();
          provider("restore");
        }
      },
    );
    await test(
      "Disabling a local account revokes an existing real SSO session",
      "identity-lifecycle",
      async () => {
        const login = await organizationLogin();
        async function disable(disabled) {
          const directory = await admin("accounts");
          await admin("accounts", {
            revision: directory.revision,
            username: "organization-viewer",
            role: "viewer",
            disabled,
            access: { application_ids: ["wordpress"] },
            reason: "Qualification local account lifecycle",
          });
        }
        try {
          await disable(true);
          assert.equal(
            (
              await login.context.request.get(
                fixture.admin_origin + "/api/v1/me",
              )
            ).status(),
            401,
          );
          return { subsequent_request_revoked: true };
        } finally {
          await disable(false);
          await login.context.close();
        }
      },
    );
    await test(
      "Provider account disable blocks new sign-in; local sessions remain bounded",
      "identity-lifecycle",
      async () => {
        const login = await organizationLogin();
        provider("disable");
        try {
          await organizationLogin("2", false, { providerDenied: true });
          assert.equal(
            (
              await login.context.request.get(
                fixture.admin_origin + "/api/v1/me",
              )
            ).status(),
            200,
          );
          return {
            new_sign_in_rejected: true,
            existing_session_requires_local_revocation_or_expiry: true,
          };
        } finally {
          provider("restore");
          await login.context.close();
        }
      },
    );
    await test(
      "Provider outage rejects code exchange and preserves traffic and local recovery",
      "identity-lifecycle",
      async () => {
        const held = await organizationLogin("2", true, { holdCallback: true });
        provider("stop");
        try {
          await held.context.unrouteAll();
          const rejected = await held.context.request.get(held.callbackURL, {
            maxRedirects: 0,
          });
          assert.equal(rejected.status(), 401);
          assert.match(
            await rejected.text(),
            /Identity provider exchange failed/,
          );
          assert.equal(
            (
              await held.context.request.get(
                fixture.admin_origin + "/api/v1/me",
              )
            ).status(),
            401,
          );
          assert.equal(
            (await wordpress.get("/wp-json/wp/v2/types/post")).status(),
            200,
          );
          const local = await request.newContext({
            baseURL: fixture.admin_origin,
          });
          contexts.push(local);
          const response = await local.post("/api/v1/login", {
            data: {
              username: "qualification-admin",
              password: fixture.password,
            },
            headers: { Origin: fixture.admin_origin },
          });
          assert.equal(response.status(), 200);
          assert.equal((await local.get("/api/v1/me")).status(), 200);
        } finally {
          provider("restore");
          await held.context.close();
        }
        const recovered = await organizationLogin();
        await recovered.context.close();
        return {
          exchange_failed_closed: true,
          inspection_available: true,
          local_administrator_available: true,
          provider_recovery_passed: true,
        };
      },
    );
    await test(
      "Pilot collector uses a scoped token and rejects bootstrap monitoring",
      "operations",
      async () => {
        const accounts = await admin("accounts");
        if (
          !accounts.accounts.some(
            (account) => account.username === "qualification-monitor",
          )
        ) {
          await admin("accounts", {
            revision: accounts.revision,
            username: "qualification-monitor",
            role: "viewer",
            disabled: false,
            password: fixture.password,
            reason: "Dedicated deployment monitoring owner in the isolated lab",
          });
        }
        const directory = await admin("tokens");
        const issued = await admin("tokens", {
          revision: directory.revision,
          owner: "qualification-monitor",
          name: "Isolated pilot collector qualification",
          scopes: ["monitoring:read"],
          lifetime_hours: 1,
          reason:
            "Exercise real monitoring endpoints without administrative authority",
        });
        const credential = path.resolve(out, "monitoring-token.private.txt");
        const manifestPath = path.join(out, "pilot-smoke.private.json");
        const database = path.join(out, "pilot-smoke-" + randomUUID() + ".db");
        const canaryURL =
          fixture.wordpress_origin + "/wp-json/wp/v2/types/post";
        const response = await fetch(canaryURL);
        assert.equal(response.status, 200);
        const canary = Buffer.from(await response.arrayBuffer());
        assert.equal(JSON.parse(canary).slug, "post");
        await fs.writeFile(credential, issued.secret, { mode: 0o600 });
        await fs.writeFile(
          manifestPath,
          JSON.stringify(
            {
              schema: 1,
              pilot_id: "lab-smoke-" + fixture.tag,
              owner: "Qualification runner (isolated lab only)",
              host: fixture.vm_dir,
              qualification_evidence: resultPath,
              capacity_evidence: "M3 reference evidence; no lab capacity claim",
              management_url: fixture.admin_origin,
              token_file: credential,
              oidc_issuer: fixture.idp_origin + "/realms/openwaf-lab",
              canaries: [
                {
                  name: "wordpress-schema",
                  url: canaryURL,
                  status: 200,
                  sha256: createHash("sha256").update(canary).digest("hex"),
                },
              ],
            },
            null,
            2,
          ),
          { mode: 0o600 },
        );
        function collect(operation) {
          const run = spawnSync(
            process.platform === "win32" ? "python" : "python3",
            [
              path.resolve(__dirname, "../../scripts/pilot.py"),
              operation,
              "--manifest",
              manifestPath,
              "--database",
              database,
            ],
            { encoding: "utf8", timeout: 60000 },
          );
          assert.ok(!run.error, "collector subprocess failed");
          return { code: run.status, body: JSON.parse(run.stdout) };
        }
        try {
          const started = collect("start");
          assert.equal(started.code, 0);
          assert.equal(started.body.healthy, true);
          await fs.writeFile(credential, fixture.token);
          const excessive = collect("sample");
          assert.equal(excessive.code, 1);
          assert.equal(excessive.body.checks.monitoring_credential.ok, false);
          await fs.writeFile(credential, issued.secret);
          assert.equal(collect("sample").body.healthy, true);
          const status = collect("status");
          assert.equal(status.body.observation_ready_for_review, false);
          assert.equal(status.body.samples, 3);
          const evidence = await fs.readFile(database);
          assert.ok(!evidence.includes(Buffer.from(issued.secret)));
          assert.ok(!evidence.includes(Buffer.from(fixture.token)));
          return {
            scoped_monitoring_passed: true,
            bootstrap_rejected: true,
            database_contains_no_bearer_secrets: true,
            business_pilot_started: false,
          };
        } finally {
          const latest = await admin("tokens");
          await admin("tokens/" + issued.token.id + "/revoke", {
            revision: latest.revision,
            reason: "Qualification complete",
          });
        }
      },
    );
    report.passed =
      report.cases.length > 0 && report.cases.every((value) => value.passed);
    report.finished = new Date().toISOString();
    await save();
    if (!report.passed) process.exitCode = 1;
  } finally {
    const restored = spawnSync(
      process.platform === "win32" ? "python" : "python3",
      [
        path.resolve(__dirname, "../../scripts/m4_idp.py"),
        "restore",
        "--fixture",
        fixturePath,
      ],
      { encoding: "utf8", timeout: 230000 },
    );
    report.provider_settings_restored = restored.status === 0;
    if (!report.provider_settings_restored) {
      report.passed = false;
      process.exitCode = 1;
    }
    for (const context of contexts) await context.dispose();
    if (browser) await browser.close();
    await save();
  }
}
main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
