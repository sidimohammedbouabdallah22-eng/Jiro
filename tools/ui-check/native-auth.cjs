// Synthetic authenticator fixture. Read/write private credentials through pipes only.
const { chromium } = require("playwright");
const assert = require("node:assert/strict");
const { createHmac } = require("node:crypto");

function otp(secret, step) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bits = [...secret]
    .map((value) => alphabet.indexOf(value).toString(2).padStart(5, "0"))
    .join("");
  const key = Buffer.from(
    (bits.match(/.{8}/g) || []).map((value) => parseInt(value, 2)),
  );
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const hash = createHmac("sha1", key).update(counter).digest();
  return ((hash.readUInt32BE(hash[19] & 15) & 0x7fffffff) % 1000000)
    .toString()
    .padStart(6, "0");
}
async function main() {
  let input = "";
  for await (const chunk of process.stdin) input += chunk;
  const fixture = JSON.parse(input);
  const executablePath =
    process.env.CHROME_PATH ||
    (process.platform === "win32"
      ? "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
      : undefined);
  const browser = await chromium.launch({ executablePath, headless: true });
  try {
    const page = await browser.newPage();
    const cdp = await page.context().newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    const { authenticatorId } = await cdp.send(
      "WebAuthn.addVirtualAuthenticator",
      {
        options: {
          protocol: "ctap2",
          transport: "internal",
          hasResidentKey: true,
          hasUserVerification: true,
          isUserVerified: true,
          automaticPresenceSimulation: true,
        },
      },
    );
    if (fixture.credential)
      await cdp.send("WebAuthn.addCredential", {
        authenticatorId,
        credential: fixture.credential,
      });
    await page.goto(fixture.origin);
    const identity = await page.evaluate(async (fixture) => {
      async function api(path, body) {
        const response = await fetch("/api/v1/" + path, {
          method: body ? "POST" : "GET",
          headers: { "Content-Type": "application/json" },
          body: body ? JSON.stringify(body) : undefined,
        });
        const value = await response.json();
        if (!response.ok)
          throw new Error(
            path + " " + response.status + " " + JSON.stringify(value),
          );
        return value;
      }
      if (!fixture.credential) {
        await api("login", {
          username: "qa-admin",
          password: fixture.password,
        });
        const begin = await api("me/passkeys/begin", {
          password: fixture.password,
        });
        const credential = await navigator.credentials.create({
          publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(
            begin.options.publicKey,
          ),
        });
        await api("me/passkeys/finish", {
          ceremony_id: begin.ceremony_id,
          name: "Native interruption fixture",
          response: credential.toJSON(),
        });
      }
      const begin = await api("login/passkey/begin", { username: "qa-admin" });
      const credential = await navigator.credentials.get({
        publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(
          begin.options.publicKey,
        ),
      });
      await api("login/passkey/finish", {
        ceremony_id: begin.ceremony_id,
        response: credential.toJSON(),
      });
      let identity = await api("me");
      if (!fixture.credential) {
        const policy = await api("security-policy");
        await api("security-policy", {
          revision: policy.revision,
          require_admin_mfa: true,
          reason: "Native passkey enforcement qualification",
        });
        identity = await api("me");
      }
      return identity;
    }, fixture);
    assert.equal(identity.username, "qa-admin");
    assert.equal(identity.strong_authentication, true);
    assert.equal(Boolean(identity.mfa_enrollment_required), false);
    async function api(path, body) {
      return page.evaluate(
        async ({ path, body }) => {
          const response = await fetch("/api/v1/" + path, {
            method: body ? "POST" : "GET",
            headers: { "Content-Type": "application/json" },
            body: body ? JSON.stringify(body) : undefined,
          });
          const value = await response.json();
          if (!response.ok)
            throw new Error(path + " returned " + response.status);
          return value;
        },
        { path, body },
      );
    }
    let totp = fixture.totp;
    if (!totp) {
      const directory = await api("accounts");
      await api("accounts", {
        revision: directory.revision,
        username: "qa-otp",
        role: "administrator",
        disabled: false,
        password: fixture.password,
        reason: "Native TOTP persistence fixture",
      });
      await api("login", { username: "qa-otp", password: fixture.password });
      const setup = await api("me/mfa/setup", { password: fixture.password });
      const step = Math.floor(Date.now() / 30000);
      await api("me/mfa/enable", {
        password: fixture.password,
        code: otp(setup.secret, step),
      });
      totp = {
        secret: setup.secret,
        password: fixture.password,
        last_step: step,
      };
    }
    const step = Math.max(Math.floor(Date.now() / 30000), totp.last_step + 1);
    assert.ok(
      step <= Math.floor(Date.now() / 30000) + 1,
      "wait for the next TOTP window before retrying this fixture",
    );
    await api("login", {
      username: "qa-otp",
      password: totp.password,
      code: otp(totp.secret, step),
    });
    const totpIdentity = await api("me");
    assert.equal(totpIdentity.strong_authentication, true);
    assert.equal(totpIdentity.username, "qa-otp");
    totp.last_step = step;
    const { credentials } = await cdp.send("WebAuthn.getCredentials", {
      authenticatorId,
    });
    assert.equal(credentials.length, 1);
    process.stdout.write(
      JSON.stringify({ identity, credential: credentials[0], totp }),
    );
  } finally {
    await browser.close();
  }
}
main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
