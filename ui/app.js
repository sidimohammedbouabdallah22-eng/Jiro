"use strict";
const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
let config = null,
  events = [],
  dirty = false,
  busy = false,
  signedIn = false;
let draftExceptions = [],
  editingException = -1,
  comparedRevision = null;
let storedEvents = [],
  nextBefore = 0,
  eventSearchTimer,
  eventQueryGeneration = 0;
let auditEntries = [];
let authenticationOptions = {oidc:false,passkeys:false};
let currentUser = { role: "viewer", bootstrap: false },
  accountDocument = null;
const trafficKeys = [
  "requests_per_second",
  "burst",
  "client_requests_per_second",
  "client_burst",
  "client_body_kib_per_second",
  "client_body_burst_kib",
  "max_concurrent",
  "max_client_concurrent",
  "max_client_buffer_mib",
  "admission_wait_ms",
];
let selectedApplicationID = null,
  comparedSchema = null;
const applicationPolicyKeys = [
  "mode",
  "paranoia",
  "inbound_threshold",
  "outbound_threshold",
  "request_limit",
  "response_limit",
  "inspect_response",
  "exclusions",
  "custom_rules",
  "scoped_exceptions",
];
function editedConfig(deployment = config) {
  if (deployment.schema_version === 1) return deployment;
  const app =
    deployment.applications.find(
      (app) => app.application_id === selectedApplicationID,
    ) || deployment.applications[0];
  return {
    schema_version: 1,
    revision: deployment.revision,
    application_id: app.application_id,
    name: app.name,
    upstream: app.upstream,
    ...app.policy,
    traffic_controls: app.traffic_controls,
    upstream_pool: app.upstream_pool,
  };
}
function applicationFromForm(leaf, hosts) {
  const policy = {};
  for (const key of applicationPolicyKeys) policy[key] = leaf[key];
  return {
    application_id: leaf.application_id,
    name: leaf.name,
    hosts,
    upstream: leaf.upstream,
    policy,
    ...(leaf.upstream_pool ? {upstream_pool: leaf.upstream_pool} : {}),
    ...(leaf.traffic_controls
      ? { traffic_controls: leaf.traffic_controls }
      : {}),
  };
}
function hostnames(value) {
  return value
    .split(/[,\s]+/)
    .filter(Boolean)
    .map((host) => host.toLowerCase().replace(/\.$/, ""));
}
function applicationControls() {
  const apps = config.schema_version === 2 ? config.applications : [config];
  $("#new-application").disabled =
    busy ||
    currentUser.role === "viewer" ||
    config.schema_version === 1 ||
    apps.length >= 8 || !!currentUser.access;
  $("#remove-application").disabled =
    busy || currentUser.role === "viewer" || apps.length <= 1 || !!currentUser.access;
}
function addPoolRow(backend = {}) {
  const row = document.createElement("div");
  row.className = "field-grid pool-backend";
  for (const [key, title] of [["id", "Backend ID"], ["url", "Backend URL"], ["tls_server_name", "TLS server name override"]]) {
    const label = document.createElement("label");
    const input = document.createElement("input");
    input.dataset.backendField = key;
    input.value = backend[key] || "";
    input.maxLength = key === "url" ? 2048 : 253;
    input.required = key !== "tls_server_name";
    if (key === "url") input.type = "url";
    label.append(document.createTextNode(title), input);
    row.append(label);
  }
  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "secondary";
  remove.textContent = "Remove backend";
  remove.addEventListener("click", () => { row.remove(); dirty = true; draftStatus(); poolControls(); });
  row.append(remove);
  $("#pool-backends").append(row);
}
function fillPoolForm(application) {
  const pool = application?.upstream_pool;
  $("#pool-enabled").checked = !!pool;
  $("#pool-threshold").value = pool?.failure_threshold || 3;
  $("#pool-cooldown").value = pool?.cooldown_seconds || 30;
  $("#pool-header-timeout").value = pool?.header_timeout_seconds || 30;
  $("#pool-backends").replaceChildren();
  for (const backend of pool?.backends || [{id:"primary",url:editedConfig().upstream}]) addPoolRow(backend);
  poolControls();
}
function poolControls() {
  const readOnly = busy || currentUser.role === "viewer" || !!currentUser.access || config?.schema_version !== 2;
  $("#pool-enabled").disabled = readOnly;
  $("#pool-settings").hidden = !$("#pool-enabled").checked;
  $$("#pool-settings input, #pool-settings button").forEach((input) => { input.disabled = readOnly || !$("#pool-enabled").checked; });
  $("#add-pool-backend").disabled = readOnly || $$(".pool-backend").length >= 8;
}
function readPoolForm() {
  const backends = $$(".pool-backend").map((row) => Object.fromEntries([...row.querySelectorAll("input")].map((input) => [input.dataset.backendField, input.value.trim()])));
  if (!backends.length) throw new Error("A pool requires at least one backend.");
  return {backends, failure_threshold:Number($("#pool-threshold").value), cooldown_seconds:Number($("#pool-cooldown").value), header_timeout_seconds:Number($("#pool-header-timeout").value)};
}
function renderUpstreams(status) {
  const application = status.applications.find((application) => application.application_id === selectedApplicationID);
  $("#pool-observations").textContent = application?.backends.map((backend) => `${backend.id} · ${backend.state.replaceAll("_", " ")} · ${backend.consecutive_failures} failures`).join(" | ") || "No backend observations for this application.";
}
$("#pool-enabled").addEventListener("change", poolControls);
$("#add-pool-backend").addEventListener("click", () => {
  addPoolRow({id:"backend-" + ($$(".pool-backend").length + 1)});
  dirty = true;
  draftStatus();
  poolControls();
});
const titles = {
  access: [
    "Accounts & access",
    "Manage local identities, permissions and your password.",
  ],
  overview: [
    "Security overview",
    "A clear view of your application perimeter.",
  ],
  application: [
    "Application configuration",
    "Connect your upstream and control traffic limits.",
  ],
  policy: [
    "Security policy",
    "Tune the real OWASP Core Rule Set for your application.",
  ],
  rules: [
    "Rules & exceptions",
    "Investigate, tune, and extend your inspection policy.",
  ],
  events: [
    "Security events",
    "Understand what the firewall observed and why it intervened.",
  ],
  system: [
    "System",
    "Runtime details and the scope of this foundation release.",
  ],
  history: [
    "Policy history",
    "Review changes and restore a previous policy safely.",
  ],
};
function notice(message, error = false) {
  const el = $("#notice");
  el.textContent = message;
  el.classList.toggle("error", error);
  el.hidden = !message;
}
function showLogin() {
  const hadSession = signedIn;
  signedIn = false;
  $("#shell").hidden = true;
  $("#login").hidden = false;
  clearSecuritySecrets();
  if (hadSession) location.reload();
}
async function api(path, method = "GET", data) {
  const res = await fetch("/api/v1/" + path, {
    method,
    credentials: "same-origin",
    headers: method === "GET" ? {} : { "Content-Type": "application/json" },
    body: data === undefined ? undefined : JSON.stringify(data),
  });
  const value = await res.json();
  if (!res.ok) {
    if (res.status === 401 && path !== "login") showLogin();
    throw new Error(value.error || `HTTP ${res.status}`);
  }
  return value;
}
function navigate(view) {
  if (!titles[view]) view = "overview";
  const allowed = currentUser.mfa_enrollment_required ? ["access"] : currentUser.access ? ["application", "policy", "rules", "events", "access"] : Object.keys(titles);
  if (!allowed.includes(view)) view = allowed[0];
  $$("[data-view]").forEach((button) => { button.hidden = !allowed.includes(button.dataset.view); });
  $$("[data-page]").forEach((el) => (el.hidden = el.dataset.page !== view));
  $$("[data-view]").forEach((el) =>
    el.classList.toggle("active", el.dataset.view === view),
  );
  $("#page-title").textContent = titles[view][0];
  $("#page-subtitle").textContent = titles[view][1];
  $("#crumb").textContent =
    view === "rules"
      ? "Rules & exceptions"
      : view[0].toUpperCase() + view.slice(1);
  $("#save-bar").hidden = !["application", "policy", "rules"].includes(view);
  notice("");
  if (view === "history") loadHistory().catch((e) => notice(e.message, true));
  if (view === "system" && signedIn)
    loadAudit().catch((e) => notice(e.message, true));
  if (view === "access" && signedIn && currentUser.role === "administrator" && !currentUser.mfa_enrollment_required)
    loadAccounts().catch((e) => notice(e.message, true));
  if (view === "access" && signedIn && !currentUser.bootstrap && authenticationOptions.passkeys) loadPasskeys().catch((e) => notice(e.message,true));
  if (view === "events" && signedIn)
    loadStoredEvents().catch((e) => notice(e.message, true));
}
$$("[data-view]").forEach((el) =>
  el.addEventListener("click", () => (location.hash = el.dataset.view)),
);
$$("[data-go]").forEach((el) =>
  el.addEventListener("click", () => (location.hash = el.dataset.go)),
);
window.addEventListener("hashchange", () => navigate(location.hash.slice(1)));
function draftStatus() {
  $("#draft-status").textContent = dirty ? "Unsaved changes" : "Active policy";
  $("#revision-label").textContent = "Revision " + (config?.revision ?? "—");
}
function fillForm() {
  const apps = config.schema_version === 2 ? config.applications : [config];
  if (!apps.some((app) => app.application_id === selectedApplicationID))
    selectedApplicationID = apps[0].application_id;
  const application = editedConfig();
  for (const key of trafficKeys)
    $("#config-form").elements.namedItem("traffic_" + key).value =
      application.traffic_controls?.[key] || 0;
  $("#application-selector").replaceChildren(
    ...apps.map((app) => {
      const option = document.createElement("option");
      option.value = app.application_id;
      option.textContent = app.name;
      return option;
    }),
  );
  $("#application-selector").value = selectedApplicationID;
  $("#selected-application-id").value = selectedApplicationID;
  const selected =
    config.schema_version === 2
      ? apps.find((app) => app.application_id === selectedApplicationID)
      : null;
  $("#config-form").elements.hostnames.value = selected
    ? selected.hosts.join(", ")
    : "";
  $("#config-form").elements.hostnames.required = config.schema_version === 2;
  $("#routing-state").textContent = selected
    ? `${apps.length} applications use exact hostname routing. Unknown hostnames are rejected. Counters and resource limits cover the whole deployment.`
    : "Current routing accepts any hostname for this application. Save explicit hostnames to enable strict routing and add applications.";
  $("#application-filter-options").replaceChildren(
    ...apps.map((app) => {
      const option = document.createElement("option");
      option.value = app.application_id;
      option.label = app.name;
      return option;
    }),
  );
  fillPoolForm(selected);
  const form = $("#config-form");
  for (const [key, value] of Object.entries(application)) {
    const field = form.elements.namedItem(key);
    if (!field) continue;
    if (field.type === "checkbox") field.checked = value;
    else field.value = key === "exclusions" ? (value || []).join(", ") : value;
  }
  dirty = false;
  draftExceptions = structuredClone(application.scoped_exceptions || []);
  $("#change-reason").value = "";
  renderExceptions();
  draftStatus();
  $("#exclusion-chips").replaceChildren(
    ...(application.exclusions || []).map((id) => {
      const s = document.createElement("span");
      s.className = "chip";
      s.textContent = "CRS " + id;
      return s;
    }),
  );
  applicationControls();
  permissions();
}
function readForm() {
  const form = $("#config-form"),
    c = { ...editedConfig() };
  for (const key of ["name", "upstream", "mode", "custom_rules"])
    c[key] = form.elements.namedItem(key).value.trim();
  for (const key of [
    "paranoia",
    "inbound_threshold",
    "outbound_threshold",
    "request_limit",
    "response_limit",
  ])
    c[key] = Number(form.elements.namedItem(key).value);
  c.inspect_response = form.elements.inspect_response.checked;
  c.scoped_exceptions = structuredClone(draftExceptions);
  const ids = form.elements.exclusions.value.trim();
  if (ids && !/^[\d,\s]+$/.test(ids))
    throw new Error(
      "Rule exceptions must contain numeric IDs separated by commas or spaces.",
    );
  c.exclusions = ids
    ? ids
        .split(/[,\s]+/)
        .filter(Boolean)
        .map(Number)
    : [];
  if ($("#pool-enabled").checked) {
    c.upstream_pool = readPoolForm();
    c.upstream = c.upstream_pool.backends[0].url;
  } else delete c.upstream_pool;
  const hosts = hostnames(form.elements.hostnames.value);
  const traffic = Object.fromEntries(
    trafficKeys.map((key) => [
      key,
      Number(form.elements.namedItem("traffic_" + key).value),
    ]),
  );
  if (Object.values(traffic).some((value) => value !== 0))
    c.traffic_controls = traffic;
  else delete c.traffic_controls;
  if (config.schema_version === 1)
    return hosts.length
      ? {
          schema_version: 2,
          revision: config.revision,
          applications: [applicationFromForm(c, hosts)],
        }
      : c;
  return {
    ...config,
    applications: config.applications.map((app) =>
      app.application_id === selectedApplicationID
        ? applicationFromForm(c, hosts)
        : app,
    ),
  };
}
$("#config-form").addEventListener("input", () => {
  dirty = true;
  draftStatus();
});
$("#application-selector").addEventListener("change", () => {
  if (
    busy ||
    (dirty && !confirm("Discard this application's unsaved changes?"))
  ) {
    $("#application-selector").value = selectedApplicationID;
    return;
  }
  selectedApplicationID = $("#application-selector").value;
  fillForm();
  renderPolicy();
});
$("#new-application").addEventListener("click", () => {
  if (busy) return;
  if (dirty) {
    notice("Save or discard this draft before adding an application.", true);
    return;
  }
  $("#application-create-form").reset();
  $("#application-create-error").textContent = "";
  $("#application-dialog").showModal();
});
$("#close-application").addEventListener("click", () =>
  $("#application-dialog").close(),
);
$("#application-create-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (busy) return;
  const id = $("#new-application-id").value.trim();
  lock(true);
  $("#create-application").disabled = true;
  try {
    config = await api("applications", "POST", {
      revision: config.revision,
      application_id: id,
      name: $("#new-application-name").value.trim(),
      hosts: hostnames($("#new-application-hosts").value),
      upstream: $("#new-application-upstream").value.trim(),
      reason: $("#new-application-reason").value.trim(),
    });
    selectedApplicationID = id;
    fillForm();
    renderPolicy();
    $("#application-dialog").close();
    notice(
      "Application created in detection mode. Review its policy before enabling enforcement.",
    );
  } catch (e) {
    $("#application-create-error").textContent = e.message;
  } finally {
    lock(false);
    $("#create-application").disabled = false;
  }
});
$("#remove-application").addEventListener("click", () => {
  if (busy) return;
  if (dirty) {
    notice("Save or discard this draft before removing an application.", true);
    return;
  }
  $("#application-remove-description").textContent =
    `Remove ${editedConfig().name}? Its hostnames will be rejected until reassigned.`;
  $("#remove-application-reason").value = "";
  $("#application-remove-error").textContent = "";
  $("#application-remove-dialog").showModal();
});
$("#close-remove-application").addEventListener("click", () =>
  $("#application-remove-dialog").close(),
);
$("#application-remove-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (busy) return;
  const id = selectedApplicationID;
  lock(true);
  $("#delete-application").disabled = true;
  try {
    config = await api(
      `applications/${encodeURIComponent(id)}/delete`,
      "POST",
      {
        revision: config.revision,
        reason: $("#remove-application-reason").value.trim(),
      },
    );
    selectedApplicationID = null;
    fillForm();
    renderPolicy();
    $("#application-remove-dialog").close();
    notice(
      "Application removed as deployment revision " + config.revision + ".",
    );
  } catch (e) {
    $("#application-remove-error").textContent = e.message;
  } finally {
    lock(false);
    $("#delete-application").disabled = false;
  }
});
function lock(value) {
  busy = value;
  ["save", "validate", "discard"].forEach(
    (id) => ($("#" + id).disabled = value),
  );
  $$(
    "#config-form input, #config-form textarea, #config-form select, #config-form button",
  ).forEach((el) => (el.disabled = value));
  if (config) applicationControls();
  permissions();
}

function permissions() {
  $("#identity-label").textContent =
    `${currentUser.username || "Bootstrap"} · ${currentUser.role}`;
  $("#accounts-panel").hidden = currentUser.role !== "administrator" || currentUser.mfa_enrollment_required;
  $("#password-panel").hidden = currentUser.bootstrap || currentUser.mfa_enrollment_required;
  $("#tokens-panel").hidden = currentUser.role !== "administrator" || currentUser.mfa_enrollment_required;
  $("#mfa-panel").hidden = currentUser.bootstrap;
  $("#mfa-status").textContent = currentUser.mfa_enabled ? "Authenticator MFA is enabled." : "Authenticator MFA is available for this account.";
  $("#mfa-setup").hidden = !!currentUser.mfa_enabled;
  $("#mfa-disable").hidden = !currentUser.mfa_enabled;
  $("#enrollment-required-panel").hidden = !currentUser.mfa_enrollment_required;
  $("#mfa-policy-panel").hidden = currentUser.role !== "administrator" || currentUser.mfa_enrollment_required;
  $("#mfa-policy-stepup").hidden = currentUser.bootstrap;
  $("#passkeys-panel").hidden = currentUser.bootstrap || !authenticationOptions.passkeys;
  $("#oidc-bindings-panel").hidden = currentUser.role !== "administrator" || currentUser.mfa_enrollment_required || !authenticationOptions.oidc;
  if (currentUser.mfa_enrollment_required) {
    $("#connection").textContent = "● Enrollment required";
    $("#side-mode").textContent = "Enrollment-only access";
    $("#last-updated").textContent = "Confirm your authenticator to continue";
  }
  if (!config) return;

  const readOnly = currentUser.role === "viewer";
  $$(
    "#config-form input, #config-form textarea, #config-form select, #config-form button",
  ).forEach((el) => {
    el.disabled = busy || readOnly;
  });
  applicationControls();
  poolControls();
  $("#application-selector").disabled = busy;
  if (currentUser.access) for (const name of ["upstream", "hostnames"]) $("#config-form").elements.namedItem(name).disabled = true;
  for (const key of trafficKeys)
    $("#config-form").elements.namedItem("traffic_" + key).disabled =
      busy || readOnly || config?.schema_version !== 2;
  for (const id of ["save", "validate"])
    $("#" + id).disabled = busy || readOnly;

}

$("#login-method").addEventListener("change", () => {
  const account = $("#login-method").value === "account";
  $("#account-login-fields").hidden = !account;
  $("#token-login-fields").hidden = account;
  $("#token").disabled = account;
  $("#token").required = !account;
  for (const id of ["login-username", "login-password", "login-code"]) {
    $("#" + id).disabled = !account;
    $("#" + id).required = account && id !== "login-code";
  }
});

async function loadAccounts() {
  $("#mfa-policy-form button").disabled = true;
  accountDocument = await api("accounts");
  const selected = $("#account-selector").value;
  const blank = document.createElement("option");
  blank.value = "";
  blank.textContent = "Create account";
  $("#account-selector").replaceChildren(
    blank,
    ...accountDocument.accounts.map((account) => {
      const option = document.createElement("option");
      option.value = account.username;
      option.textContent = `${account.username} · ${account.role}${account.disabled ? " · disabled" : ""}`;
      return option;
    }),
  );
  $("#account-selector").value = accountDocument.accounts.some(
    (account) => account.username === selected,
  )
    ? selected
    : "";
  fillAccount();
  $("#oidc-binding-user").replaceChildren(...accountDocument.accounts.map((account) => { const option=document.createElement("option");option.value=account.username;option.textContent=account.username;return option; }));
  $("#oidc-binding-list").textContent = accountDocument.accounts.filter((account) => account.oidc?.length).map((account) => account.username + " · " + account.oidc.map((binding) => binding.issuer + " / " + binding.subject).join(", ")).join("\n");
  await loadTokens();
  securityPolicyDocument = await api("security-policy");
  $("#require-admin-mfa").checked = securityPolicyDocument.require_admin_mfa;
  $("#mfa-policy-form button").disabled = false;
}
function fillAccount() {
  const account = accountDocument?.accounts.find(
    (account) => account.username === $("#account-selector").value,
  );
  $("#account-username").value = account?.username || "";
  $("#account-username").readOnly = !!account;
  $("#account-role").value = account?.role || "administrator";
  $("#account-disabled").checked = account?.disabled || false;
  $("#account-password").value = "";
  $("#account-password").required = !account;
  $("#account-reason").value = "";
  $("#reset-mfa").hidden = !currentUser.bootstrap || !account?.mfa_enabled;
  $("#reset-passkeys").hidden = !currentUser.bootstrap || !account?.passkey_count;
  $("#account-access-mode").value = account?.access ? "assigned" : "all";
  fillAssignmentOptions("account-applications", config.applications || [], account?.access?.application_ids || []);
  accountAccessControls();
}
let tokenDocument = null, securityPolicyDocument = null;
function fillAssignmentOptions(id, applications, selected) {
  const fieldset = $("#" + id);
  const legend = fieldset.querySelector("legend");
  fieldset.replaceChildren(legend, ...applications.map((application) => {
    const label = document.createElement("label");
    const input = document.createElement("input");
    input.type = "checkbox";
    input.value = application.application_id;
    input.checked = selected.includes(input.value);
    label.append(input, document.createTextNode(" " + application.name + " · " + input.value));
    return label;
  }));
}
function accountAccessControls() {
  const administrator = $("#account-role").value === "administrator";
  const legacy = config?.schema_version !== 2;
  if (administrator || legacy) $("#account-access-mode").value = "all";
  $("#account-access-mode").disabled = administrator || legacy;
  $("#account-applications").hidden = $("#account-access-mode").value !== "assigned";
}
function fillTokenAssignments() {
  const owner = accountDocument?.accounts.find((account) => account.username === $("#automation-owner").value);
  const applications = (config?.applications || []).filter((application) => !owner?.access || owner.access.application_ids.includes(application.application_id));
  const selected = $$("#automation-applications input:checked").map((input) => input.value);
  fillAssignmentOptions("automation-applications", applications, selected);
  $("#automation-applications").hidden = $("#automation-access-mode").value !== "assigned";
  $("#automation-access-mode").disabled = config?.schema_version !== 2;
}
function readAssignment(prefix) {
  if ($("#" + prefix + "-access-mode").value !== "assigned") return null;
  const ids = $$("#" + prefix + "-applications input:checked").map((input) => input.value);
  if (!ids.length) throw new Error("Select at least one assigned application.");
  return { application_ids: ids };
}
$("#account-role").addEventListener("change", accountAccessControls);
$("#account-access-mode").addEventListener("change", accountAccessControls);
$("#automation-access-mode").addEventListener("change", () => { fillTokenAssignments(); automationScopeControls(); });
$("#mfa-policy-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $("#mfa-policy-form button");
  button.disabled = true;
  $("#mfa-policy-error").textContent = "";
  try {
    await api("security-policy", "POST", {
      revision: securityPolicyDocument.revision,
      require_admin_mfa: $("#require-admin-mfa").checked,
      password: $("#mfa-policy-password").value,
      code: $("#mfa-policy-code").value,
      reason: $("#mfa-policy-reason").value.trim(),
    });
    $("#mfa-policy-password").value = "";
    $("#mfa-policy-code").value = "";
    await loadAccounts();
    notice("Administrator authentication policy saved.");
  } catch (error) { $("#mfa-policy-error").textContent = error.message; }
  finally { button.disabled = false; }
});
function clearSecuritySecrets() {
  for (const id of ["issued-token", "mfa-secret", "mfa-uri"]) $("#" + id).textContent = "";
  for (const id of ["issued-token-panel", "mfa-enrollment", "mfa-enable"]) $("#" + id).hidden = true;
  for (const id of ["login-password", "login-code", "mfa-password", "mfa-code", "current-password", "self-new-password", "password-code", "account-password", "mfa-policy-password", "mfa-policy-code", "passkey-password", "passkey-code"]) $("#" + id).value = "";
}
function renderAuthenticationOptions() {
  $("#passkey-signin").hidden = !authenticationOptions.passkeys;
  $("#oidc-signin").hidden = !authenticationOptions.oidc;
  const wrongOrigin = authenticationOptions.origin && location.origin !== authenticationOptions.origin;
  $("#auth-origin-hint").hidden = !wrongOrigin;
  $("#auth-origin-hint").textContent = wrongOrigin ? "Use " + authenticationOptions.origin + " for configured passkey and SSO sign-in." : "";
}
async function passkeySignIn() {
  if (dirty && !confirm("Verify identity and discard unsaved policy changes?")) return;
  if (!signedIn && $("#login-method").value !== "account") {
    $("#login-method").value = "account";
    $("#login-method").dispatchEvent(new Event("change"));
  }
  const username = signedIn ? currentUser.username : $("#login-username").value.trim();
  if (!username) { $("#login-username").focus(); return; }
  const errorElement = signedIn ? $("#passkey-error") : $("#login-error");
  errorElement.textContent = "";
  try {
    if (!window.PublicKeyCredential?.parseRequestOptionsFromJSON) throw new Error("This browser does not support passkey JSON options.");
    const begin = await api("login/passkey/begin", "POST", {username});
    const credential = await navigator.credentials.get({publicKey:PublicKeyCredential.parseRequestOptionsFromJSON(begin.options.publicKey)});
    await api("login/passkey/finish", "POST", {ceremony_id:begin.ceremony_id,response:credential.toJSON()});
    $("#login-password").value = "";
    $("#passkey-password").value = "";
    $("#passkey-code").value = "";
    await initialize();
  } catch (error) { errorElement.textContent = error.message; }
}
$("#passkey-signin").addEventListener("click", passkeySignIn);
$("#verify-passkey").addEventListener("click", passkeySignIn);
$("#oidc-signin").addEventListener("click", async () => {
  try {
    const result = await api("login/oidc", "POST", {});
    location.assign(result.url);
  } catch (error) { $("#login-error").textContent = error.message; }
});
$("#passkey-enrollment-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $("#passkey-enrollment-form button");
  button.disabled = true;
  $("#passkey-error").textContent = "";
  try {
    if (!window.PublicKeyCredential?.parseCreationOptionsFromJSON) throw new Error("This browser does not support passkey JSON options.");
    const begin = await api("me/passkeys/begin", "POST", {password:$("#passkey-password").value,code:$("#passkey-code").value});
    const credential = await navigator.credentials.create({publicKey:PublicKeyCredential.parseCreationOptionsFromJSON(begin.options.publicKey)});
    await api("me/passkeys/finish", "POST", {ceremony_id:begin.ceremony_id,name:$("#passkey-name").value.trim(),response:credential.toJSON()});
    showLogin();
  } catch (error) { $("#passkey-error").textContent = error.message; }
  finally { button.disabled = false; }
});
async function loadPasskeys() {
  const result = await api("me/passkeys");
  $("#passkey-list").replaceChildren(...result.items.map((key) => {
    const row = document.createElement("p");
    row.append(document.createTextNode(key.name + " · " + key.rp_id + " · " + new Date(key.created).toLocaleString() + " "));
    const button = document.createElement("button");
    button.type = "button";
    button.className = "secondary";
    button.textContent = "Revoke passkey";
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        await api("me/passkeys/revoke", "POST", {id:key.id,reason:"Self-service passkey revocation"});
        showLogin();
      } catch (error) { $("#passkey-error").textContent = error.message; }
      finally { button.disabled = false; }
    });
    row.append(button);
    return row;
  }));
}
$("#reset-passkeys").addEventListener("click", async () => {
  if (!$("#account-reason").reportValidity()) return;
  try {
    await api("accounts/passkeys-reset", "POST", {revision:accountDocument.revision,username:$("#account-selector").value,reason:$("#account-reason").value.trim()});
    await loadAccounts();
    notice("Passkeys recovered. Administrator MFA policy remains unchanged.");
  } catch (error) { $("#account-error").textContent = error.message; }
});
$("#oidc-binding-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await api("accounts/oidc", "POST", {revision:accountDocument.revision,username:$("#oidc-binding-user").value,subject:$("#oidc-binding-subject").value.trim(),remove:$("#oidc-binding-remove").checked,reason:$("#oidc-binding-reason").value.trim()});
    await loadAccounts();
    notice("Organization identity binding saved. Previous sessions for this account are invalid.");
  } catch (error) { $("#oidc-binding-error").textContent = error.message; }
});
async function loadTokens() {
  tokenDocument = await api("tokens");
  const owner = $("#automation-owner").value;
  $("#automation-owner").replaceChildren(...accountDocument.accounts.filter((account) => !account.disabled).map((account) => {
    const option = document.createElement("option");
    option.value = account.username;
    option.textContent = `${account.username} · ${account.role}`;
    return option;
  }));
  if (accountDocument.accounts.some((account) => account.username === owner && !account.disabled)) $("#automation-owner").value = owner;
  const legend = document.createElement("legend");
  legend.textContent = "Permissions across this deployment";
  $("#automation-scopes").replaceChildren(legend, ...tokenDocument.available_scopes.map((scope) => {
    const label = document.createElement("label"), checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.value = scope;
    label.append(checkbox, document.createTextNode(" " + scope));
    return label;
  }));
  fillTokenAssignments();
  automationScopeControls();
  $("#automation-rows").replaceChildren(...(tokenDocument.items || []).map((token) => {
    const row = document.createElement("tr");
    const account = accountDocument.accounts.find((account) => account.username === token.owner);
    const active = account && !account.disabled && account.version === token.owner_version;
    const state = Date.parse(token.expires) <= Date.now() ? "expired" : active ? "active" : "invalidated";
    for (const value of [`${token.name} / ${token.id}`, `${token.owner} · ${state}`, token.scopes.join(", "), new Date(token.expires).toLocaleString()]) {
      const cell = document.createElement("td");
      cell.textContent = value;
      row.append(cell);
    }
    const cell = document.createElement("td"), button = document.createElement("button");
    button.type = "button";
    button.className = "secondary";
    button.textContent = "Revoke";
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        await api(`tokens/${token.id}/revoke`, "POST", { revision: tokenDocument.revision, reason: "Administrator revoked automation credential through console" });
        await loadAccounts();
        notice("Automation token revoked.");
      } catch (error) { $("#automation-error").textContent = error.message; }
      finally { button.disabled = false; }
    });
    cell.append(button);
    row.append(cell);
    return row;
  }));
}
function automationScopeControls() {
  const owner = accountDocument?.accounts.find((account) => account.username === $("#automation-owner").value);
  const role = owner?.role;
  const assigned = owner?.access || $("#automation-access-mode").value === "assigned";
  $$("#automation-scopes input").forEach((input) => {
    input.disabled = (assigned && !["policy:read", "policy:write", "events:read"].includes(input.value)) || !role || (input.value === "certificates:reload" && role !== "administrator") || (input.value === "policy:write" && role === "viewer");
    if (input.disabled) input.checked = false;
  });
}
$("#automation-owner").addEventListener("change", () => { fillTokenAssignments(); automationScopeControls(); });
$("#token-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $("#token-form button");
  button.disabled = true;
  $("#automation-error").textContent = "";
  $("#issued-token").textContent = "";
  $("#issued-token-panel").hidden = true;
  try {
    const issued = await api("tokens", "POST", {
      revision: tokenDocument.revision, owner: $("#automation-owner").value,
      name: $("#automation-name").value.trim(), lifetime_hours: Number($("#automation-hours").value),
      access: readAssignment("automation"),
      scopes: $$("#automation-scopes input:checked").map((input) => input.value), reason: $("#automation-reason").value.trim(),
    });
    $("#issued-token").textContent = issued.secret;
    $("#issued-token-panel").hidden = false;
    await loadAccounts();
  } catch (error) { $("#automation-error").textContent = error.message; }
  finally { button.disabled = false; }
});
$("#clear-issued-token").addEventListener("click", () => {
  $("#issued-token").textContent = "";
  $("#issued-token-panel").hidden = true;
});
async function manageAuthenticator(operation) {
  if (!$("#mfa-password").reportValidity()) return;
  if (operation !== "setup" && !/^[0-9]{6}$/.test($("#mfa-code").value)) {
    $("#mfa-error").textContent = "Enter a six-digit authenticator code.";
    return;
  }
  $$("#mfa-form button").forEach((button) => { button.disabled = true; });
  $("#mfa-error").textContent = "";
  try {
    const result = await api(`me/mfa/${operation}`, "POST", { password: $("#mfa-password").value, code: $("#mfa-code").value });
    $("#mfa-password").value = "";
    $("#mfa-code").value = "";
    if (operation === "setup") {
      $("#mfa-secret").textContent = result.secret;
      $("#mfa-uri").textContent = result.uri;
      $("#mfa-enrollment").hidden = false;
      $("#mfa-enable").hidden = false;
    } else {
      showLogin();
      $("#login-error").textContent = "Authenticator settings changed. Sign in again with a fresh code when enabled.";
    }
  } catch (error) { $("#mfa-error").textContent = error.message; }
  finally { $$("#mfa-form button").forEach((button) => { button.disabled = false; }); }
}
$("#mfa-setup").addEventListener("click", () => manageAuthenticator("setup"));
$("#mfa-disable").addEventListener("click", () => manageAuthenticator("disable"));
$("#mfa-form").addEventListener("submit", (event) => { event.preventDefault(); manageAuthenticator("enable"); });
$("#reset-mfa").addEventListener("click", async () => {
  if (!$("#account-reason").reportValidity()) return;
  $("#reset-mfa").disabled = true;
  try {
    await api("accounts/mfa-reset", "POST", { revision: accountDocument.revision, username: $("#account-selector").value, reason: $("#account-reason").value.trim() });
    await loadAccounts();
    notice("Authenticator recovered. Previous sessions and automation tokens for this account are invalid.");
  } catch (error) { $("#account-error").textContent = error.message; }
  finally { $("#reset-mfa").disabled = false; }
});
$("#account-selector").addEventListener("change", fillAccount);
$("#account-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("#save-account").disabled = true;
  $("#account-error").textContent = "";
  try {
    const username = $("#account-username").value.trim();
    await api("accounts", "POST", {
      revision: accountDocument.revision,
      username,
      role: $("#account-role").value,
      disabled: $("#account-disabled").checked,
      password: $("#account-password").value,
      reason: $("#account-reason").value.trim(),
      update_access: true,
      access: readAssignment("account"),
    });
    $("#account-password").value = "";
    if (!currentUser.bootstrap && username === currentUser.username) {
      showLogin();
      $("#login-error").textContent = "Account updated. Sign in again.";
      return;
    }
    currentUser = await api("me");
    await loadAccounts();
    notice(
      "Account saved. Existing sessions for this account have been revoked.",
    );
  } catch (error) {
    $("#account-error").textContent = error.message;
  } finally {
    $("#save-account").disabled = false;
  }
});
$("#password-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $("#password-form button");
  button.disabled = true;
  try {
    await api("me/password", "POST", {
      current_password: $("#current-password").value,
      password: $("#self-new-password").value,
      code: $("#password-code").value,
    });
    $("#password-form").reset();
    showLogin();
    $("#login-error").textContent = "Password changed. Sign in again.";
  } catch (error) {
    $("#password-error").textContent = error.message;
  } finally {
    button.disabled = false;
  }
});
async function apply(validateOnly) {
  if (busy || !$("#config-form").reportValidity()) return;
  try {
    const c = readForm();
    const reason = $("#change-reason").value.trim();
    if (!validateOnly && !reason) {
      notice("Enter a change reason before applying this policy.", true);
      $("#change-reason").focus();
      return;
    }
    if (
      !validateOnly &&
      editedConfig(c).mode === "disabled" &&
      editedConfig().mode !== "disabled" &&
      !confirm(
        "Disable security rule inspection for this application? Request size limits will still apply.",
      )
    )
      return;
    lock(true);
    notice("Compiling Coraza and the complete CRS policy…");
    const updated = await api(
      validateOnly ? "config/validate" : "config/apply",
      "POST",
      validateOnly ? c : { config: c, reason },
    );
    if (validateOnly)
      notice(
        "Policy compiled successfully. Your changes have not been applied.",
      );
    else {
      config = updated;
      fillForm();
      renderPolicy();
      notice(
        "Policy saved and applied. New requests use revision " +
          config.revision +
          ".",
      );
      await telemetry();
    }
  } catch (e) {
    notice(e.message, true);
  } finally {
    lock(false);
  }
}
$("#config-form").addEventListener("submit", (e) => {
  e.preventDefault();
  apply(false);
});
$("#validate").addEventListener("click", () => apply(true));
$("#discard").addEventListener("click", async () => {
  if (
    dirty &&
    !confirm(
      "Discard unsaved policy changes and reload the active configuration?",
    )
  )
    return;
  try {
    config = await api("config");
    fillForm();
    renderPolicy();
    notice("Active configuration reloaded.");
  } catch (e) {
    notice(e.message, true);
  }
});
function renderPolicy() {
  if (!config) return;
  const application = editedConfig();
  const mode = application.mode;
  $("#side-mode").textContent = application.name + " · " + mode;
  $("#protection-title").textContent =
    mode === "enforcing"
      ? "Your application is in enforcing mode"
      : mode === "detection"
        ? "Your application is in detection mode"
        : "Security rule inspection is disabled";
  $("#protection-description").textContent =
    mode === "enforcing"
      ? "Every request is inspected by Coraza and the OWASP Core Rule Set."
      : mode === "detection"
        ? "Rules are evaluated and logged. Rule matches do not block traffic."
        : "Requests pass to the upstream without Coraza rule inspection.";
  $("#policy-badge").textContent = mode.toUpperCase();
  $("#posture-paranoia").textContent = "Level " + application.paranoia;
  $("#posture-response").textContent = application.inspect_response
    ? "Enabled"
    : "Off";
  $("#posture-exclusions").textContent = application.exclusions?.length || 0;
  $("#posture-revision").textContent = config.revision;
}
function chart(series) {
  const peak = Math.max(1, ...series.map((b) => b.requests));
  const points = (key) =>
    series
      .map(
        (b, i) =>
          `${i === 0 ? "M" : "L"}${((i * 800) / 59).toFixed(1)},${(185 - (b[key] * 160) / peak).toFixed(1)}`,
      )
      .join(" ");
  const line = points("requests");
  $("#chart-line").setAttribute("d", line);
  $("#chart-area").setAttribute("d", line + " L800,185 L0,185 Z");
  $("#chart-blocked").setAttribute("d", points("blocked"));
  $("#chart-peak").textContent =
    "Peak: " + Math.max(0, ...series.map((b) => b.requests)) + " / min";
}
function eventRows(target, items) {
  const rows = items.map((event) => {
    const tr = document.createElement("tr");
    tr.className = "event-row";
    tr.tabIndex = 0;
    tr.setAttribute("aria-label", "View event " + event.id);
    const time = new Date(event.time).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
    const cells = [
      time,
      event.action +
        (event.aggregated
          ? ` × ${(event.occurrences || 1).toLocaleString()}`
          : ""),
      event.ip,
      `${event.application_id || "Unassigned"} · ${event.method} ${event.path}`,
      event.status + (event.delivery_incomplete ? " · incomplete" : ""),
      event.matches?.[0]?.id || "—",
    ];
    for (let i = 0; i < cells.length; i++) {
      const td = document.createElement("td");
      if (i === 1) {
        const b = document.createElement("span");
        b.className =
          "badge " +
          (["blocked", "detected", "error"].includes(event.action)
            ? event.action
            : "");
        b.textContent = String(cells[i]).toUpperCase();
        td.append(b);
      } else td.textContent = cells[i];
      if (i === 3) {
        td.className = "request-cell";
        td.title = String(cells[i]);
      }
      tr.append(td);
    }
    const open = () => {
      $("#event-detail").textContent = JSON.stringify(event, null, 2);
      $("#event-dialog").showModal();
    };
    tr.addEventListener("click", open);
    tr.addEventListener("keydown", (e) => {
      if (e.key === "Enter") open();
    });
    return tr;
  });
  if (!rows.length) {
    const tr = document.createElement("tr"),
      td = document.createElement("td");
    td.colSpan = 6;
    td.className = "empty";
    td.textContent =
      "No matching security events. Requests that pass without rule matches are counted in traffic totals.";
    tr.append(td);
    rows.push(tr);
  }
  $(target).replaceChildren(...rows);
}
function renderEvents() {
  eventRows("#recent-events", events.slice(0, 5));
  eventRows("#all-events", storedEvents);
  $("#event-count").textContent = events.length;
  $("#filtered-count").textContent = storedEvents.length + " loaded events";
}
async function loadStoredEvents(append = false) {
  const generation = ++eventQueryGeneration;
  const query = new URLSearchParams({
    limit: "100",
    q: $("#event-search").value,
    action: $("#event-action").value,
    application: $("#event-application").value.trim() || (currentUser.access ? selectedApplicationID : ""),
  });
  if (append && nextBefore) query.set("before", nextBefore);
  const page = await api("events/search?" + query);
  if (generation !== eventQueryGeneration) return;
  storedEvents = append ? storedEvents.concat(page.items) : page.items;
  nextBefore = page.next_before || 0;
  $("#more-events").hidden = !page.has_more;
  renderEvents();
}
$("#event-search").addEventListener("input", () => {
  ++eventQueryGeneration;
  clearTimeout(eventSearchTimer);
  eventSearchTimer = setTimeout(
    () => loadStoredEvents().catch((e) => notice(e.message, true)),
    250,
  );
});
$("#event-action").addEventListener("change", () =>
  loadStoredEvents().catch((e) => notice(e.message, true)),
);
$("#event-application").addEventListener("change", () =>
  loadStoredEvents().catch((e) => notice(e.message, true)),
);
$("#more-events").addEventListener("click", async () => {
  $("#more-events").disabled = true;
  try {
    await loadStoredEvents(true);
  } catch (e) {
    notice(e.message, true);
  } finally {
    $("#more-events").disabled = false;
  }
});
$("#close-dialog").addEventListener("click", () => $("#event-dialog").close());
async function telemetry() {
  const identityNow = await api("me");
  if (!!identityNow.mfa_enrollment_required !== !!currentUser.mfa_enrollment_required) { await initialize(); return; }
  currentUser = identityNow;
  if (currentUser.mfa_enrollment_required) return;
  if (currentUser.access) {
    $("#side-mode").textContent = "Assigned application access";
    events = await api("events?application=" + encodeURIComponent(selectedApplicationID));
    renderUpstreams(await api("upstreams"));
    renderEvents();
    $("#connection").textContent = "● Connected";
    $("#last-updated").textContent = "Updated " + new Date().toLocaleTimeString();
    return;
  }
  const [status, latest, upstreams] = await Promise.all([api("status"), api("events"), api("upstreams")]);
  renderUpstreams(upstreams);
  events = latest;
  const s = status.summary;
  for (const key of ["requests", "blocked", "detected", "errors"])
    $("#metric-" + key).textContent = s[key].toLocaleString();
  $("#block-rate").textContent =
    (s.requests ? (s.blocked * 100) / s.requests : 0).toFixed(1) +
    "% of incoming traffic";
  $("#engine-version").textContent =
    "Coraza " +
    status.engine_version.split("-0.")[0] +
    (status.engine_version.includes("-0.")
      ? " (pinned development revision)"
      : "");
  $("#engine-version").title = status.engine_version;
  const storage = status.storage,
    resources = status.resources;
  const audit = status.audit,
    certificate = status.certificate;
  $("#audit-health").textContent =
    `${audit.healthy ? "Healthy" : "Unavailable"} · ${audit.records} records · ${(audit.bytes / 1048576).toFixed(2)} / ${(audit.max_bytes / 1048576).toFixed(0)} MiB`;
  $("#audit-health").classList.toggle("error", !audit.healthy);
  const auditDelivery = status.audit_export;
  $("#audit-export-health").textContent = !auditDelivery.enabled
    ? "Disabled"
    : `${auditDelivery.paused ? "Paused" : auditDelivery.healthy ? "Healthy" : "Retrying"} · ${auditDelivery.acknowledged_records} acknowledged · ${auditDelivery.pending_records} pending · ${auditDelivery.failures} failed attempts`;
  $("#audit-export-health").classList.toggle("error", !auditDelivery.healthy);
  $("#audit-export-health").title = auditDelivery.last_error || "";
  $("#certificate-health").textContent = certificate.enabled
    ? `${certificate.healthy ? "Healthy" : certificate.expiring ? "Expiry warning" : "Reload requires attention"}${certificate.last_error ? " · " + certificate.last_error : ""}`
    : "TLS is not configured";
  $("#certificate-health").classList.toggle(
    "error",
    certificate.enabled && !certificate.healthy,
  );
  $("#certificate-expiry").textContent = certificate.enabled
    ? new Date(certificate.chain_not_after).toLocaleString()
    : "—";
  $("#reload-certificate").disabled =
    !certificate.enabled || currentUser.role !== "administrator";
  $("#storage-health").textContent =
    `${storage.healthy ? "Healthy" : "Degraded"} · ${storage.stored} retained · ${storage.pending_writes} pending · ${storage.queue_dropped} dropped · ${storage.write_failed} failed · ${storage.ingest_timeouts} ingest timeouts · ${storage.write_retries} write retries`;
  $("#storage-health").title = storage.last_error || "";
  $("#storage-health").classList.toggle("error", !storage.healthy);
  const delivery = storage.export;
  $("#export-health").textContent = !delivery.enabled
    ? "Disabled"
    : `${delivery.paused ? "Paused" : delivery.healthy ? "Healthy" : "Retrying"} · ${delivery.pending_records} pending · ${delivery.acked_records} acknowledged · ${delivery.failures} failed attempts`;
  $("#export-health").title = delivery.last_error || delivery.endpoint || "";
  $("#export-health").classList.toggle("error", !delivery.healthy);
  $("#event-accounting").textContent =
    `${storage.committed_occurrences.toLocaleString()} committed occurrences in ${storage.committed_records.toLocaleString()} records · overload rows contain explicit counts`;
  $("#retention-info").textContent =
    `${storage.max_rows.toLocaleString()} events · ${storage.retention_days} days · ${storage.max_database_bytes / 1048576} MiB main database cap`;
  $("#resource-health").textContent =
    `${resources.active}/${resources.max_concurrent} active · ${Math.ceil(resources.reserved_buffer_bytes / 1048576)}/${resources.buffer_budget_bytes / 1048576} MiB buffer reservations · ${resources.overload_rejections} overload rejections · ${resources.rate_rejections} rate rejections · ${resources.fairness_rejections} share rejections`;
  const appCount = Math.max(1, status.applications.length);
  $("#admission-share").textContent =
    config.schema_version === 2
      ? `Current process shares allocate up to ${Math.floor(resources.max_concurrent / appCount)} concurrent requests and ${Math.floor(resources.buffer_budget_bytes / appCount / 1048576)} MiB of buffer reservations per application. Lower application limits reduce that ceiling.`
      : "Save explicit application hostnames to enable application shares and rate controls.";
  $("#crs-version").textContent = "OWASP CRS " + status.crs_version;
  const identity = status.client_identity;
  $("#proxy-identity").textContent = identity.trusted_networks.length
    ? `${identity.profile} · trusted ${identity.trusted_networks.join(", ")} · ${identity.forwarded_requests} forwarded · ${identity.invalid_headers} invalid`
    : "Direct connection identity · forwarding headers are untrusted";
  $("#proxy-identity").title =
    `Startup trust configuration SHA-256 ${identity.config_sha256}`;
  $("#uptime").textContent =
    Math.floor(s.uptime_seconds / 3600) +
    "h " +
    Math.floor((s.uptime_seconds % 3600) / 60) +
    "m";
  chart(s.series);
  renderEvents();
  $("#connection").textContent = "● Connected";
  $("#connection").classList.remove("offline");
  $("#last-updated").textContent = "Updated " + new Date().toLocaleTimeString();
  if (config && status.revision !== config.revision && !busy)
    notice(
      "The active policy changed in another session. Use Discard changes to reload it before editing.",
      true,
    );
}
async function initialize() {
  try {
    authenticationOptions = await api("auth/options");
    renderAuthenticationOptions();
    currentUser = await api("me");
    config = currentUser.mfa_enrollment_required ? null : await api("config");
    signedIn = true;
    $("#login").hidden = true;
    $("#shell").hidden = false;
    if (config) { fillForm(); renderPolicy(); } else { permissions(); }
    navigate(location.hash.slice(1));
    await telemetry();
  } catch (e) {
    showLogin();
    $("#login-error").textContent =
      e.message === "Sign in required" ? "" : e.message;
  }
}
$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const button = $("#login-form button");
  button.disabled = true;
  try {
    await api(
      "login",
      "POST",
      $("#login-method").value === "account"
        ? {
            username: $("#login-username").value.trim(),
            password: $("#login-password").value,
            code: $("#login-code").value,
          }
        : { token: $("#token").value.trim() },
    );
    $("#token").value = "";
    $("#login-password").value = "";
    $("#login-code").value = "";
    $("#login-error").textContent = "";
    await initialize();
  } catch (err) {
    $("#login-error").textContent = err.message;
  } finally {
    button.disabled = false;
  }
});
$("#logout").addEventListener("click", async () => {
  if (dirty && !confirm("Sign out and discard unsaved changes?")) return;
  try {
    await api("logout", "POST", {});
    showLogin();
  } catch (e) {
    notice(e.message, true);
  }
});
$("#refresh").addEventListener("click", async () => {
  try {
    await telemetry();
    if (!currentUser.mfa_enrollment_required) await loadStoredEvents();
  } catch (e) {
    notice(e.message, true);
  }
});
function download(name, value) {
  const blob = new Blob([JSON.stringify(value, null, 2)], {
      type: "application/json",
    }),
    url = URL.createObjectURL(blob),
    a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
$("#export-events").addEventListener("click", () =>
  download("openwaf-events-loaded.json", storedEvents),
);
$("#export-config").addEventListener("click", async () => {
  try {
    download("openwaf-policy.json", await api("config"));
  } catch (e) {
    notice(e.message, true);
  }
});
async function loadAudit() {
  const result = await api("audit?limit=20");
  auditEntries = result.items;
  $("#audit-entries").replaceChildren(
    ...auditEntries.map((entry) => {
      const row = document.createElement("tr");
      row.title = `Entry ${entry.sequence} · Correlation ${entry.correlation} · SHA-256 ${entry.hash}`;
      for (const value of [
        new Date(entry.time).toLocaleString(),
        entry.operation,
        entry.actor,
        entry.outcome,
        entry.revision || "—",
      ]) {
        const cell = document.createElement("td");
        cell.textContent = value;
        row.append(cell);
      }
      return row;
    }),
  );
}
$("#refresh-audit").addEventListener("click", () =>
  loadAudit().catch((e) => notice(e.message, true)),
);
$("#export-audit").addEventListener("click", () =>
  download("openwaf-administration-loaded.json", auditEntries),
);
$("#reload-certificate").addEventListener("click", async () => {
  $("#reload-certificate").disabled = true;
  try {
    await api("certificates/reload", "POST", {});
    notice("Certificate files validated and the active certificate refreshed.");
    await loadAudit();
  } catch (e) {
    notice(e.message, true);
  } finally {
    await telemetry().catch((e) => notice(e.message, true));
  }
});

function renderExceptions() {
  const list = $("#scoped-exceptions");
  const cards = draftExceptions.map((item, index) => {
    const card = document.createElement("div");
    card.className = "exception-card";
    const header = document.createElement("div");
    header.className = "exception-heading";
    const title = document.createElement("strong");
    title.textContent = item.id;
    header.append(title);
    const badge = document.createElement("span");
    badge.className = "badge";
    badge.textContent =
      item.expires_at && Date.parse(item.expires_at) <= Date.now()
        ? "EXPIRED"
        : "SCOPED";
    header.append(badge);
    const scope = document.createElement("code");
    scope.textContent = `${item.method} ${item.path} · ${item.collection}:${item.parameter}`;
    const rules = document.createElement("small");
    rules.textContent =
      "Rules " + item.rule_ids.join(", ") + " · Owner: " + item.owner;
    const reason = document.createElement("p");
    reason.textContent = item.reason;
    const expiry = document.createElement("small");
    expiry.textContent = item.expires_at
      ? "Expires " + new Date(item.expires_at).toLocaleString()
      : "No expiry set";
    const actions = document.createElement("div");
    actions.className = "exception-actions";
    for (const [label, handler] of [
      ["Edit", () => openException(index)],
      [
        "Remove",
        () => {
          draftExceptions.splice(index, 1);
          dirty = true;
          draftStatus();
          renderExceptions();
        },
      ],
    ]) {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "secondary";
      b.textContent = label;
      b.addEventListener("click", handler);
      actions.append(b);
    }
    card.append(header, scope, rules, reason, expiry, actions);
    return card;
  });
  if (!cards.length) {
    const p = document.createElement("p");
    p.className = "empty";
    p.textContent = "No scoped exceptions in this policy.";
    cards.push(p);
  }
  list.replaceChildren(...cards);
}
function openException(index = -1) {
  editingException = index;
  $("#exception-form").reset();
  $("#exception-error").textContent = "";
  $("#exception-title").textContent =
    index < 0 ? "Add scoped exception" : "Edit scoped exception";
  const e =
    index < 0
      ? {
          id: "exception-" + crypto.randomUUID().slice(0, 8),
          method: "GET",
          collection: "ARGS_GET",
          rule_ids: [],
        }
      : draftExceptions[index];
  for (const [field, key] of [
    ["id", "id"],
    ["method", "method"],
    ["path", "path"],
    ["collection", "collection"],
    ["parameter", "parameter"],
    ["owner", "owner"],
    ["reason", "reason"],
  ])
    $("#exception-" + field).value = e[key] || "";
  $("#exception-rules").value = e.rule_ids.join(", ");
  if (e.expires_at) {
    const date = new Date(e.expires_at);
    $("#exception-expiry").value = new Date(
      date.getTime() - date.getTimezoneOffset() * 60000,
    )
      .toISOString()
      .slice(0, 16);
  }
  $("#exception-dialog").showModal();
}
$("#add-exception").addEventListener("click", () => openException());
$("#close-exception").addEventListener("click", () =>
  $("#exception-dialog").close(),
);
$("#exception-form").addEventListener("submit", (event) => {
  event.preventDefault();
  try {
    const id = $("#exception-id").value.trim();
    if (draftExceptions.some((e, i) => e.id === id && i !== editingException))
      throw Error("This exception ID already exists.");
    const ids = $("#exception-rules").value.trim();
    if (!/^[\d,\s]+$/.test(ids))
      throw Error("Enter numeric rule IDs separated by commas or spaces.");
    const rule_ids = ids
      .split(/[,\s]+/)
      .filter(Boolean)
      .map(Number);
    if (
      !rule_ids.length ||
      rule_ids.length > 30 ||
      new Set(rule_ids).size !== rule_ids.length ||
      rule_ids.some((id) => id < 913000 || id >= 949000)
    )
      throw Error(
        "Choose 1–30 unique CRS detection rule IDs from 913000–948999.",
      );
    const e = {
      id,
      method: $("#exception-method").value,
      path: $("#exception-path").value.trim(),
      collection: $("#exception-collection").value,
      parameter: $("#exception-parameter").value.trim(),
      rule_ids,
      owner: $("#exception-owner").value.trim(),
      reason: $("#exception-reason").value.trim(),
    };
    if ($("#exception-expiry").value)
      e.expires_at = new Date($("#exception-expiry").value).toISOString();
    if (editingException < 0) draftExceptions.push(e);
    else draftExceptions[editingException] = e;
    dirty = true;
    draftStatus();
    renderExceptions();
    $("#exception-dialog").close();
  } catch (e) {
    $("#exception-error").textContent = e.message;
  }
});

async function loadHistory() {
  const history = await api("config/history");
  const rows = history.map((entry) => {
    const tr = document.createElement("tr");
    for (const text of [
      "r" +
        entry.revision +
        (entry.revision === config.revision ? " · active" : ""),
      new Date(entry.created_at).toLocaleString(),
      entry.actor,
      entry.reason +
        (entry.restored_from ? " · restored from r" + entry.restored_from : ""),
    ]) {
      const td = document.createElement("td");
      td.textContent = text;
      td.className = "history-cell";
      tr.append(td);
    }
    const td = document.createElement("td"),
      button = document.createElement("button");
    button.className = "secondary";
    button.type = "button";
    button.textContent = "Compare";
    button.addEventListener("click", () =>
      compareRevision(entry.revision).catch((e) => notice(e.message, true)),
    );
    td.append(button);
    tr.append(td);
    return tr;
  });
  $("#policy-history").replaceChildren(...rows);
}
async function compareRevision(revision) {
  const snapshot = await api("config/history/" + revision);
  comparedSchema = snapshot.config.schema_version;
  comparedRevision = revision;
  $("#revision-title").textContent =
    "Revision " +
    revision +
    " compared with active revision " +
    config.revision;
  const changes = [];
  for (const key of new Set([
    ...Object.keys(config),
    ...Object.keys(snapshot.config),
  ])) {
    if (key === "revision") continue;
    if (JSON.stringify(config[key]) !== JSON.stringify(snapshot.config[key]))
      changes.push(
        key +
          "\nActive: " +
          JSON.stringify(config[key], null, 2) +
          "\nSelected: " +
          JSON.stringify(snapshot.config[key], null, 2),
      );
  }
  $("#revision-diff").textContent = changes.length
    ? changes.join("\n\n")
    : "No setting differences. Revision numbers are excluded from this comparison.";
  $("#rollback-error").textContent = "";
  $("#rollback-reason").value = "";
  $("#rollback-policy").disabled =
    revision === config.revision || currentUser.role === "viewer";
  $("#revision-dialog").showModal();
}
$("#close-revision").addEventListener("click", () =>
  $("#revision-dialog").close(),
);
$("#reload-history").addEventListener("click", () =>
  loadHistory().catch((e) => notice(e.message, true)),
);
$("#rollback-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (busy) return;
  if (
    config.schema_version === 2 &&
    comparedSchema === 1 &&
    !confirm(
      "This revision restores the original catch-all application and replaces every current hostname binding. Restore the whole deployment?",
    )
  )
    return;
  if (
    dirty &&
    !confirm("Restore this revision and discard your unsaved draft?")
  )
    return;
  lock(true);
  $("#rollback-policy").disabled = true;
  try {
    config = await api("config/rollback", "POST", {
      revision: config.revision,
      target_revision: comparedRevision,
      reason: $("#rollback-reason").value.trim(),
    });
    fillForm();
    renderPolicy();
    await loadHistory();
    $("#revision-dialog").close();
    notice("Previous settings restored as revision " + config.revision + ".");
  } catch (e) {
    $("#rollback-error").textContent = e.message;
  } finally {
    lock(false);
    $("#rollback-policy").disabled =
      comparedRevision === config.revision || currentUser.role === "viewer";
  }
});
window.addEventListener("beforeunload", (e) => {
  if (dirty) {
    e.preventDefault();
    e.returnValue = "";
  }
});
setInterval(async () => {
  if (!signedIn || busy) return;
  try {
    await telemetry();
  } catch (e) {
    $("#connection").textContent = "● Disconnected";
    $("#connection").classList.add("offline");
  }
}, 5000);
initialize();
