# Administrator MFA policy and application assignments

This M3 increment adds deployment-wide administrator MFA enforcement and application assignments for local operators, viewers and automation tokens. Enforcement defaults to disabled. Existing accounts retain their deployment-wide permissions until an administrator assigns applications explicitly.

## Require administrator MFA

Open **Accounts & access**, enroll an enabled named administrator, then use **Administrator authentication policy** to require MFA. A named administrator changing this policy supplies their current password and a fresh authenticator code, or uses a passkey/assured SSO session verified within two minutes. Bootstrap recovery credentials can change it directly. Every change requires a reason, a current credential revision and a durable audit intent.

Enforcement requires at least one enabled, enrolled administrator before activation. Ordinary account changes cannot disable or demote the last ready administrator. A required administrator can disable TOTP only while retaining an enrolled passkey. Own-key revocation also preserves the last ready administrator.

An administrator can sign in with a password to obtain an enrollment-only session when that session lacks verified strong authentication. It permits identity lookup, local-factor enrollment, passkey verification and logout. Configuration, events, accounts, token issuance, policy management and other administration routes remain inaccessible. Existing weak administrator sessions become restricted on their next request. Automation tokens belonging to an administrator without an enrolled local factor are refused, and new tokens cannot be issued for that owner. Completing enrollment advances the account version and invalidates previous sessions and tokens. Full administration requires password/TOTP, a verified passkey or configured-assurance SSO.

Bootstrap authenticator recovery keeps enforcement enabled, including recovery of the last enrolled administrator. An account with no remaining local factor receives enrollment-only password access until it enrolls another factor. The bootstrap operator may explicitly disable enforcement through the separate policy form. Recovery never silently disables the deployment policy. Keep this credential separately protected.

The API adds administrator-only `GET /api/v1/security-policy` and `POST /api/v1/security-policy`. The POST body contains `revision`, `require_admin_mfa`, `reason`, `password` and `code`. Reasons have a 90-byte limit. Password/code step-up or a strong passkey/SSO session verified within two minutes is required for named administrators. Bootstrap requests omit those fields. An accepted OTP advances the credential document revision before the policy mutation, and the handler uses that new revision within the same administration lock. A failed or uncertain response can consume the code, so retry with fresh state and a fresh code.

## Assign applications

Administrators retain deployment-wide authority. Local operators and viewers can receive either deployment-wide access or one through eight explicit application IDs. Explicit assignments require hostname-routed policy schema 2. Usernames and roles retain their existing bounds. Saving an assignment advances the account version and invalidates prior sessions and owned automation tokens.

Use **Application access** in the account form and select the intended applications. Scoped operators can edit assigned application names, security policies, exceptions and traffic controls. Shared routing changes, application creation/deletion and complete-deployment rollback require deployment-wide authority. Scoped viewers can read their assigned configuration and events.

The server filters configuration and application-list responses before serialization. Scoped policy submissions must contain exactly the currently assigned applications. The server merges them into the current complete deployment under the existing policy lock, preserves every unassigned application and checks the submitted revision. Hostnames, upstreams and application IDs must remain unchanged. Scoped writes re-check the live session or token under the policy lock before activation, so a cached grant cannot write after reassignment or revocation. Full-deployment compilation and atomic activation still run. Shared validation failures use a generic response to avoid disclosing another application's policy details.

Scoped identities cannot read deployment history/snapshots, administration auditing, appliance status/metrics/health, certificates or account directories. Their console hides those pages. It uses assigned configuration and events in place of deployment-wide telemetry. Sign-out and expired sessions reload the console to discard the previous page's in-memory state.

Both recent-event and durable search routes require exactly one `application` query parameter for scoped identities. The value must be assigned. Empty, duplicate and out-of-assignment selectors are denied before storage queries. Filtering is applied before durable pagination. Combined overload records with application `*` remain inaccessible. The shared policy revision, event sequence/cursor space, resource budgets and runtime remain deployment-wide. These grants provide application-content and change authorization within one organization.

The account API accepts `access` with an `application_ids` array. Providing it selects explicit assignments. To return to deployment-wide access, send `update_access: true` and `access: null`. Omitting both preserves an existing account's assignments, including during self-service password changes and legacy-client edits. Empty assignment arrays and administrator application assignments are rejected. The console sends explicit assignment intent on every account save. Audit resources bind the public role/disabled/assignment change to a SHA-256 grant digest.

## Application-scoped automation

An issued token inherits its owner's application assignments by default. Administrators may additionally select a subset of an owner's applications, or restrict a deployment-wide owner's token to selected applications. Tokens never exceed their owner's access. Token issuance accepts the optional `access` object used for accounts. Selected applications require schema-2 routing.

Application-scoped tokens support `policy:read`, `policy:write` and `events:read`. Appliance monitoring, audit and certificate scopes are rejected for them. They retain the existing owner-version, expiry, revocation and one-time-secret behavior. Configuration reads are filtered, event queries require an assigned application, and policy writes use the same merge and routing restrictions as scoped local operators. Server enforcement covers alternate routes independently of dashboard controls.

## Application ID lifetime

Account and token assignments pin their referenced application IDs, including disabled accounts, expired tokens and owner-invalidated tokens. Remove account assignments and revoke token entries before removing an application. All normal policy activation paths, validation, raw PUT, application deletion and history rollback enforce this check. Startup and offline recovery inspection also reject credential bindings that refer to missing applications or legacy catch-all routing.

This prevents deletion/recreation from silently handing a previous grant to a different application under the same ID. Administrators deliberately remove those grants before retiring an application. Whole-checkpoint restoration restores the checkpoint's configuration and grants together. Reconcile subsequent security changes before reopening administrator access.

## Credential schema and qualification

Enabling MFA policy or assigning applications selects credential schema 3. It retains at least schema 3 after disabling enforcement or clearing assignments. Schemas 1 and 2 remain readable. Passkeys or SSO bindings select schema 4, which subsequent edits preserve. Existing state stays in its previous format until a feature requires schema 3. Upgrade capability metadata advertises schemas 1, 2, 3 and 4. Earlier executables require a compatible pre-feature checkpoint, and their rejection is tested through the actual previous M3 executable.

The existing private-file publication, Linux directory synchronization, audit-intent gates and serialized policy/shutdown ownership apply to these changes. Backups preserve enforcement, authenticator state, grants and token restrictions. Restore and candidate rehearsal verify the credential file hash. As with earlier credentials, full checkpoint restoration can revive older permissions and tokens. [Credential storage contract](M3-AUTHENTICATION.md), [Recovery procedure](BACKUP-RESTORE-UPGRADES.md)

Validation covers ready-administrator guards, restricted sessions before/after enforcement, blocked unenrolled-owner tokens, protected MFA disablement, bootstrap recovery with policy retained, assignment filtering, cross-application queries, alternate write routes, routing restrictions, preserved unassigned policies, returned-grant aliasing, application-ID retirement guards and recovery/downgrade compatibility. Browser workflows exercise enrollment-only and assigned-application consoles, MFA policy step-up, bootstrap recovery and mobile layout.

Passkeys, OIDC and upstream pools are implemented. The completion record tracks qualification of the completed formats. [M3 gates](M3-COMPLETION.md), [Organization sign-in](SSO-AND-PASSKEYS.md) The scoped M2 reference qualification remains tied to its recorded operating builds.

## Executed validation on 4 November 2026

| Check | Evidence |
|---|---|
| Complete Windows Go suite with actual current server/admin, strict schema-1 fixture and previous M3 executable | PASS, `artifacts/m3-access-full-windows.log` |
| Complete account, gateway and recovery suites under Ubuntu 24.04 WSL, including scoped-write revocation races | PASS, `artifacts/m3-access-linux-tests.log` |
| Actual prior M3 executable rejected for schema-3 recovery state | PASS in the Windows recovery suite |
| Chromium desktop/mobile policy, required enrollment, recovery and assigned-application workflows | PASS, `artifacts/m3-access-browser-final.log` |
| Complete Go vet | PASS, `artifacts/m3-access-vet.log` |

The first Linux attempt caught a fixture error from sampling the clock twice around an exact one-hour token lifetime. Both test timestamps now use the same captured instant, matching the production issuance handler. The failure remains `artifacts/m3-access-linux-tests-initial.log`. Earlier browser attempts also retain the old login-method assumption after sign-out reload and the harness classification of an explicitly tested 409 refusal. They remain in `artifacts/m3-access-browser-initial.log` and `artifacts/m3-access-browser.log`.

The local `m3-20261104-r2` Linux amd64 package includes these contracts. Assembly compares its server/admin bytes with the directly tested Linux executables. Package, executable and source hashes are recorded in `artifacts/m3-access-build-evidence.json`. This remains a local development build with the qualification limits stated above.
