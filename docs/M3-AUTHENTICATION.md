# Automation credentials and authenticator MFA

This M3 increment adds scoped automation credentials and opt-in authenticator-app MFA for named local accounts. The management listener remains loopback-only. Remote administration uses the documented authenticated tunnel. The bootstrap credential retains full recovery authority.

## Automation tokens

Sign in as an administrator, open **Accounts & access**, and use **Automation tokens**. Select an enabled named owner, explicit scopes and a lifetime from one hour through 90 days. Add a descriptive name and issuance reason. Save the returned secret in the caller's credential store. The console displays it once and provides a clear control. It is excluded from token lists and audit records. Lost issuance responses require revoking the visible metadata entry and issuing a replacement.

Send the complete secret using `Authorization: Bearer <secret>`. Tokens contain an independent random 128-bit identifier and 256-bit secret. Only a SHA-256 verifier is persisted. A token cannot be exchanged for a browser session, create credentials, manage accounts, change passwords or alter MFA.

| Scope | Granted routes |
|---|---|
| `monitoring:read` | GET/HEAD status, health and metrics |
| `events:read` | GET/HEAD recent events and event search |
| `audit:read` | GET/HEAD administration journal |
| `policy:read` | GET/HEAD configuration, applications and committed history |
| `policy:write` | PUT configuration, POST validation/apply/rollback and application create/delete |
| `certificates:reload` | POST certificate reload |

All tokens can GET/HEAD their own identity. Other routes and methods are denied. Scopes cover the entire deployment by default. Explicit application assignments narrow policy and event permissions. A policy-writing credential can change upstreams and inspection settings across applications. `policy:write` does not implicitly grant `policy:read`. Application-restricted authorization is implemented through explicit assignments. [Assignment contract](M3-AUTHORIZATION.md)

Only administrators issue/list/revoke tokens. A viewer owner may receive read scopes. An operator may additionally receive policy writes. Certificate reload requires an administrator owner. The server enforces the owner's permission ceiling independently of console controls.

Every request checks expiry, current owner version and enabled state. Account saves, password rotation and MFA configuration changes invalidate that owner's existing tokens. Successful OTP use advances the credential document revision without changing the owner's version. Explicit revocation removes the token and frees its slot. Expired and owner-invalidated entries remain visible until revoked. The store has a 64-token bound and 32 local accounts. Credential schemas 1–3 have a 64-KiB encoded limit. Schema 4, selected by passkeys or SSO bindings, permits 256 KiB. Large metadata can reach the byte limit before the entry limit. Already-authorized requests can finish during revocation.

The API uses the following operations.

- `GET /api/v1/tokens` returns the current credential revision, redacted metadata and supported scopes.
- `POST /api/v1/tokens` takes `revision`, `owner`, `name`, `scopes`, integer `lifetime_hours` and `reason`. A successful 201 response contains `token` metadata and the one-time `secret`. Names have an 80-byte limit and reasons a 500-byte limit.
- `POST /api/v1/tokens/{id}/revoke` takes `revision` and a reason of at most 90 bytes. The revocation audit record includes the stable token ID and reason.

Use the latest revision when retrying a conflict. Issuance is an explicit new-credential operation. A retry after an uncertain response can create another token. Reconcile the metadata list and revoke unused entries. Audit actors identify the stable automation ID, and issuance metadata retains its owner, issuer and reason.

## Authenticator enrollment and login

Sign in with a named account and open **Authenticator security**. Enter the current password and start enrollment. Enter the displayed setup key in an authenticator app using SHA-1, six digits and a 30-second period, or import the displayed `otpauth` URI through a trusted local tool. Enter the password again and a generated code to confirm. The pending secret is bound to that browser session and account version, expires after ten minutes and is discarded on restart. The bounded pending map holds at most 100 entries.

Confirmation publishes the authenticator secret, advances the account version, invalidates prior sessions and automation tokens, and signs the browser out. Subsequent local sign-ins require password plus authenticator code. Enrollment's confirmation code is consumed. Wait for a fresh code before signing in. All local roles may enroll. Existing accounts retain password sign-in until enrollment is confirmed. Deployment-wide administrator MFA enforcement is configurable. Unenrolled administrators receive enrollment-only access when it is enabled. [Enforcement and recovery](M3-AUTHORIZATION.md)

The verifier accepts the current 30-second step and one adjacent step in either direction. Keep the server and authenticator clocks synchronized. Each successful verification persists a monotonic accepted-step watermark before authorizing a session. Reusing a consumed step fails, including concurrent use and service restarts. An accepted future-step code also blocks earlier steps. A lost login response can consume the code without delivering a session, so use a fresh code for retry. Password checks and MFA management share the existing two verification slots and ten-failure/minute throttle.

Password changes for enrolled accounts also require a fresh authenticator code. Disabling MFA requires the current password, an unused valid code and the existing account session. Replacing an enrolled authenticator requires this disable flow followed by new enrollment. Account password resets retain the authenticator requirement. An administrator can disable TOTP during deployment enforcement only while retaining an enrolled passkey.

Recovery requires the separately held bootstrap credential. Sign in with it, select the affected account, enter a recovery reason and use **Recover selected account MFA**. Ordinary named administrator sessions cannot invoke recovery. Recovery invalidates the account's existing sessions and automation tokens. Re-enroll after recovery. An account must be enabled before authenticator recovery. Protection and rotation of the bootstrap credential remain part of the recovery procedure.

The additional API operations are `POST /api/v1/me/mfa/setup`, `/enable` and `/disable`, using `password` and `code`. Setup returns the one-time pending `secret` and `uri`. Enable and disable revoke the old account version. Bootstrap recovery uses `POST /api/v1/accounts/mfa-reset` with `revision`, `username` and `reason`. Local login and password-change payloads accept `code`. Identity and account responses expose `mfa_enabled`, with the authenticator secret and accepted-step watermark omitted.

This implementation follows the TOTP algorithm and replay rules in RFC 6238. Enrollment confirmation and recovery boundaries follow the OWASP MFA guidance. Passkeys and external identity are described in the [organization sign-in contract](SSO-AND-PASSKEYS.md). [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238), [OWASP MFA guidance](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)

## Storage, audit and upgrade safety

The existing `policy.json.accounts.json` holds tokens and authenticator state. Enabling either feature upgrades it to credential schema 2. Schema-1 files remain readable and retain their format during ordinary account edits. Schema 2 remains selected after disabling MFA or revoking all tokens. MFA enforcement and application assignments select schema 3, which remains selected after those settings are cleared. Candidate capability metadata advertises `account_schemas` 1, 2, 3 and 4 while retaining the legacy `accounts_format` field. Upgrade checks require explicit schema-2 support when that state is present. Preserve a pre-feature checkpoint for pre-M3 executables.

Credential changes serialize with policy changes and shutdown. A durable administration intent gates each management mutation. Linux publication syncs the new private file, atomically replaces the destination and syncs its parent directory. An uncertain directory-sync result refuses subsequent named-account/session/token authentication and further writes until restart resolves the published file. Bootstrap recovery authority remains available. Windows retains file-sync/atomic-replacement and process-crash qualification. Physical host/controller loss qualification for this new M3 format remains pending.

MFA secrets are stored as restricted-file secrets, with private file mode on Linux. They are included in backups alongside password and token verifiers. Backup storage must receive equivalent secret protection. Management lists, audit records and console screenshots used for validation omit secrets. The console keeps displayed issuance/enrollment secrets in page memory and clears them on sign-out or session expiry. It uses no external QR service.

Policy rollback preserves current credentials. A full recovery-set restore deliberately restores the checkpoint's credential state, including then-valid tokens, MFA settings and OTP watermark. Reconcile later revocations, password/MFA changes and accepted OTP steps before reopening administration. A restored old watermark can admit a code that was consumed after that checkpoint. Keep administrator access restricted during recovery and rotate/revoke affected credentials. [Recovery procedure](BACKUP-RESTORE-UPGRADES.md)

## Earlier token/TOTP validation record

The security tests cover token scope boundaries, expiry, persisted revocation, owner-version invalidation, secret redaction, failed writes, RFC TOTP vectors, concurrent OTP use, replay after restart, enrollment/session invalidation, bootstrap-only recovery and schema-aware backup/restore. The real-browser workflow covers issuance, revocation, mobile layout, MFA setup/confirmation, login rejection without MFA, code login and authenticated disablement. Raw results are retained under `artifacts/m3-*`.

| Executed check | Result and evidence |
|---|---|
| Complete Windows Go suite, actual server/admin and strict schema-1 fixture | PASS, `artifacts/m3-full-windows.log` |
| Pre-M3 actual Windows executable rejected for credential schema 2 | PASS through `TestSecurityCredentialsBackupRestoreAndDowngradeGuards` in that suite |
| Complete account, gateway and operations packages under Ubuntu 24.04 WSL | PASS, `artifacts/m3-linux-tests.log` |
| Real Chromium desktop/mobile workflows | PASS, `artifacts/m3-browser.log` |
| Complete `go vet` | PASS, `artifacts/m3-vet.log` |
| Shared-commit timing regression repeated twenty times | PASS, `artifacts/m3-checkpoint-repeat.log` |

The local `m3-20261103-r1` Linux amd64 package includes this contract. Its server/admin executables are compared with the directly tested Linux executables during assembly. This M3 format has unit, process-crash, recovery and browser evidence. The completion record tracks subsequent native qualification of the completed M3 formats. The M2 reference evidence remains tied to its recorded r6 operating binary.

An initial full-suite run overlapped browser execution and exposed scheduler dependence in the existing delayed-commit regression. Its 3-ms producer sleep has been replaced with a priming commit barrier that queues both producers before releasing the writer. The original 800-ms acknowledgement budget and 450-ms injected commit delay remain unchanged. Twenty isolated repeats passed. The original failed full-suite log remains `artifacts/m3-full-windows-initial.log`.
