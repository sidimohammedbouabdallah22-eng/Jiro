# Traffic controls and local access

This increment adds bounded local rate controls, application admission shares and deployment-wide administrator, operator and viewer accounts. Schema-1 installations retain their existing traffic behavior. Configure and save exact hostnames to migrate to schema 2 before setting traffic controls. [Application migration](APPLICATIONS.md)

## Rate controls

Select an application and open **Security policy**. Set the application and client requests-per-second and burst fields. Each rate/burst pair is either both zero or both positive. Zero disables that rate. Positive rates and bursts are bounded to 100,000, and a burst can contain at most ten minutes of its configured rate.

The implementation uses token buckets. Each admitted request consumes one application token and one client token when those controls are enabled. Rejected admissions consume neither. Rate decisions happen before body reading, Coraza transaction creation and backend forwarding. They apply in enforcing, detection and disabled inspection modes.

Client keys use the same canonical IP chosen for Coraza and backend identity by the trusted-proxy profile. Untrusted XFF cannot select a different rate bucket. NAT users share an IP bucket. This profile provides IP-based controls. Username, authenticated application identity, subnet and API-key based limits remain later work.

Each application retains at most 1,024 client entries when client rate or concurrency controls are enabled. Entries are retired after ten idle minutes, with a bounded scan of up to sixteen old entries per new client. Active entries remain until their admitted requests release them. A full table refuses an untracked client with 429 and Retry-After 600. It retains current clients' buckets, preserving their consumed credit under address churn.

429 responses identify rate or client-tracking capacity rejection. 503 identifies process, application-share or client-concurrency admission rejection. Both include an integer Retry-After. Rate and admission decisions are local to one process. A restart restores burst credit. Ordinary policy saves preserve credit, and a rate change settles existing credit at the activation boundary before using the new rate. Explicit disabling/re-enabling, application removal/recreation and restored checkpoints are administrative state changes.

429 and Retry-After follow the HTTP rate-rejection semantics. [HTTP 429](https://www.rfc-editor.org/rfc/rfc6585.html#section-4)

## Admission shares

A schema-2 deployment with N applications allocates each application up to floor(process concurrency / N) concurrent requests and floor(process buffer budget / N) bytes of connector buffer reservations. The process must have at least one concurrency slot per application. The **application concurrent requests** setting can lower that application's slot ceiling. **Client concurrent requests** limits simultaneous admitted requests from one validated client IP. Zero uses the application ceiling without an additional client limit.

The default process allows 64 concurrent inspections with a 256 MiB body-buffer reservation budget. With two applications each receives at most 32 slots and 128 MiB. With eight applications each receives at most eight slots and 32 MiB. Existing body/response copy accounting determines the reservation required for each request. A body that fits its configured request limit can still exceed the application's available buffer share and receive 503. The console displays current shares.

These are fixed shares. An application does not borrow another application's idle share, and requests are refused immediately when their admission ceiling is exhausted. Existing requests retain their original reservation until completion when policies or application counts change. Removed application state is freed when its last in-flight request completes. The TCP connection budget, CPU, storage and administration remain process-wide. Connection-flood isolation and multi-node fairness require additional deployment controls and qualification.

Traffic controls are an optional `traffic_controls` object on each schema-2 application. Its fields are `requests_per_second`, `burst`, `client_requests_per_second`, `client_burst`, `max_concurrent` and `max_client_concurrent`. Rate fields participate in complete-policy validation, atomic activation, history and rollback. Candidate checks include traffic-control requirements throughout committed history, even after a legacy-policy rollback.

## Events and monitoring

Rate rejections use action `rate_limited`, status 429, application ID, policy revision and validated client identity. Repeated rejections use counted summaries. Rejection storage has 61 regular application/revision/action buckets and three reserved overflow buckets for routing, capacity and rate rejection, for a maximum of 64 active summary buckets. Combined metadata uses `*` or revision/status 0 as appropriate. Occurrence counts remain explicit.

`openwaf_rate_limited_requests_total`, `openwaf_fairness_rejections_total` and `openwaf_tracked_rate_clients` expose fixed-name metrics. The status summary adds `rate_limited_requests`. Resource status exposes rate/share rejections and the maximum client entries per application. These counters and bucket state reset on restart. Retained security events and outbox accounting are durable within their storage bounds.

## Local accounts and roles

Use the existing administrator token to sign in, then open **Accounts & access**. Create the first enabled administrator before adding operators or viewers. Usernames contain 1–64 lowercase ASCII letters, digits, underscores, dots or hyphens, beginning with a letter or digit. Passwords are 15–256 UTF-8 bytes and preserve spaces. The store supports 32 named accounts including disabled accounts. Usernames are stable. Administrators enable/disable accounts and reset passwords through the same form. Account deletion remains later lifecycle work.

| Capability | Administrator | Operator | Viewer |
|---|---|---|---|
| Read configuration, policy history, events, audit, health and metrics | Yes | Yes | Yes |
| Create/remove applications, edit/validate policies and traffic controls, restore policy revisions | Yes | Yes | No |
| Reload certificate files | Yes | No | No |
| List accounts, create accounts, change roles, disable/enable users, reset others' passwords | Yes | No | No |
| Change own password and sign out | Yes | Yes | Yes |

Roles are deployment-wide by default. Explicit assignments restrict operators, viewers and automation tokens to selected applications, with filtered configuration/event reads and server-merged policy changes. [Assignment and MFA enforcement contract](M3-AUTHORIZATION.md) Unspecified non-administrator API capabilities are denied. Enforcement is on the server, including the alternate PUT configuration entry point. Viewer controls are disabled in the console. Policy-authoring operators can change upstream routing and inspection settings for every application.

Choose **Local account** on the sign-in screen to use a username and password. Sessions use random tokens, eight-hour absolute expiry, HttpOnly/SameSite cookies and a 100-session cap. Each authenticated request checks the current account version and enabled state. Updating an existing account revokes its previous sessions. Self-service password change signs the user out. Requests already authorized can complete during an account change. Sessions are discarded on service restart.

Password verifiers use Go's standard-library PBKDF2-HMAC-SHA256, 600,000 iterations and a separate random 32-byte salt per account. These password-derivation parameters apply to credential formats 1, 2 and 3. This uses the documented OWASP PBKDF2 work factor. Password verification and password-setting operations share two execution slots. Unknown and disabled usernames receive the same derivation work. The existing shared sign-in throttle refuses further sign-ins after ten failed credential checks within its one-minute window. [OWASP password storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html), [Go PBKDF2](https://pkg.go.dev/crypto/pbkdf2)

Credential guessing through self-service password change uses the same failure window as sign-in. Ten failed checks across either entry point cause further checks to return 429 until the window resets. Already authenticated read/policy requests retain their normal role behavior.

The bootstrap token remains a full-administrator credential for existing automation and recovery. Its bearer requests and token-based sessions retain full authority after accounts are enabled. Keep its file/environment source separately restricted. Rotate it through the existing server credential procedure. Scoped expiring automation credentials and opt-in authenticator MFA are implemented, including bootstrap-only authenticator recovery. Deployment-wide MFA enforcement and application assignments are implemented. External identity remains roadmap work. [Credential and MFA contract](M3-AUTHENTICATION.md)

## Durability and recovery

Accounts live beside the policy in `policy.json.accounts.json`, using a separate format and revision with a 64 KiB encoded-file limit. Writes use a private temporary file, sync and atomic replacement. Linux also syncs the parent directory and refuses named authentication after an uncertain publication result until restart. Account commits serialize with policy activation and shutdown, preserving ownership of the policy-file lease through the write. Stale revisions, invalid roles, duplicate usernames, malformed account files and disabling/demoting the last enabled administrator are refused. Out-of-band changes are refused on the next account save. Password hashes and salts are omitted from management responses and audit records. Account records retain their last change actor and reason. Durable audit intents gate account activation and self-service password changes.

Policy rollback preserves the current account store. Backup, verification, restore and candidate rehearsal include an existing account file automatically, including policy-only recovery sets. A candidate must advertise local account support when accounts are present and explicit credential schema 2 support after automation credentials or MFA have been enabled. Rehearsal preserves their file hash, revision and count. An older binary without account or traffic-control support is refused for affected state. Preserve a checkpoint from before enabling those features for an older executable.

A full checkpoint restore also restores that checkpoint's account settings and password verifiers. Reconcile subsequent revocations and password changes after recovery. Backups containing verifiers require protected storage. Existing bootstrap credential sources, deployment environment and TLS secrets follow the separate recovery coverage documented for those files. [Recovery procedure](BACKUP-RESTORE-UPGRADES.md)

The authenticated API adds `GET /api/v1/me`, administrator-only `GET /api/v1/accounts`, administrator-only `POST /api/v1/accounts`, and `POST /api/v1/me/password`. Account saves require `revision`, `username`, `role`, `disabled`, `password` and `reason`. An empty password retains an existing password. Password changes require `current_password` and `password`. All use the existing JSON/origin/audit gates.
