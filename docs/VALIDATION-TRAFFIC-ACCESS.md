# Traffic and access validation

The 3 November 2026 increment is exercised with isolated policies, temporary account/event state and harmless local backends. Results are retained in the following local evidence files.

| Evidence | Coverage |
|---|---|
| `artifacts/controls-full-tests.log` | Root Go suite on Windows, including the actual current server/admin executables and prior-binary recovery guards when executable environment variables are supplied |
| `artifacts/controls-regression.log` | Focused admission, rate, identity, role, password, account-file and recovery tests |
| `artifacts/controls-{gateway,accounts,operations}-linux.log` | Isolated Linux amd64 gateway, accounts and recovery suites |
| `artifacts/controls-browser.log` | Chrome configuration, token/account login, all roles, operator writes, viewer UI/server boundaries, account disable, self-password changes and restart persistence |
| `artifacts/controls-systemd.log` | Packaged systemd deployment, TLS/proxy/application checks, rate rejection, account roles, revocation, named audit attribution and restored-service credentials |
| `artifacts/controls-crs-regression.json` | Full established CRS compatibility profile, retaining the 16 reviewed platform adaptations |
| `artifacts/controls-admission-fuzz.log` | 92,662 executions passed admission/release conservation and client-table bounds in ten seconds with two workers |
| `artifacts/controls-vet.log` | Root `go vet` output |

## Admission checks

Deterministic tests exercise application and client token credit, refill, rate transitions, strict concurrent/buffer shares, client concurrency and resource release. A real gateway test holds two requests for one application at its ceiling, observes that application's 503 and verifies that another application still reaches its backend.

Client-table tests fill all 1,024 entries, refuse a new client, retire idle entries and retain active client state. Proxy tests check distinct validated forwarded IPs against client buckets. Rate rejection accounting verifies every rejected occurrence is durably acknowledged. Existing multi-application concurrent traffic, cancellation, response, HTTP/2, WebSocket and shutdown tests run alongside these controls.

## Account and authorization checks

Tests exercise per-account password verification and persistence, failed password writes, stale revisions, last-administrator protection, disabled identities, session versions and encoded JSON expansion beyond the account-file limit. Public responses and administration audit are checked for password/hash exposure.

Credential-throttle tests exercise ten failed current-password checks, verify refusal of the next check and verify that sign-in shares the same failure window. Password execution slots must be fully released afterward.

The server role matrix checks viewer writes against every policy/application mutation route, including PUT, operator access to account/certificate administration, read capabilities and denial of unspecified capabilities. Tests verify operator policy writes carry the individual username, role changes invalidate sessions, self-password changes revoke existing sessions, old passwords fail and disabled accounts cannot authenticate.

Account activation shares the policy/shutdown mutation lock. A regression test holds that lock and verifies that an account write is refused, then closes the gateway and verifies that further account mutation is refused. Request identity is resolved once for consistent authorization and audit attribution. Later requests observe revocation. Account activation audit records identify the target username, requested role, disabled flag and whether credentials changed, without recording passwords or verifiers.

Chrome performs the corresponding workflows through the normal interface. It also switches directly from viewer to operator to catch stale disabled-control state, and signs in after a service restart and self-password change. Accounts have their own navigation page.

## Recovery checks

The controls checkpoint test records a rate-bearing policy in committed history, rolls the active policy back and adds accounts. The recovery set must retain the traffic requirement and account metadata. Restore must preserve the administrator verifier. Candidate checks refuse missing account/traffic capabilities. An actual current executable rehearses against the checkpoint, and the preserved previous executable is refused while remaining compatible with a pre-feature checkpoint.

The packaged Linux service creates administrator, operator and viewer identities, verifies permissions and revocation, and preserves all three accounts plus traffic settings through backup, verification, candidate rehearsal and service cutover to restored state. Enabled viewer login succeeds after cutover, and the disabled operator remains refused.

## Qualification boundaries

Traffic control state is local and resets on process restart. Admission uses fixed equal shares and immediate refusal. TCP connections, CPU and disk still use shared process limits. Roles are deployment-wide. The bootstrap token retains full administrator authority. Scoped automation credentials, MFA/external identity, per-application role scope and account deletion remain roadmap work.

Linux execution uses Ubuntu 24.04 under WSL on amd64. The arm64 archive is build/checksum qualified. Native arm64, additional distributions, fresh-VM installation, representative long-duration traffic and independent access-control review remain qualification work. Earlier multi-application validation recorded an intermittent five-second database-startup deadline under concurrent qualification jobs, followed by successful isolated repeats. That finding remains part of sustained resource/startup qualification. [Earlier finding](VALIDATION-APPLICATIONS.md), [Traffic and access contract](TRAFFIC-AND-ACCESS.md)
