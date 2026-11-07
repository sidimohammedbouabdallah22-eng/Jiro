# M3 completion and qualification

The business-controls milestone covers multiple applications/upstreams, trusted identity, bounded rate controls, accounts/RBAC, an SSO option, API tokens and a rule-update pipeline. Its exit criteria require isolation/permission tests and representative workflows under enforcement. Passkey support is included in the completed authentication implementation.

## Feature implementation

| Control | Implemented boundary |
|---|---|
| Multiple applications and upstreams | Eight hostname-routed applications, eight backends per pool, verified HTTPS/SNI, bounded transports and header deadlines, passive circuits, round-robin selection and observed status |
| Trusted identity and admission | Explicit proxy CIDRs, validated forwarded identity, bounded per-application/client rates and key cardinality, fixed admission/buffer shares |
| Accounts and automation | Administrator/operator/viewer roles, application assignments, scoped expiring tokens, persisted revocation and per-request owner/version checks |
| Strong authentication | TOTP with durable replay protection, deployment administrator-MFA enforcement, enrollment-only sessions, user-verifying passkeys and bootstrap recovery |
| Organization identity | OIDC authorization code with S256 PKCE, nonce/state/browser binding, exact issuer and immutable-subject mapping, local authorization and configured assurance requirements |
| Rule updates | Exact pins, isolated candidate sources, paired CRS corpus, complete regression/accounting, dependency scan, retained review report, package and guarded upgrade/recovery procedures |
| Console | Structured pool editing and status, assigned-application views, account/token controls, SSO bindings, passkey enrollment/sign-in/revocation and reasoned recovery |

Pool health is passive. Client cancellation leaves backend failure counts unchanged. Application-level retries are omitted, with standard transport connection recovery subject to Go's replay rules. SSO grants access through explicit local accounts. These choices keep routing and authorization reviewable. [Application contract](APPLICATIONS.md), [Authentication contract](SSO-AND-PASSKEYS.md), [Rule updates](RULE-UPDATES.md)

## Qualification completed on 4 November 2026

| Gate | Current evidence |
|---|---|
| Full Windows tests with current server/admin and actual older candidates | PASS, r6 candidate pipeline `unit-integration.log`; actual older-reader checks also passed in `artifacts/m3-r5-complete-windows.log` |
| Complete vet | PASS, `artifacts/rule-candidate-b7d24d15a3cb/vet.log` |
| Desktop/mobile console, enforcement, isolation and cryptographic sign-in workflows | PASS, `artifacts/m3-r6-browser.log`, including SSO binding wrapping and a valid-signature assertion from the same RP on a different origin port |
| Management HTTPS and Secure/HttpOnly session cookie through the actual executable | PASS in the complete suite and `artifacts/m3-management-tls-test.log` |
| Upstream transport, cancellation, TLS trust/SAN, deadline, circuit epochs and WebSockets | PASS, `artifacts/m3-pool-cancellation-tests.log`, `artifacts/m3-pool-transport-tests.log` and the full suite |
| OIDC assurance, nonce, audience, issuer, expiry, authorized party, clock, cookie/state, replay and revocation | PASS, `artifacts/m3-oidc-enforced-tests.log` and the full suite |
| Credential schema 4, public-material persistence, counter publication/CAS, recovery and downgrade rejection | PASS in account/recovery suites, including the actual previous M3 executable |
| Full rule candidate pipeline with unchanged current pins | PASS, `artifacts/rule-candidate-b7d24d15a3cb/result.json`, 5,193/5,193 cases and 16 reviewed adaptations, zero skips/ignores/errors |
| Dependency scan | Zero reachable/imported-package vulnerabilities. The unused `x/crypto/openpgp` package has module advisory GO-2026-5932. `artifacts/m3-govulncheck-verbose.log` |
| Fresh Ubuntu 22.04/24.04 install and restored-service workflows | PASS, `artifacts/m3-fresh22.log`, `artifacts/m3-fresh24.log` |
| Ubuntu 22.04 native interruption, scoped credentials and r2/r6 upgrade/rollback | PASS, `artifacts/m2-operational-875be108/result.json`, functional compatibility profile |
| Complete Linux race suite | PASS, `artifacts/m3-r6-linux-race.log`, r6 server/admin executables |
| Ubuntu 24.04 two-hour reference profile, three abrupt poweroffs and r2/r6 rollback | PASS, `artifacts/m2-operational-f44d7056/result.json` and `artifacts/m3-r6-native-endurance-resumed.log` |

## Native reference result

The reference guest used Ubuntu 24.04 amd64, one vCPU and 2 GiB RAM. An external host client sent TLS traffic to two applications, each with two backends. The mix included benign searches, 16-KiB JSON submissions and 30% XSS requests. Administrator MFA, passkeys, TOTP, an explicit SSO binding, application assignments and a scoped automation credential were persisted. The configured unavailable identity provider left startup and local authentication usable.

| Sustained measurement | Result |
|---|---|
| Duration | 7,200.27 seconds |
| Completed requests | 179,791 |
| Achieved rate | 24.97 requests/second |
| Unexpected responses and network errors | 0 and 0 |
| p95 / p99 latency | 187.61 / 823.65 ms |
| Gateway average CPU | 39.14% of one vCPU |
| Gateway peak RSS | 94.84 MiB |
| Event writes failed / ingestion timeouts / queue drops | 0 / 0 / 0 |
| Export records enqueued / acknowledged / pending after drain | 58,632 / 58,632 / 0 |

The export sender recovered from one failed delivery attempt. Administration export had zero failures and no pending records after drain. Local event retention remained bounded to the configured database/row budgets. A short 50-request/second ramp passed. The 100-request/second ramp achieved 56.95 requests/second and failed its target-rate criterion. The qualified sustained reference remains 25 requests/second.

Three abrupt guest poweroffs interrupted an active journaled event write. Each restart verified the latest 100 acknowledged events locally and at the receiver, the full acknowledged administration prefix, policy state and the credential-file hash. Recovery took 41.74, 42.57 and 42.48 seconds. Passkey and TOTP login, scoped-token permissions, assigned-application isolation and observed backend health passed before the workload and after each cut. Passkey counters advanced from 2 through 5.

The actual prior r2 executable was activated before a coordinated checkpoint, then upgraded to r6. Following the endurance and interruption checks, tooling preserved the newer recovery set and restored that checkpoint with the actual r2 executable. Policy revision 2, credential state and the administration prefix matched the checkpoint, and local login worked. The independent audit receiver retained the newer timeline. Native Ubuntu 22.04 passed the corresponding functional interruption/upgrade/rollback profile.

The qualified r6 package SHA-256 is `a4a54c32ae26b0d769c3e0807c7e8780f0d97b1e89dc16a9ee1f65a6f02387e3`. Its server SHA-256 is `40ec989918bb8976a4d464ee31220e7e92f46aeadb94b5c5d72e3249104421ae`, administrator SHA-256 is `6f57125f7e3190a4c2973068ad5c5e633de4c5642118c25d1a2ce1131aebfed3` and collector SHA-256 is `0591e4bc9d03ad74d010803a8f8cbfab1224161f8b92b1d799b581b944335a5d`. Independently built executables match those package members. `artifacts/m3-r6-build-evidence.json` records source and executable hashes. Fresh r6 installation passed in `artifacts/m2-vms/openwaf-m2-24.04-10724fab/result.json`.

The final r7 documentation bundle retains those runtime bytes. Its assembly checks every non-document package member against the qualified r6 package and records the resulting package hash in `artifacts/m3-final-build-evidence.json`. Raw qualification directories contain private fixture credentials and remain excluded from publication.

## Retained failures and corrections

Native harness retries corrected dependency-restart sequencing, the fixture's rapid-start accounting, browser executable selection and UTF-8 subprocess decoding. A smoke run was superseded while its authenticator fixture was extended. The completed smoke result remains `artifacts/m2-operational-67686a54/result.json`. The first long-run attempt was superseded by the cancellation-neutral circuit correction before endurance began. Its partial evidence remains `artifacts/m2-operational-fe4723cc`.

The candidate `rule-candidate-91396e05fa42` retains a single request timeout with its original two-second corpus read deadline. Candidate `rule-candidate-b046a1f4c5bc` retains the TOTP fixture failure at a clock boundary. Tests now reserve time for password verification before submitting a previous-window code, and direct store tests capture one time value for code generation and verification. Ten focused repetitions passed. Production OTP windows and deadlines retain their original values.

Initial local race attempts encountered Go SDK validation fixtures and an unbuilt C dependency in ignored reference checkouts during recursive package discovery. Local ignored toolchain/reference module boundaries isolate those development materials. The final run targets the project package tree used by a clean checkout. Initial logs remain available.

Existing M2 operating evidence remains attached to its recorded builds. M3 is complete for the scoped Linux amd64 profile, with all milestone gates recorded above. Organization-specific IdP and hardware-authenticator validation, representative real applications, the 30-day pilot and independent security review remain M4 work. ARM64 and physical host/controller power failure remain outside the qualified amd64 guest profile. Release signing, publishing/support ownership and the owner's final license decision remain M5 work.

A chat interruption ended the r5 sustained run at approximately 69 minutes. A later host blackout interrupted r6 qualification, leaving incomplete results and damaged host log tails. Both runs remain incomplete. The resumed r6 run uses a package verified against its pre-blackout checksum and fresh process state. The completed resumed r6 result supplies the closure evidence.

The final mobile checks exposed a long SSO binding line that exceeded the viewport. The binding list now wraps, navigation checks wait for the selected view, and desktop/mobile workflows pass against the qualified r6 executable. Authentication help text also describes passkey and assured-SSO step-up.
