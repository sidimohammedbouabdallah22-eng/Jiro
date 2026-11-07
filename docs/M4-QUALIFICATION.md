# M4 application and pilot qualification

Status on 6 November 2026: **in progress**. The current boundary/replay candidate passes the thirty-minute joint business profile and all six five-minute windows. CPU-abuse testing retains eight large-Unicode timeouts with wide admission and separately verifies one-slot/body/rate mitigations. These short abuse screens do not qualify arbitrary deadlines, CPU isolation or a customer deployment. [Extended evidence and limits](M4-JOINT-ENDURANCE-ABUSE.md), [current build ledger](M4-CURRENT-CANDIDATE.md). Prior operational/TLS/identity results remain tied to their recorded binaries; the 30-day pilot has not started.

## Qualified lab scope

The test uses the M3 r7 Linux amd64 archive, with the same runtime previously qualified through native endurance and interruption tests:

- Package: `openwaf-m3-20261104-r7-linux-amd64.tar.gz`, SHA-256 `35a4c8b55fb6797d1258e798ca5f4ecbc079c62261f84db531d58058dbcd87ee`.
- Server: SHA-256 `40ec989918bb8976a4d464ee31220e7e92f46aeadb94b5c5d72e3249104421ae`.
- Host: an owned Ubuntu 24.04 amd64 VirtualBox qualification guest, 1 vCPU and 4 GiB RAM shared by the gateway and application fixtures. These shared lab resources are not a business capacity measurement.
- Products: DVWA at low security, WordPress 7.1.4 / PHP 8.3 / Apache, MariaDB 11.4.13 and Keycloak 26.8.1. Exact image digests and upstream labels are pinned in `tools/application-check/images.lock.json`. DVWA uses a content digest even though its upstream tag is `latest`.
- Policy: schema-2 separate DVWA and WordPress applications, CRS PL1 enforcing, inbound threshold 5, 1-MiB body limit, no global exclusions and no response-body inspection. WordPress has one reviewed method rule described below.
- Identity: a real Keycloak realm with conditional LoA flows: password for LoA1 and password plus OTP for LoA2. OpenWAF requires ACR `2`, uses S256 PKCE and binds an immutable provider subject explicitly to a local viewer assigned only WordPress.

Containers run on an internal Docker network. Only bounded loopback relays and owned SSH forwards expose their HTTP endpoints to the runner. The database is not published. There are no user-data mounts. DVWA, its known password and intentional vulnerabilities belong only to this isolated lab. Lab HTTP and Keycloak development mode are not a production authentication configuration.

The subsequent downstream CPU-optimization candidate repeats this full 22-case
suite successfully in `artifacts/m4-lab-8b989431/results.json`. The corrected
backend-deadline candidate repeats all 22 cases in
`artifacts/m4-lab-295530c3/results.json`, with fresh state and the same pinned
products. Its package/server hashes and distinct performance
scope are recorded in [CPU qualification](M4-CPU-QUALIFICATION.md). The original
M3 artifact identity above remains the identity of the earlier qualification.

## Checks and findings

| Workflow | Result in the qualified profile |
|---|---|
| DVWA authenticated benign lookup and harmless text upload | Allowed |
| DVWA SQL injection | Direct query returns multiple users; same request blocked through WAF |
| DVWA reflected XSS | Direct response contains executable markup; protected request blocked |
| DVWA command injection | Direct harmless marker executes; protected request blocked |
| DVWA executable upload | Direct harmless PHP marker executes; protected upload blocked |
| WordPress authenticated rich-text publishing | Published, including punctuation, HTML and a SQL example |
| WordPress multilingual search | Allowed |
| WordPress multipart PNG upload/download | Allowed; downloaded bytes match |
| WordPress post update/delete | Update allowed; DELETE initially blocked by CRS 911100; passes after narrow method tuning |
| Tuning boundaries | DELETE on a user resource remains blocked; XSS on an allowed post-deletion route remains blocked |
| XSS outside the editing workflow | Blocked |
| Real Keycloak password plus OTP | SSO succeeds with strong authentication, local viewer role and WordPress-only configuration visibility; account administration denied |
| Genuine password-only Keycloak LoA1 | Callback rejects the weaker assurance required to satisfy LoA2 |
| Local unlink of a provider subject | Existing real SSO session loses access; binding restored after the check |
| Pilot collector against the actual gateway | Monitoring-only token accepted, bootstrap credential rejected, failures persisted, no bearer secrets found in database; no business pilot started |

The method adjustment is confined to the WordPress application and `DELETE /wp-json/wp/v2/posts/<numeric-id>`, including its query string. It sets `tx.allowed_methods` before CRS for that request. It neither removes rule 911100 globally nor skips other inspection. Application authorization still decides who can delete a post. This tuning is a lab fixture that needs application-owner review before reuse.

The runner first restores the baseline policy and demonstrates the method refusal, then applies the rule through the real configuration API and exercises both positive and negative cases. Authenticated publishing passed without an XSS/SQLi exception. This is a small reviewed workflow set, not an aggregate false-positive rate or evidence of universal attack coverage.

## Reproduction and evidence

Prerequisites: a passing owned Ubuntu 24.04 VirtualBox qualification VM with the existing OpenWAF service account, Docker and socat installed, sufficient disk/RAM, OpenSSH, Node.js, Chrome and the repository's existing `tools/ui-check` Playwright dependencies. Stop unrelated gateway qualification traffic first. Package checksums are verified before fixture setup.

```powershell
python scripts/qualify-applications.py --vm-dir artifacts/m2-vms/<owned-qualified-VM> --package artifacts/openwaf-m3-20261104-r7-linux-amd64.tar.gz --disposable-vm
```

To rerun a prepared fixture, pass `--fixture <private-artifact-file> --disposable-vm`. `--prepare-only` leaves owned fixture services running for investigation and closes the runner's SSH forwards. Normal completion/failure stops owned services/containers and closes forwards; fixture state is retained. The VM is retained. Do not expose the guest or relays to public interfaces.

The retained local evidence is `artifacts/m4-lab-5b541cb4/results.json`, with earlier results preserved in the same directory and orchestration logs under `artifacts/m4-applications-*.log`. Reports record product digests, package/server checksums and runner source hashes. Private fixture/monitoring files contain credentials and remain outside source control in a restricted artifact directory. Review and sanitize all artifacts before sharing; do not publish that directory.

Initial runs exposed lab issues: database authentication readiness, internal-network port publishing assumptions, gateway readiness after restart, the required first local administrator, browser Fetch API handling and selecting an unrestricted monitoring owner. These were qualification-tool defects/configuration corrections. The WordPress method refusal was a policy compatibility finding. No production gateway code or M3 runtime was changed for this increment.

Collector regression tests run with:

```sh
python -m unittest discover -s scripts -p test_pilot.py -v
```

Their synthetic month verifies rejection of missing samples/reviews, stale evidence and blocking findings. It is not elapsed pilot evidence. The live collector check is short and deliberately records a rejected bootstrap credential.

All eight collector tests passed on Windows and native Ubuntu 24.04 (`artifacts/m4-pilot-tests.log`, `artifacts/m4-pilot-linux-tests.log`). Ubuntu systemd unit verification passed for the service/timer templates (`artifacts/m4-pilot-systemd-verify.log`). The original 17-case report is retained as `results-before-lifecycle.json`. The expanded 22-case report records runner hashes for the lifecycle extension. Comparison against all 165 recorded M3 source hashes found only documentation changes; the production runtime remains the qualified M3 binary.

## Remaining M4 gates

1. Qualify the pilot's actual IdP/TLS/client configuration and operational administrator MFA/passkey recovery. The isolated lifecycle extension covers signing-key rotation, provider outage/recovery, session expiry and disabled provider/local accounts; its results are recorded below. Existing synthetic identity regressions remain useful alongside actual-provider checks.
2. Choose the business application and continuous host. Exercise its authenticated workflows, hooks/API methods, upload sizes, trusted-proxy topology and TLS with the application owner.
3. Apply declared workload/latency/headroom budgets to the chosen deployment. The first native colocated profile passed five-request/second five/ten-minute schedules, separate large-body checks, admission concurrency, backend faults and independently verified event delivery. Higher rates encountered refusals and large JSON remains expensive. Shared lab throughput cannot inherit the M3 gateway-only capacity claim. [Results](M4-CAPACITY-RESULTS.md), [findings](M4-FINDINGS.md), [measurement protocol](CAPACITY-QUALIFICATION.md)
4. Run and review the 30-day window, alerts, backup restore and deployed-artifact upgrade/rollback drills. [Pilot procedure](PILOT.md)
5. Commission independent review and resolve release-blocking findings. Retain the supported-profile limitations and keep ARM64 experimental until separately qualified.

## Upstream references

- [DVWA source and deployment guidance](https://github.com/digininja/DVWA)
- [WordPress releases](https://wordpress.org/download/releases/) and [official image definitions](https://github.com/docker-library/official-images/blob/master/library/wordpress)
- [Keycloak container guidance](https://www.keycloak.org/server/containers), [administration and step-up authentication](https://www.keycloak.org/docs/latest/server_admin/index.html), and [pinned conditional LoA implementation](https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/authentication/authenticators/conditional/ConditionalLoaAuthenticator.java)
- [MariaDB official container source](https://github.com/MariaDB/mariadb-docker)
- [Pinned Keycloak 26.8.1 administration REST API](https://www.keycloak.org/docs-api/26.8.1/rest-api/index.html)

## Identity lifecycle extension

The runner now includes five additional real-provider scenarios, controlled by `scripts/m4_idp.py` over the owned VM's SSH connection. The control helper reads private credentials inside the guest, permits only fixed lab operations and validates the container's qualification ownership label. It does not return passwords or tokens. New signing keys are retained with their old verification keys; forced key retirement is outside this check.

The rotation case requires a changed active RS256 key ID and a successful fresh MFA login using the already-running gateway. The expiry case temporarily sets a real 30-second Keycloak token lifetime, waits for actual elapsed expiry and explicitly replays the expired OpenWAF cookie to check server-side rejection. Local account disable must invalidate a subsequent authenticated request.

Provider account disable must refuse a fresh provider login while an existing OpenWAF session remains valid within its original bound. This is the documented local-session contract: OpenWAF does not currently consume provider revocation/back-channel logout notifications. Operators needing immediate removal must revoke the local account/binding; assess this requirement with the pilot owner.

For outage testing, the runner holds a genuine authorization-code redirect before OpenWAF consumes it, stops only the owned Keycloak container, and submits the code to OpenWAF while exchange is unavailable. It checks failed authentication, continued protected application access and local password-administrator login, then restores Keycloak and verifies a fresh MFA login. This checks local administration availability; recovery of configured administrator MFA/passkeys remains an explicit pilot qualification gate.

Provider lifetime and enabled-user settings are restored in cleanup, including after failed assertions; the outer application harness subsequently stops owned lab services. Failed lifecycle development reports are retained as `results-lifecycle-runner-errors.json` and `results-lifecycle-browser-race.json`. They exposed browser selector/navigation and redirect-interception issues in the runner; they do not establish gateway security defects.

The expanded run passed all 22 cases (`artifacts/m4-lab-5b541cb4/results.json`, orchestration `artifacts/m4-lifecycle-r3.log`), including all five lifecycle scenarios. The report records successful provider-setting restoration. This extends actual-provider evidence under the loopback/public-client lab profile; it does not qualify a customer TLS topology, immediate provider revocation or administrator factor recovery.


## Sustained business abuse update, 7 November 2026

Candidate `7be7bc728f08` passes the scoped thirty-minute directional/simultaneous
abuse profile with four vCPUs/4 GiB, all 93 file workflows and six five-minute
windows. Its 9,198 requests and 6,640 occurrences independently reconcile.
The separate multi-address held-request test demonstrates slot exhaustion and
complete reclamation. A guest boot stall requires a retry and remains recorded.
Full browser/shared-NAT and selected deployment workload checks, final-package
operational repetition, independent review and the pilot remain M4 gates.
[Sustained results and limits](M4-SUSTAINED-FAIRNESS.md).
