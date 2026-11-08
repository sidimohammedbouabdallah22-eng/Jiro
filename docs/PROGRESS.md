# Progress toward an SMB deployment

8 November 2026, full local WSL2 endurance completes. Baseline and all three
five-minute external-abuse profiles pass every workload/resource gate. The
five-minute shared-source profile completes but refuses legitimate uploads.
Independent checks reconcile 19,087 requests, 136 exact files and 5,625 security
occurrences in 1,792 identical receiver records. Ingest timeouts, queue loss,
failed writes and export failures are zero. Maximum sampling gap is 1.019 seconds
and maximum one-minute CPU is 70.18%. Thirty-two false proofs are rejected.
The dedicated distribution and original VM are stopped. M4 remains open for
shared-source contention and the remaining deployment/review/pilot gates.
[Full results and scope](M4-NAT-ABUSE.md).

8 November 2026, local qualification backend. Idle-host VirtualBox testing still
reproduces long sampling/acknowledgement delays. Browser failure diagnostics and
partial-upload evidence retention are fixed with regressions. A dedicated WSL2
lab reuses the checksum-verified owned business fixtures and the same server
binary in an enforced four-CPU/four-GiB service slice. Its short baseline and
all external-abuse phases pass. All 4,265 requests, forty files and 1,043 security
occurrences reconcile with zero ingest timeouts and a 1.005-second maximum
sampling gap. Thirty-two false proofs are rejected. The shared-source upload
boundary remains failed. M4 remains open. [Profile and evidence](M4-NAT-ABUSE.md).

8 November 2026, export recovery and longer M4 testing. A reproduced empty-outbox
read-timeout health bug is fixed with a failing-before-fix regression. Two clean
two-MiB-burst baselines fail, including a legitimate upload refusal, rejecting
that workload profile. The new candidate passes a three-MiB baseline, then its
five-minute ERP phase fails latency, native sampling and one ingest
acknowledgement. All 4,502 requests, fifty-two exact files and 659 occurrences in
250 identical sender/receiver records reconcile. Remaining abuse phases have
not started. Every owned VM cleanup succeeds and restores one vCPU. M4 remains
open. [Results and binary identities](M4-NAT-ABUSE.md).

7 November 2026, resumed M4 qualification. The three-MiB body-burst endurance
run reconciles 14,683 requests, 136 committed files and 3,760 occurrences in
1,188 identical sender/receiver records, but fails coverage, native sampling
and same-source browser gates. The browser schedule now uses a fixed monotonic
epoch, records start delays and checks its timing evidence independently.
Abuse testing requires a passing no-abuse baseline. Invalidated measurements
are rejected explicitly. A subsequent diagnostic run observes heavy host CPU
contention and two ingest acknowledgement timeouts. Its twenty committed files
verify and cleanup restores the VM to powered off with one vCPU. The diagnostic
source-edit invalidation and all failures are retained. A repeat on an eligible
host and final-package qualification remain open.
[Results and measurement changes](M4-NAT-ABUSE.md).

8 November 2026. The clean fixed-schedule screen passes baseline and individual
ERP/storefront abuse gates. Combined pressure still fails file latency and
coverage, and shared-source pressure refuses legitimate uploads. All 3,983
requests, forty committed files and 756 occurrences in 282 identical receiver
records reconcile. Twenty-nine false evidence cases are rejected. A two-MiB
burst experiment stops at its failed baseline before hostile work. Ten files
verify, and stalled VM shutdown is recovered. Cleanup now records and rejects
forced shutdowns for qualification. The VM is off with one vCPU. Extended
endurance, final-package checks, independent review and pilot gates remain open.

Update on 6 November 2026: the unchanged candidate passes a thirty-minute joint ERP/storefront phase, all 2,250 endurance requests and all six five-minute resource/latency windows. The full suite reconciles 2,888 requests and 42 security occurrences. CPU-abuse qualification retains a failed wide-Unicode run with eight timeouts; a separate one-slot/body/rate mitigation run reconciles 1,364 requests and 911 security occurrences. One slot still saturates CPU, while the stricter 64-KiB/one-request-per-second profile restricts legitimate uploads. Longer hostile load, reverse/simultaneous attacks and actual deployment qualification remain open. [Exact evidence and tradeoffs](M4-JOINT-ENDURANCE-ABUSE.md).

The 5 November boundary/replay candidate `1af405f4227a` adds exact-limit JSON/multipart coverage and a joint ERP/storefront profile. All 1,013 requests and 47 security occurrences reconcile. The same package repeats all 19 ERP and eight storefront functional cases. Bursts reach 32 clients; a five-minute profile with one 700-KiB ERP file every four seconds plus one storefront read/second passes. The heavier upload screen saturates the one-vCPU guest and is rejected as an operating profile. This is preliminary lab evidence, not customer sizing. [Joint workload and limits](M4-JOINT-BUSINESS.md), [exact-build ledger](M4-CURRENT-CANDIDATE.md). Longer endurance, broader authenticated writes and final-package operational requalification remain open.

Assessment date is 5 November 2026. M2 and M3 are complete for their scoped Linux amd64 reference profiles. M4 is in progress with isolated real-product qualification, separate clean-OS WAF recovery and pilot preparation. Qualification is tracked separately from feature implementation.

| Area | Implemented foundation | Remaining gate |
|---|---|---|
| M0 security contract | Real Coraza/CRS, recorded connector decision, regression corpus and protocol checks | Wider adverse framing/protocol coverage and independent review |
| M1 dependable policy | Typed application policies, scoped exceptions, complete-deployment validation/atomic activation, history and rollback | Representative application tuning and additional adverse update qualification |
| M2 operable appliance, Linux amd64 | Bounded durable events, shared ingestion/checkpoint writer, acknowledged event/audit export, recovery tooling, monitoring, systemd package, certificate renewal consumption, transactional schema startup, administration journal, Ubuntu 22.04/24.04 amd64 fresh-VM workflows and two-hour Windows/WSL fault profiles | Closed for Ubuntu 24.04 reference sizing and guest interruption plus the concrete r5/r6 upgrade/rollback pair. Ubuntu 22.04 covers functional compatibility. ARM64 and physical host/controller power failure remain separate |
| M3 business controls | Trusted-proxy identity, isolated hostname-routed applications, bounded application/client rates, fixed admission shares, local administrator/operator/viewer accounts, versioned session revocation, scoped expiring automation tokens, authenticator MFA with deployment enforcement and enrollment-only recovery, application assignments for accounts/tokens, bootstrap-only factor recovery, named policy audit, passkeys, OIDC, bounded upstream pools and a pinned rule-update pipeline | Closed for the Linux amd64 reference profile. Native two-hour endurance, three guest poweroffs and r2/r6 upgrade/rollback passed |
| M4 qualified pilot | Full CRS accounting, pinned application/identity lifecycle checks, native colocated capacity/fault/delivery measurements, large-body profiling with a conservative downstream regex optimization, CPU-heavy application competition, reviewed tuning and a bounded pilot evidence collector | Independent patch review, actual business workload/body/admission/headroom qualification and endurance, pilot identity/TLS/factor recovery configuration, 30 reviewed pilot days, deployed drills and independent review |
| M5 release | Pinned dependencies, notices and local packages/checksums | Final license decision, publishing/support ownership, signed release artifacts, SBOM/provenance and supported upgrade line |

The project has a multi-application operating foundation with fixed admission shares and deployment-wide roles. SMB production readiness still depends on access-control review, representative abuse/sizing tests and sustained application qualification. Passing the upstream corpus establishes connector compatibility within its documented test profile and platform expectations. Pilot evidence must establish business-workflow compatibility and operating reliability.

M2 closure covers native Ubuntu 24.04 gateway-only sizing at 25 requests/second for two hours, three abrupt guest poweroffs and the concrete r5/r6 live upgrade/rollback pair. M3 now includes scoped revocable automation credentials, configurable administrator MFA enforcement and application assignments with filtered reads and merged policy writes. Passkeys, OIDC, upstream pools and pinned rule-update qualification are implemented. The final M3 native run passed 179,791 requests over two hours at 24.97 requests/second, with zero unexpected responses/network errors, 187.61-ms p95 and 94.84-MiB gateway peak RSS. Three abrupt guest poweroffs, persisted authentication/authorization and actual r2/r6 upgrade/rollback passed. [M3 gates and evidence](M3-COMPLETION.md) ARM64 is tracked separately as an experimental platform target. The shared-writer correction already passes two-hour Windows and WSL fault profiles with zero acknowledgement/client errors and complete reconciliation. Earlier failed runs remain recorded. [M3 assignment and enforcement contract](M3-AUTHORIZATION.md), [M3 credential contract](M3-AUTHENTICATION.md), [M2 gates and evidence](M2-QUALIFICATION.md), [ARM64 criteria](ARM64-QUALIFICATION.md)

The expanded M4 real-product run passed 22 cases: DVWA attack baselines and WAF blocks, ordinary WordPress workflows, narrow DELETE tuning, actual Keycloak MFA, local authorization/revocation and scoped monitoring, plus signing-key rotation, real-time session expiry, local/provider account disable and provider outage/recovery. Provider account disable blocks fresh login; existing local sessions require local revocation or expiry. This is a controlled workflow set, not an aggregate false-positive rate or customer capacity claim. [Application qualification](M4-QUALIFICATION.md)

Native capacity qualification records a successful five-request/second colocated one-vCPU reference profile: five/ten-minute mixed schedules, separately bounded large JSON, concurrent admission fairness, slow/unavailable backends and receiver outage/recovery. All 5,342 gateway requests and 1,246 security records / 1,289 occurrences reconciled, including captured database payloads. Ten and 25 requests/second produced admission refusals under those settings. Subsequent CPU profiling identifies regex scans and a conservative downstream ASCII guard: the native targeted 900-KiB sample falls from 5.23 s to 0.82 s. CPU-heavy cross-application measurements include Unicode fallback and an explicitly tested one-slot admission policy. Unicode remains expensive and shares do not establish CPU-time isolation. Customer workload/headroom and abuse endurance remain open. [CPU evidence and patch responsibilities](M4-CPU-QUALIFICATION.md), [capacity results](M4-CAPACITY-RESULTS.md), [findings](M4-FINDINGS.md)

The roadmap's pilot gate remains 30 consecutive days of reviewed operation, plus successful recovery and upgrade/rollback exercises. The collector and systemd templates are prepared; no business pilot or 30-day clock has started. A continuously available host, application owner and operational reviewer remain to be chosen. Independent review and release ownership remain requirements for a business-ready claim. [Pilot procedure](PILOT.md) · [Roadmap](../ROADMAP.md) · [Trusted proxy contract](TRUSTED-PROXIES.md)

The corrected CPU-qualification candidate passes the full 5,193-case corpus on
Windows and Linux and repeats all 22 real-product cases. Pre-expired/in-flight
total request deadlines no longer degrade backend circuits; genuine backend
timeouts still count. Repeated native competition verifies successful payload
digests, zero evidence loss and zero false backend failures on the corrected
build. The optimized-engine five/ten-minute reference also passes; its report
retains its earlier binary identity. Unicode-heavy saturation and customer
headroom remain limitations, not closed pilot gates. [Evidence and scope](M4-CPU-QUALIFICATION.md)

The same corrected binary now passes a 30-minute mixed application phase at five
requests/second (190-ms p95), with all 11,342 frontend requests independently
accounted across the full run. Verified-TLS fresh/persistent HTTP/1.1 and HTTP/2
workloads, concurrent streams, session resumption, body integrity and certificate/
authority rejection checks also pass; all 1,846 transport requests reconcile.
Both sustained operating budgets and complete native/management observation are
enforced. The test-CA issuer correction is retained as a failed fixture, with no
verification bypass or production change. [Corrected-build endurance and transport evidence](M4-ENDURANCE-TRANSPORTS.md)

The exact corrected candidate now also passes actual previous-M3 upgrade and
rollback, three abrupt guest interruptions and a separate replacement-directory
restore with copied TLS/credential/authentication assets and real post-restore
passkey/MFA checks. Event/audit receipts and archived measurement sources verify.
The VM is stopped and failed evidence retained. That same-VM run does not supply
fresh-host evidence; the later separate clean-OS drill below does. Deployed
alerts and the actual pilot remain open. [Recovery rehearsal](M4-RECOVERY-REHEARSAL.md)
The first representative business sets now pass: 14 Dolibarr cases and six
PrestaShop cases, including committed document/order state and exact delivery
accounting from captured databases. The Dolibarr set includes reader assignment,
permission boundaries and paired missing/invalid/valid CSRF-token checks.
Storefront qualification exposed a schema-2
Host rewrite; the corrected candidate preserves validated application authority
and passes full Windows/Linux tests and both 5,193-case CRS runs. Prior endurance
and recovery evidence remain identified separately; the new candidate now also
passes exact upgrade/rollback, three interruptions, replacement-directory recovery
and a 30-minute mixed reference (480-ms p95, complete event accounting). Extended business
workflows, actual business capacity, customer deployment/factor recovery, business-database recovery, alerts and the actual
pilot remain open. ERPNext follows this first cohort. [Workflow matrix](M4-BUSINESS-APPLICATIONS.md),
[5 November results and candidate identity](M4-BUSINESS-RESULTS.md) ·
[Current-build qualification ledger](M4-CURRENT-CANDIDATE.md)

The current build's verified-TLS H1/H2/resumption repeat now passes with 1,846
requests and 458 records/459 occurrences independently reconciled. A fresh
22-case DVWA/WordPress/Keycloak run also passes, including real MFA, signing-key
rotation, expiry, disable and outage/recovery. Sources and exact executable
identity verify; provider settings are restored and the VM is off. These close
the lab repeat gates, not customer configuration or the 30-day pilot.

Separate clean-OS restoration now passes on Ubuntu 24.04 amd64. The target has
no prior OpenWAF identity/state and is provisioned from the pinned stock image;
the donor is off before activation. All 16 checkpoint security events, two new
attack events, 165 existing independent audit-receiver records and all 151
restored-journal records (including shutdown) verify from captured bytes.
Policies/history, six deployment assets, passwords, enrolled passkey/TOTP and
scoped authorization survive. The checker rejects 12 invalid proofs; both VMs
end off and failed attempts remain retained. This qualifies WAF/reference
receiver recovery with controlled backends, not business-database DR. Deployed
fault/alert drills subsequently pass as described below. [Fresh-host findings and procedure](M4-FRESH-HOST-RECOVERY.md)

The deployed fault/alert lab passes 14 cases and independently reconciles 12
acknowledged alert/recovery transitions, including an uncertain-ack replay stored
once. The bounded watchdog runs separately from sampling, persists pending
delivery and alerts on failed, unreadable or missing evidence. Real certificate,
export and isolated disk-full failures are exercised. One deliberately failed
event write is accounted separately; all three committed security records and
33 final audit records reach their receivers. Windows/Linux watchdog tests and
existing Windows pilot tests pass. Actual recipient notification, automatic
scheduling and external supervision remain deployment gates. M4 and the business
pilot remain open. [Alert setup and qualification](PILOT-ALERTS.md)

The expanded business cohort now passes 19 Dolibarr and eight PrestaShop cases.
Native CSV import and multipart attachments, contacts/validated sales orders,
reader boundaries, incorrect-password rejection and cart removal/re-addition
are covered without new rule exclusions. A separate read-only DB/file probe
confirms ERP rows, totals, imported-customer uniqueness and exact document bytes.

Both products separately complete ten minutes at five requests/second, after
direct and protected screens. All 6,960 protected load requests and known 403/413
occurrences reconcile from captured databases. Endurance p95 is 111.617 ms for
Dolibarr and 251.230 ms for PrestaShop. The higher observed phase-average CPU
readings are 13.40% and 53.01%; virtualized counter disagreement is documented
and checked conservatively. Native monotonic alignment, seven adverse accounting
tests and four paging tests guard against false capacity claims. A real
post-load storefront repetition reads both event pages and verifies all 551
retained records. The VM is off, with all failed fixtures retained.

These are separate small-fixture profiles, not joint ERP/storefront or customer
sizing. Next capacity gates are larger/native formats, stronger concurrency,
authenticated commerce writes, longer endurance and combined application
contention, followed by the selected pilot workload/host. Native export,
broader roles/back-office workflows and the remaining operational/review/pilot
gates stay open. [Business results](M4-BUSINESS-RESULTS.md),
[capacity evidence and caveats](M4-BUSINESS-CAPACITY.md)


7 November 2026. Candidate `7be7bc728f08` adds bounded admission waiting,
per-client buffer budgets and accurate refusal summaries. It includes earlier
idle-connection eviction and recovery of export health after a verified late
checkpoint. Both full platform suites pass, including 5,193 CRS cases each,
focused Linux race checks and 27 real-business functional workflows.

The four-vCPU/4-GiB abuse profile passes ten minutes per direction and ten minutes
simultaneously. All 93 file workflows and six five-minute windows pass. Captured
accounting reconciles 9,198 requests and 6,640 occurrences in 2,346 records.
Thirteen false evidence claims are rejected. The two-peer held-request boundary
records two legitimate 503s and complete reclamation. Its 804 requests, seven
files and two occurrences verify, as do the prior failed run's 33 files.
Ten false boundary claims are rejected.

One boundary boot stalls before setup and requires a cold restart. That failure,
all failed profiles and the passing evidence are retained. The VM is off and its
original one-vCPU allocation is restored. Full browser/shared-NAT workload,
final-package deployment repetition, independent review and pilot gates keep M4
open. [Results and limits](M4-SUSTAINED-FAIRNESS.md),
[current-build ledger](M4-CURRENT-CANDIDATE.md).

7 November 2026, browser/NAT follow-up. Candidate `20031ed996b3` clears a
completed request-body deadline before upstream processing. A real-socket
regression reproduces an empty GET 200 on the prior package and passes with the
fix. Both platform full suites pass, including 5,193 CRS cases each, plus
focused Linux race checks. Native fixture domain rewrites, storefront module
caches and the browser measurement proxy are corrected as failures expose them.

The full-browser reference and four-wave shared-NAT screen pass. Verification
reconciles 1,201 requests, seventeen committed files, three absent refused
uploads and 339 occurrences in seventeen identical receiver records. Twelve
false evidence claims are rejected. Strict controls from the prior API-abuse
profile reject normal browser assets even with separate user addresses. The
passing NAT screen uses explicitly higher experimental limits on four vCPUs.
Their abuse/endurance qualification remains open. All failed runs are retained,
including an unresolved guest boot stall and a sampling-gap timeout run. The
VM is off and restored to one vCPU. [Browser results and next gates](M4-BROWSER-NAT.md).
