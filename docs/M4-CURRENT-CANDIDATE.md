# Current source and qualification ledger

9 November 2026, current-package operational repetition passes. Three power cuts,
replacement restore and upgrade/rollback pass. A new stock Ubuntu 24.04 OS then
restores WAF state, verified application TLS, enrolled administrator factors and
authorization. All eighteen final security records and 151 final administration
records reconcile. Fifteen deployed alert cases pass on that target, including
shipped systemd timers and watchdog notification with sampling stopped. Fourteen
alert transitions acknowledge and ten false alert claims reject. A fixture-layout
guard defect is corrected with six regressions. The selected runtime stays the
same. Fresh-host business dependencies, actual deployment certificates/provider
recovery, recipient notification, watchdog supervision, independent review and
the pilot remain open. [Fresh-host proof](M4-FRESH-HOST-RECOVERY.md),
[operational proof](M4-RECOVERY-REHEARSAL.md), [alerts](PILOT-ALERTS.md).

9 November 2026, coordinated business recovery passes. The selected upload-
reservation build restores Dolibarr and PrestaShop schema/data, installed
application state, document/custom volumes and WAF state into isolated
replacement containers/directories in the same owned WSL2 lab. Eight real
browser sessions and eight upload round trips pass. All 178 earlier files plus
four pre-checkpoint files verify after recovery, followed by four new uploads.
Two original security events survive exactly and two new blocks reach the
receiver, with zero storage/delivery failures. Ten false qualification claims
reject and twenty-eight focused checks pass. Source data and failed attempts
remain retained, with the owned lab stopped. M4 remains open for selected-host
repetition, customer TLS/factor recovery, alerts, independent review and the
business pilot. [Recovery evidence and scope](M4-BUSINESS-RECOVERY.md).

## Upload-route reservation candidate

The selected package SHA-256 is
`f7efe1e953fac810f932bb7f59fe373b0fb2b0577b328ecca40b33bd3c097063`.
The Linux server SHA-256 is
`75ee8698e1ef1b5e5bf9e039943d6d2e80e3076354cee343d5dc67a8c38ad3d8`.
All 505 runtime source files match the reviewed public source byte-for-byte.
Full Windows and native Linux tests/vet, all 5,193 native Linux CRS cases,
four reservation regressions and real-console save/reload/disable checks pass.

Short run `da17b38e` passes all five phases, with 4,352 requests, fifty exact
files and 1,128 occurrences in 338 identical receiver records. Full run
`37d22b7a` passes baseline, ERP, storefront, simultaneous and shared-source
gates. Verification covers 19,503 requests, 336 sessions, 178 files totaling
127,590,400 bytes, and 6,029 occurrences in 1,805 identical receiver records.
The native probe also verifies 239 previously committed files and forty-nine
previously refused files remain absent. Delivery failures, write failures, ingest timeouts and queue loss remain zero.
Maximum sampling gap is 1.020 seconds and one-minute CPU 64.30%.

The optional exact-route reservation preserves full CRS inspection and all
process/application/client admission limits. The qualified profile raises the
old aggregate client body rate from 160 to 192 KiB/s and burst from 3 to 5 MiB.
ERP reserves 160 KiB/s and 4 MiB for POST /api/index.php/documents/upload.
Other ERP bodies receive 32 KiB/s and 1 MiB. Storefront uses its aggregate
192 KiB/s and 5 MiB. Both applications retain their one-MiB request envelope,
24-MiB client buffer budget, four-CPU/four-GiB allocation and original pass gates.
Same-route abuse shares the reservation. M4 still requires deployment-specific
qualification, independent review and the actual business pilot.
[Results, rejected profiles and configuration](M4-NAT-ABUSE.md).

## Previous published Jiro runtime baseline

Revision `49303daae33019bab2f4260234d94b3cda8e38e6` uses the
`github.com/sidimohammedbouabdallah22-eng/Jiro` module and Jiro console branding.
It resolves Windows short directory names before disposable recovery containment
checks. A regression reproduces the earlier failure and verifies the fix,
including rejection of external state paths.

All nine hosted verification jobs pass on that revision, including both platform
suites, Linux race checks, browser workflows, service packaging, mixed load,
and 5,193 CRS cases on each platform.
[Hosted verification](https://github.com/sidimohammedbouabdallah22-eng/Jiro/actions/runs/42471401755).

The business endurance measurements below identify earlier packaged binaries.
Repeat package-sensitive gates against the selected Jiro release package before
claiming a qualified current release. M4 and the business pilot remain open.

## Jiro export-read recovery candidate

The 8 November follow-up fixes export health remaining failed after a transient
database read timeout when the durable outbox is empty. A failing-before-fix
regression verifies recovery without manufacturing a collector acknowledgement
or receiver-contact timestamp. Local event-store/gateway suites and vet pass.

The package SHA-256 is
`d382caa1fd25f747611c292fa51b57f498c49e02c34488e79509b2944bd99c13`.
The server SHA-256 is
`70d3e58d0ca98c1d104c719fb2beca0c535955dae3d8ad621528db2b9490f56b`.
Two clean-boot two-MiB-burst screens fail their baseline gates, including one
legitimate upload refusal. That profile is rejected for this workload.

The three-MiB-burst baseline passes. Its longer ERP phase completes all browser
workflows but fails latency, coverage, native sampling and one ingest
acknowledgement. All 4,502 requests, fifty-two files and 659 occurrences in 250
identical receiver records reconcile. Remaining abuse phases have not started.
Full package-sensitive qualification remains open.
[Measurements and remaining limits](M4-NAT-ABUSE.md).

The local WSL2 profile reuses this exact packaged server and a checksum-verified
cold business-fixture copy. Its service slice enforces four allocated CPUs and
four GiB aggregate memory, with twelve host CPUs recorded separately. Short
baseline, ERP, storefront and simultaneous-abuse phases pass every workload,
native-resource and delivery gate. Independent evidence verifies 4,265 requests,
forty exact files and 1,043 occurrences in 352 identical receiver records, with
zero ingest timeouts and a maximum 1.005-second native gap. Thirty-two false
claims are rejected. Shared-source upload contention remains unqualified.
These measurements retain their WSL2 service-slice scope.

The subsequent full sequence completes a one-minute baseline and all four
five-minute abuse phases on this exact server. External-source endurance passes
all gates. Verification covers 19,087 requests, 136 exact files, 5,625 occurrences
in 1,792 identical receiver records and forty-two absent refused files. Ingest
timeouts, queue loss, failed writes and export failures are zero. Maximum native
gap is 1.019 seconds and maximum one-minute allocation CPU is 70.18%. Thirty-two
false proofs are rejected. Shared-source uploads remain refused. The WSL2 lab
stops cleanly and the source VM remains off with its original settings. M4 stays
open for shared-source, deployment, independent-review and pilot gates.

## Body-budget candidate 32d099011bde

Candidate `32d099011bde` adds opt-in client/application request-body byte
budgets alongside the existing request-rate, concurrency and buffer controls.
The byte budget is checked atomically before body buffering or inspection.
Unknown lengths reserve the full request envelope. Defaults remain disabled.
The console exposes both rate and burst, with real-browser save/reload/disable
checks. [Configuration semantics](CLIENT-BODY-RATE.md).

Windows and Linux full pipelines pass, including operational tests, vet and
5,193 CRS cases each. Focused Linux race checks cover byte admission, ordinary
rate controls, admission waiting and the completed-body deadline regression.
All 708 runtime files matched its source snapshot when this build was frozen.

The archive SHA-256 is
`7bdfc03cf31dfbc0687d05419714d06c6155b3846c8b7bb232d9dcd75a7c5a36`.
The Linux server SHA-256 is
`3564efa5f9b7feddac52752c3a6641665d72734b14b8411f7d7eb27cbd8c22dc`.

The first guarded abuse screen independently reconciles 4,096 requests,
forty-two committed files and 864 occurrences into 310 identical receiver
records. Twenty-four false proofs are rejected. Individual ERP/storefront
abuse passes, while combined and same-source pressure remain failed screens.
The reduced-burst endurance experiment completed with exact file/event
accounting, but failed coverage, sampling and same-source browser gates.
Its 14,683 requests, 136 committed files and 3,760 occurrences in 1,188 identical
sender/receiver records verify independently. Twenty-four false proofs were
rejected. This profile remains unqualified.
[Abuse results, experiments and limits](M4-NAT-ABUSE.md).

M4 stays open for the remaining workload/resource gates, selected-host sizing,
final-package deployment-sensitive repetitions, independent review and pilot.

The 8 November fixed-schedule screen on this same package reconciles 3,983
requests, forty committed files and 756 occurrences in 282 receiver records.
Its individual-app profiles pass, while simultaneous and shared-source workloads
remain failed. Twenty-nine false proofs are rejected. A two-MiB burst screen
stops at its failed no-abuse baseline. Its forced VM shutdown is retained as a
failure and recovered separately. These are measurement-harness changes and
screens against the named earlier binary. Jiro package-sensitive repetitions
and longer endurance remain open.

## Previous candidate 20031ed996b3

Candidate `20031ed996b3` fixes the completed-body read deadline leaking into
upstream processing. A real-socket regression reproduces an empty GET 200 on
`7be7bc728f08` and passes on the new source. Both Windows and Linux full suites
pass, including operational tests, vet and 5,193 CRS cases each. Focused Linux
race checks pass for deadlines, HTTP/2, streaming and WebSocket behavior.

The archive SHA-256 is
`68f447d28bbc1c17d2c86a63323f590860abbd0d3392ff8312de60f2563cba34`.
The Linux server SHA-256 is
`24e7329d6486daaf48d620b86d7b90b2218a26c86b4d4a27d737ffa620ecc27d`.

The full browser reference and four-wave higher-limit shared-NAT screen pass
on this build. The comparison independently verifies 1,201 requests, seventeen
files and 339 security occurrences. Twelve false claims are rejected. Strict
limits reject normal asset bursts with separate peers and shared NAT. The
higher-limit screen requires fresh abuse qualification before adoption.
[Browser comparison and retained failures](M4-BROWSER-NAT.md).

The qualification index verifies all 707 current runtime source files against
the frozen build and records the exact proof/tool hashes. The VM ends off with
its original one-vCPU allocation restored.
[Current qualification index](../artifacts/rule-candidate-20031ed996b3/m4-browser-qualification.json).

The earlier sustained-abuse and 27-case business functional results below
belong to `7be7bc728f08`. Repeating deployment-sensitive evidence on the final
selected package remains an M4 gate.

## Previous candidate 7be7bc728f08

The previous frozen source is `7be7bc728f08`. It adds the opt-in per-client outstanding
buffer budget, preserving the full individual request envelope. Frozen-source
Linux race checks pass for the gateway and event store. Both Windows and Linux
full pipelines pass, including unit/integration, operational recovery, vet and
5,193/5,193 CRS cases on each. All 19 Dolibarr (`results-22.json`) and eight
PrestaShop (`results-13.json`) functional cases pass with independently checked
captured event payloads. The 31-minute baseline/abuse run passes all six
five-minute windows, verifies 93 file workflows and independently reconciles
9,198 requests and 6,640 security occurrences into 2,346 receiver records.

The qualified profile uses four vCPUs/4 GiB, four application slots, client
concurrency three, rate two/burst four, five-MiB client buffers, one-MiB request
envelopes and one-second bounded admission wait. Thirteen false claims are
rejected. The separate two-peer exhaustion run verifies its two legitimate 503s,
seven retained files, one absent refused file and the prior run's 33 files.
Ten false boundary claims are rejected. Its initial guest boot stall and cold
restart are retained. The VM ends off with its original one-vCPU allocation.

| Gate | Current evidence |
|---|---|
| Sustained directional and simultaneous abuse | `m4-business-abuse-ba78fad7/verification.json` and `fairness-windows.json` |
| Evidence mutation checks | Same fixture, `verifier-negative-tests.json`, thirteen cases |
| Real multi-address exhaustion | `m4-business-abuse-559ae05d/boundary-verification.json` |
| Boundary mutation checks | Same fixture, `boundary-negative-tests.json`, ten cases |
| VM restoration | `artifacts/m4-fairness-cpu-change-20261106.json` |

M4 stays open for full browser/shared-NAT and selected-host workload checks,
final-package deployment repetitions, independent review and the thirty-day
pilot. Details and retained failed profiles appear in
[Sustained business abuse qualification](M4-SUSTAINED-FAIRNESS.md).
[Configuration, sizing and limitations](CLIENT-BUFFER-BUDGET.md).
[Browser and shared-NAT workload qualification](M4-BROWSER-NAT.md).

- Archive SHA-256: `915d46bda6c31df7632500e11d613144205e6e41180e63d72d76710295fd1f9a`
- Linux server SHA-256: `7f9d9af38fc020d62ba18870e768371a08e4d57df1fb130203dd99e35fd76707`

That candidate's evidence index verifies 706 runtime source files against the
frozen candidate and records the platform, workflow, endurance, boundary and VM
restoration proofs. It also records the open M4 gates.
[Qualification index](../artifacts/rule-candidate-7be7bc728f08/m4-fairness-qualification.json).

# Previous candidate a720777a5f60

Frozen source at this stage: `a720777a5f60`. It includes bounded admission waiting,
upstream idle eviction and recovery of stale export health after a verified
late local checkpoint. Frozen-source focused Linux race checks pass for the
gateway and event store. Both Windows and Linux full pipelines pass, including
unit/integration, operational recovery, vet and 5,193/5,193 CRS cases on each.
Dolibarr (19 cases, `results-21.json`) and PrestaShop (eight cases,
`results-12.json`) pass with independently checked captured event databases.
Both functional runs record four vCPUs/4 GiB and make no capacity claim.
Its retained `be368389` screen fails ERP rate and simultaneous latency gates.
M4 remains open. [Late-checkpoint correction](M4-EXPORT-HEALTH-RECOVERY.md),
[idle-reuse correction](M4-UPSTREAM-IDLE.md).

- Archive SHA-256: `db1e3a078228194094cfcb722aa994cfd4edae5125a00b19ba6dbfb79ebb0ae1`
- Linux server SHA-256: `85e1c984f2abdb62002841f2c7af2f1595df0d323d932d480c1311eab233e9d9`

# Previous candidate 4a145e37f9b5

Frozen source for this stage: `4a145e37f9b5`, containing bounded admission waiting,
truthful refusal summaries and two-second upstream idle eviction. Focused
Linux race checks pass from this exact frozen source, including ambiguous POST
and idempotency safeguards. Both Windows and Linux full pipelines pass, including
unit/integration, operational recovery, vet and 5,193/5,193 CRS cases on each.
Its retained `b003efee` attempt stops on late-checkpoint export health.
M4 remains open. [Failure trace, reproducer and tradeoffs](M4-UPSTREAM-IDLE.md).

- Archive SHA-256: `32d92cae0f809f65232ca47f8da9eb9d3666e27cf5edb2c68be20fb1896b2ae4`
- Linux server SHA-256: `d79a8c70ca294f6c75011e9a738c271df1ff28dd4272035ef46cdc8e4f1a7cea`

# Previous candidate 7507723617cc

The lab executable at this stage is `7507723617cc`; M4 remains open. It adds opt-in
bounded admission waiting and accurate mixed-reason overload summaries.

- Archive SHA-256: `ef9583a607d859bfb89d0cb0ce3293696b3b5e69f17bb0bcf6d63c6da5d43eff`
- Linux server SHA-256: `0506471e4acaa16e82e4c63121624eaa209da4b64fe8e04f8a0c187fffb0f0e5`
- Full Windows/Linux unit/integration and vet checks pass; CRS is 5,193/5,193 on each.
- Focused race checks pass with a corrected test assertion; the frozen test's
  timing failure is retained in `linux-native/admission-race-hardened-test.json`.
- Sustained abuse qualification remains open. Zero-wait, one-vCPU varied-file
  and two-vCPU screens exposed legitimate refusals; the two-vCPU run also has
  one upstream EOF. [Detailed evidence](M4-SUSTAINED-FAIRNESS.md).
- Earlier functional, endurance and operational results below belong to their
  stated packages. They do not automatically qualify this executable.

# Previous candidate 1af405f4227a evidence

Candidate `1af405f4227a` includes the inclusive body-limit correction, safe
buffered-body reopening, client-idempotency replay guard and bounded upstream
failure categories. It is a lab candidate, not an approved release; M4 remains
open and the 30-day pilot has not started.

- Archive: `artifacts/rule-candidate-1af405f4227a/openwaf-rule-candidate-linux-amd64.tar.gz`
- Archive SHA-256: `240d163948dd98bc7b9f1b4b4a77e7b3defd9d9ad381ab158408842c6e071ea7`
- Linux server SHA-256: `488523c66b610e6945d1b66e5a1cd3c94e5ce08bd6d34249fdd7b24229ef166e`
- Coraza downstream identity remains `openwaf-ascii-presence-v1`; CRS 4.30.0.

| Gate | Exact-build evidence | Scope/status |
|---|---|---|
| Windows unit/integration, vet, vulnerability scan, connector comparison | Candidate `result.json` and logs | Passed; vulnerability evidence is time-specific |
| Linux unit/integration and vet | Candidate `linux-native/result.json` | Passed with packaged binaries |
| Full CRS | Candidate Windows/Linux regression reports | 5,193/5,193 on each platform; no failures/errors/skips/ignored cases |
| Connector race checks | Candidate `linux-native/focused-race.json` | Passed: inclusive boundaries, safe reconnect, lost response, untrusted idempotency headers and sanitized diagnostics |
| Joint business qualification | `artifacts/m4-business-joint-dce48ae1/result.json`, `verification.json` | 1,013 requests; 32-client bursts, native/exact-limit uploads, two-app admission fairness, heavy screen and five-minute lower-rate endurance |
| Longer joint business endurance | `artifacts/m4-business-joint-1d4bc198/result.json`, `verification.json`, `endurance-windows.json` | 30 minutes, 2,250 successful endurance requests; all six five-minute windows pass and all 2,888 suite requests reconcile |
| Real-business CPU abuse | Failed `artifacts/m4-business-abuse-55d4a9d2/failure-verification.json`; passing bounded `artifacts/m4-business-abuse-8c5e3522/verification.json` | Eight-slot Unicode causes eight timeouts; one-slot and body/rate mitigations measured over 90-second screens; all 1,364 mitigation requests and 911 security occurrences reconcile |
| Dolibarr 24.0.1 | `artifacts/m4-business-2be162b6/results-20.json` | All 19 cases repeated; captured event payloads independently verified |
| PrestaShop 9.2.0 | `artifacts/m4-business-77aadf7d/results-11.json` | All eight cases repeated; login, cart removal/re-addition, unpaid checkout and paged events independently verified |

The joint heavy screen is deliberately **outside** the accepted operating
profile: 26 refusals among 180 requests, 98.57% observed CPU and 2,635.706-ms
storefront p95. The lower profile completes all 375 requests with 758.974-ms
storefront p95 and 42.45% observed CPU. This is a five-minute controlled lab
result, not customer sizing or CPU isolation. All 47 security occurrences
reconcile with 27 durable/exported records; no transport failure occurred in
this run. Failed predecessors remain retained and the original large-upload
502 has not been causally explained by the small-body reconnect regression.
[Workload, corrections and limits](M4-JOINT-BUSINESS.md)

The same executable subsequently passes thirty minutes of joint business load,
with all six five-minute windows within budget. Real-business CPU abuse confirms
that large Unicode can overrun HTTP deadlines under wide admission. One slot
preserves storefront responsiveness but saturates CPU; the stricter 64-KiB,
one-request/second profile has headroom in short screens and rejects the larger
legitimate workflow. Neither is hard CPU isolation or customer sizing. Failed
screens remain failed. [Extended evidence and limits](M4-JOINT-ENDURANCE-ABUSE.md)

The longer reference endurance, verified-TLS/identity suite, operational recovery,
rollback, clean-OS restoration and deployed-alert evidence below belong to
`5777d82f469c`, not this newer executable. Repeat deployment-sensitive gates on
the final pilot package before M4 closure. M2/M3 historical closure is unchanged.

# Previous candidate 5777d82f469c (historical evidence)

Candidate `5777d82f469c` preserves validated schema-2 HTTP Host for application
virtual hosts/canonical redirects. It is a lab candidate, not an approved release.

- Archive: `artifacts/rule-candidate-5777d82f469c/openwaf-rule-candidate-linux-amd64.tar.gz`
- Archive SHA-256: `7bfe3b73b7a11318302662ad31e3ec36e671a25d88ff2f5bf182ff1a9c922cb2`
- Server SHA-256: `cef0916699fa8adef803c46e74d2a73f995156b15a550f5304283a0d3216794f`
- Coraza downstream identity: `openwaf-ascii-presence-v1`; CRS 4.30.0.

| Gate | Current-build evidence | Scope/status |
|---|---|---|
| Windows full unit/integration, vet, dependency and connector comparison | Candidate `result.json` and stage logs | Passed; a dependency check is time-specific, not a permanent vulnerability guarantee |
| Linux full unit/integration and vet | Candidate `linux-native/result.json` | Passed with packaged Linux executables |
| Full CRS | Candidate Windows/Linux `*crs-regression.json` | 5,193/5,193 on each platform; no failure/error/skip/ignored cases |
| Routing/identity race checks | Focused Linux test run | Passed; fixed target still selects dialing/TLS SNI |
| Dolibarr 24.0.1 | `artifacts/m4-business-2be162b6/results-19.json` | 19 cases; native CSV import/multipart, contacts/orders, reader boundaries and customer-form CSRF |
| PrestaShop 9.2.0 | `artifacts/m4-business-77aadf7d/results-10.json` | Eight cases; bad-password rejection, cart removal/re-addition, unpaid order and post-load paged history |
| Exact upgrade/rollback and current-build replacement | `artifacts/m2-operational-d3cee4f8/result.json` | Passed: three interrupted writes, five factor/authorization proofs, copied deployment assets and independent receipts |
| Colocated reference endurance | `artifacts/m4-capacity-ca881f91` | Passed: five requests/second, five-minute steady and 30-minute combined phase; 11,342 frontend requests accounted and complete captured event reconciliation |
| Verified-TLS H1/H2/resumption repetitions | `artifacts/m4-capacity-9e974725` | Passed: three 600-request modes and nine extra checks; all 1,846 requests and 459 security occurrences accounted |
| Real identity-provider lifecycle repetition | `artifacts/m4-lab-25395e39` | All 22 fresh application/identity cases pass; provider settings restored. Customer TLS/client/factor recovery remains open |
| Initial real-business load profiles | `artifacts/m4-business-capacity-7578cf05` and `0cbb4619` | Passed separately: 5 requests/second for ten minutes per cohort; all 6,960 protected screen/endurance requests accounted |
| Full business matrix and deployment capacity | Functional/load subsets above | Native export, broader roles/CSRF, back-office coverage, concurrency/large formats, joint contention and actual workload budgets remain open |
| Fresh-host recovery | `artifacts/m4-fresh-restore-df422373` | Passed on a separate clean Ubuntu 24.04 amd64 OS; WAF/receiver state and controlled backends, not business-database DR |
| Deployed faults and alert transport | `artifacts/m4-alerts-bdf3989b` | Passed: 14 cases, 12 acknowledged transitions, actual isolated ENOSPC and real missing-sample timeout; one intentional unacknowledged event write accounted |
| Operator alerts and supervision | Local receiver/service evidence above | Open: actual recipient notification, automatic scheduling and independent supervision need deployment qualification |
| Reviewed pilot | No continuous business host/owner/reviewer selected | Not started; requires 30 actual consecutive reviewed days |
| Independent review | Downstream patch and broader security review pending | Open; automated regression does not replace review |

The 30-minute endurance reference does not include PrestaShop/Dolibarr. Separate
business profiles now cover ERP API reads/writes/uploads and storefront reads
on a one-vCPU/4-GiB VM, one cohort at a time. Ten-minute p95 is 111.617 ms for
Dolibarr and 251.230 ms for PrestaShop; higher observed phase-average CPU measures
are 13.40% and 53.01%. These are tested points, not maximum throughput or SMB
sizing claims. Virtualized CPU counters disagree; the checker enforces both
readings conservatively. [Profile, evidence and limits](M4-BUSINESS-CAPACITY.md)
ARM64 and physical host/controller power failure remain separate qualifications.

Fresh-host recovery independently verifies all 16 checkpoint events, two new
attack events, all 165 current independent audit-receiver records and all 151
captured restored-journal records, including shutdown delivery. Policies,
history, six TLS/credential/authentication assets and accounts/authorization
survive. Browser passkey/TOTP, password login, scoped authorization and verified
TLS traffic pass; both VMs end powered off. This is a new OS from the pinned
stock image, not a donor clone. [Evidence, findings and scope](M4-FRESH-HOST-RECOVERY.md)

The alert watchdog now durably retries bounded, credential-free webhook payloads.
Certificate reload rejection, security/audit export outages, event-storage full,
unreadable evidence and a real 182-second sample gap produce alerts and recover.
Exact acknowledgements, uncertain-ack replay/deduplication and captured sender/
receiver bytes verify. Disk-full deliberately loses one unacknowledged write;
the test records it explicitly and does not claim lossless operation on a full
disk. The runtime binary is unchanged. [Alert setup and limits](PILOT-ALERTS.md)

The 30-minute phase completed 9,000/9,000 requests with zero network errors,
unexpected verdicts, generator refusals or scheduler delays over 100 ms. Scheduled
latency: p95 479.593 ms, p99 759.323 ms, maximum 1,638.788 ms. The gateway used
6.36% of one guest vCPU by Linux process accounting, with sampled phase peak RSS
101.41 MiB and lifetime HWM 113.125 MiB; one gateway PID was observed throughout.
These are virtualized guest observations under the recorded profile, not
physical-host or customer sizing guarantees.

The full run's 2,746 records/2,789 occurrences match the independent receiver's
IDs, payloads and totals. Known status occurrences reconcile: 2,735 rule blocks,
eight body-limit refusals, two deliberately induced backend failures and 44
admission refusals from the fairness check. Persistence errors, drops, failed
writes, ingest timeouts and final pending writes/exports are zero. Sustained
operating budgets and complete native/management measurement coverage pass.
Older owned packaged test services were stopped before measurement; the
`profile-isolation.json` snapshot records their inactive state.

Independent verification: `artifacts/m4-capacity-ca881f91/verification.json`.
Stopped database bundle SHA-256:
`c860e0deb96e9507bb16ef383954c524a51ac2f12d37e640b1a55e1861c0730c`.
The orchestration record `artifacts/m4-host-preservation-endurance-20261105.json`
confirms successful verification and final VM poweroff. No VM, fixture or failed
evidence was deleted.

## Current-build TLS and real-provider repeat

The verified-TLS repetition passes with full native/management coverage, zero
loss/write/ingest errors and fully drained delivery. Each mode runs 600 requests
at five requests/second for two minutes:

| Mode | Observed p95 | Connections | Reused requests |
|---|---:|---:|---:|
| Fresh HTTP/1.1 TLS | 232.556 ms | 600 | 0 |
| Persistent HTTP/1.1 TLS | 701.875 ms | 9 | 591 |
| Persistent HTTP/2 TLS | 184.947 ms | 3 | 597 |

These consecutive lab observations are not a comparative protocol benchmark or
customer sizing result. Nine additional checks pass: complete TLS-1.2 mixed
corpus; HTTP/1 and HTTP/2 large-body verdicts; three overlapping HTTP/2 streams
on one warmed verified connection; nine resumptions in ten TLS-1.3 connections;
HTTP/1 and HTTP/2 SNI/Host mismatch rejection; untrusted-CA rejection; wrong
certificate-hostname rejection. Certificate verification remains enabled.

Captured sender/receiver databases match 458 records/459 occurrences, including
455 rule blocks, two body-limit refusals and two hostname-mismatch occurrences.
The bundle SHA-256 is
`63cb09e5270f5df9e259cc06d836348cb297fa564372e52212621e2421c520cf`.
Independent evidence: `artifacts/m4-capacity-9e974725/verification.json`.

The fresh DVWA/WordPress/Keycloak fixture passes all 22 cases on this exact server:
paired direct exploits/WAF blocks, publishing/search/multipart/tuning, real OTP
LoA2 with local viewer/application grants, genuine LoA1 rejection, local unlink,
changed signing keys, real-time expiry, local/provider disable behavior, provider
outage/recovery and least-privilege pilot monitoring. Its settings are restored
and its source snapshots and packaged executable verified independently.
`artifacts/m4-lab-25395e39/verification.json` includes eight rejected proof
mutations. The later business expansion supplies 49 scoped application/identity
cases across this build's three cohorts (22 + 19 + 8), not a complete business
workflow matrix. Native ERP import/multipart and the post-load storefront
repetition are recorded separately in the business evidence.

The provider uses the existing isolated HTTP-loopback/public-client/PKCE lab
profile. It does not qualify a customer's HTTPS identity topology, factor
recovery or immediate provider-side revocation of existing local sessions.
Provider disable blocks new login; local revocation or expiry bounds existing
sessions. The private CA is a transport-test CA, not a production certificate.

Fresh application qualification now preserves its six measurement sources,
checks package/executable identity in both host and guest, refuses silent reuse
with another package or overwrite of existing results, and checks source drift
around browser execution. Low-space and tampered-package preflights were tested
to fail before filesystem/service changes. These are harness changes; the
qualified production executable remains unchanged.

The sequence record `artifacts/m4-current-transports-identity-20261105.json`
identifies both successful runs and verifies final VM poweroff. All fixtures,
private credentials and evidence remain retained under their existing access
controls; no pilot clock has started.

Historical M2/M3 closure and prior-binary studies remain valid within their
recorded scope. Do not combine different executable identities into one claimed
current-build qualification. [Roadmap](../ROADMAP.md), [business scope](M4-BUSINESS-RESULTS.md),
[recovery scope](M4-RECOVERY-REHEARSAL.md)
