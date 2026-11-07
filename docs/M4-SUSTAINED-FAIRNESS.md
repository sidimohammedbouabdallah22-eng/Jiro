# Sustained business abuse qualification

Candidate `7be7bc728f08` passes the scoped thirty-minute abuse schedule in
`artifacts/m4-business-abuse-ba78fad7`. Qualification covers ten minutes of ERP
abuse, ten minutes of storefront abuse and ten minutes against both applications.
All six five-minute windows pass independent checks. M4 remains open.

## Qualified workload and limits

One Ubuntu 24.04 amd64 VM has four vCPUs and 4 GiB RAM. It hosts the gateway,
reference event receiver, pinned Dolibarr 24.0.1 and PrestaShop 9.2.0 cohorts,
both databases and source-bound relays. The gateway service budget is 512 MiB.
The client uses HTTP/1.1 through SSH from Windows. Data-plane TLS and customer
host sizing have separate qualification gates.

| Control | Measured setting |
|---|---:|
| Process active requests / connections | 16 / 64 |
| Process buffer reservation budget | 64 MiB |
| Request context / body-read deadline | 30 s / 15 s |
| Request envelope per application | 1 MiB |
| Application concurrent requests | 4 |
| Client concurrent requests | 3 |
| Client sustained rate / burst | 2 requests/s / 4 |
| Client outstanding buffer budget | 5 MiB |
| Admission wait | 1,000 ms |
| Pending caps, process / application / client-application | 8 / 4 / 1 |

The original full CRS/PL1 policies, thresholds, exclusions and narrow ERP method
rules match their baseline snapshots. Response inspection is disabled in this
business profile. The byte budget admits a full one-MiB request while limiting
the measured hostile address to one concurrent large body per application.
[Buffer sizing](CLIENT-BUFFER-BUDGET.md) and
[admission waiting](ADMISSION-WAIT.md) describe the configuration and lifecycle.

Each targeted application gets four closed-loop workers, each attempting at
most one request/second. They submit valid 900-KiB JSON with a Unicode sentinel
that exercises the expensive matcher fallback. ERP probes omit the required
customer name and return the known validation error when admitted. Storefront
probes POST to a preflight-verified product view.

Legitimate traffic schedules one storefront read per second and a real 700-KiB
ERP CSV upload/download every twenty seconds. The CSV includes varied UTF-8
names, punctuation, quoted commas and embedded line breaks. Downloads must
match the exact decoded bytes. Every operation uses one client attempt.
Qualification requires every legitimate result to be 200, storefront p95 at
most two seconds, complete upload/download p95 at most ten seconds and at most
one percent of legitimate starts over 100 ms late.

Actual Linux TCP peers are `.2` for the ERP client, `.3` for the storefront,
`.10` for the hostile address and `.11` for an identity control. Rotating forged
X-Forwarded-For values are submitted by the hostile client. Trusted proxy
networks are empty and forwarded identity use is zero. Paired ERP XSS controls
from both hostile lanes retain their real source identities and return 403.

## Thirty-minute result

| Phase | Storefront p95 ms | Upload/download p95 ms | Observed average CPU |
|---|---:|---:|---:|
| Sixty-second baseline | 287.198 | 3,012.469 | 9.39% |
| ERP abuse, 600 seconds | 745.682 | 4,022.326 | 35.79% |
| Storefront abuse, 600 seconds | 749.453 | 3,560.056 | 35.36% |
| Simultaneous abuse, 600 seconds | 1,269.074 | 4,362.055 | 58.49% |

All 1,860 storefront reads and 93 file workflows complete successfully. The
93 files total 66,662,400 bytes and verify on disk. Protected ERP customer and
storefront customer/address/order/cart state hashes match before and after.

Independent checks reconcile all 9,198 requests and 6,640 security occurrences
into 2,346 identical sender/receiver records. The outbox and write queues drain,
persistence-error counters are zero and process identities stay stable. Queue
outcomes reconcile 2,414 entered waits with 498 admissions and 1,916 expiries.
Pending admissions finish at zero. The peak sampled gateway RSS is 161,576 KiB
and minimum guest available memory is 2,861,976 KiB.

All six five-minute windows pass. Their largest storefront p95 is 1,419.090 ms
and largest file-workflow p95 is 4,457.251 ms. Thirteen fabricated claims are
rejected, covering identity, envelope, file bytes, timing, CPU, delivery,
protected state, source provenance, burst/buffer settings and sampler version.
Policies and canonical URLs are restored, owned cohorts stop and the VM ends
off. The evidence is in `result.json`, `verification.json`,
`fairness-windows.json` and `verifier-negative-tests.json` beside captured
requests, native samples, source snapshots and both SQLite databases.

The earlier eighty-second screen `m4-business-abuse-4f3d36c2` uses client
concurrency two and sampler version one. It verifies fifteen files and 1,283
requests, with 879 occurrences in 311 records. Its twelve negative-proof cases
pass. The sustained result above uses the separately recorded three-client
policy and sampler version two.

## Findings and corrections

| Retained experiment | Finding |
|---|---|
| `90d92af7`, zero wait on `1af405f4227a` | Ten-minute reverse phase has three refused storefront reads and one refused download. Later checks retain all 63 acknowledged files. |
| `83ac58bd`, one vCPU, varied CSV | Workflow p95 reaches 11.59-19.37 seconds, with one refused download. All fifteen uploads verify on disk. |
| `e2819e85`, two vCPUs | Twenty-nine legitimate refusals and one admitted probe with upstream EOF. Captured accounting reconciles 1,245 requests and 882 occurrences. |
| `0b33e067`, four vCPUs, one-client concurrency | Nine legitimate refusals despite acceptable aggregate p95. Fifteen files and all 910 occurrences verify. |
| `29de5db4` and `314112a5` | Ordinary first uploads fail on upstream connection closure. The traced case reuses a connection after 5.104580 idle seconds, writes 102,400 TCP payload bytes and receives closure without a response. |
| `b003efee`, preflight | Verified receiver ACKs and a late local checkpoint leave stale unhealthy export status. Both records are present at the receiver. |
| `be368389`, four slots/two clients | One legitimate 429 and simultaneous storefront p95 of 3,697.089 ms at 88.07% average CPU. Fifteen files and all 483 occurrences verify. |
| `f8c60585`, longer two-client profile | One legitimate 503 under overlapping slow reads, plus three sampling gaps of at least four seconds. All 33 file workflows complete and all 1,626 occurrences reconcile. A later boundary-run probe verifies all 33 files on disk. |

The implementation adds bounded admission waiting, per-client outstanding buffer
reservations and explicit queue metrics/dashboard settings. Mixed-reason
capacity summaries receive an accurate aggregate reason. Event duration includes
admission waiting.

Both upstream transports evict idle connections after two seconds. The old
behavior fails a regression that models an ambiguous write on a closing pooled
socket. Earlier eviction completes exactly one backend POST through a fresh
connection. Mutation replay safeguards pass. Earlier EOF cases retain their
separate unresolved findings. [Idle-reuse evidence](M4-UPSTREAM-IDLE.md)

Export health recovers after a verified receiver ACK when a fresh database query
confirms an empty outbox and the writer publishes drained state. The actual ACK
time and failure history are retained. The regression delays checkpoint result
publication past its caller deadline and verifies recovery with one collector
request. [Export-health recovery](M4-EXPORT-HEALTH-RECOVERY.md)

## Measurement integrity

Version one queried systemd twice and re-hashed the 36,601,273-byte executable
on every sample. Version two resolves process IDs at monitor startup and reads
CPU/RSS directly from procfs. It hashes the executable at startup and whenever
PID/start time or device/inode/size/mtime/ctime changes. Every row records the
signature, verified hash and recomputation marker. The independent checker
requires stable process identities and valid attestation transitions.

The four-second sample-gap gate applies throughout measured phases. Native
monotonic timestamps align workload windows. Per-process/cgroup CPU percentages
use one-vCPU units, and their sum is divided by four for comparison with guest
busy percentages. The larger reading is reported. CPU readings are phase/window
averages. All four source-relay service cgroups include their children alongside
the four Docker cgroups.

## Remaining M4 gates

The four-vCPU boundary run `m4-business-abuse-559ae05d` verifies 804 requests
and two security occurrences in two identical sender/receiver records. Its
baseline and eighty-second 32-KiB Unicode multi-address screen pass, with
830.016-ms storefront p95 and 3,320.799-ms file-workflow p95 in that screen.
Seven new files verify on disk and the refused file is absent. The prior failed
endurance run's 33 files also verify, totaling 23,654,400 bytes, with matching
protected-state hashes. Ten fabricated boundary claims are rejected.

In the held-request case, two genuine peers occupy all four slots per
application using eight incomplete 32-KiB requests. The recorded reservation is
1,048,608 bytes. One legitimate read and one upload each receive 503 after their
admission wait expires. Completing the held requests returns active, reserved
and pending counts to zero. The per-client budget therefore has a measured
multi-address slot-exhaustion boundary.

The first boundary boot stalls in initramfs before lab setup. Console, serial
and hypervisor logs are retained. ACPI shutdown is unresponsive, and a cold
restart with the same allocation reaches login and completes the test. Its cause
remains unresolved. All owned services/cohorts finish stopped and the VM is off.
The original one-vCPU/4-GiB allocation is restored after qualification.

The accepted schedule has one hostile address per targeted application and
separate legitimate peers. Full browser asset bursts, shared NAT, authenticated
commerce writes under abuse, customer data sizes and the actual pilot host
require their own workload qualification. Hard CPU isolation remains open.

The final package still needs deployment-sensitive TLS, recovery/rollback and
alert repetitions, independent connector/management/downstream-patch review,
and the reviewed thirty-day pilot. M4 closure depends on those gates. The
[exact-build ledger](M4-CURRENT-CANDIDATE.md) identifies earlier package evidence.
