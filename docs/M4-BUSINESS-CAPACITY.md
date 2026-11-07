# Business-workload capacity evidence

Update on 6 November 2026: the unchanged candidate passes a thirty-minute joint ERP/storefront phase, all 2,250 endurance requests and all six five-minute resource/latency windows. The full suite reconciles 2,888 requests and 42 security occurrences. CPU-abuse qualification retains a failed wide-Unicode run with eight timeouts; a separate one-slot/body/rate mitigation run reconciles 1,364 requests and 911 security occurrences. One slot still saturates CPU, while the stricter 64-KiB/one-request-per-second profile restricts legitimate uploads. Longer hostile load, reverse/simultaneous attacks and actual deployment qualification remain open. [Exact evidence and tradeoffs](M4-JOINT-ENDURANCE-ABUSE.md).

The 5 November boundary/replay candidate `1af405f4227a` adds exact-limit JSON/multipart coverage and a joint ERP/storefront profile. All 1,013 requests and 47 security occurrences reconcile. The same package repeats all 19 ERP and eight storefront functional cases. Bursts reach 32 clients; a five-minute profile with one 700-KiB ERP file every four seconds plus one storefront read/second passes. The heavier upload screen saturates the one-vCPU guest and is rejected as an operating profile. This is preliminary lab evidence, not customer sizing. [Joint workload and limits](M4-JOINT-BUSINESS.md), [exact-build ledger](M4-CURRENT-CANDIDATE.md). Longer endurance, broader authenticated writes and final-package operational requalification remain open.

These measurements extend the earlier WordPress/DVWA reference with the pinned
Dolibarr and PrestaShop business fixtures. They are controlled lab profiles,
not customer sizing, maximum throughput or the 30-day pilot.

## Profile and acceptance

One product cohort runs at a time on the owned Ubuntu 24.04 amd64 VM: one vCPU,
4 GiB RAM, PHP application, MariaDB, gateway, reference event receiver and
loopback relay. Other containers are refused by preflight. The client runs on
the external Windows host, with eight workers and at most 24 pending requests.
Each request opens a fresh HTTP/1.1 connection over the managed SSH forwarding
path. Application TLS, HTTP/2 and persistent connections are not measured here;
their separate transport evidence does not supply business-profile timings.

The functional report, package/server identity, image/version metadata and
measurement sources are pinned in each artifact. The unchanged server is
`cef0916699fa8adef803c46e74d2a73f995156b15a550f5304283a0d3216794f`, from candidate
`5777d82f469c`. Gateway limits remain 16 concurrent requests, 64 connections,
64 MiB buffer budget, 1-MiB request limit and the fixture's 30-second deadline.
The application and DB container memory limits are 1 GiB and 512 MiB; gateway
and reference receiver service limits are 512 MiB and 192 MiB.

Each cohort gets a 60-second direct-business baseline, 60-second protected
screens at 1, 2 and 5 requests/second, then a ten-minute protected run at the
highest accepted screen. A failed screen remains recorded. The supported point
must satisfy correct application/verdict assertions, every planned request
completed, p95 scheduled latency at most two seconds, at most 1% scheduling
delay above 100 ms, observed CPU budgets and at least 512 MiB guest memory
available. A rate limit is a tested ceiling, not a discovered saturation point.

Dolibarr's 20-request cycle contains ten customer reads, two real 16-KiB
customer-note updates, two exact 64-KiB document downloads, two overwriting
64-KiB document uploads, one customer-list read, two SQLi/XSS refusals and one
over-limit body refusal. The base64 upload request is larger than its decoded
file. Updates/files use bounded synthetic fixture state. These are real product
API operations, not an echo backend. Native CSV/multipart browser workflows
have separate functional coverage.

PrestaShop's cycle contains ten product reads, five search reads, two anonymous
cart reads, two SQLi/XSS refusals and one over-limit body refusal. This measures
storefront reads, not authenticated checkout/order-write throughput. The real
unpaid checkout remains separately verified in the functional suite.
ERP load uses the synthetic administrator API key; storefront load uses fresh
anonymous requests. Production role/session mixes and database/catalog scale
are not represented by these small synthetic fixtures.

## Completed Dolibarr profile

Evidence: `artifacts/m4-business-capacity-7578cf05/result.json`, `verification.json`
and `committed-business-state-1.json`; functional anchor:
`artifacts/m4-business-2be162b6/results-19.json`.

| Phase | Offered rate | Duration | Scheduled p95 | Accepted |
|---|---:|---:|---:|---|
| Direct business baseline | 1/s | 60 s | 499.821 ms | Yes |
| Protected mixed | 1/s | 60 s | 326.540 ms | Yes |
| Protected mixed | 2/s | 60 s | 109.359 ms | Yes |
| Protected mixed | 5/s | 60 s | 110.337 ms | Yes |
| Protected business endurance | 5/s | 600 s | 111.617 ms | Yes |

The ten-minute phase completes all 3,000 requests; p99 is 133.026 ms and no
request begins more than 100 ms late. One gateway PID is observed throughout.
Its sampled peak RSS is 86.3 MiB; gateway process CPU is 7.60% of one vCPU.
The higher observed CPU measure described below is 13.40%; minimum guest memory
available is about 3.1 GiB. These are virtualized observations, not a physical
host guarantee. Cold/warm cache and workload differences mean the direct and
protected figures must not be presented as an isolated WAF overhead comparison.

All 3,480 protected requests across screens and endurance reconcile with
frontend counters. The 348 rule blocks and 174 body-limit refusals match captured
event payloads and occurrence totals. All 645 retained sender records/occurrences,
including 123 preexisting records, match the receiver. Final pending writes/
exports, persistence errors, queue drops, failed writes and ingest timeouts are
zero. No sample gap over six seconds or gateway PID change is accepted.

After measurement, a separate read-only application DB/file probe confirms the
native imported customer exists exactly once, contact/customer linkage, a
validated one-line order totaling 250 with quantity two, exact native attachment
bytes, persisted capacity edits and the capacity attachment hash. The probe runs
outside the measured period. Its PHP source and report hashes are retained.

## CPU accounting limitation and verification

This VM's `/proc/stat` busy percentage is lower than the sum of the separately
observed gateway/relay/collector and application/DB cgroup CPU usage. The lab does
not establish why these virtualized counters disagree. Do not infer physical
spare CPU or add overlapping/unknown external workloads from one reading.

Acceptance now checks both readings and uses the higher observed value against
the 85% budget; gateway process CPU separately must stay at or below 80%. The
Dolibarr raw data also passes this stricter post-check: its endurance readings
are 9.77% guest busy and 13.40% component total. Original measurement sources
remain immutable; the newer runner records both values explicitly. Deployment
qualification still needs trustworthy host accounting and operator acceptance.
CPU budgets are phase averages. They do not bound instantaneous CPU or provide
CPU-time isolation between applications.

Native sampling and phase brackets use the guest's monotonic clock, rather than
assuming host/VM wall clocks agree. The independent checker recomputes coverage,
PID stability, CPU/memory observations, scheduled latency and all request/verdict
and stopped-database totals. Seven adverse accounting tests pass on Windows and
Linux, including clock skew, measurement gaps, restarts, scheduling delay and a
low guest-busy value masking high component CPU.

Recheck with `scripts/check-business-capacity-evidence.py <result.json> --package
<candidate.tar.gz>`. Captured archives and operational reports remain restricted;
the load logs omit request credentials, bodies and response payloads.

## Completed PrestaShop profile

Evidence: `artifacts/m4-business-capacity-0cbb4619/result.json` and
`verification.json`; functional anchor:
`artifacts/m4-business-77aadf7d/results-9.json`.

| Phase | Offered rate | Duration | Scheduled p95 | Accepted |
|---|---:|---:|---:|---|
| Direct business baseline | 1/s | 60 s | 197.064 ms | Yes |
| Protected mixed | 1/s | 60 s | 184.120 ms | Yes |
| Protected mixed | 2/s | 60 s | 222.308 ms | Yes |
| Protected mixed | 5/s | 60 s | 248.549 ms | Yes |
| Protected business endurance | 5/s | 600 s | 251.230 ms | Yes |

All 3,000 endurance requests complete; p99 is 327.548 ms, with no starts more
than 100 ms late. The conservative phase-average CPU reading is 53.01%
(guest busy 41.45%); gateway process CPU is 2.23% and sampled peak RSS is
82.9 MiB. PHP and MariaDB contribute most of the observed CPU. Minimum guest
memory available is about 3.0 GiB. One gateway PID and complete measurement
coverage are verified.

Across screens and endurance, all 3,480 protected requests reconcile. The
348 rule blocks and 174 body-limit refusals match the captured payloads and
occurrences. All 546 retained sender/receiver records match; 24 precede this
measurement. Final pending writes/exports, persistence errors, queue drops,
failed writes and ingest timeouts are zero.

A post-load storefront repetition,
`artifacts/m4-business-77aadf7d/results-10.json`, passes all eight cases and checks
both pages of retained history: 546 before and 551 after, including one explicitly
classified browser cancellation. It independently verifies unpaid order 10,
quantity two and product total 50. This does not rewrite the capacity run's
earlier functional anchor/order 9.

The workflow oracle now uses the real API cursor with a 10,000-event bound.
Duplicate IDs, invalid/nondecreasing cursors and excess history fail; history is
never silently truncated to the first 499 rows. Four adverse paging tests pass.
The complete post-load history still matches the captured receiver database.

Combined reproducible verification:
`artifacts/m4-business-expansion-verifier-20261105.py` and
`artifacts/m4-business-expansion-verification-20261105.json`. Both cohort profiles
account for **6,960 protected requests**, separately from direct baselines and
functional traffic. The VM ends powered off; all fixtures and failed evidence
remain retained.

## Remaining qualification

Both expanded functional sets and initial capacity profiles pass. Larger/native
upload formats, high concurrency/admission boundaries,
authenticated commerce writes, cold-cache behavior, longer business endurance,
joint ERP/storefront CPU contention and the actual pilot workload/topology need
their own profiles. The existing generic concurrency/CPU studies do not silently
qualify these products. Broader application roles, native CSV export, back-office
commerce workflows, customer TLS/identity, business-database recovery, actual
operator delivery, independent review and reviewed pilot days remain open.
