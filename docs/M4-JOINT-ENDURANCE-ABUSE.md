# Joint endurance and CPU-abuse measurement protocol

Status on 6 November 2026: controlled lab qualification completed; M4 remains open. This protocol supplements
[M4 joint business qualification](M4-JOINT-BUSINESS.md) on candidate
`1af405f4227a`; it does not authorize a customer pilot or imply production sizing.

## Longer endurance

Repeat the complete joint suite and extend its accepted large-file phase to
1,800 seconds: one 700-KiB ERP file every four seconds and one storefront
read per second. This offers 450 real ERP file writes and 1,800 storefront
reads in the extended phase. The existing read screen, heavy upload screen,
burst and held-body cases remain part of the run. Each file has a unique name;
no history, failed fixture or disk is deleted.

The accepted profile requires no unexpected HTTP/network responses, no
admission refusals during endurance, p95 scheduled storefront latency <=2 s,
ERP large-upload p95 <=10 s, <=1% storefront/client starts over 100 ms late,
observed CPU <=85%, available guest memory >=512 MiB, stable gateway/receiver
PIDs, no sampled OOM kills, no persistence loss and drained export queues.
Phase clocks use guest monotonic brackets. Each five-minute endurance window is also checked against the latency,
scheduling, CPU and available-memory budgets; a quiet remainder must not hide
a bad interval. Sender and receiver payloads and
aggregated verdict occurrences must reconcile independently from captured
SQLite databases. File hashes and refused-file absence are checked on disk.

## Completed longer endurance

`artifacts/m4-business-joint-1d4bc198/result.json`, `verification.json` and
`endurance-windows.json` pass on the unchanged `1af405f4227a` candidate. All
2,250 endurance requests succeed (450 ERP uploads plus 1,800 storefront reads),
with 3,091.600-ms ERP p95 and 878.614-ms storefront p95. Observed full-phase CPU
is 57.14%; all six five-minute windows pass, with storefront p95 between
688.145 and 967.840 ms and observed CPU between 52.24% and 68.74%. No request
starts over 100 ms late. Gateway peak RSS is 165.3 MiB in the early window;
later five-minute peaks range from 111.2 to 117.1 MiB. This window does not
establish freedom from longer-term memory leaks.

The entire suite reconciles 2,888 requests and 42 security occurrences in 26
identical sender/receiver records: two 403s, two 413s and 38 expected admission
refusals from the earlier stress/fairness cases. There are no unexpected HTTP
or network outcomes, PID changes or sampled OOM kills. All queues and temporary
spools drain. The independent file probe verifies 525 files / 375,749,784 bytes
and absence of all 31 refused uploads. Canonical settings are restored and the
owned VM is powered off before CPU qualification starts. These observations
extend the accepted lab profile; customer sizing remains open.

## CPU-abuse sequence

Use the same pinned real ERP/storefront cohorts in a separate sequential run.
Keep one vCPU/4 GiB, the original gateway limits and all CRS settings. The
storefront receives a fixed open-loop one-request/second schedule. Four
independent abuse workers each make at most one attempt/second; slow responses
reduce their achieved rate. This is explicitly a closed-loop abuse screen,
not a measured attacker throughput ceiling.

Each phase lasts 90 seconds, followed by full draining of synchronous inspection
and event export. The native resource window ends when scheduled traffic ends;
its extra drain interval is recorded separately. Do not abandon an inspection
worker while releasing its resource reservation.

| Phase | ERP probe | ERP admission / body / rate limits | Required storefront budget |
|---|---|---|---|
| Baseline | None | 8 slots / 1 MiB / no rate limit | Yes |
| ASCII screen | 900-KiB valid JSON | 8 / 1 MiB / none | Record result |
| Unicode fallback screen | Same raw size, one non-ASCII sentinel | 8 / 1 MiB / none | Record result |
| One-slot screen | Same Unicode body | 1 / 1 MiB / none | Record result |
| Bounded oversize | Same 900-KiB Unicode body | 1 / 64 KiB / 1 per second, burst 1 | Yes |
| Bounded smaller fallback | 32-KiB JSON with escaped Unicode sentinel | 1 / 64 KiB / 1 per second, burst 1 | Yes |

Required storefront acceptance is all responses successful and content-validated,
scheduled p95 <=2 s and <=1% starts over 100 ms late. Resource/PID/OOM and complete
request/event accounting remain mandatory. Attack-phase CPU is reported rather
than misrepresented as normal-load headroom. All probes must produce the
expected backend validation result or an explicit configured refusal; transport
failures, timeouts, cancellations or unexplained verdicts fail the run.

The API target is Dolibarr's customer-create endpoint with a `payload` field and
no mandatory `name`. The pinned source validates mandatory fields before
`create()`. A small preflight verifies its actual 400 response, and a read-only
hash/count of the customer table must remain unchanged across the experiment.
The Unicode body uses a final U+00E9 to force the conservative ASCII guard's
fallback. Its escaped variant proves JSON decoding still reaches that path.

The bounded profile is a deliberate deployment tradeoff: it rejects legitimate
uploads above 64 KiB and can limit other ERP users sharing the application.
It must not be described as preserving the 700-KiB business operating point or
as CPU isolation. It is applied only to the temporary owned fixture. Paired XSS,
body-size and rate checks must still work; the original policy and both product
canonical settings must be restored before shutdown.

## CPU results and retained failure

All screens use the unchanged candidate and full CRS. Run A is
`artifacts/m4-business-abuse-55d4a9d2`; it **fails** qualification. Its eight-slot
ASCII screen exceeds the two-second storefront budget. Its eight-slot Unicode
screen records eight 45-second client timeouts; the gateway later persists eight
502 events classified `timeout`, with durations 51,912.355–55,689.700 ms. The
configured 30-second HTTP context did not preempt synchronous inspection. The
gateway did not restart, no sampled container OOM kill occurred and all eight
events were exported durably. `failure-verification.json` verifies this failed
evidence; its `evidence_verified` flag does not turn the qualification into a
pass. This extends existing finding M4-ISO-003 to the real ERP/storefront cohort.
It does not establish the cause of the older, roughly three-second upload 502.

After the failed screen drained and the VM shut down, run B
(`artifacts/m4-business-abuse-8c5e3522`) used `--bounded-only --failed-screen ...`
to preserve that adverse result and qualify the remaining profiles. It repeated
its own baseline, then tested one-slot and explicit body/rate limits. Customer
hashes before A, before B and after B are identical. No engine/rule exclusion
was introduced and no production/default policy was changed.

| Run / phase | ERP outcomes | Storefront p95 | Observed CPU | Result |
|---|---|---:|---:|---|
| A baseline | No probes | 1,427.301 ms | 30.40% | Storefront budget passed |
| A ASCII, eight slots | 40 expected backend validation responses | 2,385.051 ms | 100.00% | Storefront budget failed |
| A Unicode, eight slots | Eight client timeouts / gateway timeout events | 1,484.700 ms | 100.00% | Integrity failed despite storefront p95 |
| B baseline | No probes | 1,944.225 ms | 30.90% | Storefront budget passed |
| B Unicode, one slot | Nine validated probes; 270 admission refusals | 884.125 ms | 99.92% | Storefront budget passed; no CPU headroom |
| B oversized Unicode, 64-KiB cap + rate | 80 body refusals, 279 rate refusals, one admission refusal | 490.049 ms | 36.89% | Required bounded screen passed |
| B 32-KiB escaped Unicode + rate | 82 validated probes, 181 rate refusals, 97 admission refusals | 548.417 ms | 50.74% | Required bounded screen passed |

All storefront schedules above offer one request/second for 90 seconds. Body
sizes and rules are those in the protocol table. Different cache/startup states
and VM runs mean these numbers are not an isolated causal WAF-overhead study.
The source, configuration and separate baseline are retained for each run.

The one-slot profile preserves the one-MiB request envelope and eliminates the
observed heavy-client timeouts in this 90-second screen, but remains CPU
saturated and refuses most ERP attempts. Its **admitted** large probes have
12,718.602-ms p95; a percentile dominated by fast 503s would hide that cost.
For the admitted smaller Unicode probes, p95 is 599.119 ms. These per-status
latencies are independently derived in `response-latencies.json`; the aggregate
heavy percentile must not be presented as admitted-probe performance.

Run B reconciles all 1,364 requests and 911 security occurrences into 442
identical sender/receiver records: 368 admission refusals, 81 body refusals,
461 rate refusals and one XSS block. Queues drain with zero persistence errors,
no dropped events and no network/client errors. The paired XSS/body/rate
controls pass. The original policy and both canonical configurations are
restored, temporary spool bytes and active reservations return to zero, and the
owned VM is powered off. The verifier independently checks the retained failed
reference, exact probe bodies, scheduled latencies, resource samples, policy
limits, hashes/state equality and full SQLite receipts. Ten false evidence
claims are rejected in `verifier-negative-tests.json`.

The tested direction is ERP inspection abuse against legitimate storefront
reads. ERP-user availability during abuse, reverse/simultaneous attacks, longer
hostile-load endurance and real customer inputs remain unqualified. The strict
profile rejects the earlier 700-KiB upload workflow and is not an accepted full
ERP business configuration. Both mitigation screens are short experiments;
neither establishes hard CPU isolation or SMB production readiness.

## Evidence and exit

The abuse driver preserves measurement sources, byte lengths/hashes of public
synthetic probes, raw request outcomes/scheduled latencies, complete native
samples, before/after counters, exact phase policies, application-state hashes
and captured sender/receiver databases. Credentials, log payloads and raw
application rows are not included in its public report. Its independent checker
recomputes schedules, probe identities, policy limits, resource windows,
latencies, verdict totals and exact durable payload equality.

The combined exact-build/source/evidence/shutdown check is retained as
`artifacts/m4-joint-endurance-abuse-verifier-20261106.py` and its passing JSON
result. Verification tools are copied into each fixture's `evidence-tools`
directory; the immutable measurement sources remain in `source`. Seven adverse
resource/probe tests pass, and qualification/verification reject Python `-O` so
assertion checks cannot be silently disabled in the new tools.

Longer hostile-load endurance, larger/real customer data, different transports,
authenticated commerce/export writes, CPU/process separation and the final
pilot host still need their own qualification. The unresolved historical upload
502 remains tracked until a causal explanation or an explicit accepted residual
limitation is established. A passing repeat alone is not proof of its cause.
