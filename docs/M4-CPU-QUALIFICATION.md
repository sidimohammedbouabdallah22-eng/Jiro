# Large-body CPU and application contention

Assessment: 4 November 2026. These measurements qualify a specific lab workload,
not customer capacity or hard isolation between applications. M4 remains open.

Evidence index: `artifacts/m4-cpu-qualification.json`. Current production sources
match the corrected qualified candidate; late changes are documentation/tests
(`m4-cpu-source-integrity.json`). Owned service/container shutdown and the VM's
final state are recorded in `m4-cpu-cleanup.json`. Retained private fixtures are
not publication material.

## Diagnosis and correction

The production compiler's full-CRS JSON benchmark separates inspection from HTTP,
upstreams and storage. CPU profiles attribute approximately 95% of the original
large-body CPU samples to Go's regex matcher. Rule debug traces show expensive
scans across multiple CRS rules; no rule was removed or disabled to improve speed.
Debug traces have substantial overhead and are not the source of timing claims.

The downstream patch `openwaf-ascii-presence-v1` computes necessary ASCII
character-presence conditions from each regex's syntax tree. For sufficiently
large ASCII values, an impossible condition can reject a non-match before the
original regex scan. Every possible match still uses the original matcher and
capture handling. Optional/unknown constructs impose no condition; analysis is
bounded and falls back on uncertainty. Non-ASCII input also falls back. The
upstream experimental `SecRxPreFilter` remains Off; this patch does not enable it.

The exact upstream source snapshot, original file hashes, retained notices and
patch rationale are in [the downstream record](../third_party/coraza/OPENWAF-PATCHES.md).
All four Go modules explicitly use that source. Status and candidate metadata
identify the downstream patch. The update tool refuses a different engine pin
until the patch is rebased and reviewed. This is a maintenance obligation and a
proposed ADR awaiting independent/maintainer review, not an upstream release.

## Isolated inspection measurements

Native Ubuntu 24.04 amd64, one vCPU, 4 GiB, AMD Ryzen 5 5600G exposed by VirtualBox;
Go 1.27.3, GOMAXPROCS=1. Three timed iterations per case, full configured CRS,
repetitive benign JSON, no concurrent application load:

| JSON body | Original matcher | Downstream guard | Ratio |
|---|---:|---:|---:|
| 64 KiB | 375.31 ms | 59.54 ms | 6.3x |
| 256 KiB | 1,494.55 ms | 240.91 ms | 6.2x |
| 900 KiB | 5,232.50 ms | 820.25 ms | 6.4x |

These are small, targeted benchmark samples. They do not establish a general
speedup for arbitrary JSON, Unicode, multipart uploads, response inspection or
every regex. The 900-KiB case still allocates about 24.8 MB cumulatively per
inspection; the patch targets CPU and does not establish a memory reduction.
Logs and CPU profiles: `artifacts/m4-native-before.*` and `m4-native-after.*`.
The baseline binary uses build tag `openwaf.no_ascii_guard` against otherwise
identical source. A separate complete application experiment compares the
previous qualified M3 package with the candidate package.

To reproduce the isolated benchmark on Linux, build the gateway test binary
with and without that tag, then run each sequentially on the same idle guest:

```sh
GOMAXPROCS=1 ./gateway.test -test.run='^$' \
  -test.bench=BenchmarkJSONInspection -test.benchtime=3x \
  -test.cpuprofile=inspection.cpu
```

## CPU-heavy application competition

`scripts/qualify-contention.py` uses the pinned real-product fixture and separate
native gateway/backend/collector measurement. Each phase schedules 120 WordPress
REST reads at two/second over 60 seconds, using a predeclared two-second p95
ceiling and zero wrong outcomes, network errors, generator refusals or scheduling
misses above 100 ms. Four additional closed-loop workers send 900-KiB JSON to a
separate application, at most one start per worker/second. This heavy generator
measures interference and completed/refused attempts; it is not an offered-rate
capacity claim for uploads.

The comparison includes no heavy traffic, four application admission slots with
ASCII JSON, four slots with a non-ASCII sentinel, and the same Unicode workload
after a real audited policy activation bounds that application to one slot.
The sentinel deliberately defeats the optimization. All ordinary reads must
remain correct; heavy refusals/timeouts remain visible rather than being counted
as successfully inspected uploads. Each phase waits for in-flight work and event
export to drain. CPU summaries include that drain interval.

| Phase | Original WordPress p95 | Patched WordPress p95 | Original heavy 200 / 503 / timeout | Patched heavy 200 / 503 / timeout |
|---|---:|---:|---:|---:|
| Uncontended | 93 ms | 73 ms | — | — |
| ASCII, four slots | 535 ms | 512 ms | 0 / 80 / 8 | 48 / 0 / 0 |
| Unicode, four slots | 660 ms | 572 ms | 0 / 84 / 8 | 2 / 78 / 8 |
| Unicode, one slot | 259 ms | 278 ms | 7 / 180 / 0 | 7 / 180 / 0 |

All 480 legitimate reads per package were correct, with zero legitimate network
errors or generator misses. Every successful heavy response passes byte-length
and SHA-256 verification, with zero invalid responses. Gateway CPU averaged
76–83% of one vCPU during the
heavy phases, including drain time. These are saturated shared-host observations,
not a supported upload operating point with spare capacity. Original report:
`artifacts/m4-capacity-058b4ff2/results.json`; corrected candidate report:
`artifacts/m4-capacity-2f69b774/results.json`.

The candidate removed the ASCII phase's heavy-client timeouts and made 48 uploads
complete, but the Unicode four-slot phase still has eight client timeouts. The
one-slot policy eliminated those observed timeouts by refusing excess work. It
bounds simultaneous work while Unicode still uses the original matcher. This is an explicit lab policy
activation, not an automatic change to users' configured admission limits.

Both runs preserve native resource samples, exact package/server hashes, policy
revisions and independently captured stopped databases. The offline verifier
checks measurement source hashes, complete legitimate schedules, demonstrated
CPU load, frontend totals and every sender/receiver event ID and payload. It
rejects incomplete or low-CPU experiments and false latency verdicts.
The original run accounts for all 849 frontend requests and reconciles 118
records / 360 occurrences; the candidate accounts for all 805 requests and
reconciles 89 records / 266 occurrences. Different
overload outcomes change the number of events. Both stopped-database comparisons
pass, with zero failed writes, ingestion timeouts or queue drops and no final
pending export. See each run's `verification.json` and `databases.tar`.

Backend state independently confirms the attribution correction: the original
probe accumulates eight failures in the ASCII phase and reaches an unavailable
circuit with 11 failures after the Unicode phase. The corrected probe retains
zero backend failures and observed-healthy status throughout the heavy phases,
including the Unicode timeouts. These are total-request budget failures, not a
reason to mark this responsive backend unavailable. Actual backend timeout/TLS
failure regressions still open its circuit.

```powershell
python scripts/qualify-contention.py --fixture artifacts/m4-lab-295530c3/fixture.private.json --package artifacts/rule-candidate-71b7c654bab5/openwaf-rule-candidate-linux-amd64.tar.gz --seconds 60
python scripts/capture-capacity-databases.py --base-fixture artifacts/m4-lab-295530c3/fixture.private.json --capacity-fixture artifacts/<run>/fixture.private.json
python scripts/check-contention-evidence.py artifacts/<run>/results.json
```

The archived `source/scripts` files identify the exact driver used for each run.
Private fixtures contain credentials and must not be published.
Earlier exploratory reports `m4-capacity-61d90d45` / `m4-capacity-8eaa044d` are
retained, including heavy-client timeouts. They did not retain a separate heavy
digest-failure count and are superseded by the stricter comparison above. The
interrupted first repeat coordinator remains an incomplete artifact, not a pass.

## Validation and remaining limits

The corrected pipeline `artifacts/rule-candidate-71b7c654bab5/result.json` passes
all 5,193 applicable CRS cases, with 16 reviewed platform adaptations and zero
skips/failures, connector comparison, root tests, vet and dependency checks. The
candidate separately passes the 22-case DVWA/WordPress/Keycloak lifecycle suite
in `artifacts/m4-lab-295530c3/results.json`. Its server SHA-256 is
`3f67d19f2d793a3afa8eca340f14e0bc7d998e4c3affa636dd41924ccc84fa81`.
Linux upstream engine tests pass in
default/no-memoize configurations, with operator/integration checks for multiphase
and no-multiline variants. Linux gateway race tests pass. Differential operator
tests, a bounded 30-second fuzz run and large-body tail-XSS/Unicode-prefix-SQLi
regressions also pass. The fuzz run is limited evidence, not proof of correctness.
Windows upstream tests retain absolute Unix-path/file-lock failures; Linux
results establish the scoped appliance qualification.

The optimized-engine reference also passes the full capacity protocol in
`artifacts/m4-capacity-d19dd6e5/results.json`: 1,500 requests over five minutes
(74-ms p95), then 3,000 over ten minutes (459-ms p95), at five/second. The separate
large-body phase has 833-ms p95. Backend faults, admission checks and the receiver
outage pass. All 5,342 frontend requests and 1,246 records / 1,289 occurrences
reconcile against captured databases, with no failed writes, ingestion timeouts,
queue drops or final pending export. The database bundle SHA-256 is
`96b7da85134faca93c2d5ada8225e389610c32f478d4afe2616a0f7906ed5178`.
Ordinary mixed-traffic improvement is not uniform; these observations do not
establish a general throughput increase or a higher supported rate.

That sustained run uses the first optimized candidate (`eaaed1b…`, server
`876b8fab…`). Subsequent investigation reproduces a separate connector defect:
an already-expired request budget can count as a backend failure before transport
starts, or when the total budget expires during transport. The narrow correction
checks context before calling transport and excludes total-context expiry from
backend health attribution. Genuine transport/header timeouts still count. Both
deadline regressions fail before the fix and pass afterward; client cancellation,
TLS failure and header-timeout checks also pass. Corrected
candidate qualification is recorded separately below; the completed sustained
run is not relabeled as a different binary.

The corrected candidate pipeline is
`artifacts/rule-candidate-71b7c654bab5/result.json` (all stages pass). Its package
SHA-256 is `7d598f7246786847bf46eab51039ce893b5e036aa4eb9a6b90b063a137f72623`.
The full Linux CRS run also passes all 5,193 cases with the same 16 reviewed
adaptations and zero skips/failures (`artifacts/m4-final-linux-crs.json`). Targeted
Linux race checks cover the pool fixes (`m4-final-pool-linux-race.log`).

The intermediate `rule-candidate-5bf3134f5497` remains failed: under parallel host
load, a shared-writer test exceeded its non-default 800-ms wall-clock budget while
still making exactly one durable commit. The test now uses the normal five-second
budget and continues to require both producers in the shared queue, exactly one
durable commit, correct counters and replay behavior. Ten repeats and the final
full pipeline pass. Production storage code and its default budget are unchanged.

Retaining experiments filled the original 12-GiB test disk to about 223 MiB free.
The owned dynamic VDI was expanded cold to 32 GiB; Ubuntu automatically grew the
existing filesystem, leaving about 20 GiB free. Completed capacity database files
remain byte-identical to the captured evidence. No evidence was removed.
`artifacts/m4-lab-storage-expansion.json` records the change. Subsequent capacity
setups require at least 2 GiB free before creating state and record actual initial
filesystem capacity/free space; Linux tests verify refusal before mutation. CPU
and RAM stay at one vCPU/4 GiB. Repeated competition uses the same expanded disk
for both packages; earlier measurements retain their original environment.

A non-ASCII byte or sufficiently varied ASCII content can force expensive regex
evaluation. Application concurrency controls bound admitted work, not CPU time.
The HTTP context deadline does not preempt a synchronous regex evaluation;
inspection may continue until its current work returns. Do not implement timeout
by abandoning an inspection goroutine while releasing its resource reservation.
For stricter shared-host abuse requirements, qualify smaller body limits and
per-application admission settings, or separate traffic processes/CPU allocations
and repeat the actual business workload. A 60-second competition experiment is
not endurance qualification of hostile traffic.

The customer deployment, workflow/body distribution, TLS/connection pattern,
latency/headroom budgets and independent review remain required before the
[pilot](PILOT.md). The 30-day business pilot has not started.

Subsequent [corrected-build endurance and transport qualification](M4-ENDURANCE-TRANSPORTS.md)
passes a 30-minute mixed schedule and verified private-CA HTTP/1.1/HTTP/2 modes.
It closes the corrected-binary sustained-reference gap above without relabeling
the earlier optimized-engine binary. Actual customer transport/body distribution
and deployment headroom still require qualification.

References: [Coraza directives](https://www.coraza.io/docs/seclang/directives/),
[upstream recommended configuration](https://github.com/corazawaf/coraza/blob/main/coraza.conf-recommended),
the pinned source and its tests. The measured local snapshot is the authority for
this candidate; a moving upstream main branch does not identify its behavior.
