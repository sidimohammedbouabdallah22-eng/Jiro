# Joint ERP/storefront qualification

M4 remains open. These tests use one owned Ubuntu 24.04 amd64 VM with one vCPU
and 4 GiB RAM, one gateway, Dolibarr 24.0.1, PrestaShop 9.2.0, both MariaDB
containers and a reference security-event receiver. They do not size a customer
installation or start the 30-day pilot. Existing single-product capacity results
remain tied to their original executable.

## Workload and boundaries

The runner `scripts/qualify-joint-business.py` temporarily gives the two real
applications distinct canonical hostnames and restores their original settings.
It preserves the validated application Host through the gateway. Traffic uses
HTTP/1.1 through an SSH tunnel; this is not business TLS/HTTP/2 qualification.
The applications use small synthetic data sets, an ERP administrator API key
and anonymous storefront reads. Checkout capacity is outside this profile.

Gateway limits are 16 active requests, 64 connections, a 64-MiB buffer budget,
a 30-second deadline and eight admissions per application. Both applications
retain a 1-MiB request limit. The suite checks 64/256/700-KiB API files, native
900-KiB multipart uploads, request envelopes exactly at 1 MiB and one byte over,
and byte-identical downloads. Base64 files have larger request envelopes.

Four, eight, sixteen and thirty-two simultaneous clients mix ERP uploads with
storefront reads. Refusals must be bounded 503 responses and resources must be
reclaimed. A separate test holds eight incomplete ERP upload bodies while eight
storefront requests run. That proves admission fairness, not CPU-time isolation.

Timed workloads measure scheduled-to-completion latency, including client queue
and scheduling delay. The heavy screen offers one 700-KiB file per second with
two storefront reads per second; it is deliberately allowed to exceed the
operating budget, but unexpected transport failures still fail qualification.
The lower operating profile offers one such ERP file every four seconds and one
storefront read per second for five minutes. Supported profiles require every
request to succeed, storefront p95 at most two seconds, ERP p95 at most ten
seconds for large uploads (two seconds for reads), at most 1% starts delayed over
100 ms, observed CPU at most 85%, and at least 512 MiB available guest memory.
The higher of process/container CPU accounting and guest CPU-busy accounting is
used; their virtualized discrepancy remains unexplained. The component sum
contains the gateway, receiver and four application/database cgroups; the two
loopback relays are covered by guest busy accounting rather than separate
process counters.

The native monitor records process identity/CPU/RSS, Docker CPU/memory/OOM kills
and guest memory/CPU once per second. The suite verifies actual committed files
by size and SHA-256 and verifies refused files are absent. It checks temporary
Coraza spool cleanup, drained admission/buffer budgets and event delivery.
`scripts/check-joint-business-evidence.py` independently recomputes phase counts,
latencies/resources, database integrity, exact sender/receiver payload equality,
aggregated verdict occurrences and an empty export outbox. Failed runs and their
private fixtures are retained.

## Connector corrections

The first joint run (`m4-business-joint-9a2f7565`) exposed an inclusive-limit
mismatch: a request exactly at the configured limit was rejected by Coraza's
exclusive buffer check. The gateway still rejects the first excess byte; its
Coraza buffer sentinel is now one byte higher. Regression tests cover requests
in enforcing/detection/disabled modes, JSON/form/multipart and streaming/known
lengths, response limits, and malicious content at the final allowed bytes.
No CRS exclusion or vendor-source change was used.

A later run (`m4-business-joint-18b599ca`) retained an unexplained upstream 502
under CPU-heavy uploads, followed by admission refusals. It must not be recorded
as a passing capacity result. A deterministic transport test independently
found missing replay metadata for small buffered POSTs on a reused connection
that writes zero bytes. The connector now supplies that metadata while leaving
Go's conservative retry rules in control. Lost-response tests require the
backend POST to execute exactly once. Client idempotency headers are preserved
for the application but cannot enable transport replay of body-bearing mutations.
Large-body transport errors are not blindly retried and the original 502's
cause has not been proven by this small-body regression.

Security events now expose a bounded `upstream_error_class` category for proxy
failures. Raw errors, backend URLs, credentials and untrusted response text are
not persisted in that field. This improves diagnosis without logging payloads.

## Final-build results on 5 November 2026

Candidate `1af405f4227a`, Linux server
`488523c66b610e6945d1b66e5a1cd3c94e5ce08bd6d34249fdd7b24229ef166e`,
is recorded in `artifacts/m4-business-joint-dce48ae1/result.json` and its
independent `verification.json`. Both Windows and Linux full CRS regressions
pass 5,193/5,193 cases; full unit/integration, vet, connector comparison,
vulnerability scanning and focused Linux race checks pass.

| Phase | ERP / storefront offered rates | Duration | Requests | ERP / storefront scheduled p95 | Observed CPU | Operating budget |
|---|---|---:|---:|---:|---:|---|
| Steady reads | 1/s / 2/s | 120 s | 360 | 70.815 / 309.706 ms | 40.62% | Passed |
| 700-KiB CPU screen | 1/s / 2/s | 60 s | 180 | 17,214.024 / 2,635.706 ms | 98.57% | Failed: 26 admission refusals and insufficient headroom |
| 700-KiB endurance | 0.25/s / 1/s | 300 s | 375 | 1,867.832 / 758.974 ms | 42.45% | Passed: all 375 succeeded |

The complete suite accounts for 1,013 requests, with two 403 attack blocks,
two 413 body-limit refusals and 43 bounded 503 admission refusals. The latter
include bursts, the held-body fairness test and the heavy screen. There are no
502s, network failures, process restarts or sampled OOM kills. All 47 security
occurrences reconcile between the gateway and receiver, including aggregation
into 27 identical records; export/write queues drain with no persistence errors.
The final spool is empty and all admission/buffer reservations are reclaimed.
One hundred forty-five committed files (103,365,784 bytes) match on disk; all
36 refused upload files are absent. Both canonical configurations are restored,
owned cohorts stopped and the VM powered off after the joint run. Later
functional repetitions use the same owned VM separately.

The independent verifier also rejects nine deliberately altered evidence claims:
request count, latency, CPU, source hash, cleanup, export occurrences, file count,
status count and database archive hash. Its intentionally false reports are
named `rejected-proof-*` and are not qualification results. The prior
`m4-business-joint-9b294b2e` passed timed profiles but failed when the harness
saved the file-probe result; it remains a failed run. The final run fixes that
reporting error and repeats the measurements on the final guarded candidate.

The combined final-source/package/business/VM-state check is retained in
`artifacts/m4-joint-final-verifier-20261105.py` and its passing JSON result.

## Longer endurance and CPU-abuse extension

The same candidate now passes a 30-minute joint profile (all 2,250 endurance requests) with all six five-minute windows meeting budget. A separate wide-admission Unicode screen fails with eight timeouts; one-slot and explicit smaller-body/rate profiles are then measured with complete event reconciliation. The failed screen remains failed. [Full results, configurations and limits](M4-JOINT-ENDURANCE-ABUSE.md).

## Remaining scope

The original five-minute profile and its 30-minute extension are scoped lab
operating points. Longer hostile-load endurance, mixed authenticated roles, export/back-office/checkout write load,
customer-scale state, deliberate expensive Unicode/regex fallback traffic,
business TLS topology and real deployment headroom remain M4 gates. Admission
shares cannot guarantee CPU-time isolation. Independent connector/downstream
review, business-database disaster recovery, deployed alert ownership and the
actual reviewed 30-day pilot remain open.

The next qualification sequence is longer hostile-load endurance at explicitly
chosen body/admission limits, reverse/simultaneous contention and wider
authenticated export/checkout workflows. Repeat transport, identity,
backup/restore/rollback and deployed alerts on the final pilot executable before
starting the reviewed pilot clock.
