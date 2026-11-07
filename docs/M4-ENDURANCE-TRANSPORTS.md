# Corrected-build endurance and application transports

This M4 increment qualifies the corrected package from
`artifacts/rule-candidate-71b7c654bab5`, without changing production server code.
Its SHA-256 is `7d598f7246786847bf46eab51039ce893b5e036aa4eb9a6b90b063a137f72623`;
server SHA-256 is `3f67d19f2d793a3afa8eca340f14e0bc7d998e4c3affa636dd41924ccc84fa81`.
Earlier optimized-engine endurance predates the backend deadline-attribution fix
and retains its original binary identity. This exercise does not start a business
pilot or close M4.

## Predeclared protocol

The native reference remains Ubuntu 24.04 amd64, one vCPU/4 GiB, sharing resources
with pinned WordPress, DVWA, MariaDB and idle Keycloak. The owned dynamic disk is
32 GiB. The fixture remains isolated and exposes only loopback services through
owned SSH forwards. CRS PL1 enforcement and the same three-application admission,
body-buffer, request-timeout and bounded event-storage settings apply. Response
inspection is disabled.

The corrected-build capacity protocol repeats direct/inspected baselines, exact
large-body verdicts, backend failure/recovery, simultaneous admission and receiver
outage checks. It then schedules the combined mixed workload at five/second for
30 minutes, following a five-minute steady phase. The selected operating point
must meet a two-second scheduled p95 ceiling, at most 85% gateway CPU of one vCPU,
90% overall guest busy time and 1% scheduling misses over 100 ms, with no unexpected
application outcome, network error or generator refusal. These are lab engineering
budgets, not an operator-agreed customer SLO.

Both samplers now permit at most 6,000 observations at a nominal two-second
interval. Qualification requires coverage at both ends of every measured interval
and no gap over six seconds. The offline verifier independently checks the native
JSONL samples, gateway process identity and interval summaries. Correct responses
alone cannot pass an incomplete observation period.

`--endurance-seconds` supports 600, 1,800, 3,600 or 7,200 seconds. The requested
rate/duration must fit the 10,000-record retained-history reconciliation profile;
oversized plans are refused before setup. Longer available schedules are not
claimed as completed unless actually run. Smoke schedules never supply full-run
qualification.

The separate TLS experiment uses the same application workload with an external
Go client at five/second for 120 seconds in each mode:

1. TLS HTTP/1.1 with a fresh connection for each request.
2. TLS HTTP/1.1 with persistent connections.
3. TLS HTTP/2 with persistent connections.

The generator records the actual response protocol, TLS version, verified chain,
connection identity, reuse, latency and wrong outcomes. Redirects are not followed.
Connection counts must distinguish fresh and persistent modes. Application bodies
are checked by expected content or SHA-256, including authenticated edits, actual
multipart image upload/download and controlled JSON echo. No model or AI component
is used.

Additional checks require TLS 1.2 over the full 20-case mixed corpus; correct
64/256/900-KiB and oversized-body verdicts over HTTP/1.1 and HTTP/2; three concurrent
HTTP/2 streams on one warmed, verified TLS connection; TLS 1.3 session resumption
over ten fresh connections; HTTP authority/SNI mismatch refusal in both protocols;
and certificate rejection for an untrusted CA and incorrect hostname. The three
streams leave one application admission slot for completion overlap with warmup;
the separate admission test exercises refusal at the configured boundary.

Certificates are generated for the owned fixture, with 45-day validity so ordinary
health is outside the existing 30-day expiry-warning window. The CA is trusted
only by the test clients. No machine-wide trust-store installation occurs. Private
keys remain in the owned guest. This is a private-CA TLS termination test, not
qualification of the pilot's public CA, actual identity-provider TLS, management
TLS, upstream TLS or certificate issuance provider.

## Independent delivery evidence

Every experiment settles in-flight work and known security occurrences before
draining export. The transport runner explicitly waits for the final routing
rejection summaries, rather than sampling an unflushed one-second window.
Stopped sender/receiver database captures must contain identical event IDs and
payloads, matching acknowledged record/occurrence totals and zero loss counters.

The offline checker additionally compares captured event status counts against
the independent workload: blocked SQLi/XSS, body-size rejection and the transport
authority/SNI refusals must be present. Two empty but matching databases cannot
qualify protection evidence. Aggregated refusals retain their counted occurrences.

Measurement sources are archived with each report. The TLS experiment also pins
the actual generator binary and Go source hashes. Generator CPU is measured
separately from native gateway, application and receiver CPU/RSS. Credentials,
cookies and raw request bodies are confined to restricted private fixture inputs;
the report contains outcomes and bounded metadata.

## Results

Corrected-build endurance passes in `artifacts/m4-capacity-1336c458/results.json`.
The combined phase completes 9,000 requests over its 30-minute schedule at
five/second: p95 189.74 ms, p99 572.72 ms, zero unexpected outcomes/network errors
or generator refusals. Gateway CPU averages 5.4% of one vCPU; observed phase peak
RSS is 96.75 MiB (process lifetime high-water 110.45 MiB). Overall guest busy time
averages 13.3%. Sustained latency, CPU and generator budgets pass.

The full corrected-build run accounts for all 11,342 frontend requests and
independently reconciles 2,746 records / 2,789 occurrences, including 2,735 blocked
SQLi/XSS requests, eight body-limit refusals, two expected backend errors and 44
admission refusals. Captured databases match by event ID/payload, exact known
status occurrences and receiver totals. No write failures, ingestion timeouts,
queue drops or final pending export occur; gateway PID remains stable. Native and
management monitoring coverage both pass independent interval checks. Bundle
SHA-256: `d358eb0724b0418afee44fe158f4dcc337c6c268949cec63f020f96e078d200d`.

TLS transport qualification passes in `artifacts/m4-capacity-8c2c5dae/results.json`.
Each main mode completes 600 mixed requests at five/second:

| Verified TLS mode | Connections | Reuse observations | Scheduled p95 | Gateway CPU, one-vCPU basis |
|---|---:|---:|---:|---:|
| HTTP/1.1, fresh | 600 | 0 | 266.2 ms | 5.02% |
| HTTP/1.1, persistent | 4 | 596 | 188.1 ms | 4.02% |
| HTTP/2, persistent | 3 | 597 | 129.2 ms | 4.27% |

These are sequential two-minute observations in the shared lab, not a universal
protocol speed comparison. All modes meet the declared budgets with zero wrong
outcomes, network errors or generator refusals. Observed gateway peak RSS during
the three modes remains below 95 MiB; native gateway PID is stable.

All nine additional checks pass. Raw client traces show three overlapping HTTP/2
requests on one verified connection. Nine of ten fresh TLS 1.3 connections resume
sessions. The TLS 1.2 mixed corpus, both large-body sets, both authority/SNI refusals
and the two specific certificate verification failures pass.

The complete transport run accounts for 1,846 frontend requests, including setup,
and independently reconciles 458 records / 459 occurrences. Captured status counts
exactly match 455 SQLi/XSS blocks, two body-size refusals and two authority/SNI
refusals. The latter share one counted summary. There are no failed writes,
ingestion timeouts, queue drops or final pending export. Native and management
monitoring coverage and all event ID/payload comparisons pass. Bundle SHA-256:
`5e48ef14ce70394ac9eb9c1b059a2273dfad93d5a45248687449fd61b9129a43`.

The initial fixture
`artifacts/m4-capacity-c306658f` remains failed: Python's strict certificate
verification rejected a test CA missing its key-usage extension. The issuer
fixture now declares CA signing usage and explicit leaf identifiers. Verification
was not disabled. The corrected fixture has its own source snapshot and run
identity. `artifacts/m4-endurance-transports.json` indexes both successful reports;
cleanup and final power state are recorded separately. No production code change
was needed in this increment.

## Reproduction

```powershell
python scripts/qualify-capacity.py --fixture artifacts/m4-lab-295530c3/fixture.private.json --package artifacts/rule-candidate-71b7c654bab5/openwaf-rule-candidate-linux-amd64.tar.gz --max-rate 5 --endurance-seconds 1800
go build -trimpath -o artifacts/m4-transportcheck.exe ./tools/transportcheck
python scripts/qualify-transports.py --fixture artifacts/m4-lab-295530c3/fixture.private.json --package artifacts/rule-candidate-71b7c654bab5/openwaf-rule-candidate-linux-amd64.tar.gz --seconds 120
python scripts/capture-capacity-databases.py --base-fixture artifacts/m4-lab-295530c3/fixture.private.json --capacity-fixture artifacts/<run>/fixture.private.json
python scripts/check-capacity-evidence.py artifacts/<endurance-run>/results.json
python scripts/check-transport-evidence.py artifacts/<transport-run>/results.json
```

Run measured guest workloads sequentially. A capture requires both database
writers inactive and the owned guest running; return an originally stopped guest
to poweroff after captures and cleanup verification. Preserve failed runs and
their source snapshots. Do not publish private artifacts.

The actual business workload, deployment resources, supported connection/body
distribution and headroom need operator agreement and further endurance. The
30-day reviewed pilot and independent security review remain separate gates.
