# M4 native application capacity evidence

Status on 4 November 2026: **the scoped reference run passed**, including independent verification of captured databases. Customer deployment capacity remains open until an application owner supplies workload, latency/error budgets and required headroom. The supported observation here is five ordinary mixed requests/second on this exact colocated one-vCPU profile; it is not maximum WAF throughput or a company-size certification.

## Completed reference result

The full run is `artifacts/m4-capacity-cc8d554f/results.json`, with orchestration in `artifacts/m4-capacity-full-r3.log`. It spans 22.8 minutes including setup, baselines and faults. The host is an AMD Ryzen 5 5600G with six cores/twelve threads and approximately 23.8 GiB RAM, using VirtualBox 7.2.22. The Ubuntu 24.04 guest exposes one CPU, about 3.82 GiB usable memory and kernel `6.8.0-147-generic`. The report records exact environment and source hashes.

| Phase | Offered rate | Completed requests | Scheduled p95 latency | Gateway CPU, one-vCPU basis |
|---|---:|---:|---:|---:|
| Direct benign baseline | 5/s | 300 | 249 ms | 0.6% idle gateway |
| Inspected benign baseline | 5/s | 300 | 591 ms | 18.7% |
| Direct large JSON baseline | 2/s | 120 | 35 ms | 0.7% idle gateway |
| Large-body schedule | 0.25/s | 30 | 6,890 ms | 49.8% |
| Mixed rate screen | 5/s | 300 | 444 ms | 18.1% |
| Five-minute mixed schedule | 5/s | 1,500 | 566 ms | 21.0% |
| Receiver outage, 30 seconds | 5/s | 150 | 474 ms | 19.6% |
| Ten-minute combined schedule | 5/s | 3,000 | 464 ms | 16.1% |

Every phase completed its full request budget with zero unexpected outcomes, network errors or generator queue refusals. The ten-minute schedule had 56-ms p50, 663-ms p99 and 948-ms maximum scheduled latency. Highest observed gateway RSS/high-water reading across the run was 106,292 KiB, approximately 104 MiB. Native and management monitoring covered the run with 658 management samples and no unavailable samples. These are workload-specific observations, not statistical guarantees of future latency or false-positive rates.

The 52-request simultaneous test produced four successful probe responses, 44 intentional probe admission refusals and four successful WordPress reads. Header timeout, backend unavailability and recovery checks passed. Individual valid 64/256/900-KiB bodies arrived with matching length/digest; the over-limit body returned 413. This does not qualify near-limit bodies at five requests/second: their separate schedule is explicitly 0.25/s.

During receiver outage the pending outbox grew from zero to 35 records, export health degraded and eight transport failures were recorded. Local ingestion kept succeeding. After restart all pending records drained and health recovered. Final accounting is:

- **5,342 gateway requests**, independently reconciled with generated traffic and setup/fault requests.
- **1,246 event records / 1,289 occurrences**, with every sender ID and payload matching the receiver.
- The occurrences comprise 1,235 attack blocks, eight over-limit body refusals, two intentional backend errors and 44 deliberate admission refusals. The 44 admission occurrences were preserved in one summary record.
- Zero persistence errors, failed writes, queue drops or ingestion timeouts; zero final export backlog. Local administration audit remained healthy.

`verification.json` includes the report, database-bundle and verifier hashes. `databases.tar` contains stopped sender/receiver databases; the verifier checked their SQLite integrity and independently compared IDs, payloads and totals. Six negative checks rejected smoke results, incomplete schedules, absent outage backlog, mismatched receiver evidence, historical ingestion loss and changed measurement sources. Three runner regression tests also passed. The production runtime remains the qualified M3 r7 binary.

## Measurement contract

`scripts/qualify-capacity.py` drives the owned Linux fixture from a separate Windows process. It uses the qualified M3 r7 server and reference event-collector binaries without changing production gateway code. `scripts/m4_capacity_guest.py` creates a fresh capacity state directory beneath the owned M4 lab root and starts dedicated gateway, controlled backend, receiver and measurement services. Existing application containers supply the pinned WordPress, DVWA, MariaDB and idle Keycloak products. Credentials remain in restricted artifacts and systemd credentials; the controlled backend receives no management/export credential file.

The reference guest has one vCPU and 4 GiB RAM under VirtualBox. Its kernel, exposed CPU model and actual memory, plus generator OS/CPU details, are recorded in each report. Application and controlled-backend CPU/memory are measured alongside the gateway; the gateway's `/proc` CPU and RSS are separate from the external generator. Container CPU/memory comes from cgroup v2. Samples are taken every two seconds, with process high-water RSS retained. Process restarts are distinguished rather than subtracting CPU counters from different PIDs.

The application transport is loopback HTTP carried over SSH. This measures a specific colocated lab topology, including its forwarding costs. It does not size a customer TLS endpoint, distributed collector, different vCPU allocation or response-inspection policy. WordPress retains the functional fixture's configured home URL; this runner targets its API and media paths explicitly rather than qualifying browser navigation under a new public origin.

Policies use CRS PL1 enforcement and a 1-MiB request limit, without response inspection. There are three isolated applications. Global admission is 32 active requests, 128 connections and 64 MiB of body-buffer reservations. DVWA/WordPress each allow eight active/client requests; the controlled probe allows four. The gateway has a 15-second total request deadline and five-second body-read deadline; the probe's upstream header deadline is one second. The external client's deadline is 20 seconds. Gateway, backend and receiver service memory caps are 512, 128 and 256 MiB respectively. Security-event and receiver databases each have a 256-MiB main-file budget. Local event retention and export outbox bounds are each 10,000 records.

The deterministic 20-request ordinary workload contains:

- 50% WordPress: reads, multilingual search, authenticated post edits, real multipart PNG uploads and byte-verified downloads.
- 20% authenticated benign DVWA lookups.
- 5% valid 64-KiB JSON to the controlled echo backend, checked by byte length and SHA-256.
- 25% SQL injection/reflected XSS against isolated DVWA. Direct vulnerability baselines are verified first; protected requests must return 403.

Direct and inspected benign baselines use the same benign-only cycle. Large-body phases are separate: valid 64-KiB, 256-KiB and 900-KiB JSON bodies plus a 1-MiB-plus-one-byte body that must return 413. The controlled backend verifies exact bytes and digest; these are JSON-body measurements, not qualification of every upload format or business endpoint.

## Load and fault accounting

Offered-load scheduling uses fixed due times, 16 workers, a 32-entry queue and a 100,000-scheduled-request budget across all phases. Latency from scheduled time includes client queuing; service latency is recorded separately. Scheduler delays over 100 ms, generator queue refusals, network errors and wrong application outcomes remain visible. A saturated generator cannot silently reduce the advertised rate.

The staircase screens 5, 10 and 25 requests/second. Lab screening ceilings are two-second ordinary p95, 85% gateway CPU of one vCPU, 90% overall guest CPU and at most 1% scheduling lateness. These engineering ceilings select a candidate for a five-minute steady schedule and ten-minute combined schedule. They are not customer SLOs. Higher-rate admission refusals may establish a boundary only when overload counters increase and there are no other unexpected verdicts, network/generator errors or persistence failures. Such a phase retains its failed functional verdict and is excluded from the supported candidate point.

The fairness burst starts 48 slow probe requests alongside four WordPress reads. Probe 503 admission refusals are intentional; WordPress must remain usable. Separate backend checks verify a normal delay, bounded header timeout, unavailable backend refusal and recovery.

A separate reference receiver is stopped for 30 seconds while mixed traffic continues. The report retains backlog growth, exporter failures and health degradation, then waits for recovery/drain. It compares every retained sender event ID and payload to the receiver, reconciles record/occurrence counters and checks sticky persistence failures. Aggregated overload occurrences remain counted individually in totals. This is an outage within a finite spool budget, not unlimited outage durability. Local administration audit health is checked; independent audit-export fault qualification remains the existing M3 evidence.

## Retained adverse findings

- `artifacts/m4-capacity-07012d10/results.json`: the short two-request/second large-body phase exceeded this one-vCPU profile, with an admission refusal and a client timeout. The 25-request/second mixed screen also encountered admission refusals; its lower-rate short phases passed. Independent reconciliation still matched 179 records and 222 occurrences, including overload summaries. The run remains failed and does not count as capacity qualification.
- `artifacts/m4-capacity-ac852586/results.json`: the deliberately short five-second total request deadline was insufficient for a near-limit 900-KiB JSON body. The subsequent profile records the 15-second deadline explicitly and measures large bodies at 0.25 requests/second. It makes no claim that large bodies meet the ordinary mixed-request latency ceiling.
- Earlier development reports retain a missing temporary archive and native-sampler handling of restarted backend/receiver PIDs. The runner now uploads/verifies the archive and tracks process generations. These were tooling corrections.
- `artifacts/m4-capacity-353214ff/results.json`: the first full run completed baseline/body checks and 5/10-request screens but stopped reporting a short failed 25-request screen because fewer than two native samples existed. The corrected runner retains short-screen verdicts and marks CPU coverage insufficient. Its retained database/postmortem attributes two refusals to the WordPress admission share.
- `artifacts/m4-capacity-a609bf5b/results.json`: with complete short-screen reporting, 25 requests/second produced three admission refusals. A longer 10-request/second steady schedule encountered one refusal after 791 scheduled requests, and the combined schedule encountered another after 1,451. Both stopped rather than passing. All 874 receiver records and 919 occurrences reconciled; write/drop/ingestion-timeout counters remained zero. This run remains failed. A one-minute rate screen did not establish sustained capacity.

## Reproduction and review

Use the private fixture from the pinned, owned M4 application lab:

```powershell
python scripts/qualify-capacity.py --fixture artifacts/m4-lab-5b541cb4/fixture.private.json --max-rate 5
python scripts/capture-capacity-databases.py --base-fixture artifacts/m4-lab-5b541cb4/fixture.private.json --capacity-fixture artifacts/<capacity-run>/fixture.private.json
python scripts/check-capacity-evidence.py artifacts/<capacity-run>/results.json
python -m unittest discover -s scripts -p test_capacity.py -v
```

`--smoke` shortens schedules for runner verification and never supplies full capacity evidence. Normal cleanup stops owned capacity services and application containers, closes SSH forwards and returns an originally stopped VM to a shutdown request. Retain artifacts and verify the VM's final state. Reports and measurements are bounded; a failed run is retained rather than overwritten. Never publish the whole artifact directory: private fixture files contain secrets.

`--max-rate` bounds the screening staircase to 5, 10 or 25 requests/second. Lowering it after a retained failure produces a distinct experiment; it does not change admission limits or rewrite the failed result. Each request uses a fresh connection, so these figures do not describe the throughput of a persistent-connection or HTTP/2 workload.

Database capture requires the owned guest to be running with both capacity writers inactive. If the run returned an originally stopped VM to shutdown, start that owned guest and wait for SSH before capture; return it to shutdown afterward. The helper reads only the two bounded state databases into a restricted local `databases.tar` and refuses to overwrite a prior capture. The verifier checks both SQLite databases independently in memory, including database integrity, every event ID/payload, occurrence totals and bundle SHA-256. It never extracts arbitrary tar paths into the workspace.

The read-only verifier rejects smoke/incomplete schedules, source-hash changes, unexplained verdicts, missing outage evidence, monitoring gaps and mismatched event or frontend-request totals. Its success still leaves the deployment capacity gate open. Review the resulting workload/size-specific envelope with the operator before the [pilot](PILOT.md).

The subsequent [CPU profiling and competition study](M4-CPU-QUALIFICATION.md) identifies regex scanning, implements a conservative downstream optimization and measures both ASCII and deliberately expensive Unicode traffic. Its package, workload and results are separate from the original M3 capacity evidence above. The original simultaneous fairness check covers slow backend I/O. Neither study promises CPU-time isolation between applications. Validate actual upload formats, TLS and persistent-connection traffic against the selected business workflow.

The capacity runner now accepts an explicit checksummed `--package` and archives its measurement sources. The read-only verifier uses that source snapshot, so later tooling changes cannot silently invalidate or rewrite the older measured profile.

The later [real-business profiles](M4-BUSINESS-CAPACITY.md) separately qualify
Dolibarr API reads/writes/uploads and PrestaShop storefront reads, each at five
requests/second for ten minutes. Their 6,960 protected requests reconcile from
captured databases. They do not extend this earlier reference to arbitrary
commerce/ERP workloads or cohosting; actual deployment capacity remains open.
