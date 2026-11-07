# M2 operational qualification

M2 is complete for the agreed single-node Linux amd64 reference scope as of 3 November 2026. Ubuntu 24.04 supplies sizing and interruption evidence. Ubuntu 22.04 supplies functional compatibility evidence. ARM64 remains experimental. This milestone establishes the operating baseline. Representative pilots, independent security review and release qualification remain M4/M5 requirements.

## Agreed platform scope

M2 targets a single-node Linux amd64 appliance. Ubuntu 24.04 is the reference sizing platform, with Ubuntu 22.04 included in service and recovery compatibility checks. The reference VM has one vCPU and 2 GiB RAM. ARM64 is an experimental build target tracked separately in [ARM64 qualification](ARM64-QUALIFICATION.md).

The amd64 acceptance work covered gateway-PID-only sizing under externally driven traffic, abrupt VM interruption with externally retained acknowledgement evidence, and actual r5 to r6 upgrade and rollback cutover. The sizing target is a two-hour 25-request/second TLS profile, two applications, zero incorrect responses or network errors, p95 below one second, gateway peak RSS below 512 MiB, and healthy final storage/export. CPU consumption is recorded separately for the gateway process. The fixture uses packaged resource defaults of 64 active requests, 256 connections and a 256-MiB admission buffer, with 1-MiB policy body limits and a ten-second request deadline. Source event commits retain their five-second deadline.

Hard-reset qualification requires three hypervisor poweroffs with a dirty SQLite journal and an in-flight unacknowledged request. Previously acknowledged events, policy revision, account state and administration records must survive and reconcile with reference receiver receipts after restart. Recovery is measured with a 180-second bound. These checks qualify guest interruption on the reference VM storage stack. Physical host/controller power loss requires separate platform evidence.

Upgrade qualification uses the actual packaged r5 and r6 executable hashes, a verified stopped-service checkpoint, private-copy candidate rehearsal, live r6 activation and live r5 rollback. Checkpoint events, audit prefix and account login must survive cutover. Post-checkpoint state is preserved separately before the explicit recovery-point switch.

## Native Ubuntu 24.04 reference result

The full operational profile passed on 3 November 2026. Evidence is `artifacts/m2-operational-a02485b6/result.json`, with platform/hardware records, command diagnostics, host acknowledgement snapshots and the exact executed host/guest source files alongside it. The guest used one vCPU and 2 GiB RAM, Ubuntu 24.04.5, kernel 6.8.0-147-generic and systemd 255 under VirtualBox 7.2.22. The external Windows client used certificate-verified TLS through loopback SSH forwards. Gateway-only process measurements exclude the separate backend and receiver processes. Host CPU/storage and guest CPU remain shared.

| Two-hour steady measurement | Observed |
|---|---|
| Requests / elapsed time | 180,000 / 7,200.419 seconds |
| Achieved rate | 24.9985 requests/second |
| Expected responses | 126,000 accepted, 54,000 blocked |
| Incorrect responses / network errors / sampling errors | 0 / 0 / 0 |
| End-to-end latency p50 / p95 / p99 | 52.88 / 146.58 / 383.74 ms |
| Gateway peak RSS | 97,116,160 bytes, approximately 92.62 MiB |
| Gateway CPU | 3,059.44 CPU seconds, 42.49% of one vCPU on average |
| Process continuity / final storage and export | Same PID/start identity, healthy |

The 120-second 50-request/second probe passed at 49.75 requests/second with zero incorrect/network responses and 196.11-ms p95. The exploratory 100-request/second probe achieved 61.87 requests/second and failed its throughput target. Qualification covers the documented 25-request/second reference workload. Payload sizes, inspection settings, attack mix, backend behavior, SSH transport and storage affect these results.

Three abrupt hypervisor poweroffs each observed a dirty SQLite rollback journal and an in-flight unacknowledged request. Recovery took 41.73, 42.55 and 42.00 seconds. After each restart, all 100 sampled acknowledged event payload hashes, the complete acknowledged administration prefix, account-file hash and acknowledged policy revision matched local and independent receiver state. Audit prefixes grew from 16 to 27 to 38 records. SQLite integrity checks passed. Physical host/controller power failure and future format migrations require separate qualification.

The actual live r5 â†’ r6 â†’ restored-r5 sequence passed, including viewer logins at every stage, 100 checkpoint events, 49 checkpoint audit records and the original policy revision. Post-upgrade revision 6 was preserved separately before selecting checkpoint revision 5. The checkpoint manifest SHA-256 remained `620e669429cbf7c45408988fdc521217b1b79a8972e58bf2b2777752cb0da9bd` throughout rehearsal and rollback.

| Executed server | SHA-256 |
|---|---|
| r5 rollback binary | `80e798208cbf35546890f027a517531a6aa244b67e669a948add399d7b6e1b93` |
| r6 reference binary | `6dadfe66a2e09b2a8b6c2e0b2462247a09d7981f0af7f1e23b06c6001bfddfda` |

R5 retains its recorded earlier writer limitations. This establishes recovery compatibility for this exact local-build pair. The current operating reference is r6. Signed releases and a maintained public upgrade line remain M5 work. [Reproduction procedure](M2-OPERATIONAL-RUNBOOK.md)

Ubuntu 22.04.5 additionally passed the functional-only repeat in `artifacts/m2-operational-5c6f2a40/result.json`. It verified six acknowledged event payloads, 16 audit records and account/policy state after its abrupt guest interruption, then the same actual r5/r6 binary pair through rehearsal, live upgrade and rollback. All three viewer logins passed. Rollback preserved six checkpoint events, 27 audit records and policy revision 3. Its checkpoint manifest remained `76faca3e282a09c16602cf3435e0c20c7efa12668f3a951c20c2778f47b4aa7c`. This supplementary result makes no throughput claim.

### Retained operational failures

An initial eight-active-request/eight-MiB-buffer fixture returned three capacity rejections in its first ramp, and its client pacing shared a loop with SSH sampling. That failed result remains `artifacts/m2-operational-0f244c4f/result.json`. The qualified repeat uses the packaged 64-active-request/256-MiB-buffer defaults and independently paced traffic. Persistence deadlines were retained.

Ubuntu 22.04's cold ten-second smoke probe returned correct responses and healthy storage but achieved 20.12 requests/second, below the 25-request/second throughput gate. Its failure remains `artifacts/m2-operational-09edfefe/result.json`. Ubuntu 22.04 has no capacity qualification from this run. Its supplementary checks target functional service and recovery compatibility.

The first immediate-cut functional run also lost newly written test helper/configuration bytes before fixture setup had reached durable storage. `artifacts/m2-functional-bootstrap-diagnostic.log` records both helper files at zero bytes. The fixture now synchronizes setup files and service boot links before starting services or creating acknowledged workload state. It performs no global sync between workload acknowledgements and interruption. The failed runs and bootstrap diagnostics remain retained. The repeat preserved all six sampled acknowledged events, 16 administration records, account state and policy revision after an abrupt cut, recovering in 45.99 seconds.

## Storage startup evidence

Event-store schema creation now runs in one SQLite transaction. A partial schema setup rolls back before reopen. Version-2 reopen avoids rewriting the application schema version. Startup errors report the active stage and elapsed duration. Event and reference-collector startup use an independently configurable 30-second budget through `-storage-startup-timeout`, bounded from one second through two minutes. The ordinary five-second SQLite busy budget remains unchanged.

This reduces separate schema-commit operations and makes future startup stalls attributable to a stage. The precise cause of the earlier concurrent Linux schema timeout remains unconfirmed. SQLite's commit protocol and synchronization costs informed the transaction grouping. [SQLite atomic commit](https://www.sqlite.org/atomiccommit.html), [SQLite pragmas](https://www.sqlite.org/pragma.html)

The injected-stall test interrupts a deliberately expensive schema trigger, checks bounded timeout and transactional rollback, removes the fault, and verifies successful reopen. The contention test performs 128 create/reopen operations across eight workers during sustained traffic. Windows observed p50 14.92 ms, p95 24.24 ms and maximum 324.81 ms. Linux x86-64 WSL observed p50 9.19 ms, p95 16.27 ms and maximum 19.54 ms. Raw evidence is in `artifacts/m2-startup-windows.log` and `artifacts/m2-startup-linux.log`.

## Current execution evidence

- Independent audit-delivery tests cover outages, lost and incomplete acknowledgements, receiver reopen, byte-exact deduplication, full journal replay and backup/restore destination binding.
- Offline audit-export tests cover exclusive leasing, read-only source bytes and repeated replay through the actual administration CLI.
- Account crash tests kill subprocesses immediately before and after atomic publication, then reopen and verify the corresponding complete revision and password verifier.
- Two-application synthetic profiles exercise independent event and audit collectors, receiver outages, lost acknowledgements, gateway restarts and collector restarts. Thirty-minute Windows and x86-64 WSL results are recorded in `artifacts/m2-soak-*-30m.json` with logs beside them. Final reports must have an empty `invariant_failures` list and reconciled security occurrences and audit records.

The soak harness shares a process/machine between client, backend, gateway and receiver. Go heap samples cover the combined harness. The native operational profile above supplies separate gateway-process RSS/CPU evidence. Real deployment networks require pilot-specific measurement.

| Thirty-minute result | Windows amd64 | Ubuntu 24.04 x86-64 WSL |
|---|---|---|
| Requests | 88,908 | 88,432 |
| Security occurrences observed, committed and received | 30,834 each | 30,622 each |
| Audit records in source and independent receiver | 901 each | 900 each |
| Gateway / collector restarts | 10 / 6 | 10 / 6 |
| Injected lost acknowledgements | 596 | 613 |
| Event queue drops / failed writes / invariant failures | 0 / 0 / 0 | 0 / 0 / 0 |

These profiles intentionally include cancellations and capacity rejections. Counted overload summaries explain the difference between security occurrence totals and stored event-row counts. Both runs drained pending delivery before final reconciliation.

The full Windows Go suite passed with actual current server/admin binaries and the strict schema-1 recovery fixture. The fixture is a test-only reader, documented in `tools/recoverycheck/README.md`. It has a deliberately narrower capability contract than preserved server builds. An initial run supplied the wrong binary to that drill and failed its rejection assertion. The corrected run is retained as `artifacts/m2-full-windows.log`, with the setup failure separately preserved. Full Linux gateway and audit tests, account crash tests, `go vet`, browser workflows and all 5,193 CRS compatibility cases also passed. The CRS profile retains its 16 documented adaptations. [CRS accounting](REGRESSION-AND-OPERATING-LIMITS.md)

The staged Ubuntu 24.04 WSL systemd exercise passed package installation refusal on existing paths, restricted identity, TLS renewal, two-application rate controls, local roles/revocation, credential-file audit export, backup/candidate rehearsal and restored-service cutover. The independent receiver retained the restored journal's canonical records. Evidence is in `artifacts/m2-linux-service.log`. This exercise uses an isolated temporary unit and paths. Fresh installation into the normal service paths subsequently passed on both distributions, as recorded below.

## Scoped closure gates

| Gate | Required evidence |
|---|---|
| Fresh Linux installation, amd64 | Passed on disposable Ubuntu 22.04 and 24.04 VirtualBox guests with package m2-20261103-r4. Raw results and the credential compatibility correction are recorded below |
| Native ARM64 | Deferred beyond the scoped amd64 M2 milestone. Experimental promotion criteria are tracked separately |
| Extended sizing | Passed native Ubuntu 24.04 two-hour external-client profile with gateway-only RSS/CPU and explicit workload limits, recorded above |
| Power interruption | Passed three abrupt guest poweroffs with dirty in-flight SQLite transactions and acknowledged-state reconciliation. Physical host/controller failure and future format migrations remain separate |
| Recovery qualification | Passed actual r5/r6 binary rehearsal, live upgrade and live rollback with checkpoint state and login verification |

The manual `.github/workflows/m2-qualification.yml` prepares native VM installation and sustained jobs for Linux amd64, Linux arm64 and Windows. Sustained jobs default to two hours and accept one through 240 minutes. Hosted jobs still await execution. The fresh-VM script requires a disposable VM acknowledgement, refuses WSL and existing installation paths, and exercises the real service and restored-service cutover. Preparing the workflow does not count as executing these gates. Native public ARM64 runners use the `ubuntu-24.04-arm` label. [GitHub runner availability](https://github.blog/changelog/2025-08-07-arm64-hosted-runners-for-public-repositories-are-now-generally-available/)

## Fresh VM execution on 3 November

Both amd64 guests used checksum-verified official Ubuntu cloud images, one vCPU and 2 GiB RAM under VirtualBox 7.2.22 on this Hyper-V-enabled Windows host. The initial two-vCPU guest reported a CPU soft-lockup warning. The clean one-vCPU repeats passed. A separate failed repeat exposed VirtualBox's transient UUID registration for the shared read-only VMDK. The runner now clones a private per-run image copy and closes its registration, preserving the cached download for subsequent runs.

Ubuntu 22.04 first rejected `%d` in the packaged service's credential path. The service, audit-export override and qualification scripts now use `${CREDENTIALS_DIRECTORY}` expansion in `ExecStart`. Package r4 passed the corrected fresh-install and restored-service workflow on both distributions. The initial failure is retained in `artifacts/m2-vms/openwaf-m2-22.04-16f99633/qualification.log`.

| Distribution | Passing result |
|---|---|
| Ubuntu 22.04.5 amd64 | `artifacts/m2-vms/openwaf-m2-22.04-05ba601a/result.json` |
| Ubuntu 24.04 amd64 | `artifacts/m2-vms/openwaf-m2-24.04-1c30da61/result.json` |

Both results identify package SHA-256 `82a0b54bc23b7144c4b99285491e6ccfdd7c1e5c95afd44f9d15a50aa90de17b`, fresh-install script SHA-256 `d47236a1225caf7ce34c9113c1654722b77e446e766d0f6f73911d1a525fe116` and service-workflow script SHA-256 `fb8b1fc55e7b916f3092c63552a0a5f5245205bd36fd0f5a1ee896ef96ce998c`. Raw guest OS, systemd version, service and recovery output is in the adjacent `qualification.log`. VM disks and SSH credentials remain private in ignored artifacts. [Reproduction and cleanup](VIRTUALBOX-QUALIFICATION.md)

The fuller workflow passes TLS renewal, two-application/rate controls, local roles/revocation and credential-file audit export on both distributions. Restored-service tests now explicitly select `state/events.db` and assert preservation of checkpoint event IDs. Earlier cutover checks validated policy and backend responses while inadvertently opening a fresh default event database. Their passing output is superseded by these stronger checks.

Native Ubuntu also exposed assumptions in the staged test harness. `/run` is mounted `noexec`, and `PrivateTmp` hides a staging directory beneath `/var/tmp` from the service. Staging now uses an owned `/var/lib/openwaf-qualification-stage.*` directory. State-path substitutions run before injecting that directory into executable paths. The staged sysusers check writes only into its disposable root, avoiding the newer `--dry-run` option unsupported by systemd 249. All intermediate failures remain in their per-VM logs.

## Initial two-hour fault runs

Both profiles completed their requested two hours and reconciled every security occurrence and audit record, with zero dropped or failed writes. Both failed the stricter traffic/persistence qualification gate. Preserve these failures when comparing subsequent runs.

| Result | Windows | Linux x86-64 WSL |
|---|---|---|
| Requests | 178,056 | 176,342 |
| Observed / committed / received security occurrences | 62,863 each | 63,336 each |
| Local / independently received audit records | 3,595 each | 3,599 each |
| Unexpected client network errors | 5 | 6 |
| Persistence acknowledgement timeouts | 7 | 6 |
| Gateway / collector restarts | 12 / 8 | 12 / 8 |

Raw reports are `artifacts/m2-soak-windows-2h.json` and `artifacts/m2-soak-linux-2h.json`, with logs beside them. The runs overlapped image hashing, disk cloning and multiple VirtualBox boots on the same host. Host contention is a hypothesis requiring a controlled repeat. The original evidence does not establish a precise cause for each timeout. A persistence acknowledgement can time out after enqueue and still commit, so complete final reconciliation does not turn an uncertain acknowledgement into a passing qualification result.

The harness now retains at most 32 timestamped failure observations and samples per-process persistence/ingest timeout counters alongside its existing resource samples. The original five-second persistence and client budgets remain in place. Repeats must retain the original failure artifacts and identify their workload environment.

## Two-hour repeats with qualification VMs stopped

The same rate-25, two-application profile ran with 15-second collector outages every minute, gateway restarts every ten minutes, receiver restarts every fifteen minutes and injected lost acknowledgements. `artifacts/m2-controlled-environment.log` records the empty running-VM inventory, host memory and harness executable hashes before launch. Both operating-system harnesses still shared the workstation. This repeat does not establish an isolated appliance capacity rating.

| Result | Windows | Linux x86-64 WSL |
|---|---|---|
| Elapsed seconds | 7,202.27 | 7,201.70 |
| Requests | 178,759 | 177,278 |
| Observed / committed / received security occurrences | 61,229 each | 61,780 each |
| Local / independently received audit records | 3,599 each | 3,600 each |
| Unexpected client network errors | 0 | 12 |
| Persistence acknowledgement timeouts | 0 | 14 |
| Dropped records / failed writes | 0 / 0 | 0 / 0 |
| Gateway / receiver restarts | 12 / 8 | 12 / 8 |
| Qualification result | PASS | FAIL |

Reports are `artifacts/m2-soak-windows-2h-controlled.json` and `artifacts/m2-soak-linux-2h-controlled.json`. Windows passes this bounded endurance profile. Linux's observations include client header-wait deadlines and acknowledgement timeouts while up to twelve writes were pending. Maximum measured batch/retry duration was 3,659.814 ms. The subsequent writer regression below isolates a contention mechanism. Platform I/O latency for every historical observation remains unattributed. VM activity alone cannot explain the reproduced failure.

At this stage the Linux sustained gate remained open. The subsequent shared-writer correction and passing repeats below supersede this failed qualification result. Preserve the failed WSL profile as a regression target. Complete final reconciliation proves delivery of observed records in these runs, while uncertain acknowledgements remain a failed operating contract.

Process-kill recovery and SQLite FULL synchronization are supporting evidence. Physical power interruption and storage-controller behavior require their own qualification. The scoped guest-interruption matrix subsequently passed as recorded above. Physical storage-controller power failure remains unqualified.

## Shared writer correction

Ingestion previously formed its group before waiting on a writer mutex also used by the independent export-checkpoint transaction. Separate FULL-synchronous commits could consume the acknowledgement budget in sequence while later producers waited outside the already-formed ingestion group. A delayed-commit regression reproduces that mechanism with an 800 ms ingestion budget and 450 ms commit delays. The original implementation makes two commits and fails ingestion. The correction combines eligible ingestion and checkpoint operations in one transaction and passes in approximately 0.52 seconds.

Validated export receipts now enter the bounded writer queue. They carry identifiers and sequence numbers, with at most 32 receipts per request. The existing ten-millisecond grouping window, 128-item bound, five-second default ingestion deadline, two-second checkpoint acknowledgement deadline, FULL synchronization, database schema and wire protocol are retained. Receipt removal and both delivery/ingestion counters commit atomically. Retried checkpoints count only existing outbox receipts, preventing counter inflation after an uncertain local acknowledgement.

Evidence is retained in `artifacts/m2-checkpoint-baseline.log`, `artifacts/m2-checkpoint-fixed.log` and `artifacts/m2-checkpoint-fixed-linux.log`. Regression coverage also checks combined-transaction rollback, retained pending receipts, replayed checkpoint accounting and the existing collector-committed/local-checkpoint-failed retry path. That existing fault test now waits for the actual writer rollback before releasing its database lock, distinguishing a failed transaction from a queued checkpoint whose caller timed out.

Two-hour Windows and Linux WSL repeats with the corrected writer passed under the same rate-25 fault profile, with both qualification VMs stopped during endurance. The five-second ingestion/client budgets and fault/restart schedules match the failed repeats. Reports use the `artifacts/m2-soak-*-2h-writer.json` suffix, and executable hashes are in `artifacts/m2-writer-environment.log`.

| Corrected writer result | Windows | Linux x86-64 WSL |
|---|---|---|
| Elapsed seconds | 7,203.29 | 7,202.22 |
| Requests | 178,854 | 177,614 |
| Observed / committed / received security occurrences | 59,188 each | 59,966 each |
| Local / independently received audit records | 3,601 each | 3,601 each |
| Unexpected client errors / statuses | 0 / 0 | 0 / 0 |
| Persistence acknowledgement timeouts / failed writes / drops | 0 / 0 / 0 | 0 / 0 / 0 |
| Gateway / receiver restarts | 12 / 8 | 12 / 8 |
| Maximum measured writer/retry milliseconds | 1,997.387 | 2,526.655 |
| Final storage / export health | healthy / healthy | healthy / healthy |
| Final pending exports / invariant failures | 0 / 0 | 0 / 0 |

The WSL regression profile moves from fourteen acknowledgement timeouts and twelve client errors to zero of each. The focused delayed-commit fixture and these unchanged-deadline repeats support the shared-writer correction. They establish this bounded synthetic endurance profile. Native Linux isolated gateway RSS/CPU/latency sizing, native ARM64 and power-interruption qualification remain separate M2 gates.

The complete Windows Go suite passed with rebuilt server/admin executables and the schema-1 fixture. Linux storage and recovery suites, browser workflows and `go vet` passed. Evidence includes `artifacts/m2-writer-full-current.log`, `artifacts/m2-writer-eventstore-linux.log`, `artifacts/m2-writer-recovery-linux.log`, `artifacts/m2-writer-ui.log` and `artifacts/m2-writer-vet.log`.

The rebuilt amd64 package also passed fresh installation and the complete packaged service/recovery workflow on Ubuntu 22.04 and 24.04, using one-vCPU, 2-GiB disposable VirtualBox guests. Results are `artifacts/m2-vms/openwaf-m2-22.04-27a65cb3/result.json` and `artifacts/m2-vms/openwaf-m2-24.04-af0a1646/result.json`, with raw logs alongside them. Both identify candidate package SHA-256 `e36ca57a655662e9a22af98cea6f002d443a80d3f4a2d864882933030bf893bc`. The final release assembly compares its executable, unit, configuration and installer bytes with this qualified candidate. ARM64 remains build-only pending native execution. Qualification guests are stopped and their private artifacts are retained under the previously recorded cleanup-policy restriction.
