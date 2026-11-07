# Event delivery validation — 2 November 2026

The final repeated ten-minute runs passed on Windows amd64 and Linux amd64 under WSL, with a target of 200 requests/second per fixture. Client, WAF, backend and reference collector shared their respective process/machine. Both fixtures used eight inspection slots, an 8 MiB buffer-admission budget, a 64 MiB sender database, a 256 MiB collector database and just 300 retained local-history rows.

| Final evidence | Windows | Linux |
|---|---:|---:|
| Requests | 118,139 | 119,127 |
| Observed = locally committed = acknowledged = collected occurrences | 59,581 | 61,055 |
| Individual/summary records at collector | 30,842 | 30,929 |
| Gateway restarts | 10 | 10 |
| Collector restarts | 6 | 6 |
| Injected outage responses | 242 | 239 |
| Injected lost acknowledgements after receiver commit | 260 | 275 |
| Queue drops / failed writes / ingest timeouts / persistence errors | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 |
| Unexpected network errors / statuses | 0 / 0 | 0 / 0 |
| Final pending export records | 0 | 0 |
| Sampled maximum export backlog | 874 | 899 |
| Sampled peak process Go heap | 67.4 MiB | 67.8 MiB |
| Maximum local commit operation, including serialization-lock wait | 2,068.952 ms | 2,185.719 ms |
| Sender / collector main database size | 2.49 / 62.22 MiB | 2.53 / 62.45 MiB |

Occurrence totals exceed record totals because pre-inspection capacity rejections use explicit counted summaries. Inspected security events retain individual IDs. Receiver primary-key deduplication prevented lost acknowledgements/replays from inflating those totals. Ordinary local history eviction did not remove pending exports.

The occasional two-second commit waits are material operating evidence: acknowledged durability can add latency and reduce admitted throughput. The five-second default commit budget covered these runs; this does not prove an upper latency bound on another host. Sampled heap is not RSS and does not prove absence of all leaks. Ten minutes does not replace multi-hour/days-long, power-loss or representative-application qualification.

Machine-readable evidence:

- `artifacts/soak-windows-10m.json` and `artifacts/soak-linux-10m.json`: final passing runs, samples and complete counters.
- `artifacts/soak-windows-before-retries.json` and `artifacts/soak-linux-before-retries.json`: retained first runs. Occurrence totals reconciled, but the two-second append-acknowledgement checks failed; these are not counted as passes.
- `artifacts/qualification-flood-fixed.json`: unpaced mixed-load flood probe; no drops, failed writes, ingest timeouts or occurrence mismatches.

Go tests and vet pass. Windows and Linux test binaries cover local backpressure, retention independence, pause/restart, immutable IDs, receiver commit failures, failed local export checkpoints, redirect refusal and forced export-process termination/replay. Browser checks pass with delivery/accounting health visible. All 5,193 CRS cases still pass with the established 16 reviewed platform adaptations; the unchanged upstream differences remain documented separately.

See [event delivery](EVENT-DELIVERY.md) for the protocol, setup, migration, finite-outbox behavior and known crash windows. CI includes short Windows/Linux collector-outage/restart soaks; local race instrumentation remains dependent on an appropriate C toolchain and is configured separately in Linux CI.
