# Flood accounting and reliable event delivery

OpenWAF now uses acknowledged local group commits and a transactional SQLite export outbox. This replaces the gateway's former discard-on-full event queue. The wire protocol and reference collector provide **at-least-once transport with durable receiver deduplication**, not an unrestricted exactly-once guarantee.

## What is recorded during floods

Inspected blocked/detected/error/cancelled transactions retain individual event IDs and rule evidence. The finalizer waits for its local event commit using bounded backpressure. The 256-entry memory queue does not silently discard gateway events when full. Up to 128 records share a 10 ms group-commit window. The normal inspection admission gate remains held until the transaction finishes logging, so a flood cannot create unlimited waiting inspection transactions.

Capacity rejections occur before inspection and have no rule evidence. They are summarized once a second by policy revision. Every rejection increments both immediate traffic counters and an explicit `occurrences` count; this is aggregation, not sampling. Summary records include `aggregated: true`, first `time`, `last_seen`, and the count. Common IP/path/method fields are retained; `*` means that field varied within the window. A fixed bound of 64 revision buckets prevents policy churn from creating unlimited cardinality. Revision 0 explicitly identifies the overflow bucket containing multiple revisions. Individual rejected requests cannot be reconstructed from these summaries.

Flush and graceful shutdown publish outstanding summaries. An abrupt crash can lose the current in-memory summary window and an event that has not yet reached a durable commit. This design does not claim a per-request crash-proof overload audit trail.

`-event-write-timeout` defaults to five seconds. Ordinary local BUSY/LOCKED/interrupted writes are retried within a bounded budget; permanent quota, read-only and other storage failures are reported. Commit results already available at a deadline take precedence over a timeout. A deadline after enqueue can be uncertain: the write may still finish later. `ingest_timeouts`, `write_failed`, and gateway `event_persistence_errors` make those conditions visible. Response completion for buffered responses may include this commit wait; event `duration_ms` measures transaction processing before the final storage wait. The buffer/concurrency controls and the WAF decision still operate during storage trouble, but durable logging cannot be guaranteed when storage stays unavailable.

The legacy internal nonblocking Enqueue helper remains for fault-injection tests; the production gateway uses acknowledged Append.

## Durable outbox

When export is enabled, local history and the export record commit in one transaction. A pending export has its own copy of the event and survives local history eviction, retention expiry, process restart and a lost network acknowledgement. Pending exports are never removed by history retention. The exporter removes a batch only after validating the collector's complete acknowledgement and committing the local acknowledgement checkpoint.

Validated acknowledgement checkpoints use the same bounded writer queue as ingestion. The existing ten-millisecond group window can combine receipt deletion, acknowledgement counters and new event/outbox records into one FULL-synchronous transaction. A transaction failure rolls back both operations. A repeated checkpoint only counts receipts actually removed, preserving counters when the first local acknowledgement was uncertain. Queue entries carry at most 32 receipt identifiers without copying their event payloads. The 128-item group limit covers ingestion and checkpoint requests together. The SQLite schema and collector protocol remain unchanged.

Default flags are `-event-db-mib 64`, `-event-export-rows 10000`, and no export URL. Enabling export allocates a logical quarter of the main database budget to local history and another quarter to the outbox, leaving room for indexes/pages and metadata. The main database retains its physical page cap; the rollback journal can require additional temporary disk space. Capacity is constrained by **both rows and bytes**. For an average accounted event size of 2 KiB, a 16 MiB outbox holds approximately 8,000 records; the outage allowance depends on actual event rate and aggregation, not HTTP request rate.

When that finite outbox fills, a new local+outbox transaction fails atomically and storage health degrades. It does not evict an unacknowledged event or falsely report export success. Later traffic can therefore lack durable events if an outage exceeds the configured capacity. Monitor backlog and ingest failures, restore collector delivery, and size disk/row budgets for the required outage window. No bounded local spool can retain unlimited events through an unlimited outage.

The destination binding and source ID are persisted. Removing the URL pauses delivery while continuing to spool new events; restoring the original URL resumes. Changing the destination is rejected while deliveries are pending. Tokens come from environment variables and are not written into policy history, the outbox, status responses or destination URLs. Export starts with newly committed events after enablement; it does not claim to have backfilled previously retained history.

Export retries use exponential backoff and jitter, a five-second HTTP timeout, and bounded batches of 32. Failed/malformed/partial acknowledgements, network errors, 4xx/5xx responses, or failed local checkpoints retain the outbox entries. Numeric Retry-After is honored up to 30 seconds. Redirects and ambient HTTP proxy use are disabled. HTTPS verifies the system trust chain; plain HTTP is allowed only to an explicit loopback IP.

## Run the reference receiver

Use separate terminals, a separate receiver database, and a shared random secret of at least 32 characters:

```powershell
# Receiver terminal; replace the placeholder with a generated secret.
$env:OPENWAF_COLLECTOR_TOKEN = '<random-collector-secret-at-least-32-characters>'
go run ./cmd/event-collector -listen 127.0.0.1:9095 -db data/collector.db
```

```powershell
# WAF terminal, after stopping the previous instance and backing up its state.
$env:OPENWAF_EVENT_EXPORT_TOKEN = '<the-same-collector-secret>'
# OPENWAF_ADMIN_TOKEN must also be set as usual.
go run ./cmd/waf-server -config config/policy.json `
  -event-export-url http://127.0.0.1:9095/v1/events
```

The existing Windows launcher also accepts `./scripts/start.ps1 -EventExportUrl http://127.0.0.1:9095/v1/events`, with optional `-EventExportRows` and `-EventWriteTimeout`. Set `OPENWAF_EVENT_EXPORT_TOKEN` in that terminal first; the launcher manages the administrator token as before.

Remote receiver binding requires `-tls-cert` and `-tls-key`; configure the sender with the matching HTTPS URL. The receiver's `-db-mib` defaults to 256 MiB (4–1024 MiB). It acknowledges after a SQLite synchronous FULL transaction commits, using `(source_id, event.id)` as the immutable deduplication key. Repeating an identical event does not inflate record or occurrence totals. Reusing an ID for different content returns 409. Full/corrupt/unwritable storage cannot produce a success acknowledgement.

The receiver deliberately does not auto-delete acknowledged data. At its quota it returns 503; archive/manage its database before that point. It is a small reference receiver, not a complete SIEM, searchable remote console, encrypted archive, multi-user service or HA storage system. Do not point the receiver and sender at the same database file. Use existing OS access controls and a network boundary.

## Collector protocol version 1

POST JSON to the configured endpoint with optional `Authorization: Bearer ...` and `Idempotency-Key: <batch_id>`:

```json
{
  "schema_version": 1,
  "source_id": "f6f4a25db0201674904d2ebd60811bf1",
  "batch_id": "<64 lowercase hex characters>",
  "events": [
    {
      "sequence": 42,
      "id": "event-identifier",
      "occurrences": 12,
      "event": {"id": "event-identifier", "occurrences": 12, "aggregated": true}
    }
  ]
}
```

The persisted source ID is 16 random bytes encoded as 32 hex characters. Batch identity is SHA-256 of its UTF-8 source ID followed, for each ordered event ID, by a zero byte and that ID's UTF-8 bytes. A retry may regroup events; deduplication must use source+event ID, not just the batch key. Each event is bounded to 16 KiB. The reference receiver accepts at most 32 events in a request capped at 1 MiB.

After durably committing **all** events, return 2xx JSON:

```json
{"batch_id":"<the-request-batch-id>","acked_ids":["event-identifier"]}
```

The sender requires exactly that batch ID and every ID exactly once. A bare 200/204, HTML success page, partial list or duplicate ID list does not acknowledge the batch. The response is capped at 8 KiB. External collectors must implement these durability and deduplication semantics; OpenWAF cannot verify a dishonest receiver's storage promises. Generic webhook endpoints require an adapter.

Application-level deduplication is what permits safe POST retries after ambiguous delivery; HTTP POST alone does not provide that property. See [RFC 9110 retry semantics](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2.2). SQLite transaction/journal behavior underpins the local atomic outbox, with storage/filesystem assumptions and distinct power-loss limitations: [atomic commit](https://www.sqlite.org/atomiccommit.html), [synchronous settings](https://www.sqlite.org/pragma.html#pragma_synchronous). Forced process termination tests do not establish power-loss guarantees.

## Upgrade and operate

The event database migrates from schema 1 to 2, adding persistent accounting, destination settings and the export outbox. Stop the old process and back up the event database before upgrading; keep a matching old binary for restoring that backup. Schema-1 binaries reject the newer database. Policy/history schema remains unchanged. Lifetime committed/export counters begin with schema 2; they do not reconstruct events already lost or evicted by the old runtime.

The System page reports storage, explicit occurrence accounting and collector delivery. `/api/v1/status` includes `committed_records`, `committed_occurrences`, `write_retries`, `max_commit_ms`, `ingest_timeouts`, and `export` with pending/enqueued/acknowledged record and occurrence counts, attempts, failures, last error and last success. Queued/pending writes, retry counters and health errors are process-local; committed/enqueued/acknowledged totals survive restart. Watch failures even after a process restart clears process-local health counters.

Back up stopped sender and receiver databases. An old receiver restore can forget deduplication IDs and previously acknowledged events; restoring only one side of an export pipeline is not a tested coordinated recovery procedure. Trusted-host compromise, storage-device loss, guaranteed remote delivery beyond spool capacity, payload inspection/redaction changes, and production HA remain separate work.

## Reproduce qualification

`go run ./cmd/waf-qualify -duration 3s` checks unpaced floods, counted overload accounting and hard budgets. `go run ./cmd/waf-soak -duration 10m -rate 200` runs mixed traffic with intentional cancellations, 15-second collector outages per 45-second cycle, lost acknowledgements after actual receiver commits, gateway restarts every minute and receiver restarts every 90 seconds. Reports reconcile observed occurrences, durable local totals, acknowledged deliveries and receiver totals; retention is only 300 local rows to exercise outbox independence. The command fails on missing/mismatched counts, unexpected statuses/network errors, persistence failures/timeouts or observed resource-budget violations.

Reports include sampled heap/goroutine/backlog data, database sizes and commit latency/retry evidence. All fixture components share a machine/process; heap is not RSS, and neither these tests nor their latency figures certify production capacity. Longer multi-hour/days-long and representative-application tests remain release gates. The first ten-minute reports are retained as `artifacts/soak-*-before-retries.json`; their counts reconciled but acknowledgement-deadline checks failed. Final repeated reports are `artifacts/soak-windows-10m.json` and `artifacts/soak-linux-10m.json`.
