# Independent administration audit delivery

The administration journal can deliver its canonical records to a separate reference collector using the existing complete-batch acknowledgement protocol. Use a dedicated receiver database, credential and operational owner for this stream. A separately administered host provides an independent copy of acknowledged records. A local hash chain alone permits a sufficiently privileged host administrator to rewrite the complete journal.

## Configure delivery

Start the receiver with a private token file containing at least 32 characters.

```sh
event-collector -listen 127.0.0.1:9101 -db /srv/openwaf-audit/receipts.db -token-file /etc/openwaf-audit/token
```

Set `OPENWAF_AUDIT_EXPORT_URL` to the receiver's `/v1/events` endpoint and `OPENWAF_AUDIT_EXPORT_TOKEN_FILE` to the sender's credential file. The equivalent server flags are `-audit-export-url` and `-audit-export-token-file`. The token environment variable is `OPENWAF_AUDIT_EXPORT_TOKEN`. Supplying both a file and a nonempty token environment variable is rejected. Use HTTPS with a trusted server certificate for remote receivers. Cleartext HTTP is restricted to loopback by the shared export validator. Redirects are refused.

Linux packages include `docs/audit-export.conf.example` with a `LoadCredential` unit override. Install the root-owned token at the path specified there, configure the URL in `openwaf.env`, then reload systemd and restart the service. Preserve deployment-specific arguments when applying the example's `ExecStart` override. Credential paths use `${CREDENTIALS_DIRECTORY}` expansion in `ExecStart`, which supports Ubuntu 22.04's systemd 249. The newer `%d` specifier caused fresh-install qualification to fail on that distribution. [systemd credentials](https://systemd.io/CREDENTIALS/), [systemd execution environment](https://freedesktop.org/software/systemd/man/latest/systemd.exec.html)

## Delivery and recovery contract

- The first configured live export appends a synchronized `audit.export.bound` record containing the SHA-256 of the exact destination URL. Subsequent starts reject a different URL. Starting a bound journal with the URL omitted pauses delivery and degrades health while records are pending.
- Every process start replays the entire bounded journal. The source ID is the first 128 bits of the first record's SHA-256. Record IDs, original sequence numbers and complete hash-chain fields remain unchanged. The receiver commits before acknowledging and deduplicates immutable records by source and ID.
- Each batch contains at most 32 records. A missing, partial or mismatched acknowledgement leaves the batch pending. Retry backoff is bounded. `acknowledged_records` measures this exporter lifetime and resets on restart. Receiver receipts survive source replay.
- Local appends remain synchronized independently of receiver availability. Export progress never deletes local audit records. The existing 32 MiB journal quota still applies. A full journal blocks audited management mutations until an operator performs stopped-service archival.
- `/api/v1/status` exposes `audit_export`. Health includes `administration_export_healthy`. The System screen and fixed `openwaf_audit_export_*` metrics expose delivery state without credentials.

Backups preserve the bound journal and require a candidate advertising audit-export capability 1. Upgrade rehearsal keeps export paused and verifies journal bytes, count and terminal hash. Keep the independent receiver's current durable receipts when restoring an older sender checkpoint. This backup tool does not capture or coordinate the independent audit receiver database. Preserve that receiver separately according to its operator's recovery policy. Run only one active copy of a restored journal. Preserve a failed source offline to avoid divergent histories sharing a source ID.

## Export a stopped archive

The recovery CLI can replay an existing archive, including a full journal, without changing its contents.

```sh
waf-admin audit-export -audit-file /archive/policy.json.audit.jsonl \
  -export-url https://audit.example/v1/events \
  -export-token-file /etc/openwaf/audit-export-token -timeout 10m
```

The command takes the journal's exclusive lease and opens the source read-only. A bound archive retains its destination restriction. An older unbound archive uses the explicitly supplied destination without adding a binding record. The source directory must permit the lease file. Repeated replay relies on the receiver's durable deduplication. Verify the independent copy before archiving the stopped active journal, record the old terminal hash in the operator's archival evidence, then start a fresh journal using the documented stopped-service procedure. A new journal has a new source ID.

Tests cover receiver outages, lost acknowledgements, incomplete acknowledgements, receiver restart, full source replay, source identity across checkpoint restore, destination binding and byte-preserving offline replay. See [M2 qualification](M2-QUALIFICATION.md) for execution evidence and remaining gates.
