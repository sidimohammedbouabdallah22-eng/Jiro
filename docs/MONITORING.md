# Health and monitoring

The loopback management listener serves authenticated `GET /api/v1/health` and `GET /api/v1/metrics`. Use an automation token limited to `monitoring:read` for unattended monitoring. Authorized browser sessions and the bootstrap credential also support these endpoints. Each request shares the management listener's 16-request admission limit. The application listener routes these paths to the protected application under its normal inspection policy.

## Health semantics

The health JSON contains `ready`, `healthy`, `state`, `mode`, `revision` and named boolean `checks`.

Schema-2 deployments report mode `mixed` when application modes differ. The inspection check requires all applications to have inspection enabled. `openwaf_applications` reports the active application count, and `openwaf_unrouted_requests_total` counts hostname/authority/SNI rejections separately from inspection-capacity rejections. Counters and budgets cover the whole deployment. [Application routing contract](APPLICATIONS.md)

| Condition | HTTP status | ready | healthy | state |
|---|---|---|---|---|
| Active policy, inspection and event delivery checks pass | 200 | true | true | ready |
| Collector unavailable, paused export with pending records, or event storage failure | 200 | true | false | degraded |
| Inspection or durable event storage disabled | 200 | true | false | degraded |
| Administration journal unavailable or TLS reload/expiry checks fail | 200 | true | false | degraded |
| Gateway shutdown has started | 503 | false | false | stopping |

`ready` indicates an active policy and an accepting gateway lifecycle. Detection mode passes the inspection-enabled check. Readiness uses cached state and performs no upstream, collector, disk or certificate probes. A successful response therefore describes gateway lifecycle readiness independently of backend reachability and certificate validity. Readiness becomes unavailable when the management server has stopped.

`event_delivery_healthy` includes local storage and configured export status. Ingest timeouts, queue drops, failed writes and unacknowledged persistence attempts keep health degraded for the rest of that process lifetime, including after delivery recovers. Investigate and reconcile those counters before restarting. Collector failures alone recover their health indicator after a successful acknowledgement. With no configured destination, export is optional and passes the storage export check.

`administration_export_healthy` independently reports audit delivery. An unavailable receiver or a paused bound journal with pending records degrades health while inspection remains ready. A complete acknowledgement clears the receiver error. Audit replay progress resets on process restart while the independent receiver preserves deduplicated receipts. [Audit delivery](AUDIT-EXPORT.md)

Use `ready` for traffic routing and `healthy` plus the detailed counters for operational alerts. Removing inspecting nodes because their shared collector is unavailable can remove every traffic node during the same outage.

## Scraping

An existing Prometheus installation on the gateway host can scrape the default loopback management listener with the following job. Supply a monitoring-only automation credential through a restricted file managed by the operator.

```yaml
scrape_configs:
  - job_name: openwaf
    scrape_interval: 15s
    metrics_path: /api/v1/metrics
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/secrets/openwaf-monitoring-token
    static_configs:
      - targets: ['127.0.0.1:8081']
```

Issue the credential to a dedicated enabled account with no application restriction and select only `monitoring:read`. Plan rotation before expiry; changing the owner account may invalidate its tokens. Keep bootstrap credentials separately for recovery. [Automation credentials](M3-AUTHENTICATION.md) The management listener requires an explicit loopback bind. A remote monitoring system needs a managed secure tunnel or a local forwarding agent, with its credential stored separately from scraped samples.

For an interactive check on Windows with `OPENWAF_ADMIN_TOKEN` already supplied to the shell, run the following command.

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:8081/api/v1/health -Headers @{ Authorization = "Bearer $env:OPENWAF_ADMIN_TOKEN" }
```

The endpoint emits Prometheus text format 0.0.4 with HELP and TYPE metadata, base-unit names and a terminating newline. All series have fixed names and no labels. Paths, IP addresses, application names, rule content, tokens, source UUIDs, collector destinations and error text are excluded. The implementation follows the upstream exposition and naming specifications. [Text format](https://prometheus.io/docs/instrumenting/exposition_formats/) · [Metric naming](https://prometheus.io/docs/practices/naming/)

## Signals and alert expressions

Traffic controls add `openwaf_rate_limited_requests_total`, `openwaf_fairness_rejections_total` and `openwaf_tracked_rate_clients`. The System screen displays rate and admission-share refusals. Metrics retain fixed names without identity labels. The bootstrap credential retains full monitoring/recovery authority. Unrestricted local viewer sessions and appropriately scoped automation tokens can read monitoring endpoints. [Traffic and access contract](TRAFFIC-AND-ACCESS.md)

For reviewed pilot observation, the bounded collector samples these endpoints plus explicit business canaries and optional identity-provider discovery. Its timer and daily reviews complement the operator's independent alerting. [Pilot procedure](PILOT.md)

All metric names use the `openwaf_` prefix.

| Signal | Meaning |
|---|---|
| `ready`, `healthy`, `inspection_enabled`, `policy_revision` | Lifecycle readiness, operational health, enabled rule evaluation and active revision |
| `audit_healthy`, `audit_records`, `audit_bytes`, `audit_limit_bytes` | Administration journal availability, records and finite byte quota |
| `audit_export_enabled`, `audit_export_healthy`, `audit_export_pending_records`, `audit_export_acknowledged_records`, `audit_export_failures_total` | Independent administration delivery, current-process replay progress and receiver failures |
| `trusted_proxy_networks`, `forwarded_identity_requests_total`, `invalid_proxy_headers_total` | Configured proxy count and validated/invalid forwarded identity observations |
| `tls_enabled`, `tls_healthy`, `tls_expiring`, `tls_not_after_timestamp_seconds`, `tls_chain_not_after_timestamp_seconds` | Certificate reload/expiry state, leaf expiry and earliest supplied-chain expiry |
| `requests_total`, `blocked_requests_total`, `detected_requests_total`, `gateway_errors_total` | Completed request decisions and processing failures in this process |
| `active_requests`, `max_concurrent_requests`, `reserved_buffer_bytes`, `buffer_budget_bytes`, `max_connections` | Resource admission use and limits |
| `overload_requests_total`, `security_occurrences_total` | Counted rejection and security occurrences, including overload summaries |
| `event_persistence_errors_total`, `event_queue_dropped_total`, `event_write_failed_total`, `event_ingest_timeouts_total`, `event_write_retries_total` | Persistence acknowledgement failures, dropped records, failed writes, timeouts and temporary SQLite retries |
| `event_queue_records`, `event_queue_capacity`, `event_pending_writes` | Writer queue occupancy, capacity and pending records |
| `event_stored_records`, `event_retention_limit_records`, `event_payload_bytes`, `event_database_limit_bytes` | Retained history and configured storage bounds |
| `event_committed_records_total`, `event_committed_occurrences_total`, `event_max_commit_seconds`, `event_last_commit_timestamp_seconds` | Local commit progress and highest observed group-commit duration |
| `event_export_enabled`, `event_export_paused`, `event_export_healthy` | Bound destination and exporter state |
| `event_export_pending_records`, `event_export_limit_records`, `event_export_pending_bytes` | Durable outbox backlog and row capacity |
| `event_export_enqueued_records_total`, `event_export_acked_records_total` and corresponding `occurrences_total` metrics | Durable delivery accounting |
| `event_export_attempts_total`, `event_export_failures_total`, `event_export_last_success_timestamp_seconds` | Delivery attempts, failures and acknowledgement progress |

`gateway_errors_total` includes request processing, upstream connection and response inspection failures. Backend HTTP error responses retain their application meaning and do not automatically increment this counter. `blocked_requests_total` includes gateway/body/protocol rejections recorded as blocked. It is unsuitable as an attack count.

Traffic and local write counters reset on process restart. Export enqueued/acknowledged counters persist with the event database. Restoring an earlier checkpoint can reset their observed values. Use Prometheus counter functions such as `rate` and `increase` where appropriate. Export attempt/failure counters and last-success time are process-local. Timestamp metrics use zero when no observation exists.

Individual metric groups are sampled under their existing locks. Cross-group comparisons are eventually consistent while traffic or export is active. Scraping does not flush overload summaries or event writes. Main SQLite allocation, rollback-journal use, filesystem free space, total process memory, CPU, connection occupancy and latency distributions require further instrumentation or host monitoring. `event_payload_bytes` measures retained JSON payload, and `reserved_buffer_bytes` measures connector admission reservations.

Example alert expressions can be used in the operator's existing alert rules.

```promql
# Scrape target unavailable or inaccessible
up{job="openwaf"} == 0

# Operational degradation, including sticky evidence-loss signals
openwaf_healthy == 0

# Traffic capacity rejections over five minutes
increase(openwaf_overload_requests_total[5m]) > 0

# Export spool above 80% of its row limit
(openwaf_event_export_pending_records / openwaf_event_export_limit_records > 0.8)
  and on(job, instance) (openwaf_event_export_enabled == 1)

# New unacknowledged local persistence attempts
increase(openwaf_event_persistence_errors_total[5m]) > 0
```

Choose alert duration and severity for the workload. A growing backlog during an outage requires intervention before finite row or byte quotas are reached. A quiet application can legitimately have an old last-commit or last-export-success timestamp.

## Verification

`go test ./internal/gateway -run TestMonitoring -v` exercises authentication, public-listener routing, real clean/CRS-blocked traffic, fixed text metadata, sensitive-data exclusion, collector outage, outbox exhaustion, recovery with sticky persistence failures, disabled inspection/storage and shutdown readiness.

The existing browser check also exercises authenticated health and metrics over the compiled server's real management listener. It checks 23 requests and three blocked requests against the emitted counters. Its sanitized metric snapshot is written to `artifacts/monitoring-metrics.txt`.

The trusted-proxy increment on 3 November 2026 adds three identity signals, bringing the current total to 60 fixed, label-free metric families. The Prometheus parser check is recorded in `artifacts/trusted-proxy-parser.log`. Proxy CIDRs and configuration hashes remain in authenticated status and event/audit evidence rather than metric labels. [Trusted proxy contract](TRUSTED-PROXIES.md)

Validation on 2 November 2026 passed the full root Go test suite and `go vet` on Windows, the complete gateway test binary on Linux through WSL, and the Chrome browser check against `bin/openwaf-next.exe`. The appliance increment extends the original 48 metrics to 57 with administration-journal and certificate state. The Prometheus common v0.67.5 parser accepted the current compiled-server snapshot and verified the request/block counters. Runtime dependencies remain unchanged. Current evidence is saved in `artifacts/appliance-all-tests.log`, `artifacts/appliance-gateway-linux-tests.log`, `artifacts/appliance-browser-check.log` and `artifacts/appliance-parser-check.log`. [Appliance validation](VALIDATION-APPLIANCE-OPERATIONS.md)
