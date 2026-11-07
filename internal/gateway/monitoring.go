package gateway

import (
	"fmt"
	"strings"
	"time"

	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/eventstore"
)

// HealthReport separates traffic readiness from failures requiring operator review.
// A collector outage must not remove a still-inspecting gateway from service.
type HealthReport struct {
	Ready    bool            `json:"ready"`
	Healthy  bool            `json:"healthy"`
	State    string          `json:"state"`
	Mode     string          `json:"mode"`
	Revision uint64          `json:"revision"`
	Checks   map[string]bool `json:"checks"`
}

func (g *Gateway) Health() HealthReport {
	return g.health(g.StorageStatus())
}

func (g *Gateway) health(storage eventstore.Status) HealthReport {
	active := g.active.Load()
	audit := g.AuditStatus()
	certificate := g.CertificateStatus()
	report := HealthReport{
		Ready: !g.closed.Load() && active != nil,
		Checks: map[string]bool{
			"administration_audit_healthy":   audit.Healthy,
			"administration_export_healthy":  g.AuditExportStatus().Healthy,
			"certificate_healthy":            certificate.Healthy,
			"durable_events_enabled":         storage.Enabled,
			"event_delivery_healthy":         storage.Healthy,
			"event_persistence_acknowledged": g.persistenceFailures.Load() == 0,
		},
	}
	if active != nil {
		report.Mode, report.Checks["inspection_enabled"] = active.config.inspectionState()
		report.Revision = active.config.Revision
	}
	report.Healthy = report.Ready
	for _, ok := range report.Checks {
		report.Healthy = report.Healthy && ok
	}
	report.State = "ready"
	if !report.Healthy {
		report.State = "degraded"
	}
	if !report.Ready {
		report.State = "stopping"
	}
	return report
}

func metricBool(value bool) int {
	if value {
		return 1
	}
	return 0
}

func metricTimestamp(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.Unix()
}

// Only fixed metric names are emitted. User-controlled values never become labels,
// help strings or samples. Scraping reads cached state without querying SQLite,
// compiling policy, flushing writes or contacting the upstream/collector.
func (g *Gateway) metricsText() string {
	var out strings.Builder
	metric := func(name, kind, help string, value any) {
		fmt.Fprintf(&out, "# HELP openwaf_%s %s\n# TYPE openwaf_%s %s\nopenwaf_%s %v\n", name, help, name, kind, name, value)
	}
	storage := g.StorageStatus()
	audit := g.AuditStatus()
	auditExport := g.AuditExportStatus()
	certificate := g.CertificateStatus()
	health := g.health(storage)
	metric("ready", "gauge", "Gateway has an active policy and is accepting traffic.", metricBool(health.Ready))
	metric("healthy", "gauge", "All operational health checks pass.", metricBool(health.Healthy))
	metric("inspection_enabled", "gauge", "Rule inspection is enabled, including detection-only mode.", metricBool(health.Checks["inspection_enabled"]))
	metric("policy_revision", "gauge", "Active policy revision.", health.Revision)
	appCount := 1
	if active := g.active.Load(); active.config.SchemaVersion == 2 {
		appCount = len(active.config.Applications)
	}
	metric("applications", "gauge", "Applications in the active deployment.", appCount)
	metric("trusted_proxy_networks", "gauge", "Configured trusted proxy CIDR count.", len(g.proxyTrust.networks))
	metric("forwarded_identity_requests_total", "counter", "Requests with validated forwarding identity, including later rejected requests.", g.proxyTrust.forwarded.Load())
	metric("invalid_proxy_headers_total", "counter", "Requests with invalid forwarding headers from configured proxies.", g.proxyTrust.invalid.Load())
	metric("audit_healthy", "gauge", "Administration journal is writable and open.", metricBool(audit.Healthy))
	metric("audit_export_enabled", "gauge", "Independent audit delivery is configured.", metricBool(auditExport.Enabled))
	metric("audit_export_healthy", "gauge", "Audit delivery is healthy or disabled.", metricBool(auditExport.Healthy))
	metric("audit_export_pending_records", "gauge", "Journal records awaiting audit delivery in this process.", auditExport.Pending)
	metric("audit_export_acknowledged_records", "gauge", "Audit records acknowledged in this exporter lifetime.", auditExport.Acknowledged)
	metric("audit_export_failures_total", "counter", "Audit collector failures in this process.", auditExport.Failures)
	metric("audit_records", "gauge", "Records in the active administration journal.", audit.Records)
	metric("audit_bytes", "gauge", "Bytes in the active administration journal.", audit.Bytes)
	metric("audit_limit_bytes", "gauge", "Administration journal size limit in bytes.", audit.MaxBytes)
	metric("tls_enabled", "gauge", "Application TLS is configured.", metricBool(certificate.Enabled))
	metric("tls_healthy", "gauge", "Certificate validity, expiry warning and reload checks pass.", metricBool(certificate.Healthy))
	metric("tls_expiring", "gauge", "Certificate expires within thirty days, including already expired.", metricBool(certificate.Expiring))
	metric("tls_not_after_timestamp_seconds", "gauge", "Active certificate expiry in Unix seconds or zero when TLS is disabled.", metricTimestamp(certificate.NotAfter))
	metric("tls_chain_not_after_timestamp_seconds", "gauge", "Earliest supplied chain certificate expiry in Unix seconds or zero when TLS is disabled.", metricTimestamp(certificate.ChainNotAfter))
	metric("start_timestamp_seconds", "gauge", "Gateway process start time in Unix seconds.", g.started.Unix())
	metric("uptime_seconds", "gauge", "Seconds since gateway creation.", time.Since(g.started).Seconds())

	g.mu.Lock()
	total, blocked, detected, upstreamErrors := g.total, g.blocked, g.detected, g.upstreamErrors
	security, overloaded := g.securitySeen, g.overloaded
	unrouted := g.unrouted
	rateLimited := g.rateLimited
	g.mu.Unlock()
	metric("requests_total", "counter", "Completed application requests including capacity rejections in this process.", total)
	metric("blocked_requests_total", "counter", "Requests recorded as blocked in this process.", blocked)
	metric("detected_requests_total", "counter", "Requests recorded as detected in this process.", detected)
	metric("gateway_errors_total", "counter", "Request processing, upstream or response inspection errors in this process.", upstreamErrors)
	metric("security_occurrences_total", "counter", "Security event occurrences observed in this process.", security)
	metric("overload_requests_total", "counter", "Application capacity rejections in this process.", overloaded)
	metric("unrouted_requests_total", "counter", "Unknown, invalid or misdirected hostname requests in this process.", unrouted)
	metric("rate_limited_requests_total", "counter", "Application and client rate rejections in this process.", rateLimited)
	metric("event_persistence_errors_total", "counter", "Unacknowledged event persistence attempts in this process.", g.persistenceFailures.Load())

	g.budget.mu.Lock()
	limits, active, reserved := g.budget.limits, g.budget.active, g.budget.reserved
	fairness := g.budget.fairRejected
	pending, entered, admitted, expired := g.budget.pending, g.budget.waitEntered, g.budget.waitAdmitted, g.budget.waitExpired
	cancelled, changed, rateRefused, capacityRefused := g.budget.waitCancelled, g.budget.waitPolicyChanged, g.budget.waitRateRefused, g.budget.waitCapacityRefused
	tracked := 0
	for _, app := range g.budget.applications {
		tracked += len(app.clients)
	}
	g.budget.mu.Unlock()
	metric("active_requests", "gauge", "Requests holding inspection admission.", active)
	metric("pending_admissions", "gauge", "Requests waiting without an inspection reservation.", pending)
	metric("pending_admission_limit", "gauge", "Hard process limit on pending admissions.", maxPendingAdmissions)
	metric("admission_wait_entered_total", "counter", "Requests entering bounded admission waiting.", entered)
	metric("admission_wait_admitted_total", "counter", "Waiting requests subsequently admitted.", admitted)
	metric("admission_wait_expired_total", "counter", "Requests exhausting their admission wait budget.", expired)
	metric("admission_wait_cancelled_total", "counter", "Waiting requests cancelled before admission.", cancelled)
	metric("admission_wait_policy_changed_total", "counter", "Waits ended by policy activation.", changed)
	metric("admission_wait_rate_refused_total", "counter", "Waiting requests refused by a rate limit.", rateRefused)
	metric("admission_wait_capacity_refused_total", "counter", "Requests refused because waiting capacity is full.", capacityRefused)
	metric("fairness_rejections_total", "counter", "Requests refused by application or client admission shares.", fairness)
	metric("tracked_rate_clients", "gauge", "Client entries retained in bounded admission tables.", tracked)
	metric("max_concurrent_requests", "gauge", "Configured inspection admission limit.", limits.MaxConcurrent)
	metric("max_connections", "gauge", "Configured application connection admission limit.", limits.MaxConnections)
	metric("reserved_buffer_bytes", "gauge", "Current connector buffer admission reservations in bytes.", reserved)
	metric("buffer_budget_bytes", "gauge", "Configured connector buffer admission budget in bytes.", limits.BufferBytes)

	metric("event_store_enabled", "gauge", "Durable security event storage is enabled.", metricBool(storage.Enabled))
	metric("event_store_healthy", "gauge", "Event storage and configured export health checks pass.", metricBool(storage.Healthy))
	metric("event_queue_records", "gauge", "Records and barriers currently in the local writer queue.", storage.Queued)
	metric("event_queue_capacity", "gauge", "Local writer queue capacity.", storage.QueueCapacity)
	metric("event_pending_writes", "gauge", "Event records awaiting write completion.", storage.Pending)
	metric("event_stored_records", "gauge", "Retained local security event records.", storage.Stored)
	metric("event_payload_bytes", "gauge", "Retained local event payload bytes excluding SQLite overhead.", storage.PayloadBytes)
	metric("event_database_limit_bytes", "gauge", "Configured main event database size limit in bytes.", storage.MaxBytes)
	metric("event_retention_limit_records", "gauge", "Configured local security event retention row limit.", storage.MaxRows)
	metric("event_queue_dropped_total", "counter", "Local writer queue drops in this process.", storage.QueueDropped)
	metric("event_write_failed_total", "counter", "Failed local event writes in this process.", storage.WriteFailed)
	metric("event_ingest_timeouts_total", "counter", "Event admission or acknowledgement timeouts in this process.", storage.IngestTimeouts)
	metric("event_write_retries_total", "counter", "Temporary SQLite write retries in this process.", storage.WriteRetries)
	metric("event_committed_records_total", "counter", "Local event records committed in this process.", storage.CommittedRecords)
	metric("event_committed_occurrences_total", "counter", "Local event occurrences committed in this process.", storage.CommittedOccurrences)
	metric("event_max_commit_seconds", "gauge", "Maximum observed group commit duration in this process.", storage.MaxCommitMilliseconds/1000)
	metric("event_last_commit_timestamp_seconds", "gauge", "Last local event commit in Unix seconds or zero before first commit.", metricTimestamp(storage.LastCommit))

	export := storage.Export
	metric("event_export_enabled", "gauge", "An event collector destination is bound to this store.", metricBool(export.Enabled))
	metric("event_export_paused", "gauge", "Bound event export is paused by startup configuration.", metricBool(export.Paused))
	metric("event_export_healthy", "gauge", "Configured event export health checks pass.", metricBool(export.Healthy))
	metric("event_export_pending_records", "gauge", "Durable unacknowledged export records.", export.Pending)
	metric("event_export_pending_bytes", "gauge", "Durable unacknowledged export payload bytes.", export.PendingBytes)
	metric("event_export_limit_records", "gauge", "Configured export outbox row limit.", export.MaxRows)
	metric("event_export_enqueued_records_total", "counter", "Export records enqueued over this database lifetime.", export.Enqueued)
	metric("event_export_enqueued_occurrences_total", "counter", "Export occurrences enqueued over this database lifetime.", export.EnqueuedOccurrences)
	metric("event_export_acked_records_total", "counter", "Export records acknowledged over this database lifetime.", export.Acked)
	metric("event_export_acked_occurrences_total", "counter", "Export occurrences acknowledged over this database lifetime.", export.AckedOccurrences)
	metric("event_export_attempts_total", "counter", "Export delivery attempts in this process.", export.Attempts)
	metric("event_export_failures_total", "counter", "Export delivery failures in this process.", export.Failures)
	metric("event_export_last_success_timestamp_seconds", "gauge", "Last export acknowledgement in Unix seconds or zero before first success in this process.", metricTimestamp(export.LastSuccess))
	return out.String()
}
