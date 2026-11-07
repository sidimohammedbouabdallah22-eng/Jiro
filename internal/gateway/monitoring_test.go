package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/eventcollector"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/eventstore"
)

func TestAuditExportOutageKeepsInspectionReady(t *testing.T) {
	token := strings.Repeat("a", 64)
	collector, err := eventcollector.Open(eventcollector.Options{Path: filepath.Join(t.TempDir(), "audit.db"), Token: token})
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	var available atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !available.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		collector.ServeHTTP(w, r)
	}))
	defer server.Close()
	g, err := NewWithOptions(filepath.Join(t.TempDir(), "policy.json"), Options{
		AuditExport: eventstore.ExportOptions{URL: server.URL + "/v1/events", Token: token, RetryMin: 10 * time.Millisecond, RetryMax: 20 * time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close(context.Background())
	deadline := time.Now().Add(5 * time.Second)
	for g.AuditExportStatus().Failures == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	health := g.Health()
	if g.AuditExportStatus().Failures == 0 || !health.Ready || health.Healthy || health.Checks["administration_export_healthy"] {
		t.Fatalf("audit outage health %+v export %+v", health, g.AuditExportStatus())
	}
	if w := request(g, "GET", "/?q="+url.QueryEscape("<script>alert(1)</script>"), "", ""); w.Code != http.StatusForbidden {
		t.Fatalf("inspection during audit outage returned %d", w.Code)
	}
	samples := monitoringSamples(t, g.metricsText())
	if samples["openwaf_audit_export_healthy"] != 0 || samples["openwaf_audit_export_pending_records"] == 0 {
		t.Fatal("audit outage missing from metrics")
	}
	available.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := g.WaitAuditExport(ctx); err != nil {
		t.Fatal(err)
	}
	if health := g.Health(); !health.Ready || !health.Healthy || !health.Checks["administration_export_healthy"] {
		t.Fatalf("audit delivery health did not recover %+v", health)
	}
}

func monitoringRequest(handler http.Handler, path, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

// Check the fixed, label-free text contract, including metadata ordering and a
// terminal newline. No production Prometheus dependencies are needed for it.
func monitoringSamples(t *testing.T, body string) map[string]float64 {
	t.Helper()
	if !strings.HasSuffix(body, "\n") {
		t.Fatal("metrics missing terminal newline")
	}
	lines := strings.Split(strings.TrimSuffix(body, "\n"), "\n")
	if len(lines)%3 != 0 {
		t.Fatal("metrics missing HELP, TYPE or sample")
	}
	samples := map[string]float64{}
	for i := 0; i < len(lines); i += 3 {
		fields := strings.Fields(lines[i+2])
		if len(fields) != 2 || !strings.HasPrefix(fields[0], "openwaf_") {
			t.Fatalf("invalid sample %q", lines[i+2])
		}
		name := fields[0]
		if !strings.HasPrefix(lines[i], "# HELP "+name+" ") {
			t.Fatalf("missing HELP for %s", name)
		}
		if lines[i+1] != "# TYPE "+name+" counter" && lines[i+1] != "# TYPE "+name+" gauge" {
			t.Fatalf("invalid TYPE for %s", name)
		}
		if _, exists := samples[name]; exists {
			t.Fatalf("duplicate sample %s", name)
		}
		value, err := strconv.ParseFloat(fields[1], 64)
		if err != nil || value < 0 {
			t.Fatalf("invalid sample value %q", fields[1])
		}
		samples[name] = value
	}
	return samples
}

func TestMonitoringAuthenticationTrafficAndShutdown(t *testing.T) {
	g, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "private backend response")
	})
	const token = "monitor-test-administrator-secret-123456"
	admin := NewAdmin(g, token)
	for _, path := range []string{"/api/v1/health", "/api/v1/metrics"} {
		for _, credential := range []string{"", "invalid-secret"} {
			if w := monitoringRequest(admin, path, credential); w.Code != http.StatusUnauthorized {
				t.Fatalf("unauthorized %s returned %d", path, w.Code)
			}
		}
	}
	if w := request(g, "GET", "/api/v1/metrics", "", ""); w.Body.String() != "private backend response" {
		t.Fatal("public listener did not route monitoring path to application")
	}
	if w := request(g, "GET", "/private-customer-path?q="+url.QueryEscape("<script>alert(1)</script>"), "", ""); w.Code != 403 {
		t.Fatalf("attack returned %d", w.Code)
	}
	w := monitoringRequest(admin, "/api/v1/metrics", token)
	if w.Code != 200 || w.Header().Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("metrics response %d %v", w.Code, w.Header())
	}
	for _, secret := range []string{token, "private-customer-path", "script", "127.0.0.1", "primary", g.path} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatalf("metrics disclosed %q", secret)
		}
	}
	samples := monitoringSamples(t, w.Body.String())
	for name, want := range map[string]float64{
		"openwaf_requests_total": 2, "openwaf_blocked_requests_total": 1,
		"openwaf_security_occurrences_total": 1, "openwaf_event_committed_occurrences_total": 1,
		"openwaf_ready": 1, "openwaf_healthy": 1, "openwaf_active_requests": 0,
		"openwaf_event_queue_capacity": 256, "openwaf_event_export_pending_records": 0,
	} {
		if got, exists := samples[name]; !exists || got != want {
			t.Errorf("%s got %v, want %v", name, got, want)
		}
	}
	g.Close(context.Background())
	w = monitoringRequest(admin, "/api/v1/health", token)
	var health HealthReport
	if err := json.Unmarshal(w.Body.Bytes(), &health); err != nil {
		t.Fatal(err)
	}
	if w.Code != 503 || health.Ready || health.Healthy || health.State != "stopping" {
		t.Fatalf("shutdown health %d %+v", w.Code, health)
	}
	if got := monitoringSamples(t, monitoringRequest(admin, "/api/v1/metrics", token).Body.String())["openwaf_ready"]; got != 0 {
		t.Fatalf("shutdown readiness %v", got)
	}
}

func TestMonitoringCollectorOutageAndPersistenceFailure(t *testing.T) {
	var recoverCollector atomic.Bool
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !recoverCollector.Load() {
			w.WriteHeader(503)
			return
		}
		var batch eventstore.ExportBatch
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		ack := eventstore.ExportAck{BatchID: batch.BatchID}
		for _, e := range batch.Events {
			ack.IDs = append(ack.IDs, e.ID)
		}
		_ = json.NewEncoder(w).Encode(ack)
	}))
	defer collector.Close()
	g, err := NewWithOptions(filepath.Join(t.TempDir(), "policy.json"), Options{
		EventStore: eventstore.Options{Export: eventstore.ExportOptions{
			URL: collector.URL + "/private-collector-endpoint", Token: "private-export-credential", MaxRows: 1,
			RetryMin: 10 * time.Millisecond, RetryMax: 20 * time.Millisecond,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close(context.Background())
	attack := "/?q=" + url.QueryEscape("<script>alert(1)</script>")
	request(g, "GET", attack, "", "")
	deadline := time.Now().Add(5 * time.Second)
	for g.StorageStatus().Export.Failures == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if g.StorageStatus().Export.Failures == 0 {
		t.Fatal("collector failure was not observed")
	}
	admin := NewAdmin(g, "test-monitor-token")
	w := monitoringRequest(admin, "/api/v1/health", "test-monitor-token")
	var health HealthReport
	if err = json.Unmarshal(w.Body.Bytes(), &health); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || !health.Ready || health.Healthy || health.State != "degraded" {
		t.Fatalf("collector outage removed readiness or failed to degrade health %+v", health)
	}
	text := g.metricsText()
	if strings.Contains(text, "private-collector-endpoint") || strings.Contains(text, "private-export-credential") {
		t.Fatal("metrics leaked export settings")
	}
	samples := monitoringSamples(t, text)
	if samples["openwaf_event_export_pending_records"] != 1 || samples["openwaf_event_export_healthy"] != 0 {
		t.Fatal("collector outage missing from metrics")
	}
	if w = request(g, "GET", attack, "", ""); w.Code != 403 {
		t.Fatalf("outbox exhaustion changed inspection verdict %d", w.Code)
	}
	samples = monitoringSamples(t, g.metricsText())
	if samples["openwaf_event_persistence_errors_total"] != 1 || samples["openwaf_event_write_failed_total"] != 1 || samples["openwaf_ready"] != 1 {
		t.Fatal("failed persistence missing from metrics or removed readiness")
	}
	recoverCollector.Store(true)
	deadline = time.Now().Add(5 * time.Second)
	for g.StorageStatus().Export.Pending != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	samples = monitoringSamples(t, g.metricsText())
	if samples["openwaf_event_export_pending_records"] != 0 || samples["openwaf_event_export_acked_records_total"] != 1 || samples["openwaf_healthy"] != 0 {
		t.Fatal("export recovery concealed historical persistence failure")
	}
}

func TestMonitoringDisabledInspectionAndStorage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	c := Defaults()
	c.Mode = "disabled"
	if err := persist(path, c); err != nil {
		t.Fatal(err)
	}
	g, err := NewWithOptions(path, Options{DisableEventStore: true})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close(context.Background())
	health := g.Health()
	if !health.Ready || health.Healthy || health.Checks["inspection_enabled"] || health.Checks["durable_events_enabled"] {
		t.Fatalf("disabled feature health %+v", health)
	}
	samples := monitoringSamples(t, g.metricsText())
	if samples["openwaf_event_store_enabled"] != 0 || samples["openwaf_inspection_enabled"] != 0 || samples["openwaf_ready"] != 1 {
		t.Fatal("disabled features missing from metrics")
	}
}
