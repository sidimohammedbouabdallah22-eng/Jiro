// waf-soak is an isolated, bounded fault-and-load qualification, not production sizing.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/adminaudit"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/eventcollector"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/eventstore"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/gateway"
)

type sample struct {
	Seconds           float64 `json:"seconds"`
	Heap              uint64  `json:"heap_bytes"`
	Goroutines        int     `json:"goroutines"`
	Active            int     `json:"active"`
	Reserved          int64   `json:"reserved_bytes"`
	Backlog           int64   `json:"export_pending"`
	Committed         uint64  `json:"committed_occurrences"`
	Acked             uint64  `json:"acked_occurrences"`
	MaxCommitMS       float64 `json:"max_commit_ms"`
	IngestTimeouts    uint64  `json:"ingest_timeouts"`
	PersistenceErrors uint64  `json:"persistence_errors"`
}

type failureObservation struct {
	Seconds   float64 `json:"seconds"`
	Operation string  `json:"operation"`
	Detail    string  `json:"detail"`
}
type result struct {
	Applications             int                   `json:"applications"`
	AuditRecords             uint64                `json:"audit_records"`
	AuditCollector           eventcollector.Totals `json:"audit_collector"`
	Generated                time.Time             `json:"generated"`
	OS                       string                `json:"os"`
	Go                       string                `json:"go"`
	RequestedDuration        string                `json:"requested_duration"`
	Elapsed                  float64               `json:"elapsed_seconds"`
	Rate                     int                   `json:"target_requests_per_second"`
	Requests                 uint64                `json:"requests"`
	Statuses                 map[int]uint64        `json:"statuses"`
	NetworkErrors            uint64                `json:"unexpected_network_errors"`
	ExpectedCancellations    uint64                `json:"expected_client_cancellations"`
	UnexpectedStatuses       uint64                `json:"unexpected_statuses"`
	GatewayRestarts          int                   `json:"gateway_restarts"`
	CollectorRestarts        int                   `json:"collector_restarts"`
	CollectorOutageResponses uint64                `json:"collector_outage_responses"`
	LostAcknowledgements     uint64                `json:"injected_lost_acknowledgements"`
	ExpectedOccurrences      uint64                `json:"observed_security_occurrences"`
	Collector                eventcollector.Totals `json:"collector"`
	Storage                  eventstore.Status     `json:"storage"`
	QueueDropped             uint64                `json:"queue_dropped_all_processes"`
	WriteFailed              uint64                `json:"write_failed_all_processes"`
	IngestTimeouts           uint64                `json:"ingest_timeouts_all_processes"`
	PersistenceErrors        uint64                `json:"persistence_errors_all_processes"`
	WriteRetries             uint64                `json:"write_retries_all_processes"`
	MaxCommitMS              float64               `json:"max_commit_ms_all_processes"`
	DatabaseBytes            int64                 `json:"event_database_bytes"`
	CollectorBytes           int64                 `json:"collector_database_bytes"`
	Samples                  []sample              `json:"samples"`
	Failures                 []string              `json:"invariant_failures"`
	FailureObservations      []failureObservation  `json:"failure_observations,omitempty"`
	Note                     string                `json:"note"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	duration := flag.Duration("duration", 5*time.Minute, "Soak duration (10s..24h), with at most 1000000 scheduled requests")
	rate := flag.Int("rate", 200, "Target requests/second (10..1000); 16 client workers")
	cycle := flag.Duration("cycle", 45*time.Second, "Collector outage cycle (minimum 2s)")
	outage := flag.Duration("outage", 15*time.Second, "Collector downtime in each cycle (positive and shorter than cycle)")
	restart := flag.Duration("restart", time.Minute, "Gateway restart interval; collector restarts every 1.5 intervals (minimum 2s)")
	out := flag.String("out", "artifacts/soak-report.json", "JSON report path")
	applications := flag.Int("applications", 1, "Protected applications, 1..8")
	auditExport := flag.Bool("audit-export", false, "Exercise an independent audit receiver with outages/replay")
	flag.Parse()
	if *duration < 10*time.Second || *duration > 24*time.Hour || *rate < 10 || *rate > 1000 || *cycle < 2*time.Second || *outage <= 0 || *outage >= *cycle || *restart < 2*time.Second || *applications < 1 || *applications > 8 {
		return fmt.Errorf("invalid bounded soak settings")
	}
	if *duration > time.Duration(1000000)*time.Second/time.Duration(*rate) {
		return fmt.Errorf("requested duration and rate exceed the 1000000-request budget; reduce rate or duration")
	}
	dir, err := os.MkdirTemp("", "openwaf-soak-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	token := "isolated-soak-collector-token-at-least-32-characters"
	collectorOptions := eventcollector.Options{Path: filepath.Join(dir, "collector.db"), Token: token, MaxBytes: 256 << 20}
	receiver, err := eventcollector.Open(collectorOptions)
	if err != nil {
		return err
	}
	var collector atomic.Pointer[eventcollector.Collector]
	collector.Store(receiver)
	var auditCollector atomic.Pointer[eventcollector.Collector]
	auditOptions := eventcollector.Options{Path: filepath.Join(dir, "audit-collector.db"), Token: token, MaxBytes: 64 << 20}
	if *auditExport {
		auditReceiver, e := eventcollector.Open(auditOptions)
		if e != nil {
			return e
		}
		auditCollector.Store(auditReceiver)
	}
	defer func() {
		if c := collector.Load(); c != nil {
			c.Close()
		}
		if c := auditCollector.Load(); c != nil {
			c.Close()
		}
	}()
	var faults atomic.Bool
	faults.Store(true)
	var collectorRequests, outageResponses, lostAcks atomic.Uint64
	start := time.Now()
	collectorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if faults.Load() && time.Since(start)%*cycle >= *cycle-*outage {
			outageResponses.Add(1)
			http.Error(w, "injected collector outage", 503)
			return
		}
		c := collector.Load()
		if r.URL.Path == "/v1/audit" {
			c = auditCollector.Load()
			r = r.Clone(r.Context())
			r.URL.Path = "/v1/events"
		}
		if c == nil {
			http.Error(w, "collector restarting", 503)
			return
		}
		recorder := httptest.NewRecorder()
		c.ServeHTTP(recorder, r)
		if recorder.Code == 200 && faults.Load() && collectorRequests.Add(1)%17 == 0 {
			lostAcks.Add(1)
			http.Error(w, "injected lost acknowledgement after commit", 503)
			return
		}
		for k, values := range recorder.Header() {
			w.Header()[k] = values
		}
		w.WriteHeader(recorder.Code)
		_, _ = w.Write(recorder.Body.Bytes())
	}))
	defer collectorServer.Close()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		delay := 5 * time.Millisecond
		if r.URL.Path == "/slow" {
			delay = 100 * time.Millisecond
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(delay):
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("healthy"))
	}))
	defer backend.Close()
	path := filepath.Join(dir, "policy.json")
	policy := gateway.Defaults()
	policy.Upstream = backend.URL
	policy.RequestLimit = 1 << 20
	if *applications > 1 {
		var apps []gateway.Application
		for index := 0; index < *applications; index++ {
			leaf := policy
			leaf.ApplicationID = fmt.Sprintf("app-%d", index)
			leaf.Name = leaf.ApplicationID
			apps = append(apps, gateway.ApplicationFromConfig(leaf, []string{fmt.Sprintf("application-%d.test", index)}))
		}
		policy = gateway.Config{SchemaVersion: 2, Revision: 1, Applications: apps}
	}
	data, _ := json.Marshal(policy)
	if err = os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	options := gateway.Options{Resources: gateway.ResourceLimits{MaxConcurrent: 8, MaxConnections: 64, BufferBytes: 8 << 20, RequestTimeout: 10 * time.Second}, EventStore: eventstore.Options{MaxBytes: 64 << 20, MaxRows: 300, Export: eventstore.ExportOptions{URL: collectorServer.URL + "/v1/events", Token: token, RetryMin: 50 * time.Millisecond, RetryMax: time.Second}}}
	if *auditExport {
		options.AuditExport = eventstore.ExportOptions{URL: collectorServer.URL + "/v1/audit", Token: token, RetryMin: 50 * time.Millisecond, RetryMax: time.Second}
	}
	first, err := gateway.NewWithOptions(path, options)
	if err != nil {
		return err
	}
	var active atomic.Pointer[gateway.Gateway]
	active.Store(first)
	defer func() {
		if g := active.Load(); g != nil {
			g.Close(context.Background())
		}
	}()
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g := active.Load()
		if g == nil {
			http.Error(w, "gateway restarting", 503)
			return
		}
		g.ServeHTTP(w, r)
	}))
	defer front.Close()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxConnsPerHost = 16
	transport.MaxIdleConnsPerHost = 16
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	report := result{Generated: time.Now().UTC(), OS: runtime.GOOS, Go: runtime.Version(), RequestedDuration: duration.String(), Rate: *rate, Statuses: map[int]uint64{}, Failures: []string{}, Note: "Client, gateway, backend and durable reference collector share one process/machine. Short synthetic soak, not capacity certification. Events include explicit counted overload summaries. Collector faults and restarts are intentional. Heap is sampled every two seconds; OS RSS and power-loss durability are not measured."}
	report.Applications = *applications
	var mu sync.Mutex
	// All callers hold mu. Keep diagnostics finite even during a long failure.
	recordFailure := func(operation, detail string) {
		if len(report.FailureObservations) < 32 {
			if len(detail) > 300 {
				detail = detail[:300]
			}
			report.FailureObservations = append(report.FailureObservations, failureObservation{Seconds: time.Since(start).Seconds(), Operation: operation, Detail: detail})
		}
	}
	var workers sync.WaitGroup
	jobs := make(chan uint64)
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for seq := range jobs {
				target := "/"
				method := "GET"
				body := ""
				attack := seq%10 >= 5 && seq%10 <= 7
				cancelled := seq%50 == 49
				if attack {
					target = "/?q=%3Cscript%3Ealert(1)%3C/script%3E"
				} else if seq%10 == 8 {
					method = "POST"
					body = `{"message":"` + strings.Repeat("a", 16<<10) + `"}`
				} else if cancelled {
					target = "/slow"
				}
				ctx := context.Background()
				cancel := func() {}
				if cancelled {
					ctx, cancel = context.WithTimeout(ctx, 2*time.Millisecond)
				}
				req, _ := http.NewRequestWithContext(ctx, method, front.URL+target, strings.NewReader(body))
				req.Host = "application.test"
				if *applications > 1 {
					req.Host = fmt.Sprintf("application-%d.test", seq%uint64(*applications))
				}
				req.Header.Set("User-Agent", "OpenWAF soak")
				if body != "" {
					req.Header.Set("Content-Type", "application/json")
				}
				resp, requestErr := client.Do(req)
				status := 0
				if requestErr == nil {
					status = resp.StatusCode
					_, requestErr = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
				expectedCancel := cancelled && requestErr != nil && ctx.Err() != nil
				cancel()
				mu.Lock()
				report.Requests++
				if expectedCancel {
					report.ExpectedCancellations++
				} else if requestErr != nil {
					report.NetworkErrors++
					recordFailure("client request", requestErr.Error())
				} else {
					report.Statuses[status]++
					expected := 200
					if attack {
						expected = 403
					}
					if status != expected && status != 503 {
						report.UnexpectedStatuses++
					}
				}
				mu.Unlock()
			}
		}()
	}
	accumulate := func(g *gateway.Gateway) {
		status := g.StorageStatus()
		report.QueueDropped += status.QueueDropped
		report.WriteFailed += status.WriteFailed
		report.IngestTimeouts += status.IngestTimeouts
		report.WriteRetries += status.WriteRetries
		report.MaxCommitMS = max(report.MaxCommitMS, status.MaxCommitMilliseconds)
		summary := g.Summary()
		report.ExpectedOccurrences += summary["security_occurrences"].(uint64)
		report.PersistenceErrors += summary["event_persistence_errors"].(uint64)
	}
	sendTick := time.NewTicker(time.Second / time.Duration(*rate))
	defer sendTick.Stop()
	sampleTick := time.NewTicker(2 * time.Second)
	defer sampleTick.Stop()
	end := time.NewTimer(*duration)
	defer end.Stop()
	nextGateway := *restart
	nextCollector := *restart * 3 / 2
	var sequence uint64
	var sampledGateway *gateway.Gateway
	var sampledTimeouts uint64
	recordSample := func() {
		g := active.Load()
		if g == nil {
			return
		}
		var memory runtime.MemStats
		runtime.ReadMemStats(&memory)
		resources := g.ResourceStatus()
		status := g.StorageStatus()
		persistenceErrors := g.Summary()["event_persistence_errors"].(uint64)
		report.Samples = append(report.Samples, sample{Seconds: time.Since(start).Seconds(), Heap: memory.HeapAlloc, Goroutines: runtime.NumGoroutine(), Active: resources["active"].(int), Reserved: resources["reserved_buffer_bytes"].(int64), Backlog: status.Export.Pending, Committed: status.CommittedOccurrences, Acked: status.Export.AckedOccurrences, MaxCommitMS: status.MaxCommitMilliseconds, IngestTimeouts: status.IngestTimeouts, PersistenceErrors: persistenceErrors})
		if sampledGateway != g {
			sampledGateway, sampledTimeouts = g, 0
		}
		if status.IngestTimeouts > sampledTimeouts {
			recordFailure("event acknowledgement", fmt.Sprintf("timeouts=%d queued=%d pending_writes=%d max_commit_ms=%.3f", status.IngestTimeouts, status.Queued, status.Pending, status.MaxCommitMilliseconds))
			sampledTimeouts = status.IngestTimeouts
		}
		if resources["active"].(int) > 8 || resources["reserved_buffer_bytes"].(int64) > 8<<20 {
			report.Failures = append(report.Failures, "observed resource budget violation")
		}
	}
loop:
	for {
		select {
		case <-end.C:
			break loop
		case <-sampleTick.C:
			if *auditExport {
				if _, e := active.Load().RecordAudit(adminaudit.Record{Operation: "soak.sample", Actor: "qualification", Outcome: "success"}); e != nil {
					report.Failures = append(report.Failures, "audit append failed: "+e.Error())
				}
			}
			mu.Lock()
			recordSample()
			fmt.Printf("%.0fs requests=%d restarts=%d/%d export_pending=%d\n", time.Since(start).Seconds(), report.Requests, report.GatewayRestarts, report.CollectorRestarts, active.Load().StorageStatus().Export.Pending)
			mu.Unlock()
		case <-sendTick.C:
			if sequence >= 1000000 {
				continue
			}
			elapsed := time.Since(start)
			if elapsed >= nextGateway {
				g := active.Swap(nil)
				ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
				g.Close(ctx)
				shutdownErr := ctx.Err()
				cancel()
				mu.Lock()
				accumulate(g)
				mu.Unlock()
				if shutdownErr != nil {
					report.Failures = append(report.Failures, "gateway shutdown deadline expired")
				}
				replacement, e := gateway.NewWithOptions(path, options)
				if e != nil {
					close(jobs)
					workers.Wait()
					return fmt.Errorf("restart gateway: %w", e)
				}
				active.Store(replacement)
				report.GatewayRestarts++
				nextGateway += *restart
			}
			if elapsed >= nextCollector {
				old := collector.Swap(nil)
				old.Close()
				replacement, e := eventcollector.Open(collectorOptions)
				if e != nil {
					close(jobs)
					workers.Wait()
					return fmt.Errorf("restart collector: %w", e)
				}
				collector.Store(replacement)
				if *auditExport {
					oldAudit := auditCollector.Swap(nil)
					oldAudit.Close()
					replacementAudit, e := eventcollector.Open(auditOptions)
					if e != nil {
						close(jobs)
						workers.Wait()
						return e
					}
					auditCollector.Store(replacementAudit)
				}
				report.CollectorRestarts++
				nextCollector += *restart * 3 / 2
			}
			select {
			case jobs <- sequence:
				sequence++
			case <-end.C:
				break loop
			}
		}
	}
	close(jobs)
	workers.Wait()
	faults.Store(false)
	g := active.Load()
	idleDeadline := time.Now().Add(5 * time.Second)
	for g.ResourceStatus()["active"] != 0 && time.Now().Before(idleDeadline) {
		time.Sleep(10 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	err = g.WaitEventExport(ctx)
	cancel()
	if err != nil {
		report.Failures = append(report.Failures, "export did not drain after recovery: "+err.Error())
	}
	if *auditExport {
		ctx, cancel = context.WithTimeout(context.Background(), 45*time.Second)
		err = g.WaitAuditExport(ctx)
		cancel()
		if err != nil {
			report.Failures = append(report.Failures, "audit export did not drain: "+err.Error())
		}
	}
	ctx, cancel = context.WithTimeout(context.Background(), 12*time.Second)
	g.Close(ctx)
	if ctx.Err() != nil {
		report.Failures = append(report.Failures, "final shutdown timed out")
	}
	cancel()
	accumulate(g)
	report.Storage = g.StorageStatus()
	recordSample()
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	totals, totalsErr := collector.Load().SourceTotals(ctx, report.Storage.Export.SourceID)
	cancel()
	if totalsErr != nil {
		return totalsErr
	}
	report.Collector = totals
	if *auditExport {
		meta, e := adminaudit.Inspect(path + ".audit.jsonl")
		if e != nil {
			return e
		}
		report.AuditRecords = meta.Records
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		auditTotals, e := auditCollector.Load().SourceTotals(ctx, g.AuditExportStatus().SourceID)
		cancel()
		if e != nil {
			return e
		}
		report.AuditCollector = auditTotals
		if auditTotals.Records != meta.Records || auditTotals.Occurrences != meta.Records {
			report.Failures = append(report.Failures, "audit journal and independent receiver do not reconcile")
		}
	}
	report.Elapsed = time.Since(start).Seconds()
	report.CollectorOutageResponses = outageResponses.Load()
	report.LostAcknowledgements = lostAcks.Load()
	if report.NetworkErrors != 0 || report.UnexpectedStatuses != 0 || report.QueueDropped != 0 || report.WriteFailed != 0 || report.IngestTimeouts != 0 || report.PersistenceErrors != 0 {
		report.Failures = append(report.Failures, "traffic or persistence errors occurred")
	}
	if report.ExpectedOccurrences != report.Storage.CommittedOccurrences || totals.Occurrences != report.ExpectedOccurrences || totals.Records != report.Storage.CommittedRecords || report.Storage.Export.Acked != totals.Records || report.Storage.Export.AckedOccurrences != totals.Occurrences || report.Storage.Export.Pending != 0 {
		report.Failures = append(report.Failures, "local/observed/acknowledged/collector counts do not reconcile")
	}
	for _, file := range []struct {
		path   string
		max    int64
		target *int64
	}{{path + ".events.db", 64 << 20, &report.DatabaseBytes}, {collectorOptions.Path, 256 << 20, &report.CollectorBytes}} {
		info, e := os.Stat(file.path)
		if e != nil {
			return e
		}
		*file.target = info.Size()
		if info.Size() > file.max {
			report.Failures = append(report.Failures, "database exceeded physical page budget")
		}
	}
	if err = os.MkdirAll(filepath.Dir(*out), 0755); err != nil {
		return err
	}
	data, err = json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(*out, append(data, '\n'), 0600); err != nil {
		return err
	}
	fmt.Printf("Soak complete: requests=%d observed/committed/collector occurrences=%d/%d/%d; drops=%d failures=%v; report %s\n", report.Requests, report.ExpectedOccurrences, report.Storage.CommittedOccurrences, totals.Occurrences, report.QueueDropped, report.Failures, *out)
	if len(report.Failures) > 0 {
		return fmt.Errorf("soak invariants failed")
	}
	return nil
}
