// waf-qualify measures a bounded, isolated local workload. It is not a capacity
// certification: the client, gateway and backend share a process and machine.
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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/eventstore"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/gateway"
)

type phase struct {
	Name              string      `json:"name"`
	Requests          int         `json:"requests"`
	Concurrency       int         `json:"concurrency"`
	Statuses          map[int]int `json:"statuses"`
	NetworkErrors     int         `json:"network_errors"`
	Unexpected        int         `json:"unexpected"`
	Seconds           float64     `json:"seconds"`
	RequestsPerSecond float64     `json:"requests_per_second"`
	P50               float64     `json:"p50_ms"`
	P95               float64     `json:"p95_ms"`
	P99               float64     `json:"p99_ms"`
	AcceptedP95       float64     `json:"accepted_p95_ms"`
	RejectedP95       float64     `json:"overloaded_p95_ms"`
	CPUSeconds        float64     `json:"combined_process_cpu_seconds"`
	PeakHeap          uint64      `json:"sampled_peak_heap_bytes"`
	PeakGoroutines    int         `json:"sampled_peak_goroutines"`
	PeakActive        int         `json:"sampled_peak_active"`
	PeakReserved      int64       `json:"sampled_peak_reserved_bytes"`
}
type report struct {
	Generated     time.Time         `json:"generated"`
	OS            string            `json:"os"`
	Arch          string            `json:"arch"`
	Go            string            `json:"go"`
	LogicalCPUs   int               `json:"logical_cpus"`
	Note          string            `json:"note"`
	Phases        []phase           `json:"phases"`
	Resources     map[string]any    `json:"resources"`
	Summary       map[string]any    `json:"summary"`
	Storage       eventstore.Status `json:"storage"`
	DatabaseBytes int64             `json:"database_bytes"`
	Failures      []string          `json:"invariant_failures"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	count := flag.Int("requests", 500, "Requests per phase (100..10000)")
	duration := flag.Duration("duration", 0, "Minimum time per phase (0..1m), with a hard cap of 100000 requests")
	out := flag.String("out", "artifacts/qualification.json", "JSON evidence path")
	flag.Parse()
	if *count < 100 || *count > 10000 || *duration < 0 || *duration > time.Minute {
		return fmt.Errorf("requests must be 100..10000; duration must be 0..1m")
	}
	dir, err := os.MkdirTemp("", "openwaf-qualification-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case <-time.After(10 * time.Millisecond):
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("healthy"))
	}))
	defer backend.Close()
	c := gateway.Defaults()
	c.Upstream = backend.URL
	c.RequestLimit = 1 << 20
	path := filepath.Join(dir, "policy.json")
	data, _ := json.Marshal(c)
	if err = os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	g, err := gateway.NewWithOptions(path, gateway.Options{Resources: gateway.ResourceLimits{MaxConcurrent: 8, MaxConnections: 64, BufferBytes: 4 << 20}, EventStore: eventstore.Options{MaxBytes: 4 << 20, MaxRows: 300}})
	if err != nil {
		return err
	}
	defer g.Close(context.Background())
	front := httptest.NewUnstartedServer(g)
	front.Listener = g.LimitListener(front.Listener)
	front.Start()
	defer front.Close()
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxConnsPerHost = 32
	tr.MaxIdleConnsPerHost = 32
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	r := report{Generated: time.Now().UTC(), OS: runtime.GOOS, Arch: runtime.GOARCH, Go: runtime.Version(), LogicalCPUs: runtime.NumCPU(), Note: "Local mixed-load qualification, not production sizing. CPU and heap include client, backend and gateway in one process. Peaks are sampled every 20ms; status 503 is expected under saturation. No external targets or active policies are used.", Failures: []string{}}
	for _, work := range []struct {
		name         string
		workers      int
		target, body string
		accepted     int
	}{{"steady clean", 4, "/", "", 200}, {"saturated clean", 32, "/", "", 200}, {"attack flood", 16, "/?q=%3Cscript%3Ealert(1)%3C/script%3E", "", 403}, {"buffer pressure", 16, "/", `{"message":"` + strings.Repeat("a", 256<<10) + `"}`, 200}} {
		p := phase{Name: work.name, Requests: *count, Concurrency: work.workers, Statuses: map[int]int{}}
		runtime.GC()
		cpuBefore, cpuErr := processCPU()
		if cpuErr != nil {
			return cpuErr
		}
		start := time.Now()
		var mu sync.Mutex
		latencies := make([]float64, 0, *count)
		acceptedLatencies := []float64{}
		rejectedLatencies := []float64{}
		sampleDone := make(chan struct{})
		sampleExit := make(chan struct{})
		go func() {
			defer close(sampleExit)
			ticker := time.NewTicker(20 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-sampleDone:
					return
				case <-ticker.C:
					var m runtime.MemStats
					runtime.ReadMemStats(&m)
					status := g.ResourceStatus()
					mu.Lock()
					p.PeakHeap = max(p.PeakHeap, m.HeapAlloc)
					p.PeakGoroutines = max(p.PeakGoroutines, runtime.NumGoroutine())
					p.PeakActive = max(p.PeakActive, status["active"].(int))
					p.PeakReserved = max(p.PeakReserved, status["reserved_buffer_bytes"].(int64))
					mu.Unlock()
				}
			}
		}()
		jobs := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < work.workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range jobs {
					req, _ := http.NewRequest("GET", front.URL+work.target, nil)
					if work.body != "" {
						req, _ = http.NewRequest("POST", front.URL+work.target, strings.NewReader(work.body))
						req.Header.Set("Content-Type", "application/json")
					}
					req.Host = "application.test"
					req.Header.Set("User-Agent", "OpenWAF qualification")
					began := time.Now()
					resp, reqErr := client.Do(req)
					status := 0
					if reqErr == nil {
						status = resp.StatusCode
						_, reqErr = io.Copy(io.Discard, resp.Body)
						resp.Body.Close()
					}
					mu.Lock()
					elapsed := float64(time.Since(began).Microseconds()) / 1000
					latencies = append(latencies, elapsed)
					if reqErr != nil {
						p.NetworkErrors++
					} else {
						p.Statuses[status]++
						if status == work.accepted {
							acceptedLatencies = append(acceptedLatencies, elapsed)
						} else if status == 503 {
							rejectedLatencies = append(rejectedLatencies, elapsed)
						}
						if status != work.accepted && status != 503 {
							p.Unexpected++
						}
					}
					mu.Unlock()
				}
			}()
		}
		for i := 0; i < 100000 && (i < *count || time.Since(start) < *duration); i++ {
			jobs <- struct{}{}
		}
		close(jobs)
		wg.Wait()
		close(sampleDone)
		<-sampleExit
		p.Seconds = time.Since(start).Seconds()
		cpuAfter, cpuErr := processCPU()
		if cpuErr != nil {
			return cpuErr
		}
		p.CPUSeconds = cpuAfter - cpuBefore
		p.Requests = len(latencies)
		p.RequestsPerSecond = float64(p.Requests) / p.Seconds
		sort.Float64s(latencies)
		p.P50 = latencies[(len(latencies)-1)*50/100]
		p.P95 = latencies[(len(latencies)-1)*95/100]
		p.P99 = latencies[(len(latencies)-1)*99/100]
		sort.Float64s(acceptedLatencies)
		sort.Float64s(rejectedLatencies)
		if len(acceptedLatencies) > 0 {
			p.AcceptedP95 = acceptedLatencies[(len(acceptedLatencies)-1)*95/100]
		}
		if len(rejectedLatencies) > 0 {
			p.RejectedP95 = rejectedLatencies[(len(rejectedLatencies)-1)*95/100]
		}
		r.Phases = append(r.Phases, p)
		fmt.Printf("%s: statuses=%v errors=%d p95=%.2fms heap=%.1fMiB CPU=%.2fs\n", p.Name, p.Statuses, p.NetworkErrors, p.P95, float64(p.PeakHeap)/(1<<20), p.CPUSeconds)
		if p.NetworkErrors != 0 || p.Unexpected != 0 || p.PeakActive > 8 || p.PeakReserved > 4<<20 {
			r.Failures = append(r.Failures, "workload/resource invariant: "+p.Name)
		}
		if p.Name == "steady clean" && p.Statuses[200] != p.Requests {
			r.Failures = append(r.Failures, "steady clean traffic was rejected")
		}
	}
	// A barrier waits for the bounded writer. Loss remains visible in health even
	// when the queue has drained; overload logging is intentionally best-effort.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	for g.ResourceStatus()["active"] != 0 && ctx.Err() == nil {
		time.Sleep(10 * time.Millisecond)
	}
	_ = g.FlushEvents(ctx)
	cancel()
	r.Resources = g.ResourceStatus()
	r.Storage = g.StorageStatus()
	r.Summary = g.Summary()
	if r.Storage.QueueDropped != 0 || r.Storage.WriteFailed != 0 || r.Storage.IngestTimeouts != 0 || r.Storage.CommittedOccurrences != r.Summary["security_occurrences"].(uint64) {
		r.Failures = append(r.Failures, "security event accounting did not reconcile without loss/timeouts")
	}
	info, err := os.Stat(path + ".events.db")
	if err != nil {
		return err
	}
	r.DatabaseBytes = info.Size()
	if r.Resources["active"] != 0 || r.Resources["reserved_buffer_bytes"] != int64(0) || r.DatabaseBytes > 4<<20 || r.Storage.Stored > 300 || r.Storage.Pending != 0 {
		r.Failures = append(r.Failures, "final resource/storage budgets did not settle")
	}
	if err = os.MkdirAll(filepath.Dir(*out), 0755); err != nil {
		return err
	}
	data, err = json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(*out, append(data, '\n'), 0600); err != nil {
		return err
	}
	fmt.Printf("Storage: retained=%d dropped=%d failed=%d; report %s\n", r.Storage.Stored, r.Storage.QueueDropped, r.Storage.WriteFailed, *out)
	if len(r.Failures) > 0 {
		return fmt.Errorf("qualification invariants failed: %v", r.Failures)
	}
	return nil
}
