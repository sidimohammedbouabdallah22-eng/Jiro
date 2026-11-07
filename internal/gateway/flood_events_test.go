package gateway

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/eventstore"
)

func TestFloodSummariesAccountForEveryRejectedRequest(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var once sync.Once
	releaseNow := func() { once.Do(func() { close(release) }) }
	defer releaseNow()
	g := protocolGateway(t, Options{Resources: ResourceLimits{MaxConcurrent: 1}}, func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
		}
		w.Write([]byte("ok"))
	})
	finished := make(chan int, 1)
	go func() { finished <- request(g, "GET", "/held", "", "").Code }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("first request not active")
	}
	const count = 500
	var wg sync.WaitGroup
	errors := make(chan int, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest("GET", fmt.Sprintf("/busy/%d", i), nil)
			r.RemoteAddr = fmt.Sprintf("192.0.2.%d:1234", i%2+1)
			w := httptest.NewRecorder()
			g.ServeHTTP(w, r)
			if w.Code != 503 {
				errors <- w.Code
			}
		}()
	}
	wg.Wait()
	close(errors)
	for code := range errors {
		t.Fatalf("capacity rejection: %d", code)
	}
	releaseNow()
	if code := <-finished; code != 200 {
		t.Fatal(code)
	}
	if err := g.FlushEvents(context.Background()); err != nil {
		t.Fatal(err)
	}
	page, err := g.QueryEvents(context.Background(), eventstore.Query{Limit: 100, Action: "overloaded"})
	if err != nil || len(page.Items) == 0 {
		t.Fatalf("summaries missing: %+v %v", page, err)
	}
	var total uint64
	for _, e := range page.Items {
		if !e.Aggregated || e.LastSeen.Before(e.Time) {
			t.Fatalf("summary metadata: %+v", e)
		}
		total += e.Occurrences
	}
	status := g.StorageStatus()
	if total != count || status.CommittedOccurrences != count || status.QueueDropped != 0 || status.IngestTimeouts != 0 || !status.Healthy || g.Summary()["overload_requests"] != uint64(count) {
		t.Fatalf("flood accounting mismatch: total=%d storage=%+v", total, status)
	}
}

func TestRevisionChurnCannotGrowSummaryCardinality(t *testing.T) {
	g := protocolGateway(t, Options{}, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	for i := 1; i <= 100; i++ {
		g.recordOverload(Event{ID: fmt.Sprintf("revision-%d", i), Time: time.Now(), PolicyRevision: uint64(i), ApplicationID: fmt.Sprintf("app%d", i%2), Action: "overloaded", Method: "GET", IP: "192.0.2.1", Path: "/busy", Status: 503})
	}
	if err := g.FlushEvents(context.Background()); err != nil {
		t.Fatal(err)
	}
	page, err := g.QueryEvents(context.Background(), eventstore.Query{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) > 64 {
		t.Fatal("unbounded revision bucket count")
	}
	var total uint64
	overflow := false
	for _, e := range page.Items {
		total += e.Occurrences
		if e.PolicyRevision == 0 {
			overflow = true
			if e.ApplicationID != "*" {
				t.Fatal("mixed-application summary claimed one application identity")
			}
		}
	}
	if total != 100 || !overflow {
		t.Fatalf("summary accounting: %d overflow=%t", total, overflow)
	}
}
