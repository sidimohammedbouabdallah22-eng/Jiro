package gateway

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestAdmissionRollupDoesNotMisattributeMixedReasons(t *testing.T) {
	g, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {})
	for i, reason := range []string{"Client concurrency share exhausted", "Application admission share exhausted"} {
		g.recordOverload(Event{ID: []string{"reason-one", "reason-two"}[i], Time: time.Now(), PolicyRevision: 1,
			ApplicationID: "primary", IP: "192.0.2.1", Method: "GET", Path: "/", Action: "overloaded", Status: 503, Reason: reason})
	}
	if err := g.flushOverloads(context.Background()); err != nil {
		t.Fatal(err)
	}
	events := g.Events()
	if len(events) != 1 || events[0].Occurrences != 2 || events[0].Status != 503 || events[0].Reason != "Aggregated capacity rejections with different reasons" {
		t.Fatal("rollup attributed mixed refusals to first cause", events)
	}
}
