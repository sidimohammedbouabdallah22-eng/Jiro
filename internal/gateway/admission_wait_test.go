package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func awaitPending(t *testing.T, b *resourceBudget, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		b.mu.Lock()
		got := b.pending
		b.mu.Unlock()
		if got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("pending admissions did not reach %d", want)
}

func TestAdmissionWaitBriefOverlapKeepsReservation(t *testing.T) {
	b := &resourceBudget{limits: ResourceLimits{}.defaults()}
	c := TrafficControls{MaxConcurrent: 1, MaxClientConcurrent: 1, AdmissionWaitMS: 1000}
	first := b.admit("shop", "one", 100, c, 2, time.Now())
	if first.status != 0 {
		t.Fatal(first)
	}
	done := make(chan admissionResult, 1)
	go func() { done <- b.admitWaiting(context.Background(), "shop", "one", 100, c, 2) }()
	awaitPending(t, b, 1)
	b.mu.Lock()
	if b.active != 1 || b.reserved != 100 {
		t.Error("waiter reserved active/body capacity")
	}
	b.mu.Unlock()
	// A second waiter from the same client is refused, not allowed to grow a queue.
	if r := b.admitWaiting(context.Background(), "shop", "one", 100, c, 2); r.status != 503 {
		t.Fatal(r)
	}
	first.release()
	r := <-done
	if r.status != 0 {
		t.Fatal("brief overlap refused", r)
	}
	r.release()
	if b.pending != 0 || b.active != 0 || b.reserved != 0 || b.fairRejected != 1 {
		t.Fatal("queue/reservation/counter leak")
	}
	if b.waitEntered != 1 || b.waitAdmitted != 1 || b.waitCapacityRefused != 1 {
		t.Fatal("wait accounting mismatch")
	}
}

func TestAdmissionWaitImpossibleReservationRefusesImmediately(t *testing.T) {
	b := &resourceBudget{limits: ResourceLimits{}.defaults()}
	c := TrafficControls{AdmissionWaitMS: 1000}
	r := b.admitWaiting(context.Background(), "shop", "one", b.limits.BufferBytes, c, 2)
	if r.status != 503 || b.pending != 0 || b.waitEntered != 0 || b.reserved != 0 {
		t.Fatal("impossible reservation entered queue")
	}
}

func TestAdmissionWaitTimeoutCancellationAndRates(t *testing.T) {
	for _, cancelEarly := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelEarly), func(t *testing.T) {
			b := &resourceBudget{limits: ResourceLimits{}.defaults()}
			c := TrafficControls{MaxConcurrent: 1, AdmissionWaitMS: 40}
			first := b.admit("shop", "busy", 4, c, 2, time.Now())
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan admissionResult, 1)
			go func() { done <- b.admitWaiting(ctx, "shop", "next", 4, c, 2) }()
			awaitPending(t, b, 1)
			if cancelEarly {
				cancel()
			}
			r := <-done
			if r.status != 503 || r.release != nil || b.pending != 0 || b.reserved != 4 || b.fairRejected != 1 {
				t.Fatal(r, b.pending)
			}
			if !cancelEarly && b.waitExpired != 1 {
				t.Fatal("timeout not counted")
			}
			first.release()
		})
	}
	b := &resourceBudget{limits: ResourceLimits{}.defaults()}
	c := TrafficControls{MaxConcurrent: 1, ClientRequestsPerSecond: 1, ClientBurst: 1, AdmissionWaitMS: 1000}
	first := b.admit("shop", "one", 4, c, 2, time.Now())
	done := make(chan admissionResult, 1)
	go func() { done <- b.admitWaiting(context.Background(), "shop", "one", 4, c, 2) }()
	awaitPending(t, b, 1)
	first.release()
	if r := <-done; r.status != 429 || b.rateRejected != 1 || b.fairRejected != 0 {
		t.Fatal("waiting bypassed/consumed rate budget", r)
	}
}

func TestAdmissionWaitGlobalAndApplicationCaps(t *testing.T) {
	b := &resourceBudget{limits: ResourceLimits{MaxConcurrent: 2}.defaults()}
	c := TrafficControls{AdmissionWaitMS: 1000}
	holds := []admissionResult{b.admit("a", "busy", 4, c, 2, time.Now()), b.admit("b", "busy", 4, c, 2, time.Now())}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan admissionResult, 8)
	for _, app := range []string{"a", "b"} {
		for i := 0; i < 4; i++ {
			go func(id, ip string) { done <- b.admitWaiting(ctx, id, ip, 4, c, 2) }(app, fmt.Sprint(i))
		}
	}
	awaitPending(t, b, 8)
	if r := b.admitWaiting(ctx, "a", "extra", 4, c, 2); r.status != 503 {
		t.Fatal("unbounded global queue", r)
	}
	cancel()
	for i := 0; i < 8; i++ {
		if r := <-done; r.status != 503 {
			t.Fatal(r)
		}
	}
	if b.pending != 0 || len(b.pendingApps) != 0 || len(b.pendingClients) != 0 || b.active != 2 || b.fairRejected != 9 {
		t.Fatal("queue cap/accounting leak")
	}
	for _, hold := range holds {
		hold.release()
	}
}

func TestAdmissionWaitPolicyEpochCancelsBeforeCapacityRelease(t *testing.T) {
	b := &resourceBudget{limits: ResourceLimits{}.defaults()}
	c := TrafficControls{MaxConcurrent: 1, AdmissionWaitMS: 1000}
	hold := b.admit("shop", "busy", 4, c, 2, time.Now())
	defer hold.release()
	done := make(chan admissionResult, 1)
	go func() { done <- b.admitWaiting(context.Background(), "shop", "next", 4, c, 2) }()
	awaitPending(t, b, 1)
	b.configureApplications(Config{SchemaVersion: 2, Applications: []Application{{ApplicationID: "shop"}, {ApplicationID: "portal"}}})
	r := <-done
	if r.status != 503 || r.reason != "Policy changed during admission" || r.release != nil {
		t.Fatal("policy activation did not cancel the old admission", r)
	}
	if b.waitPolicyChanged != 1 || b.waitExpired != 0 || b.pending != 0 || b.active != 1 || b.reserved != 4 {
		t.Fatal("policy cancellation leaked or released the held reservation")
	}
}

func TestAdmissionWaitNoHeadOfLineBlocking(t *testing.T) {
	b := &resourceBudget{limits: ResourceLimits{}.defaults()}
	c := TrafficControls{MaxConcurrent: 2, MaxClientConcurrent: 1, AdmissionWaitMS: 1000}
	bad := b.admit("shop", "bad", 4, c, 2, time.Now())
	good := b.admit("shop", "good", 4, c, 2, time.Now())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	badDone, goodDone := make(chan admissionResult, 1), make(chan admissionResult, 1)
	go func() { badDone <- b.admitWaiting(ctx, "shop", "bad", 4, c, 2) }()
	awaitPending(t, b, 1)
	go func() { goodDone <- b.admitWaiting(ctx, "shop", "good", 4, c, 2) }()
	awaitPending(t, b, 2)
	good.release()
	select {
	case r := <-goodDone:
		if r.status != 0 {
			t.Fatal(r)
		}
		r.release()
	case <-time.After(800 * time.Millisecond):
		t.Fatal("busy client blocked eligible client")
	}
	cancel()
	if r := <-badDone; r.status != 503 {
		t.Fatal(r)
	}
	bad.release()
}

func TestAdmissionWaitPolicyChangeAndShutdown(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		t.Run(fmt.Sprint(shutdown), func(t *testing.T) {
			g, _ := applicationFixture(t)
			c := g.Config()
			controls := TrafficControls{MaxConcurrent: 1, AdmissionWaitMS: 1000}
			c.Applications[0].TrafficControls = &controls
			if _, err := g.Apply(c, false); err != nil {
				t.Fatal(err)
			}
			hold := g.budget.admit("shop", "busy", 4, controls, 2, time.Now())
			defer hold.release()
			done := make(chan int, 1)
			go func() { done <- applicationRequest(g, "shop.test", "/", "").Code }()
			awaitPending(t, g.budget, 1)
			// Check the lock itself: Apply also compiles the full CRS, whose
			// runtime under race instrumentation is not an admission deadline.
			if !g.lifecycle.TryLock() {
				t.Fatal("admission wait held lifecycle lock")
			}
			g.lifecycle.Unlock()
			changed := make(chan struct{})
			go func() {
				defer close(changed)
				if shutdown {
					g.Close(context.Background())
				} else {
					_, err := g.Apply(g.Config(), false)
					if err != nil {
						t.Error(err)
					}
				}
			}()
			select {
			case <-changed:
			case <-time.After(15 * time.Second):
				t.Fatal("policy change or shutdown did not complete")
			}
			if code := <-done; code != 503 {
				t.Fatal("stale/closed runtime dispatched", code)
			}
			if g.budget.pending != 0 {
				t.Fatal("pending leak")
			}
		})
	}
}

func TestAdmissionWaitPolicyBoundsAndLegacyEncoding(t *testing.T) {
	for _, value := range []int{-1, 1001} {
		if err := (TrafficControls{AdmissionWaitMS: value}).validate(); err == nil {
			t.Fatal("unbounded wait accepted")
		}
	}
	data, err := json.Marshal(TrafficControls{MaxConcurrent: 1})
	if err != nil || strings.Contains(string(data), "admission_wait_ms") {
		t.Fatal("zero wait changes old policy encoding", string(data), err)
	}
}

func TestAdmissionWaitIncludedInEventDuration(t *testing.T) {
	g, _ := applicationFixture(t)
	c := g.Config()
	controls := TrafficControls{MaxConcurrent: 1, AdmissionWaitMS: 1000}
	c.Applications[0].TrafficControls = &controls
	if _, err := g.Apply(c, false); err != nil {
		t.Fatal(err)
	}
	hold := g.budget.admit("shop", "busy", 4, controls, 2, time.Now())
	done := make(chan int, 1)
	go func() { done <- applicationRequest(g, "shop.test", "/shop-only", "").Code }()
	awaitPending(t, g.budget, 1)
	time.Sleep(25 * time.Millisecond)
	hold.release()
	if code := <-done; code != 403 {
		t.Fatal("inspection bypassed after wait", code)
	}
	events := g.Events()
	if len(events) != 1 || events[0].Duration < 20 || events[0].UpstreamAttempted {
		t.Fatal("event omitted wait or forwarded blocked request", events)
	}
}
