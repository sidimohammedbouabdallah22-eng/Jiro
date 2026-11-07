package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestClientBufferSeparatesLargeBodiesFromSmallReads(t *testing.T) {
	b := &resourceBudget{limits: ResourceLimits{}.defaults()}
	c := TrafficControls{MaxConcurrent: 4, MaxClientConcurrent: 2, MaxClientBufferMiB: 5, ClientRequestsPerSecond: 2, ClientBurst: 4}
	heavy := bufferReservation(900<<10, Config{})
	first := b.admit("shop", "one", heavy, c, 2, time.Now())
	if first.status != 0 {
		t.Fatal(first)
	}
	tokens := b.applications["shop"].clients["one"].bucket.tokens
	if r := b.admit("shop", "one", heavy, c, 2, time.Now()); r.status != 503 || r.reason != "Client buffer share exhausted" {
		t.Fatal("second expensive body was admitted", r)
	}
	if b.applications["shop"].clients["one"].bucket.tokens != tokens {
		t.Fatal("buffer refusal consumed a rate token")
	}
	read := b.admit("shop", "one", 4, c, 2, time.Now())
	other := b.admit("shop", "two", heavy, c, 2, time.Now())
	otherApp := b.admit("portal", "one", heavy, c, 2, time.Now())
	if read.status != 0 || other.status != 0 || otherApp.status != 0 {
		t.Fatal("buffer budget leaked across clients/apps or blocked a small read")
	}
	first.release()
	read.release()
	other.release()
	otherApp.release()
	if b.active != 0 || b.reserved != 0 || b.applications["shop"].clients["one"].reserved != 0 {
		t.Fatal("client reservation was not reclaimed")
	}
}

func TestClientBufferWaitAndImpossibleReservation(t *testing.T) {
	b := &resourceBudget{limits: ResourceLimits{}.defaults()}
	c := TrafficControls{MaxClientBufferMiB: 5, AdmissionWaitMS: 1000}
	heavy := bufferReservation(900<<10, Config{})
	hold := b.admit("shop", "one", heavy, c, 2, time.Now())
	done := make(chan admissionResult, 1)
	go func() { done <- b.admitWaiting(context.Background(), "shop", "one", heavy, c, 2) }()
	awaitPending(t, b, 1)
	hold.release()
	r := <-done
	if r.status != 0 || b.waitAdmitted != 1 {
		t.Fatal("reclaimed client buffer was not available to a waiter", r)
	}
	r.release()
	entered := b.waitEntered
	r = b.admitWaiting(context.Background(), "shop", "one", 6<<20, c, 2)
	if r.status != 503 || b.pending != 0 || b.waitEntered != entered || b.reserved != 0 {
		t.Fatal("impossible client reservation occupied the queue", r)
	}
}

func TestClientBufferPolicySizingAndLegacyEncoding(t *testing.T) {
	for _, value := range []int{-1, 8193} {
		if err := (TrafficControls{MaxClientBufferMiB: value}).validate(); err == nil {
			t.Fatal("invalid client buffer accepted")
		}
	}
	data, err := json.Marshal(TrafficControls{})
	if err != nil || strings.Contains(string(data), "max_client_buffer_mib") {
		t.Fatal("zero budget changed old policy encoding")
	}
	policy := Defaults()
	policy.RequestLimit, policy.ResponseLimit = 1<<20, 2<<20
	app := ApplicationFromConfig(policy, []string{"shop.test"})
	app.TrafficControls = &TrafficControls{MaxClientBufferMiB: 5}
	c := Config{SchemaVersion: 2, Revision: 1, Applications: []Application{app}}
	limits := ResourceLimits{}.defaults()
	if err := c.Validate(); err != nil {
		t.Fatal("full one-MiB envelope does not fit", err)
	}
	b := &resourceBudget{limits: limits}
	r := b.admit("shop", "one", bufferReservation(1<<20, c.Applications[0].config(1)), *c.Applications[0].TrafficControls, 1, time.Now())
	if r.status != 0 {
		t.Fatal("maximum legitimate body was refused", r)
	}
	r.release()
	c.Applications[0].Policy.InspectResponse = true
	if err := c.Validate(); err == nil {
		t.Fatal("client budget ignored inspected response reservation")
	}
	c.Applications[0].TrafficControls.MaxClientBufferMiB = 11
	if err := c.Validate(); err != nil {
		t.Fatal("sufficient request/response budget rejected", err)
	}
}

func TestClientBufferRetainsReservationAcrossPolicyChanges(t *testing.T) {
	b := &resourceBudget{limits: ResourceLimits{}.defaults()}
	c := TrafficControls{MaxClientBufferMiB: 5}
	heavy := bufferReservation(900<<10, Config{})
	hold := b.admit("shop", "one", heavy, c, 2, time.Now())
	b.configureApplications(Config{SchemaVersion: 2})
	b.configureApplications(Config{SchemaVersion: 2, Applications: []Application{{ApplicationID: "shop", TrafficControls: &c}}})
	if r := b.admit("shop", "one", heavy, c, 1, time.Now()); r.status != 503 {
		t.Fatal("policy change forgot live client reservation", r)
	}
	hold.release()
	r := b.admit("shop", "one", heavy, c, 1, time.Now())
	if r.status != 0 {
		t.Fatal("old-policy release did not reclaim client reservation", r)
	}
	r.release()
}
