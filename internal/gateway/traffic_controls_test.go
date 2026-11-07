package gateway

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBoundedClientRatesAndRefill(t *testing.T) {
	b := &resourceBudget{limits: ResourceLimits{}.defaults()}
	now := time.Now()
	c := TrafficControls{RequestsPerSecond: 2, Burst: 2, ClientRequestsPerSecond: 1, ClientBurst: 1}
	first := b.admit("shop", "192.0.2.1", 4, c, 2, now)
	if first.status != 0 {
		t.Fatal(first)
	}
	first.release()
	if result := b.admit("shop", "192.0.2.1", 4, c, 2, now); result.status != 429 || result.retry != 1 {
		t.Fatal("client rate bypass", result)
	}
	second := b.admit("shop", "192.0.2.2", 4, c, 2, now)
	if second.status != 0 {
		t.Fatal(second)
	}
	second.release()
	if result := b.admit("shop", "192.0.2.3", 4, c, 2, now); result.status != 429 {
		t.Fatal("application rate bypass")
	}
	other := b.admit("portal", "192.0.2.1", 4, c, 2, now)
	if other.status != 0 {
		t.Fatal("rate leaked to another application")
	}
	other.release()
	refilled := b.admit("shop", "192.0.2.1", 4, c, 2, now.Add(time.Second))
	if refilled.status != 0 {
		t.Fatal("bucket did not refill")
	}
	refilled.release()
	if b.active != 0 || b.reserved != 0 {
		t.Fatal("rate rejection leaked admission")
	}
}

func TestBusyApplicationCannotOccupyAnotherApplicationsShare(t *testing.T) {
	g, _ := applicationFixture(t)
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
		fmt.Fprint(w, "released")
	}))
	defer up.Close()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	g.budget.mu.Lock()
	g.budget.limits.MaxConcurrent = 4
	g.budget.mu.Unlock()
	c := g.Config()
	c.Applications[0].Upstream = up.URL
	if _, err := g.Apply(c, false); err != nil {
		t.Fatal(err)
	}
	done := make(chan int, 2)
	for i := 0; i < 2; i++ {
		go func() { done <- applicationRequest(g, "shop.test", "/", "").Code }()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("held requests did not reach backend")
		}
	}
	if w := applicationRequest(g, "shop.test", "/", ""); w.Code != 503 {
		t.Fatal("busy application exceeded its share", w.Code)
	}
	if w := applicationRequest(g, "portal.test", "/", ""); w.Code != 200 {
		t.Fatal("other application was starved", w.Code)
	}
	close(release)
	for i := 0; i < 2; i++ {
		if code := <-done; code != 200 {
			t.Fatal("held request failed", code)
		}
	}
}

func TestAdmissionFairnessAndClientConcurrency(t *testing.T) {
	b := &resourceBudget{limits: ResourceLimits{MaxConcurrent: 4, BufferBytes: 4 << 20}.defaults()}
	now := time.Now()
	c := TrafficControls{MaxClientConcurrent: 1}
	one := b.admit("shop", "192.0.2.1", 1<<20, c, 2, now)
	if one.status != 0 {
		t.Fatal(one)
	}
	if result := b.admit("shop", "192.0.2.1", 4, c, 2, now); result.status != 503 {
		t.Fatal("client monopolized concurrency")
	}
	two := b.admit("shop", "192.0.2.2", 1<<20, c, 2, now)
	if two.status != 0 {
		t.Fatal(two)
	}
	if result := b.admit("shop", "192.0.2.3", 4, c, 2, now); result.status != 503 {
		t.Fatal("application exceeded reserved share")
	}
	other := b.admit("portal", "192.0.2.1", 2<<20, c, 2, now)
	if other.status != 0 {
		t.Fatal("busy application starved another", other)
	}
	one.release()
	two.release()
	other.release()
	if b.active != 0 || b.reserved != 0 {
		t.Fatal("admission release leaked resources")
	}
}

func TestClientTableBoundExpiryAndActiveRetention(t *testing.T) {
	b := &resourceBudget{limits: ResourceLimits{}.defaults()}
	now := time.Now()
	c := TrafficControls{ClientRequestsPerSecond: 1, ClientBurst: 1}
	for i := 0; i < maxClientBuckets; i++ {
		r := b.admit("shop", fmt.Sprint(i), 4, c, 1, now)
		if r.status != 0 {
			t.Fatal(i, r)
		}
		r.release()
	}
	if r := b.admit("shop", "overflow", 4, c, 1, now); r.status != 429 || len(b.applications["shop"].clients) != maxClientBuckets {
		t.Fatal("unbounded client table")
	}
	active := b.admit("shop", "0", 4, c, 1, now.Add(time.Second))
	if active.status != 0 {
		t.Fatal(active)
	}
	after := b.admit("shop", "after-expiry", 4, c, 1, now.Add(11*time.Minute))
	if after.status != 0 {
		t.Fatal("idle entries did not expire", after)
	}
	after.release()
	if b.applications["shop"].clients["0"] == nil {
		t.Fatal("active client entry was evicted")
	}
	active.release()
}

func TestRateRejectionsPersistAndSurvivePolicyUpdates(t *testing.T) {
	g, _ := applicationFixture(t)
	c := g.Config()
	c.Applications[0].Policy.Mode = "disabled"
	c.Applications[0].TrafficControls = &TrafficControls{RequestsPerSecond: 1, Burst: 1, ClientRequestsPerSecond: 1, ClientBurst: 1}
	if _, err := g.Apply(c, false); err != nil {
		t.Fatal(err)
	}
	if w := applicationRequest(g, "shop.test", "/", ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	for i := 0; i < 100; i++ {
		w := applicationRequest(g, "shop.test", "/", "")
		if w.Code != 429 || w.Header().Get("Retry-After") == "" {
			t.Fatalf("rate rejection %d", w.Code)
		}
	}
	// A save with the same rate preserves consumed credit.
	c = g.Config()
	c.Applications[0].Name = "Updated shop"
	if _, err := g.Apply(c, false); err != nil {
		t.Fatal(err)
	}
	g.budget.mu.Lock()
	tokens := g.budget.applications["shop"].bucket.tokens
	g.budget.mu.Unlock()
	if tokens < 0 || tokens > 1 {
		t.Fatal("invalid policy-update credit")
	}
	if w := applicationRequest(g, "portal.test", "/", ""); w.Code != 200 {
		t.Fatal("rate leaked across application")
	}
	if err := g.flushOverloads(context.Background()); err != nil {
		t.Fatal(err)
	}
	if g.Summary()["rate_limited_requests"] != uint64(100) {
		t.Fatal(g.Summary())
	}
	if g.StorageStatus().CommittedOccurrences != 100 {
		t.Fatal("rate rejection occurrences were lost")
	}
	state, err := CheckState(g.path, false)
	if err != nil || !state.TrafficControls {
		t.Fatal("upgrade metadata lost rate requirements", err)
	}
}

func TestTokenBucketPolicyChangePreservesCredit(t *testing.T) {
	now := time.Now()
	var bucket tokenBucket
	bucket.refill(now, 10, 10)
	bucket.tokens = 0
	bucket.refill(now.Add(100*time.Millisecond), 1, 10)
	if bucket.tokens != 1 {
		t.Fatal("old rate was not settled at policy change", bucket.tokens)
	}
	bucket.tokens = 0
	bucket.refill(now.Add(200*time.Millisecond), 1, 10)
	if bucket.tokens < 0.099 || bucket.tokens > 0.101 {
		t.Fatal("policy change reset credit or retained old rate", bucket.tokens)
	}
}

func TestRateIdentityUsesValidatedProxyProfile(t *testing.T) {
	g, _ := applicationFixture(t)
	trust, err := newProxyTrust([]string{"192.0.2.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	g.proxyTrust = trust
	c := g.Config()
	c.Applications[0].TrafficControls = &TrafficControls{ClientRequestsPerSecond: 1, ClientBurst: 1}
	if _, err := g.Apply(c, false); err != nil {
		t.Fatal(err)
	}
	for i, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.1"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Host = "shop.test"
		r.RemoteAddr = "192.0.2.1:1234"
		r.Header.Set("X-Forwarded-For", ip)
		r.Header.Set("User-Agent", "OpenWAF rate test")
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		want := 200
		if i == 2 {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("validated client key %s: %d", ip, w.Code)
		}
	}
}

func FuzzAdmissionAccounting(f *testing.F) {
	f.Add([]byte{0, 0, 1, 2, 3, 4, 7, 0, 1, 5})
	f.Fuzz(func(t *testing.T, sequence []byte) {
		if len(sequence) > 128 {
			sequence = sequence[:128]
		}
		b := &resourceBudget{limits: ResourceLimits{MaxConcurrent: 16, BufferBytes: 4 << 20}.defaults()}
		now := time.Now()
		var releases []func()
		for i, value := range sequence {
			if value%3 == 0 && len(releases) > 0 {
				releases[0]()
				releases = releases[1:]
			} else {
				c := TrafficControls{RequestsPerSecond: int(value%7) + 1, Burst: 8, ClientRequestsPerSecond: 1, ClientBurst: 4, MaxClientConcurrent: 2}
				r := b.admit(fmt.Sprint(value%2), fmt.Sprint(value%32), int64(value)+1024, c, 2, now.Add(time.Duration(i)*time.Millisecond))
				if r.status == 0 {
					releases = append(releases, r.release)
				}
			}
			active := 0
			var reserved int64
			for _, app := range b.applications {
				active += app.active
				reserved += app.reserved
				if app.active < 0 || app.reserved < 0 || len(app.clients) > maxClientBuckets {
					t.Fatal("invalid application accounting")
				}
			}
			if b.active != active || b.reserved != reserved || b.active > 16 || b.reserved > 4<<20 {
				t.Fatal("global admission conservation failed")
			}
		}
		for _, release := range releases {
			release()
		}
		if b.active != 0 || b.reserved != 0 {
			t.Fatal("admission did not fully release")
		}
	})
}
