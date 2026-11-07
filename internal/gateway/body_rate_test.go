package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBodyByteBudgetRefillAndAtomicAdmission(t *testing.T) {
	b := &resourceBudget{limits: ResourceLimits{}.defaults()}
	now := time.Now()
	c := TrafficControls{ClientBodyKiBPerSecond: 128, ClientBodyBurstKiB: 4096, bodyKiB: 1024}
	for i := 0; i < 4; i++ {
		result := b.admit("shop", "192.0.2.1", 4, c, 2, now)
		if result.status != 0 {
			t.Fatal(result)
		}
		result.release()
	}
	if result := b.admit("shop", "192.0.2.1", 4, c, 2, now); result.status != 429 || result.retry != 8 {
		t.Fatal("body budget bypass", result)
	}
	for _, target := range []struct{ app, ip string }{{"portal", "192.0.2.1"}, {"shop", "192.0.2.2"}} {
		result := b.admit(target.app, target.ip, 4, c, 2, now)
		if result.status != 0 {
			t.Fatal("body quota crossed identity boundary", result)
		}
		result.release()
	}
	c.bodyKiB = 0
	asset := b.admit("shop", "192.0.2.1", 4, c, 2, now)
	if asset.status != 0 {
		t.Fatal("body quota blocked an asset", asset)
	}
	asset.release()
	c.bodyKiB = 1024
	refilled := b.admit("shop", "192.0.2.1", 4, c, 2, now.Add(8*time.Second))
	if refilled.status != 0 {
		t.Fatal("body quota did not refill", refilled)
	}
	refilled.release()
	// A capacity refusal cannot spend body credit.
	c.MaxConcurrent = 1
	held := b.admit("other", "192.0.2.1", 4, c, 2, now)
	if held.status != 0 {
		t.Fatal(held)
	}
	if result := b.admit("other", "192.0.2.1", 4, c, 2, now); result.status != 503 {
		t.Fatal(result)
	}
	held.release()
	if tokens := b.applications["other"].clients["192.0.2.1"].bodyBucket.tokens; tokens != 3072 {
		t.Fatal("capacity refusal consumed body credit", tokens)
	}
}

type unreadBodyProbe struct{ reads int }

func (p *unreadBodyProbe) Read([]byte) (int, error) { p.reads++; return 0, io.EOF }
func (p *unreadBodyProbe) Close() error             { return nil }

func TestBodyByteBudgetGatewayAndUnknownLength(t *testing.T) {
	g, _ := applicationFixture(t)
	c := g.Config()
	c.Applications[0].Policy.Mode = "disabled"
	c.Applications[0].Policy.RequestLimit = 1 << 20
	c.Applications[0].TrafficControls = &TrafficControls{ClientBodyKiBPerSecond: 2, ClientBodyBurstKiB: 1024}
	if _, err := g.Apply(c, false); err != nil {
		t.Fatal(err)
	}
	if response := applicationRequest(g, "shop.test", "/", strings.Repeat("a", 1<<20)); response.Code != 200 {
		t.Fatal("initial body refused", response.Code)
	}
	if response := applicationRequest(g, "shop.test", "/asset", ""); response.Code != 200 {
		t.Fatal("asset refused", response.Code)
	}
	probe := &unreadBodyProbe{}
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Host, r.Body, r.ContentLength = "shop.test", probe, -1
	r.Header.Set("User-Agent", "OpenWAF body quota test")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != 429 || probe.reads != 0 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("unknown-length quota bypass: status=%d reads=%d", w.Code, probe.reads)
	}
	if g.ResourceStatus()["active"] != 0 || g.ResourceStatus()["reserved_buffer_bytes"] != int64(0) {
		t.Fatal("body quota leaked reservations")
	}
}

func TestBodyByteBudgetValidation(t *testing.T) {
	for _, controls := range []TrafficControls{
		{ClientBodyKiBPerSecond: 1}, {ClientBodyBurstKiB: 1},
		{ClientBodyKiBPerSecond: -1, ClientBodyBurstKiB: 1},
		{ClientBodyKiBPerSecond: 1, ClientBodyBurstKiB: 601},
	} {
		if controls.validate() == nil {
			t.Fatal("invalid body budget accepted", controls)
		}
	}
	if err := (TrafficControls{ClientBodyKiBPerSecond: 128, ClientBodyBurstKiB: 512}).validateBuffer(Config{RequestLimit: 1 << 20}); err == nil {
		t.Fatal("burst smaller than one supported request accepted")
	}
}
