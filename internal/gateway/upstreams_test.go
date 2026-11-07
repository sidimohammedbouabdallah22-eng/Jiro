package gateway

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPoolClientCancellationDoesNotTripBackendCircuit(t *testing.T) {
	p := newUpstreamRuntime(UpstreamPool{Backends: []Backend{{ID: "one", URL: "http://127.0.0.1:1"}}, FailureThreshold: 1, CooldownSeconds: 10, HeaderTimeoutSeconds: 1})
	defer p.close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request, _ := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1:1", nil)
	if _, err := p.selectBackend(time.Now()).RoundTrip(request); err == nil {
		t.Fatal("expected cancelled transport")
	}
	if p.status()[0].Failures != 0 || p.status()[0].State != "unknown" {
		t.Fatal("client cancellation opened backend circuit")
	}
}

func TestPoolExpiredRequestBudgetDoesNotTripBackendCircuit(t *testing.T) {
	p := newUpstreamRuntime(UpstreamPool{Backends: []Backend{{ID: "one", URL: "http://127.0.0.1:1"}}, FailureThreshold: 1, CooldownSeconds: 10, HeaderTimeoutSeconds: 1})
	defer p.close()
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1:1", nil)
	if _, err := p.selectBackend(time.Now()).RoundTrip(request); err == nil {
		t.Fatal("expected exhausted request budget")
	}
	if p.status()[0].Failures != 0 || p.status()[0].State != "unknown" {
		t.Fatal("budget exhausted before transport opened backend circuit")
	}
}

func TestPoolRequestDeadlineDuringTransportDoesNotTripBackendCircuit(t *testing.T) {
	entered := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
	}))
	defer backend.Close()
	p := newUpstreamRuntime(UpstreamPool{Backends: []Backend{{ID: "one", URL: backend.URL}}, FailureThreshold: 1, CooldownSeconds: 10, HeaderTimeoutSeconds: 1})
	defer p.close()
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, "GET", backend.URL, nil)
	if _, err := p.selectBackend(time.Now()).RoundTrip(request); err == nil {
		t.Fatal("expected request deadline")
	}
	select {
	case <-entered:
	default:
		t.Fatal("request expired before transport began")
	}
	if p.status()[0].Failures != 0 || p.status()[0].State != "unknown" {
		t.Fatal("total request deadline opened backend circuit")
	}
}

func TestPoolTLSVerificationAndHeaderDeadline(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer backend.Close()
	config := UpstreamPool{Backends: []Backend{{ID: "tls", URL: backend.URL, ServerName: "example.com"}}, FailureThreshold: 1, CooldownSeconds: 1, HeaderTimeoutSeconds: 1}
	p := newUpstreamRuntime(config)
	defer p.close()
	req, _ := http.NewRequest("GET", backend.URL, nil)
	if response, err := p.selectBackend(time.Now()).RoundTrip(req); err == nil {
		response.Body.Close()
		t.Fatal("accepted untrusted backend certificate")
	}
	if p.status()[0].State != "unavailable" {
		t.Fatal("TLS failure did not open circuit")
	}
	trusted := newUpstreamRuntime(config)
	defer trusted.close()
	roots := x509.NewCertPool()
	roots.AddCert(backend.Certificate())
	trusted.backends[0].transport.TLSClientConfig.RootCAs = roots
	response, err := trusted.selectBackend(time.Now()).RoundTrip(req)
	if err != nil {
		t.Fatal("trusted matching SAN rejected", err)
	}
	response.Body.Close()
	wrong := newUpstreamRuntime(config)
	defer wrong.close()
	wrong.backends[0].transport.TLSClientConfig.RootCAs = roots
	wrong.backends[0].transport.TLSClientConfig.ServerName = "wrong.test"
	if response, err := wrong.selectBackend(time.Now()).RoundTrip(req); err == nil {
		response.Body.Close()
		t.Fatal("accepted wrong backend SAN")
	}
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer slow.Close()
	config.Backends = []Backend{{ID: "slow", URL: slow.URL}}
	timed := newUpstreamRuntime(config)
	defer timed.close()
	req, _ = http.NewRequest("GET", slow.URL, nil)
	started := time.Now()
	if response, err := timed.selectBackend(time.Now()).RoundTrip(req); err == nil {
		response.Body.Close()
		t.Fatal("header timeout was ignored")
	}
	if time.Since(started) > 3*time.Second {
		t.Fatal("header deadline exceeded")
	}
}

func TestPoolInspectionRoundRobinAndNoPOSTReplay(t *testing.T) {
	var failedCalls, healthyCalls atomic.Int32
	failed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		failedCalls.Add(1)
		w.WriteHeader(500)
		fmt.Fprint(w, "backend failure")
	}))
	defer failed.Close()
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		healthyCalls.Add(1)
		data, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/plain")
		w.Write(data)
	}))
	defer healthy.Close()
	g, _ := applicationFixture(t)
	c := g.Config()
	c.Applications[0].Upstream = failed.URL
	c.Applications[0].Pool = &UpstreamPool{Backends: []Backend{{ID: "one", URL: failed.URL}, {ID: "two", URL: healthy.URL}}, FailureThreshold: 1, CooldownSeconds: 30, HeaderTimeoutSeconds: 1}
	if _, err := g.Apply(c, false); err != nil {
		t.Fatal(err)
	}
	if got := g.active.Load().applications["shop"].pool.status()[0].State; got != "unknown" {
		t.Fatal("unobserved backend reported ready", got)
	}
	front := httptest.NewServer(g)
	defer front.Close()
	send := func(body string) int {
		req, _ := http.NewRequest("POST", front.URL+"/api", strings.NewReader(body))
		req.Host = "shop.test"
		req.Header.Set("User-Agent", "OpenWAF pool test")
		req.Header.Set("Content-Type", "application/json")
		resp, err := front.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}
	if status := send(`{"value":"<script>alert(1)</script>"}`); status != 403 {
		t.Fatal("inspection bypassed", status)
	}
	if failedCalls.Load() != 0 || healthyCalls.Load() != 0 {
		t.Fatal("blocked request reached pool")
	}
	if status := send(`{"value":"benign"}`); status != 500 {
		t.Fatal(status)
	}
	if failedCalls.Load() != 1 || healthyCalls.Load() != 0 {
		t.Fatal("POST was replayed to another backend")
	}
	for range 3 {
		if status := send(`{"value":"benign"}`); status != 200 {
			t.Fatal(status)
		}
	}
	if failedCalls.Load() != 1 || healthyCalls.Load() != 3 {
		t.Fatal("circuit did not exclude failed backend")
	}
	state := g.active.Load().applications["shop"].pool.status()
	if state[0].State != "unavailable" || state[1].State != "observed_healthy" {
		t.Fatal(state)
	}
}

func TestPoolCircuitEpochAndSingleRecoveryTrial(t *testing.T) {
	p := newUpstreamRuntime(UpstreamPool{Backends: []Backend{{ID: "one", URL: "http://127.0.0.1:1"}}, FailureThreshold: 1, CooldownSeconds: 1, HeaderTimeoutSeconds: 1})
	defer p.close()
	old := p.selectBackend(time.Now())
	failing := p.selectBackend(time.Now())
	no, yes := false, true
	failing.finish(&no)
	old.finish(&yes)
	if p.selectBackend(time.Now()) != nil || p.status()[0].State != "unavailable" {
		t.Fatal("old response cleared a newer circuit failure")
	}
	p.mu.Lock()
	p.backends[0].blockedUntil = time.Now().Add(-time.Second)
	p.mu.Unlock()
	trial := p.selectBackend(time.Now())
	if trial == nil || p.selectBackend(time.Now()) != nil {
		t.Fatal("recovery trial was not exclusive")
	}
	trial.finish(&yes)
	if p.status()[0].State != "observed_healthy" {
		t.Fatal("successful trial failed to recover backend")
	}
}
