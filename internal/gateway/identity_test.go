package gateway

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestProxyTrustConfiguration(t *testing.T) {
	for _, networks := range [][]string{{"0.0.0.0/0"}, {"::/0"}, {"192.0.2.1/24"}, {"192.0.2.1"}, {"::ffff:192.0.2.0/120"}, {"bad"}, {"127.0.0.1/32", "127.0.0.1/32"}, strings.Split(strings.Repeat("127.0.0.1/32,", 32)+"127.0.0.1/32", ",")} {
		if _, err := newProxyTrust(networks); err == nil {
			t.Fatalf("invalid trust configuration accepted %v", networks)
		}
	}
	a, err := newProxyTrust([]string{"2001:db8::/32", "192.0.2.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := newProxyTrust([]string{"192.0.2.0/24", "2001:DB8::/32"})
	if err != nil || a.configHash != b.configHash {
		t.Fatal("equivalent trust configurations have different digests")
	}
}

func TestForwardedIdentityBoundaryAndBounds(t *testing.T) {
	trust, err := newProxyTrust([]string{"10.0.0.0/8", "2001:db8:ffff::/48"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, peer         string
		xff, proto         []string
		tls                bool
		ip, scheme         string
		forwarded, invalid bool
	}{
		{"untrusted-spoof", "192.0.2.1:5000", []string{"203.0.113.7"}, []string{"https"}, false, "192.0.2.1", "http", false, false},
		{"untrusted-malformed", "192.0.2.1:5000", []string{"unknown"}, []string{"https,http"}, true, "192.0.2.1", "https", false, false},
		{"direct-trusted-peer", "10.0.0.1:5000", nil, nil, false, "10.0.0.1", "http", false, false},
		{"single-proxy", "10.0.0.1:5000", []string{"203.0.113.7"}, []string{"https"}, false, "203.0.113.7", "https", true, false},
		{"trusted-chain", "10.0.0.1:5000", []string{"198.51.100.99, 203.0.113.7, 10.1.0.2"}, nil, false, "203.0.113.7", "http", true, false},
		{"untrusted-middle", "10.0.0.1:5000", []string{"198.51.100.99, 192.0.2.8, 10.1.0.2"}, nil, false, "192.0.2.8", "http", true, false},
		{"all-trusted", "10.0.0.1:5000", []string{"10.2.0.3, 10.1.0.2"}, nil, false, "10.2.0.3", "http", true, false},
		{"multiple-header-lines", "10.0.0.1:5000", []string{"203.0.113.7", "10.1.0.2"}, nil, false, "203.0.113.7", "http", true, false},
		{"ipv6", "[2001:db8:ffff::1]:5000", []string{"2001:db8:1234::7"}, nil, true, "2001:db8:1234::7", "https", true, false},
		{"mapped-ipv4", "[::ffff:10.0.0.1]:5000", []string{"::ffff:203.0.113.7"}, nil, false, "203.0.113.7", "http", true, false},
		{"empty", "10.0.0.1:5000", []string{""}, nil, false, "10.0.0.1", "http", false, true},
		{"empty-hop", "10.0.0.1:5000", []string{"203.0.113.7,"}, nil, false, "10.0.0.1", "http", false, true},
		{"port", "10.0.0.1:5000", []string{"203.0.113.7:443"}, nil, false, "10.0.0.1", "http", false, true},
		{"unknown", "10.0.0.1:5000", []string{"unknown"}, nil, false, "10.0.0.1", "http", false, true},
		{"unicode-whitespace", "10.0.0.1:5000", []string{"\u00a0203.0.113.7"}, nil, false, "10.0.0.1", "http", false, true},
		{"zone", "10.0.0.1:5000", []string{"fe80::1%eth0"}, nil, false, "10.0.0.1", "http", false, true},
		{"unspecified", "10.0.0.1:5000", []string{"0.0.0.0"}, nil, false, "10.0.0.1", "http", false, true},
		{"multicast", "10.0.0.1:5000", []string{"ff02::1"}, nil, false, "10.0.0.1", "http", false, true},
		{"proto-without-client", "10.0.0.1:5000", nil, []string{"https"}, false, "10.0.0.1", "http", false, true},
		{"multiple-protos", "10.0.0.1:5000", []string{"203.0.113.7"}, []string{"https", "http"}, false, "10.0.0.1", "http", false, true},
		{"proto-chain", "10.0.0.1:5000", []string{"203.0.113.7"}, []string{"https,http"}, false, "10.0.0.1", "http", false, true},
		{"too-many-hops", "10.0.0.1:5000", []string{strings.Repeat("203.0.113.7,", 16) + "203.0.113.7"}, nil, false, "10.0.0.1", "http", false, true},
		{"oversized", "10.0.0.1:5000", []string{strings.Repeat(" ", 2048) + "203.0.113.7"}, nil, false, "10.0.0.1", "http", false, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://application.test/", nil)
			r.RemoteAddr = test.peer
			r.Header["X-Forwarded-For"] = test.xff
			r.Header["X-Forwarded-Proto"] = test.proto
			if test.tls {
				r.TLS = &tls.ConnectionState{}
			}
			got := trust.resolve(r)
			if got.IP != test.ip || got.Scheme != test.scheme || got.Forwarded != test.forwarded || got.Invalid != test.invalid {
				t.Fatalf("identity %+v", got)
			}
			if got.Forwarded && got.Port != 0 {
				t.Fatal("client source port was invented")
			}
		})
	}
}

func FuzzForwardedIdentityBoundary(f *testing.F) {
	f.Add("198.51.100.99", "https")
	f.Add("10.1.0.1, 10.2.0.2", "http")
	f.Add("unknown", "https,http")
	trust, err := newProxyTrust([]string{"10.0.0.0/8"})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, prefix, proto string) {
		if len(prefix) > 4096 || len(proto) > 4096 {
			return
		}
		r := httptest.NewRequest("GET", "http://application.test/", nil)
		r.RemoteAddr = "10.0.0.1:5000"
		r.Header.Set("X-Forwarded-For", prefix+", 203.0.113.7")
		r.Header.Set("X-Forwarded-Proto", proto)
		identity := trust.resolve(r)
		if identity.Forwarded && (identity.Invalid || identity.IP != "203.0.113.7") {
			t.Fatalf("untrusted prefix replaced the boundary %+v", identity)
		}
	})
}

func TestTrustedProxyCorazaAndBackendAgree(t *testing.T) {
	seen := make(chan http.Header, 8)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen <- r.Header.Clone(); w.Write([]byte("ok")) }))
	defer up.Close()
	path := filepath.Join(t.TempDir(), "policy.json")
	c := Defaults()
	c.Upstream = up.URL
	c.CustomRules = `SecRule REMOTE_ADDR "@ipMatch 203.0.113.7" "id:10001,phase:1,deny,status:403,log,msg:'Blocked client address'"`
	if err := persist(path, c); err != nil {
		t.Fatal(err)
	}
	g, err := NewWithOptions(path, Options{TrustedProxies: []string{"127.0.0.1/32"}})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close(context.Background())
	front := httptest.NewServer(g)
	defer front.Close()
	call := func(xff string) *http.Response {
		r, _ := http.NewRequest("GET", front.URL+"/", nil)
		r.Host = "application.test"
		r.Header.Set("User-Agent", "OpenWAF identity test")
		r.Header.Set("X-Forwarded-For", xff)
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-Forwarded-Host", "evil.test")
		r.Header.Set("X-Real-IP", "198.51.100.99")
		r.Header.Set("True-Client-IP", "198.51.100.99")
		response, err := front.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		return response
	}
	if response := call("198.51.100.99, 203.0.113.7"); response.StatusCode != 403 {
		t.Fatal("Coraza did not use selected client", response.StatusCode)
	}
	events := g.Events()
	if len(events) != 1 || events[0].IP != "203.0.113.7" || events[0].PeerIP != "127.0.0.1" || events[0].UpstreamAttempted {
		t.Fatalf("incorrect attribution %+v", events)
	}
	if events[0].ProxyConfigSHA256 != g.ProxyStatus().ConfigSHA256 {
		t.Fatal("event omitted effective trust configuration digest")
	}
	if response := call("198.51.100.99, 203.0.113.8"); response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}
	select {
	case headers := <-seen:
		if headers.Get("X-Forwarded-For") != "203.0.113.8" || headers.Get("X-Real-IP") != "203.0.113.8" || headers.Get("X-Forwarded-Proto") != "https" || headers.Get("X-Forwarded-Host") != "application.test" || headers.Get("True-Client-IP") != "" {
			t.Fatalf("backend forwarding mismatch %v", headers)
		}
	default:
		t.Fatal("clean request did not reach backend")
	}
	if response := call("unknown"); response.StatusCode != 400 {
		t.Fatal("invalid trusted forwarding reached upstream", response.StatusCode)
	}
	if len(seen) != 0 {
		t.Fatal("rejected request reached backend")
	}
	metrics := monitoringSamples(t, g.metricsText())
	if metrics["openwaf_trusted_proxy_networks"] != 1 || metrics["openwaf_forwarded_identity_requests_total"] != 2 || metrics["openwaf_invalid_proxy_headers_total"] != 1 {
		t.Fatal("identity accounting mismatch")
	}
	g.Close(context.Background())
	g2, err := NewWithOptions(path, Options{TrustedProxies: []string{"127.0.0.1/32"}})
	if err != nil {
		t.Fatal(err)
	}
	defer g2.Close(context.Background())
	var found bool
	for _, event := range g2.Events() {
		if event.PeerIP == "127.0.0.1" && event.IP == "203.0.113.7" && event.ProxyConfigSHA256 == g2.ProxyStatus().ConfigSHA256 {
			found = true
		}
	}
	if !found {
		t.Fatal("proxy attribution lost across restart")
	}
	data, _ := json.Marshal(g2.ProxyStatus())
	if !strings.Contains(string(data), "127.0.0.1/32") {
		t.Fatal("active trust settings unavailable")
	}
}

func TestMalformedProxyIdentityRejectedInEveryMode(t *testing.T) {
	for _, mode := range []string{"enforcing", "detection", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.json")
			config := Defaults()
			config.Mode = mode
			if err := persist(path, config); err != nil {
				t.Fatal(err)
			}
			g, err := NewWithOptions(path, Options{TrustedProxies: []string{"10.0.0.0/8"}})
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close(context.Background())
			r := httptest.NewRequest("GET", "http://application.test/", nil)
			r.RemoteAddr = "10.0.0.1:1234"
			r.Header.Set("X-Forwarded-For", "unknown")
			w := httptest.NewRecorder()
			g.ServeHTTP(w, r)
			if w.Code != 400 || g.Events()[0].UpstreamAttempted || g.Events()[0].IP != "10.0.0.1" {
				t.Fatal("malformed identity was accepted", w.Code)
			}
		})
	}
}

func TestOverloadSummaryRetainsEffectiveIdentity(t *testing.T) {
	g, err := NewWithOptions(filepath.Join(t.TempDir(), "policy.json"), Options{TrustedProxies: []string{"10.0.0.0/8"}, Resources: ResourceLimits{MaxConcurrent: 1}})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close(context.Background())
	if !g.budget.acquire(1) {
		t.Fatal("admission setup failed")
	}
	defer g.budget.release(1)
	for _, peer := range []string{"10.0.0.1:1234", "10.0.0.2:1234"} {
		r := httptest.NewRequest("GET", "http://application.test/", nil)
		r.RemoteAddr = peer
		r.Header.Set("X-Forwarded-For", "203.0.113.7")
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		if w.Code != 503 {
			t.Fatal(w.Code)
		}
	}
	if err = g.FlushEvents(context.Background()); err != nil {
		t.Fatal(err)
	}
	events := g.Events()
	if len(events) != 1 || events[0].IP != "203.0.113.7" || events[0].PeerIP != "*" || events[0].Occurrences != 2 {
		t.Fatalf("overload attribution %+v", events)
	}
}
