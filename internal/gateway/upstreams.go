package gateway

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// Keep idle reuse below common short backend keep-alive windows. A buffered
// mutation must not be replayed after an ambiguous write on a closing socket.
// This reduces that race; it cannot guarantee delivery across backend closure.
const upstreamIdleTimeout = 2 * time.Second

type Backend struct {
	ID         string `json:"id"`
	URL        string `json:"url"`
	ServerName string `json:"tls_server_name,omitempty"`
}

type UpstreamPool struct {
	Backends             []Backend `json:"backends"`
	FailureThreshold     int       `json:"failure_threshold"`
	CooldownSeconds      int       `json:"cooldown_seconds"`
	HeaderTimeoutSeconds int       `json:"header_timeout_seconds"`
}

func (p *UpstreamPool) validate(primary string) error {
	if p == nil {
		return nil
	}
	if len(p.Backends) < 1 || len(p.Backends) > 8 || p.Backends[0].URL != primary || p.FailureThreshold < 1 || p.FailureThreshold > 10 || p.CooldownSeconds < 1 || p.CooldownSeconds > 300 || p.HeaderTimeoutSeconds < 1 || p.HeaderTimeoutSeconds > 120 {
		return errors.New("pool requires 1..8 backends, primary matching upstream, threshold 1..10, cooldown 1..300s and header timeout 1..120s")
	}
	ids, urls := map[string]bool{}, map[string]bool{}
	for _, b := range p.Backends {
		u, err := url.Parse(b.URL)
		if !identifier.MatchString(b.ID) || ids[b.ID] || urls[b.URL] || err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
			return errors.New("invalid or duplicate upstream backend")
		}
		if b.ServerName != "" {
			name, e := normalizeHostname(b.ServerName)
			if e != nil || name != b.ServerName || net.ParseIP(name) != nil || u.Scheme != "https" {
				return errors.New("backend TLS server name requires canonical DNS and HTTPS")
			}
		}
		ids[b.ID], urls[b.URL] = true, true
	}
	return nil
}

type backendRuntime struct {
	config       Backend
	target       *url.URL
	transport    *http.Transport
	failures     int
	epoch        uint64
	blockedUntil time.Time
	probing      bool
	lastAttempt  time.Time
	lastSuccess  time.Time
}

type upstreamRuntime struct {
	mu       sync.Mutex
	config   UpstreamPool
	backends []*backendRuntime
	next     int
	retired  atomic.Bool
}

func newUpstreamRuntime(config UpstreamPool) *upstreamRuntime {
	p := &upstreamRuntime{config: config}
	for _, b := range config.Backends {
		target, _ := url.Parse(b.URL)
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.Proxy = nil
		tr.DisableCompression = true
		tr.ResponseHeaderTimeout = time.Duration(config.HeaderTimeoutSeconds) * time.Second
		tr.IdleConnTimeout = upstreamIdleTimeout
		tr.MaxConnsPerHost, tr.MaxIdleConns, tr.MaxIdleConnsPerHost = 64, 2, 2
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: b.ServerName}
		p.backends = append(p.backends, &backendRuntime{config: b, target: target, transport: tr})
	}
	return p
}

type backendSelection struct {
	pool    *upstreamRuntime
	backend *backendRuntime
	epoch   uint64
	done    atomic.Bool
}

func (p *upstreamRuntime) selectBackend(now time.Time) *backendSelection {
	p.mu.Lock()
	defer p.mu.Unlock()
	for range p.backends {
		b := p.backends[p.next]
		p.next = (p.next + 1) % len(p.backends)
		if now.Before(b.blockedUntil) || b.probing {
			continue
		}
		if !b.blockedUntil.IsZero() {
			b.probing = true
		}
		b.lastAttempt = now
		return &backendSelection{pool: p, backend: b, epoch: b.epoch}
	}
	return nil
}

func (s *backendSelection) finish(success *bool) {
	if !s.done.CompareAndSwap(false, true) {
		return
	}
	p, b := s.pool, s.backend
	p.mu.Lock()
	defer p.mu.Unlock()
	if b.epoch != s.epoch {
		return
	}
	b.probing = false
	if success == nil {
		return
	}
	if *success {
		b.failures = 0
		b.blockedUntil = time.Time{}
		b.lastSuccess = time.Now()
		return
	}
	b.failures++
	if b.failures >= p.config.FailureThreshold {
		b.epoch++
		b.blockedUntil = time.Now().Add(time.Duration(p.config.CooldownSeconds) * time.Second)
	}
}

func (s *backendSelection) RoundTrip(r *http.Request) (*http.Response, error) {
	// Inspection can exhaust the request budget before transport begins. This
	// says nothing about backend health and must not open its circuit.
	if err := r.Context().Err(); err != nil {
		s.finish(nil)
		return nil, err
	}
	resp, err := s.backend.transport.RoundTrip(r)
	success := err == nil && resp.StatusCode < 500
	if r.Context().Err() != nil {
		// The total request budget includes inspection and queueing. Its expiry
		// is not evidence that this backend missed its own header deadline.
		s.finish(nil)
	} else {
		s.finish(&success)
	}
	if resp != nil {
		resp.Body = &poolResponseBody{ReadCloser: resp.Body, pool: s.pool, transport: s.backend.transport}
	}
	return resp, err
}

type poolResponseBody struct {
	io.ReadCloser
	pool      *upstreamRuntime
	transport *http.Transport
}

func (b *poolResponseBody) Write(data []byte) (int, error) {
	writer, ok := b.ReadCloser.(io.Writer)
	if !ok {
		return 0, errors.New("backend response is not a duplex stream")
	}
	return writer.Write(data)
}
func (b *poolResponseBody) Close() error {
	err := b.ReadCloser.Close()
	if b.pool.retired.Load() {
		b.transport.CloseIdleConnections()
	}
	return err
}

func (p *upstreamRuntime) close() {
	p.retired.Store(true)
	for _, b := range p.backends {
		b.transport.CloseIdleConnections()
	}
}

type BackendStatus struct {
	ID          string    `json:"id"`
	URL         string    `json:"url"`
	State       string    `json:"state"`
	Failures    int       `json:"consecutive_failures"`
	LastAttempt time.Time `json:"last_attempt"`
	LastSuccess time.Time `json:"last_success"`
	RetryAfter  time.Time `json:"retry_after"`
}

func (p *upstreamRuntime) status() []BackendStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	items := []BackendStatus{}
	for _, b := range p.backends {
		state := "unknown"
		if !b.lastSuccess.IsZero() {
			state = "observed_healthy"
		}
		if b.failures > 0 {
			state = "degraded"
		}
		if !b.blockedUntil.IsZero() {
			state = "unavailable"
		}
		if b.probing {
			state = "trial_in_flight"
		}
		items = append(items, BackendStatus{ID: b.config.ID, URL: b.config.URL, State: state, Failures: b.failures, LastAttempt: b.lastAttempt, LastSuccess: b.lastSuccess, RetryAfter: b.blockedUntil})
	}
	return items
}

func hasUpstreamPools(c Config) bool {
	for _, a := range c.Applications {
		if a.Pool != nil {
			return true
		}
	}
	return false
}

func (a *Admin) upstreamStatus(w http.ResponseWriter, r *http.Request) {
	p, _ := a.identity(r)
	g := a.gateway
	g.lifecycle.RLock()
	defer g.lifecycle.RUnlock()
	deployment := g.active.Load()
	items := []map[string]any{}
	for _, app := range deployment.config.ApplicationList() {
		if p.Access != nil && !slices.Contains(p.Access.IDs, app.ApplicationID) {
			continue
		}
		state := []BackendStatus{{ID: "primary", URL: app.Upstream, State: "unprobed_single_upstream"}}
		if rt := deployment.applications[app.ApplicationID]; rt != nil && rt.pool != nil {
			state = rt.pool.status()
		}
		items = append(items, map[string]any{"application_id": app.ApplicationID, "backends": state})
	}
	reply(w, 200, map[string]any{"revision": deployment.config.Revision, "applications": items})
}
