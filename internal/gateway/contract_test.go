package gateway

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestForwardedIdentityComesFromConnection(t *testing.T) {
	seen := make(chan http.Header, 1)
	g, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) { seen <- r.Header.Clone(); _, _ = w.Write([]byte("ok")) })
	front := httptest.NewServer(g)
	defer front.Close()
	r, _ := http.NewRequest("GET", front.URL+"/", nil)
	r.Host = "application.test"
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Forwarded", "for=203.0.113.10;proto=https")
	r.Header.Set("X-Forwarded-For", "203.0.113.10")
	r.Header.Set("X-Forwarded-Host", "evil.test")
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Real-IP", "203.0.113.10")
	r.Header.Set("CF-Connecting-IP", "203.0.113.10")
	resp, err := front.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal("identity fixture blocked", resp.StatusCode)
	}
	h := <-seen
	if h.Get("Forwarded") != "" || h.Get("X-Forwarded-For") != "127.0.0.1" || h.Get("X-Forwarded-Host") != "application.test" || h.Get("X-Forwarded-Proto") != "http" || h.Get("X-Real-IP") != "127.0.0.1" || h.Get("CF-Connecting-IP") != "" {
		t.Fatal("untrusted forwarded identity survived", h)
	}
}

func TestRealListenerRejectsMalformedFraming(t *testing.T) {
	reached := make(chan bool, 10)
	g, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) { reached <- true; _, _ = w.Write([]byte("ok")) })
	front := httptest.NewServer(g)
	defer front.Close()
	for _, raw := range []string{
		"POST / HTTP/1.1\r\nHost: application.test\r\nContent-Length: 1\r\nContent-Length: 5\r\nConnection: close\r\n\r\nx",
		"POST / HTTP/1.1\r\nHost: application.test\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: application.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nZ\r\nbroken\r\n0\r\n\r\n",
	} {
		conn, err := net.DialTimeout("tcp", front.Listener.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, err = io.WriteString(conn, raw)
		if err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			_ = conn.Close()
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		_ = conn.Close()
		if response.StatusCode < 400 {
			t.Fatal("malformed framing accepted", response.StatusCode)
		}
		select {
		case <-reached:
			t.Fatal("malformed request reached backend")
		default:
		}
	}
}

func TestInFlightTransactionKeepsItsPolicyRevision(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	g, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("new-policy-marker"))
	})
	c := g.Config()
	c.InspectResponse = true
	c, err := g.Apply(c, false)
	if err != nil {
		t.Fatal(err)
	}
	before := c.Revision
	front := httptest.NewServer(g)
	defer front.Close()
	finished := make(chan int, 1)
	go func() {
		r, _ := http.NewRequest("GET", front.URL+"/slow", nil)
		r.Host = "application.test"
		r.Header.Set("User-Agent", "Mozilla/5.0")
		resp, err := front.Client().Do(r)
		if err != nil {
			finished <- 0
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		finished <- resp.StatusCode
	}()
	<-started
	c.CustomRules = `SecRule RESPONSE_BODY "@contains new-policy-marker" "id:10003,phase:4,deny,status:403,log,msg:'New response policy'"`
	if _, err = g.Apply(c, false); err != nil {
		close(release)
		t.Fatal(err)
	}
	close(release)
	if status := <-finished; status != 200 {
		t.Fatal("in-flight request acquired new response policy", status)
	}
	if w := request(g, "GET", "/slow", "", ""); w.Code != 403 {
		t.Fatal("new request did not acquire new policy", w.Code)
	}
	found := false
	for _, evt := range g.Events() {
		if evt.Path == "/slow" && evt.Action == "blocked" {
			found = true
			if evt.PolicyRevision <= before || !evt.UpstreamAttempted {
				t.Fatal("event revision/upstream evidence incorrect", evt)
			}
		}
	}
	if !found {
		t.Fatal("new policy event missing")
	}
}

func TestScopedExceptionDoesNotExcludeDuplicateSource(t *testing.T) {
	g, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	c := g.Config()
	c.Paranoia = 2
	e := comparisonException()
	e.Method = "POST"
	c.ScopedExceptions = []ScopedException{e}
	if _, err := g.Apply(c, false); err != nil {
		t.Fatal(err)
	}
	value := "price+%3C+100"
	if w := request(g, "POST", "/search?q="+value, "application/x-www-form-urlencoded", "other=hello"); w.Code != 200 {
		t.Fatal("query exception did not work", w.Code)
	}
	if w := request(g, "POST", "/search?q="+value, "application/x-www-form-urlencoded", "q="+value); w.Code != 403 {
		t.Fatal("query exception excluded body source as well", w.Code)
	}
}

func TestCancelledClientCancelsUpstream(t *testing.T) {
	started := make(chan struct{})
	cancelled := make(chan struct{})
	g, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done(); close(cancelled) })
	front := httptest.NewServer(g)
	defer front.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, _ := http.NewRequestWithContext(ctx, "GET", front.URL+"/", nil)
	r.Host = "application.test"
	r.Header.Set("User-Agent", "Mozilla/5.0")
	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, err := front.Client().Do(r)
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("backend did not start")
	}
	cancel()
	select {
	case <-cancelled:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream did not receive cancellation")
	}
	<-done
}

func TestEncodedEligibleResponseFailsClosed(t *testing.T) {
	g, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write([]byte("opaque fixture"))
	})
	c := g.Config()
	c.InspectResponse = true
	if _, err := g.Apply(c, false); err != nil {
		t.Fatal(err)
	}
	w := request(g, "GET", "/", "", "")
	if w.Code != 502 || strings.Contains(w.Body.String(), "opaque fixture") {
		t.Fatal("uninspected encoded response leaked", w.Code)
	}
}
