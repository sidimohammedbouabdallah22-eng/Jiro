package gateway

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// A backend/relay can acknowledge a write while closing an idle connection,
// leaving the outcome ambiguous. Such a mutation cannot safely be replayed.
type closingIdleConn struct {
	net.Conn
	poisoned *atomic.Bool
}

func (c *closingIdleConn) Write(p []byte) (int, error) {
	if c.poisoned.Load() {
		_ = c.Conn.Close()
		return len(p), nil
	}
	return c.Conn.Write(p)
}

func TestIdleUpstreamEvictedBeforeBufferedMutation(t *testing.T) {
	var posts, dials atomic.Int32
	g, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			posts.Add(1)
			body, _ := io.ReadAll(r.Body)
			if string(body) != `{"message":"safe"}` {
				t.Error("mutation body changed")
			}
		}
		_, _ = io.WriteString(w, "ok")
	})
	var poisoned atomic.Bool
	g.transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err == nil && dials.Add(1) == 1 {
			return &closingIdleConn{Conn: c, poisoned: &poisoned}, nil
		}
		return c, err
	}
	if w := request(g, "GET", "/", "", ""); w.Code != 200 {
		t.Fatal("warm-up", w.Code)
	}
	poisoned.Store(true)
	// Use the real product timeout: the previous 90-second policy reused this
	// poisoned connection, wrote the POST, then returned 502 without replay.
	time.Sleep(2200 * time.Millisecond)
	w := request(g, "POST", "/", "application/json", `{"message":"safe"}`)
	if w.Code != 200 || posts.Load() != 1 || dials.Load() != 2 {
		t.Fatalf("status=%d backend POSTs=%d dials=%d", w.Code, posts.Load(), dials.Load())
	}
}

func TestPoolUsesSameConservativeIdleWindow(t *testing.T) {
	p := newUpstreamRuntime(UpstreamPool{Backends: []Backend{{ID: "one", URL: "http://127.0.0.1:3000"}}, HeaderTimeoutSeconds: 30})
	defer p.close()
	if got := p.backends[0].transport.IdleConnTimeout; got != 2*time.Second {
		t.Fatal("pool idle reuse window", got)
	}
}
