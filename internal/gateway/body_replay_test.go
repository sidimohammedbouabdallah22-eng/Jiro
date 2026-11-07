package gateway

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
)

type zeroWriteConn struct {
	net.Conn
	armed *atomic.Bool
}

func TestClientIdempotencyHeaderDoesNotEnablePOSTReplay(t *testing.T) {
	for _, header := range []string{"Idempotency-Key", "X-Idempotency-Key"} {
		t.Run(header, func(t *testing.T) {
			var posts atomic.Int32
			g, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "POST" {
					posts.Add(1)
					if r.Header.Get(header) != "opaque-key" {
						t.Error("application header changed")
					}
					_, _ = io.Copy(io.Discard, r.Body)
					c, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					_ = c.Close()
					return
				}
				_, _ = io.WriteString(w, "ok")
			})
			if w := request(g, "GET", "/", "", ""); w.Code != 200 {
				t.Fatal(w.Code)
			}
			r := httptest.NewRequest("POST", "http://example.test/", strings.NewReader(`{"message":"safe"}`))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("User-Agent", "OpenWAF integration test")
			r.Header.Set(header, "opaque-key")
			w := httptest.NewRecorder()
			g.ServeHTTP(w, r)
			if w.Code != 502 || posts.Load() != 1 {
				t.Fatalf("status=%d backend POSTs=%d", w.Code, posts.Load())
			}
		})
	}
}

func TestUpstreamErrorCategoriesNeverExposeErrorText(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{context.DeadlineExceeded, "timeout"}, {syscall.EPIPE, "write_closed"},
		{syscall.ECONNRESET, "connection_reset"}, {syscall.ECONNREFUSED, "connection_refused"},
		{io.EOF, "eof"}, {io.ErrUnexpectedEOF, "unexpected_eof"}, {net.ErrClosed, "connection_closed"},
		{fmt.Errorf("https://user:secret@private.invalid/untrusted-body"), "other"},
	} {
		if got := upstreamErrorClass(fmt.Errorf("sensitive wrapper: %w", tc.err)); got != tc.want {
			t.Fatalf("category=%q want=%q", got, tc.want)
		}
	}
}

func (c *zeroWriteConn) Write(p []byte) (int, error) {
	if c.armed.Load() {
		return 0, syscall.EPIPE
	}
	return c.Conn.Write(p)
}

func TestBufferedPOSTRetriesOnlyBeforeAnyWrite(t *testing.T) {
	for _, ambiguous := range []bool{false, true} {
		t.Run(map[bool]string{false: "zero_written", true: "response_lost"}[ambiguous], func(t *testing.T) {
			body := `{"message":"` + strings.Repeat("a", 100) + `"}`
			var posts, dials atomic.Int32
			g, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "POST" {
					posts.Add(1)
					got, _ := io.ReadAll(r.Body)
					if string(got) != body {
						t.Error("buffered body changed")
					}
					if ambiguous {
						conn, _, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
							return
						}
						_ = conn.Close()
						return
					}
				}
				_, _ = io.WriteString(w, "ok")
			})
			var armed atomic.Bool
			g.transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				if dials.Add(1) == 1 {
					return &zeroWriteConn{Conn: c, armed: &armed}, nil
				}
				return c, nil
			}
			if w := request(g, "GET", "/", "", ""); w.Code != 200 {
				t.Fatal("warm-up", w.Code)
			}
			armed.Store(!ambiguous)
			w := request(g, "POST", "/", "application/json", body)
			want := 200
			if ambiguous {
				want = 502
			}
			if w.Code != want || posts.Load() != 1 {
				t.Fatalf("status=%d want=%d backend POSTs=%d", w.Code, want, posts.Load())
			}
			if !ambiguous && dials.Load() != 2 {
				t.Fatalf("expected one safe reconnect, got %d connections", dials.Load())
			}
		})
	}
}
