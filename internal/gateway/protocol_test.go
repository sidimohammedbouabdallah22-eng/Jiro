package gateway

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func protocolGateway(t *testing.T, options Options, backend http.HandlerFunc) *Gateway {
	t.Helper()
	up := httptest.NewServer(backend)
	t.Cleanup(up.Close)
	path := filepath.Join(t.TempDir(), "policy.json")
	c := Defaults()
	c.Upstream = up.URL
	if err := persist(path, c); err != nil {
		t.Fatal(err)
	}
	g, err := NewWithOptions(path, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close(context.Background()) })
	return g
}
func protocolRequest(t *testing.T, client *http.Client, method, target, body string) *http.Response {
	t.Helper()
	r, err := http.NewRequest(method, target, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Host = "application.test"
	r.Header.Set("User-Agent", "OpenWAF protocol test")
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
func waitIdle(t *testing.T, g *Gateway) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if g.ResourceStatus()["active"] == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("request capacity did not return to idle")
}

func TestHTTP2InspectionAndBodyPreservation(t *testing.T) {
	var reached atomic.Int32
	g := protocolGateway(t, Options{}, func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Trailer", "X-Result")
		w.Write(b)
		w.Header().Set("X-Result", "complete")
	})
	c := g.Config()
	c.InspectResponse = true
	c.RequestLimit = 1024
	if _, err := g.Apply(c, false); err != nil {
		t.Fatal(err)
	}
	front := httptest.NewUnstartedServer(g)
	front.EnableHTTP2 = true
	front.StartTLS()
	defer front.Close()
	client := front.Client()
	client.Timeout = 5 * time.Second
	for _, tt := range []struct {
		name, body string
		status     int
	}{{"clean", `{"message":"hello"}`, 200}, {"attack", `{"message":"<script>alert(1)</script>"}`, 403}, {"oversize", `{"message":"` + strings.Repeat("a", 2048) + `"}`, 413}} {
		t.Run(tt.name, func(t *testing.T) {
			resp := protocolRequest(t, client, "POST", front.URL+"/", tt.body)
			b, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if resp.ProtoMajor != 2 || resp.StatusCode != tt.status {
				t.Fatalf("protocol/status: %s %d", resp.Proto, resp.StatusCode)
			}
			if tt.status == 200 && (string(b) != tt.body || resp.Trailer.Get("X-Result") != "complete") {
				t.Fatalf("body/trailer changed: %q %v", b, resp.Trailer)
			}
		})
	}
	if reached.Load() != 1 {
		t.Fatal("blocked HTTP/2 body reached upstream")
	}
}

func TestHTTP2CancellationIsolatedPerStream(t *testing.T) {
	started := make(chan struct{})
	cancelled := make(chan struct{})
	g := protocolGateway(t, Options{}, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			close(started)
			<-r.Context().Done()
			close(cancelled)
			return
		}
		w.Write([]byte("healthy"))
	})
	front := httptest.NewUnstartedServer(g)
	front.EnableHTTP2 = true
	front.StartTLS()
	defer front.Close()
	client := front.Client()
	client.Timeout = 5 * time.Second
	client.Transport.(*http.Transport).MaxConnsPerHost = 1
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, _ := http.NewRequestWithContext(ctx, "GET", front.URL+"/slow", nil)
	r.Header.Set("User-Agent", "OpenWAF protocol test")
	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, err := client.Do(r)
		if err == nil {
			resp.Body.Close()
		}
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("slow stream did not start")
	}
	resp := protocolRequest(t, client, "GET", front.URL+"/fast", "")
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.ProtoMajor != 2 || resp.StatusCode != 200 || string(b) != "healthy" {
		t.Fatal("second stream blocked")
	}
	cancel()
	select {
	case <-cancelled:
	case <-time.After(3 * time.Second):
		t.Fatal("stream cancellation did not reach backend")
	}
	<-done
	resp = protocolRequest(t, client, "GET", front.URL+"/after", "")
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal("cancelled stream broke connection")
	}
	waitIdle(t, g)
}

func TestStreamingFlushAndCancellation(t *testing.T) {
	for _, inspect := range []bool{false, true} {
		for _, mime := range []string{"text/event-stream", "application/octet-stream", "text/plain"} {
			if inspect && mime == "text/plain" {
				continue
			}
			t.Run(fmt.Sprintf("inspect=%t/%s", inspect, mime), func(t *testing.T) {
				cancelled := make(chan struct{})
				g := protocolGateway(t, Options{}, func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", mime)
					w.Write([]byte("data: first\n\n"))
					w.(http.Flusher).Flush()
					<-r.Context().Done()
					close(cancelled)
				})
				c := g.Config()
				c.InspectResponse = inspect
				if _, err := g.Apply(c, false); err != nil {
					t.Fatal(err)
				}
				front := httptest.NewServer(g)
				defer front.Close()
				client := front.Client()
				client.Timeout = 3 * time.Second
				resp := protocolRequest(t, client, "GET", front.URL+"/events", "")
				line, err := bufio.NewReader(resp.Body).ReadString('\n')
				resp.Body.Close()
				if err != nil || line != "data: first\n" || resp.StatusCode != 200 {
					t.Fatalf("first event not flushed: %q %v %d", line, err, resp.StatusCode)
				}
				select {
				case <-cancelled:
				case <-time.After(3 * time.Second):
					t.Fatal("stream disconnect leaked upstream")
				}
				waitIdle(t, g)
			})
		}
	}
}

func TestTruncatedResponseNeverLooksSuccessful(t *testing.T) {
	for _, inspect := range []bool{false, true} {
		t.Run(fmt.Sprint(inspect), func(t *testing.T) {
			g := protocolGateway(t, Options{}, func(w http.ResponseWriter, r *http.Request) {
				conn, rw, err := w.(http.Hijacker).Hijack()
				if err != nil {
					return
				}
				defer conn.Close()
				rw.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 100\r\n\r\npartial-secret")
				rw.Flush()
			})
			c := g.Config()
			c.InspectResponse = inspect
			if _, err := g.Apply(c, false); err != nil {
				t.Fatal(err)
			}
			front := httptest.NewServer(g)
			defer front.Close()
			client := front.Client()
			client.Timeout = 3 * time.Second
			r, _ := http.NewRequest("GET", front.URL+"/", nil)
			r.Header.Set("User-Agent", "OpenWAF protocol test")
			resp, err := client.Do(r)
			if inspect {
				if err != nil {
					t.Fatal(err)
				}
				b, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode != 502 || strings.Contains(string(b), "partial-secret") {
					t.Fatal("partial inspected response leaked")
				}
			} else {
				if err == nil {
					_, err = io.ReadAll(resp.Body)
					resp.Body.Close()
				}
				if err == nil {
					t.Fatal("truncated stream appeared complete")
				}
			}
			waitIdle(t, g)
			events := g.Events()
			if len(events) != 1 || events[0].Action != "error" {
				t.Fatalf("failure missing from telemetry: %+v", events)
			}
			if !inspect && (!events[0].DeliveryIncomplete || events[0].Status != 200) {
				t.Fatalf("committed status/delivery evidence: %+v", events[0])
			}
		})
	}
}

func TestWebSocketHandshakeInspectionAndTunnelCleanup(t *testing.T) {
	for _, pool := range []bool{false, true} {
		t.Run(fmt.Sprint("pool=", pool), func(t *testing.T) { testWebSocketHandshakeAndCleanup(t, pool) })
	}
}
func testWebSocketHandshakeAndCleanup(t *testing.T, pool bool) {
	var reached atomic.Int32
	g := protocolGateway(t, Options{}, func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:]))
		rw.Flush()
		frame := make([]byte, 10)
		if _, err = io.ReadFull(rw, frame); err != nil {
			return
		}
		if frame[0] != 0x81 || frame[1] != 0x84 {
			return
		}
		for i := 0; i < 4; i++ {
			frame[6+i] ^= frame[2+i]
		}
		rw.Write(append([]byte{0x81, 4}, frame[6:]...))
		rw.Flush()
		io.Copy(io.Discard, rw)
	})
	c := g.Config()
	c.InspectResponse = true
	if pool {
		app := ApplicationFromConfig(c, []string{"application.test"})
		app.Pool = &UpstreamPool{Backends: []Backend{{ID: "primary", URL: c.Upstream}}, FailureThreshold: 2, CooldownSeconds: 1, HeaderTimeoutSeconds: 2}
		c = Config{SchemaVersion: 2, Revision: c.Revision, Applications: []Application{app}}
	}

	if _, err := g.Apply(c, false); err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(g)
	defer front.Close()
	for _, attack := range []bool{true, false} {
		conn, err := net.DialTimeout("tcp", front.Listener.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		target := "/ws"
		if attack {
			target += "?q=%3Cscript%3Ealert(1)%3C/script%3E"
		}
		fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: application.test\r\nUser-Agent: OpenWAF protocol test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", target)
		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			conn.Close()
			t.Fatal(err)
		}
		if attack {
			resp.Body.Close()
			conn.Close()
			if resp.StatusCode != 403 {
				t.Fatalf("malicious handshake: %d", resp.StatusCode)
			}
			continue
		}
		if resp.StatusCode != 101 || resp.Header.Get("Sec-WebSocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
			conn.Close()
			t.Fatalf("upgrade failed: %d", resp.StatusCode)
		}
		conn.Write([]byte{0x81, 0x84, 1, 2, 3, 4, 'p' ^ 1, 'i' ^ 2, 'n' ^ 3, 'g' ^ 4})
		frame := make([]byte, 6)
		_, err = io.ReadFull(reader, frame)
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			g.Close(ctx)
			cancel()
			if _, closeErr := reader.ReadByte(); closeErr == nil {
				t.Fatal("shutdown left upgraded connection open")
			}
		}
		conn.Close()
		if err != nil || string(frame[2:]) != "ping" {
			t.Fatalf("WebSocket echo failed: %q %v", frame, err)
		}
		waitIdle(t, g)
	}
	if reached.Load() != 1 {
		t.Fatal("malicious handshake reached backend")
	}
}

func TestRequestTrailersRejectedBeforeBackend(t *testing.T) {
	var reached atomic.Int32
	g := protocolGateway(t, Options{}, func(w http.ResponseWriter, r *http.Request) { reached.Add(1); w.Write([]byte("unexpected")) })
	for _, http2 := range []bool{false, true} {
		t.Run(fmt.Sprint(http2), func(t *testing.T) {
			front := httptest.NewUnstartedServer(g)
			front.EnableHTTP2 = http2
			if http2 {
				front.StartTLS()
			} else {
				front.Start()
			}
			defer front.Close()
			r, _ := http.NewRequest("POST", front.URL+"/", strings.NewReader(`{"a":1}`))
			r.ContentLength = -1
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("User-Agent", "OpenWAF protocol test")
			r.Trailer = http.Header{"X-Uninspected": []string{"value"}}
			resp, err := front.Client().Do(r)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != 400 {
				t.Fatalf("request trailers accepted: %d", resp.StatusCode)
			}
		})
	}
	if reached.Load() != 0 {
		t.Fatal("request trailers reached backend")
	}
}

func TestHTTP1ChunkedFramingDoesNotDesynchronizePipeline(t *testing.T) {
	g := protocolGateway(t, Options{}, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "%s:%s", r.URL.Path, b)
	})
	front := httptest.NewServer(g)
	defer front.Close()
	conn, err := net.Dial("tcp", front.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	// Go selects chunked framing and removes the conflicting Content-Length.
	// Both backend requests must retain exactly that normalized boundary.
	io.WriteString(conn, "POST /first HTTP/1.1\r\nHost: application.test\r\nUser-Agent: OpenWAF protocol test\r\nContent-Type: application/json\r\nContent-Length: 99\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n\"hi\"\r\n0\r\n\r\nGET /second HTTP/1.1\r\nHost: application.test\r\nUser-Agent: OpenWAF protocol test\r\nConnection: close\r\n\r\n")
	reader := bufio.NewReader(conn)
	for _, want := range []string{`/first:"hi"`, "/second:"} {
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 || string(b) != want {
			t.Fatalf("pipeline: %d %q %v", resp.StatusCode, b, err)
		}
	}
}

func TestUpstreamTLSVerificationFailsClosed(t *testing.T) {
	var reached atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1); w.Write([]byte("secret")) }))
	defer upstream.Close()
	g := protocolGateway(t, Options{}, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("unused")) })
	c := g.Config()
	c.Upstream = upstream.URL
	if _, err := g.Apply(c, false); err != nil {
		t.Fatal(err)
	}
	w := request(g, "GET", "/", "", "")
	if w.Code != 502 || strings.Contains(w.Body.String(), "secret") || reached.Load() != 0 {
		t.Fatal("untrusted upstream certificate accepted")
	}
	events := g.Events()
	if len(events) != 1 || events[0].Action != "error" || !events[0].UpstreamAttempted {
		t.Fatal("TLS failure missing from telemetry")
	}
}

func TestUnsupportedUpgradeCannotTunnelUninspectedHTTP(t *testing.T) {
	var reached atomic.Int32
	g := protocolGateway(t, Options{}, func(w http.ResponseWriter, r *http.Request) { reached.Add(1); w.WriteHeader(101) })
	for _, mode := range []string{"enforcing", "detection", "disabled"} {
		c := g.Config()
		c.Mode = mode
		if _, err := g.Apply(c, false); err != nil {
			t.Fatal(err)
		}
		for _, upgrade := range []string{"h2c", "other-protocol", "websocket, h2c"} {
			r := httptest.NewRequest("GET", "/", nil)
			r.Header.Set("Connection", "Upgrade")
			r.Header.Set("Upgrade", upgrade)
			w := httptest.NewRecorder()
			g.ServeHTTP(w, r)
			if w.Code != 400 {
				t.Fatalf("%s/%s: %d", mode, upgrade, w.Code)
			}
		}
	}
	if reached.Load() != 0 {
		t.Fatal("unsupported protocol reached backend")
	}
}

func TestWebSocketResponseHeaderRuleBlocksUpgrade(t *testing.T) {
	g := protocolGateway(t, Options{}, func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		rw.Flush()
		io.Copy(io.Discard, rw)
	})
	c := g.Config()
	c.CustomRules = `SecRule RESPONSE_STATUS "@eq 101" "id:10009,phase:3,deny,status:403,log,msg:'Upgrade blocked'"`
	if _, err := g.Apply(c, false); err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(g)
	defer front.Close()
	conn, err := net.DialTimeout("tcp", front.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	io.WriteString(conn, "GET /ws HTTP/1.1\r\nHost: application.test\r\nUser-Agent: OpenWAF protocol test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 || resp.Header.Get("Upgrade") != "" {
		t.Fatalf("response-header block bypassed: %d %v", resp.StatusCode, resp.Header)
	}
	waitIdle(t, g)
}
