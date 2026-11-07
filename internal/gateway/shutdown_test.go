package gateway

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestShutdownDeadlineRetainsLeaseUntilTransactionsLog(t *testing.T) {
	g := protocolGateway(t, Options{Resources: ResourceLimits{BodyReadTimeout: time.Second}}, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	front := httptest.NewServer(g)
	defer front.Close()
	conn, err := net.Dial("tcp", front.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	io.WriteString(conn, "POST /slow-body HTTP/1.1\r\nHost: application.test\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{")
	deadline := time.Now().Add(2 * time.Second)
	for g.ResourceStatus()["active"] == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if g.ResourceStatus()["active"] != 1 {
		t.Fatal("body reader not active")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	g.Close(ctx)
	cancel()
	other, err := New(g.path)
	if err == nil {
		other.Close(context.Background())
		t.Fatal("policy lease released with active transaction")
	}
	conn.Close()
	waitIdle(t, g)
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		other, err = New(g.path)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("drained gateway did not release lease: %v", err)
	}
	defer other.Close(context.Background())
	found := false
	for _, e := range other.Events() {
		if e.Path == "/slow-body" {
			found = true
		}
	}
	if !found {
		t.Fatal("last transaction lost during shutdown")
	}
}

func TestHTTP2AdmissionBoundsStreamsOnOneConnection(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	defer close(release)
	g := protocolGateway(t, Options{Resources: ResourceLimits{MaxConcurrent: 1}}, func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
		}
		w.Write([]byte("ok"))
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
	req, _ := http.NewRequestWithContext(ctx, "GET", front.URL+"/slow", nil)
	req.Host = "application.test"
	req.Header.Set("User-Agent", "OpenWAF protocol test")
	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
		}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("first stream not active")
	}
	resp := protocolRequest(t, client, "GET", front.URL+"/busy", "")
	resp.Body.Close()
	if resp.ProtoMajor != 2 || resp.StatusCode != 503 || resp.Header.Get("Retry-After") != "1" {
		t.Fatalf("HTTP/2 admission: %s %d", resp.Proto, resp.StatusCode)
	}
	cancel()
	<-done
	waitIdle(t, g)
}

func TestGatewayShutdownReturns503ToConnectedClient(t *testing.T) {
	entered := make(chan struct{})
	g := protocolGateway(t, Options{}, func(w http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done() })
	front := httptest.NewServer(g)
	defer front.Close()
	status := make(chan int, 1)
	go func() {
		req, _ := http.NewRequest("GET", front.URL+"/", nil)
		req.Host = "application.test"
		req.Header.Set("User-Agent", "OpenWAF shutdown test")
		resp, err := front.Client().Do(req)
		if err != nil {
			status <- 0
			return
		}
		resp.Body.Close()
		status <- resp.StatusCode
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("request not active")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	g.Close(ctx)
	if got := <-status; got != 503 {
		t.Fatalf("shutdown produced a misleading successful response: %d", got)
	}
}
