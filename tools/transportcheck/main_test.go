package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTransportReuseAndActualHTTP2(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		sum := sha256.Sum256(body)
		json.NewEncoder(w).Encode(map[string]any{"marker": "capacity-backend", "bytes": len(body), "sha256": hex.EncodeToString(sum[:])})
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	g := &generator{c: configuration{Target: server.Listener.Addr().String()}, roots: roots}
	c := testCase{Host: "example.com", Method: "POST", Path: "/", Body: []byte("original request bytes"), Kind: "echo", Expected: 200}
	for _, protocol := range []int{1, 2} {
		tr := g.transport(protocol, false, 0)
		cl := client(tr)
		tracker := &connections{}
		for i := 0; i < 3; i++ {
			obs := g.request(cl, tracker, c, time.Now())
			if !obs.Correct || !obs.Verified || obs.Protocol != protocol || (i > 0 && !obs.Reused) {
				t.Fatalf("protocol/reuse/body verification failed: %+v", obs)
			}
		}
		if tracker.count() != 1 {
			t.Fatal("persistent connection was not reused")
		}
		tr.CloseIdleConnections()
	}
	tr := g.transport(1, true, 0)
	defer tr.CloseIdleConnections()
	cl := client(tr)
	tracker := &connections{}
	for i := 0; i < 3; i++ {
		obs := g.request(cl, tracker, c, time.Now())
		if !obs.Correct || obs.Reused {
			t.Fatal("fresh-connection mode reused a connection")
		}
	}
	if tracker.count() != 3 {
		t.Fatal("fresh-connection mode did not create distinct connections")
	}
}

func TestEchoStatusAndPayloadIntegrityAreIndependent(t *testing.T) {
	c := testCase{Host: "probe.capacity.test", Body: []byte("expected"), Expected: 200}
	if validResponse(c, 200, []byte(`{"marker":"capacity-backend","bytes":8,"sha256":"wrong"}`)) {
		t.Fatal("accepted corrupted echo with status 200")
	}
	c.Expected = 413
	if !validResponse(c, 413, []byte("bounded refusal")) || validResponse(c, 200, []byte("wrong")) {
		t.Fatal("body limit verdict was not enforced")
	}
}
