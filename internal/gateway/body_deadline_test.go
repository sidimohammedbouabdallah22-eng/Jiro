package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCompletedBodyDeadlineDoesNotCancelSlowUpstream(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			g := protocolGateway(t, Options{Resources: ResourceLimits{
				BodyReadTimeout: time.Second,
				RequestTimeout:  5 * time.Second,
			}}, func(w http.ResponseWriter, r *http.Request) {
				select {
				case <-time.After(1500 * time.Millisecond):
					w.Write([]byte("complete upstream response"))
				case <-r.Context().Done():
				}
			})
			front := httptest.NewServer(g)
			defer front.Close()
			body := ""
			if method == http.MethodPost {
				body = `{"message":"complete request"}`
			}
			response := protocolRequest(t, front.Client(), method, front.URL, body)
			defer response.Body.Close()
			data, err := io.ReadAll(response.Body)
			if err != nil || response.StatusCode != http.StatusOK || string(data) != "complete upstream response" {
				t.Fatalf("slow upstream returned status %d, body %q, error %v", response.StatusCode, data, err)
			}
			waitIdle(t, g)
			if events := g.Events(); len(events) != 0 {
				t.Fatalf("completed response recorded a security event: %+v", events)
			}
		})
	}
}
