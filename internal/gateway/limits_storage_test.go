package gateway

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/eventstore"
)

func TestSlowBodyAndUpstreamTimeout(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
		w.Write([]byte("late"))
	}))
	defer up.Close()
	path := filepath.Join(t.TempDir(), "policy.json")
	c := Defaults()
	c.Upstream = up.URL
	if e := persist(path, c); e != nil {
		t.Fatal(e)
	}
	g, e := NewWithOptions(path, Options{Resources: ResourceLimits{BodyReadTimeout: 3 * time.Second, RequestTimeout: time.Second}})
	if e != nil {
		t.Fatal(e)
	}
	defer g.Close(context.Background())
	front := httptest.NewServer(g)
	defer front.Close()
	u, _ := url.Parse(front.URL)
	conn, e := net.Dial("tcp", u.Host)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(7 * time.Second))
	conn.Write([]byte("POST / HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{"))
	response, e := http.ReadResponse(bufio.NewReader(conn), nil)
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode != 400 {
		t.Fatalf("slow body: %d", response.StatusCode)
	}
	// Response completion now also includes a durable event commit. Verify
	// inspection/read duration independently from that storage wait.
	if events := g.Events(); len(events) == 0 || events[0].Duration > 2500 {
		t.Fatal("body deadline exceeded the shorter request deadline")
	}
	w := request(g, "GET", "/", "", "")
	if w.Code != 502 || g.Events()[0].Duration > 2500 {
		t.Fatalf("upstream deadline: %d", w.Code)
	}
	if g.ResourceStatus()["active"] != 0 {
		t.Fatal("timeout leaked admission")
	}
}

func TestAdmissionReleaseAndDurableEvents(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { entered <- struct{}{}; <-release; w.Write([]byte("ok")) }))
	defer up.Close()
	path := filepath.Join(t.TempDir(), "policy.json")
	c := Defaults()
	c.Upstream = up.URL
	if e := persist(path, c); e != nil {
		t.Fatal(e)
	}
	g, e := NewWithOptions(path, Options{Resources: ResourceLimits{MaxConcurrent: 1}})
	if e != nil {
		t.Fatal(e)
	}
	defer g.Close(context.Background())
	finished := make(chan int, 1)
	go func() { finished <- request(g, "GET", "/", "", "").Code }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream not reached")
	}
	overloaded := request(g, "GET", "/busy", "", "")
	close(release)
	if overloaded.Code != 503 || overloaded.Header().Get("Retry-After") != "1" {
		t.Fatalf("overload: %d", overloaded.Code)
	}
	if code := <-finished; code != 200 {
		t.Fatalf("first request: %d", code)
	}
	if g.ResourceStatus()["active"] != 0 || g.ResourceStatus()["reserved_buffer_bytes"] != int64(0) {
		t.Fatal("reservation leaked")
	}
	if e = g.FlushEvents(context.Background()); e != nil {
		t.Fatal(e)
	}
	page, e := g.QueryEvents(context.Background(), eventstore.Query{Limit: 10, Action: "overloaded"})
	if e != nil || len(page.Items) != 1 {
		t.Fatalf("stored overload: %+v %v", page, e)
	}
	id := page.Items[0].ID
	if page.Items[0].IP == "" {
		t.Fatal("overload event lost peer identity")
	}
	g.Close(context.Background())
	g2, e := New(path)
	if e != nil {
		t.Fatal(e)
	}
	defer g2.Close(context.Background())
	page, e = g2.QueryEvents(context.Background(), eventstore.Query{Limit: 10, Search: "/busy"})
	if e != nil || len(page.Items) != 1 || page.Items[0].ID != id {
		t.Fatalf("restart: %+v %v", page, e)
	}
}
func TestResourceBudgetAndMalformedTargets(t *testing.T) {
	b := resourceBudget{limits: ResourceLimits{MaxConcurrent: 2, BufferBytes: 100}}
	if !b.acquire(60) || b.acquire(41) || !b.acquire(40) || b.acquire(0) {
		t.Fatal("budget admission")
	}
	b.release(60)
	b.release(40)
	if !b.acquire(100) {
		t.Fatal("budget release")
	}
	g, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	for _, tt := range []struct {
		method, target string
		status         int
	}{{"CONNECT", "/", 405}, {"GET", "/path#fragment", 400}} {
		r := httptest.NewRequest(tt.method, "/", nil)
		r.RequestURI = tt.target
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		if w.Code != tt.status {
			t.Fatalf("%s %s: %d", tt.method, tt.target, w.Code)
		}
	}
	e, data := serializeEvent(Event{ID: "test", Path: strings.Repeat("x", 10000), Matches: make([]Match, 100)})
	if !e.Truncated || len(data) > eventstore.MaxRecordBytes {
		t.Fatal("unbounded event")
	}
	if label := ruleLabel(`SecRule ARGS "@rx x" "id:1,msg:'Static %{MATCHED_VAR}'"`); label != "Static %{MATCHED_VAR}" {
		t.Fatal(label)
	}
}

func TestProductionParserLimits(t *testing.T) {
	reached := 0
	g, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) { reached++; w.Write([]byte("ok")) })
	args := make([]string, 257)
	for i := range args {
		args[i] = "p" + strconv.Itoa(i) + "=value"
	}
	for _, tt := range []struct{ contentType, body string }{{"application/x-www-form-urlencoded", strings.Join(args, "&")}, {"application/json", strings.Repeat(`{"a":`, 70) + `1` + strings.Repeat(`}`, 70)}} {
		w := request(g, "POST", "/", tt.contentType, tt.body)
		if w.Code < 400 {
			t.Fatalf("parser limit accepted %s: %d", tt.contentType, w.Code)
		}
	}
	if reached != 0 {
		t.Fatal("parser-limited body reached backend")
	}
}
