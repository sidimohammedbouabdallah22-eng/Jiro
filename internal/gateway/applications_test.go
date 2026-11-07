package gateway

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/eventstore"
)

func applicationFixture(t *testing.T) (*Gateway, string) {
	t.Helper()
	var apps []Application
	for _, id := range []string{"shop", "portal"} {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, id)
		}))
		t.Cleanup(upstream.Close)
		c := Defaults()
		c.ApplicationID, c.Name, c.Upstream = id, id, upstream.URL
		c.CustomRules = fmt.Sprintf(`SecRule REQUEST_URI "@streq /%s-only" "id:10001,phase:1,deny,status:403,log,msg:'Application boundary'"`, id)
		apps = append(apps, ApplicationFromConfig(c, []string{id + ".test"}))
	}
	apps[1].Policy.Mode = "detection"
	apps[0].Policy.RequestLimit = 1024
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := persist(path, Config{SchemaVersion: 2, Revision: 1, Applications: apps}); err != nil {
		t.Fatal(err)
	}
	g, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close(context.Background()) })
	return g, path
}

func applicationRequest(g *Gateway, host, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", path, strings.NewReader(body))
	r.Host = host
	r.Header.Set("User-Agent", "OpenWAF application test")
	if body != "" {
		r.Method = "POST"
		r.Header.Set("Content-Type", "text/plain")
	}
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	return w
}

func TestApplicationProxyPreservesValidatedAuthority(t *testing.T) {
	for _, schema := range []int{1, 2} {
		t.Run(fmt.Sprint(schema), func(t *testing.T) {
			const external = "shop.test:8080"
			var expected string
			var calls atomic.Int64
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Host != expected || r.Header.Get("X-Forwarded-Host") != external {
					http.Redirect(w, r, "http://"+external+r.URL.Path, http.StatusFound)
					return
				}
				fmt.Fprint(w, "canonical storefront")
			}))
			defer upstream.Close()
			c := Defaults()
			c.Upstream = upstream.URL
			expected = strings.TrimPrefix(upstream.URL, "http://")
			if schema == 2 {
				expected = external
				c = Config{SchemaVersion: 2, Revision: 1, Applications: []Application{ApplicationFromConfig(c, []string{"shop.test"})}}
			}
			path := filepath.Join(t.TempDir(), "policy.json")
			if err := persist(path, c); err != nil {
				t.Fatal(err)
			}
			g, err := New(path)
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close(context.Background())
			r := httptest.NewRequest("GET", "/search", nil)
			r.Host = external
			r.Header.Set("X-Forwarded-Host", "attacker.invalid")
			w := httptest.NewRecorder()
			g.ServeHTTP(w, r)
			if w.Code != 200 || w.Body.String() != "canonical storefront" {
				t.Fatalf("canonical authority lost: status=%d location=%q", w.Code, w.Header().Get("Location"))
			}
			if schema == 2 {
				before := calls.Load()
				r.Host = "unassigned.invalid"
				w = httptest.NewRecorder()
				g.ServeHTTP(w, r)
				if w.Code != 421 || calls.Load() != before {
					t.Fatal("unassigned authority reached backend")
				}
			}
		})
	}
}

func TestApplicationRoutingAndPolicyIsolation(t *testing.T) {
	g, _ := applicationFixture(t)
	if health := g.Health(); health.Mode != "mixed" || !health.Checks["inspection_enabled"] {
		t.Fatalf("mixed application health: %+v", health)
	}
	for _, tt := range []struct {
		host, path, body string
		status           int
		backend          string
	}{
		{"SHOP.TEST.:080", "/", "", 200, "shop"},
		{"portal.test", "/", "", 200, "portal"},
		{"shop.test", "/shop-only", "", 403, ""},
		{"portal.test", "/shop-only", "", 200, "portal"},
		{"portal.test", "/portal-only", "", 200, "portal"},
		{"shop.test", "/portal-only", "", 200, "shop"},
		{"shop.test", "/", strings.Repeat("x", 1025), 413, ""},
		{"portal.test", "/", strings.Repeat("x", 1025), 200, "portal"},
		{"unknown.test", "/", "", 421, ""},
		{"shop.test:0", "/", "", 400, ""},
		{"shop.test", "http://portal.test/", "", 400, ""},
	} {
		t.Run(tt.host+tt.path+fmt.Sprint(len(tt.body)), func(t *testing.T) {
			w := applicationRequest(g, tt.host, tt.path, tt.body)
			if w.Code != tt.status || (tt.backend != "" && w.Body.String() != tt.backend) {
				t.Fatalf("got %d %q, want %d %q", w.Code, w.Body.String(), tt.status, tt.backend)
			}
		})
	}
	for _, sni := range []string{"portal.test", "unassigned.test"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Host = "shop.test"
		r.TLS = &tls.ConnectionState{ServerName: sni}
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		if w.Code != 421 {
			t.Fatalf("SNI mismatch accepted: %d", w.Code)
		}
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = "unknown.test"
	r.Header.Set("X-Forwarded-Host", "shop.test")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != 421 {
		t.Fatal("forwarded host selected an application")
	}
	if err := g.flushOverloads(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"shop", "portal"} {
		rows, err := g.eventStore.Query(context.Background(), eventstore.Query{Application: id, Limit: 100})
		if err != nil || len(rows) == 0 {
			t.Fatalf("%s event search: %v %d", id, err, len(rows))
		}
		for _, row := range rows {
			var e Event
			if err := json.Unmarshal(row.Data, &e); err != nil {
				t.Fatal(err)
			}
			if e.ApplicationID != id || !strings.HasPrefix(e.Host, id+".test") || e.PolicyRevision != 1 {
				t.Fatalf("incorrect attribution: %+v", e)
			}
		}
	}
	if rows, err := g.eventStore.Query(context.Background(), eventstore.Query{Application: "sho", Limit: 100}); err != nil || len(rows) != 0 {
		t.Fatal("application filter was not exact", err)
	}
}

func TestApplicationsAtomicFailureAndRestart(t *testing.T) {
	g, path := applicationFixture(t)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c := g.Config()
	c.Applications[0].Hosts[0] = "changed.test"
	c.Applications[1].Policy.CustomRules = "SecRule INVALID [ broken"
	if _, err := g.Apply(c, false); err == nil {
		t.Fatal("partially invalid deployment accepted")
	}
	if w := applicationRequest(g, "shop.test", "/shop-only", ""); w.Code != 403 {
		t.Fatal("failed compilation changed routing")
	}
	c = g.Config()
	c.Applications[0].Hosts[0] = "changed.test"
	write := g.writePolicy
	g.writePolicy = func(string, Config) error { return errors.New("simulated disk failure") }
	if _, err := g.Apply(c, false); err == nil {
		t.Fatal("failed persistence accepted")
	}
	g.writePolicy = write
	stored, _ := os.ReadFile(path)
	if string(original) != string(stored) || g.Config().Revision != 1 {
		t.Fatal("failed deployment modified committed state")
	}
	if w := applicationRequest(g, "changed.test", "/", ""); w.Code != 421 {
		t.Fatal("failed persistence published hostname")
	}
	c = g.Config()
	c.Applications[0].Hosts[0] = "changed.test"
	updated, err := g.Apply(c, false)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Revision != 3 {
		t.Fatalf("orphan revision reused: %d", updated.Revision)
	}
	// A caller cannot mutate the committed snapshot through returned slices.
	updated.Applications[0].Hosts[0] = "mutated.test"
	if w := applicationRequest(g, "changed.test", "/shop-only", ""); w.Code != 403 {
		t.Fatal("active policy was aliased")
	}
	g.Close(context.Background())
	restarted, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close(context.Background())
	if w := applicationRequest(restarted, "changed.test", "/shop-only", ""); w.Code != 403 {
		t.Fatal("routing lost after restart")
	}
	if _, err := restarted.Rollback(3, 1, "test", "Restore application deployment"); err != nil {
		t.Fatal(err)
	}
	if w := applicationRequest(restarted, "shop.test", "/shop-only", ""); w.Code != 403 {
		t.Fatal("rollback failed")
	}
}

func TestApplicationMigrationAndHistoricalSchemaRequirements(t *testing.T) {
	g, path := fixture(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })
	legacy := g.Config()
	before := policyDigest(legacy)
	data, err := json.Marshal(legacyDocument(legacy))
	if err != nil {
		t.Fatal(err)
	}
	var roundtrip Config
	if err := json.Unmarshal(data, &roundtrip); err != nil || policyDigest(roundtrip) != before {
		t.Fatal("legacy serialization changed", err)
	}
	c := Config{SchemaVersion: 2, Revision: legacy.Revision, Applications: []Application{ApplicationFromConfig(legacy, []string{"example.test"})}}
	if _, err := g.Apply(c, true); err != nil {
		t.Fatal(err)
	}
	if g.Config().SchemaVersion != 1 {
		t.Fatal("validation migrated active policy")
	}
	if _, err := g.Apply(c, false); err != nil {
		t.Fatal(err)
	}
	legacy.Revision = 2
	if _, err := g.Apply(legacy, false); err == nil {
		t.Fatal("ordinary apply restored catch-all")
	}
	if _, err := g.Rollback(2, 1, "test", "Explicit legacy rollback"); err != nil {
		t.Fatal(err)
	}
	state, err := CheckState(path, true)
	if err != nil || !reflect.DeepEqual(state.PolicySchemas, []int{1, 2}) || state.Schema != 1 {
		t.Fatalf("historical schemas missing: %+v %v", state, err)
	}
}

func TestApplicationDocumentValidation(t *testing.T) {
	base := Config{SchemaVersion: 2, Revision: 1, Applications: []Application{ApplicationFromConfig(Defaults(), []string{"example.test"})}}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Applications[0].Hosts = nil },
		func(c *Config) { c.Applications[0].Hosts = []string{"Example.test"} },
		func(c *Config) { c.Applications[0].Hosts = []string{"example.test."} },
		func(c *Config) { c.Applications[0].Hosts = []string{"*.example.test"} },
		func(c *Config) { c.Applications[0].Hosts = []string{"example.test:80"} },
		func(c *Config) { c.Applications = append(c.Applications, c.Applications[0]) },
		func(c *Config) {
			a := c.Applications[0]
			a.ApplicationID = "other"
			c.Applications = append(c.Applications, a)
		},
		func(c *Config) { c.Applications[0].Hosts = make([]string, MaxApplicationHosts+1) },
		func(c *Config) { c.Applications = make([]Application, MaxApplications+1) },
		func(c *Config) {
			c.Applications[0].Policy.CustomRules = "#" + strings.Repeat("x", 63<<10)
			second := ApplicationFromConfig(c.Applications[0].config(c.Revision), []string{"second.test"})
			second.ApplicationID = "second"
			c.Applications = append(c.Applications, second)
		},
	} {
		c := base.clone()
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Fatalf("invalid deployment accepted: %+v", c)
		}
	}
	for _, document := range []string{
		`{"schema_version":2,"revision":1,"applications":[],"upstream":"http://localhost"}`,
		`{"schema_version":2,"revision":1,"applications":[{"unknown":true}]}`,
		`null`,
	} {
		var c Config
		if err := json.Unmarshal([]byte(document), &c); err == nil {
			t.Fatalf("unexpected document accepted: %s", document)
		}
	}
	for _, authority := range []string{"user@example.test", "[example.test]", "example.test:", "example.test:65536", "example.test:+80", "127.000.0.1", "[fe80::1%25eth0]", "example.test/", "example..test", " example.test"} {
		if _, _, err := requestAuthority(authority); err == nil {
			t.Fatalf("unsafe authority accepted: %q", authority)
		}
	}
	for input, want := range map[string]string{"EXAMPLE.TEST.:080": "example.test:80", "[2001:db8::1]:443": "[2001:db8::1]:443", "127.0.0.1": "127.0.0.1"} {
		_, got, err := requestAuthority(input)
		if err != nil || got != want {
			t.Fatalf("authority %q = %q %v", input, got, err)
		}
	}
}

func FuzzApplicationAuthority(f *testing.F) {
	for _, value := range []string{"SHOP.TEST.:080", "[2001:db8::1]:443", "[::ffff:127.0.0.1]", "unknown.test", "user@shop.test", "shop.test:0", "[fe80::1%eth0]"} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		host, authority, err := requestAuthority(value)
		if err != nil {
			return
		}
		nextHost, nextAuthority, err := requestAuthority(authority)
		if err != nil || nextHost != host || nextAuthority != authority {
			t.Fatalf("unstable canonical authority %q -> %q -> %q: %v", value, authority, nextAuthority, err)
		}
		if normalized, err := normalizeHostname(host); err != nil || normalized != host {
			t.Fatalf("noncanonical host %q: %v", host, err)
		}
	})
}

func TestApplicationRejectionRollupBoundsAndAccounting(t *testing.T) {
	g := &Gateway{rollups: map[rejectionKey]Event{}}
	for i := 0; i < 200; i++ {
		for _, action := range []string{"unrouted", "overloaded"} {
			g.recordOverload(Event{Action: action, PolicyRevision: uint64(i + 1), ApplicationID: fmt.Sprint(i), Host: fmt.Sprintf("%d.test", i), Time: time.Now()})
		}
	}
	if len(g.rollups) > 64 || g.unrouted != 200 || g.overloaded != 200 {
		t.Fatal("unbounded or miscounted rejections")
	}
	counts := map[string]uint64{}
	for _, e := range g.rollups {
		counts[e.Action] += e.Occurrences
	}
	if counts["unrouted"] != 200 || counts["overloaded"] != 200 {
		t.Fatalf("lost rollup occurrences: %v", counts)
	}
	mixed := &Gateway{rollups: map[rejectionKey]Event{}}
	for _, status := range []int{400, 421} {
		mixed.recordOverload(Event{Action: "unrouted", PolicyRevision: 1, Status: status, Time: time.Now()})
	}
	for _, e := range mixed.rollups {
		if e.Occurrences != 2 || e.Status != 0 {
			t.Fatalf("mixed status summary claimed one status: %+v", e)
		}
	}
}

func TestApplicationsConcurrentActivationKeepsInflightRoute(t *testing.T) {
	g, _ := applicationFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(entered) })
		<-release
		fmt.Fprint(w, "old backend")
	}))
	defer up.Close()
	defer func() {
		once.Do(func() {})
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	c := g.Config()
	c.Applications[0].Upstream = up.URL
	if _, err := g.Apply(c, false); err != nil {
		t.Fatal(err)
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- applicationRequest(g, "shop.test", "/", "") }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("backend did not receive request")
	}
	c = g.Config()
	c.Applications[0].Upstream = c.Applications[1].Upstream
	if _, err := g.Apply(c, false); err != nil {
		t.Fatal(err)
	}
	if w := applicationRequest(g, "shop.test", "/", ""); w.Code != 200 || w.Body.String() != "portal" {
		t.Fatal("new route was not activated")
	}
	close(release)
	select {
	case w := <-done:
		if w.Code != 200 || w.Body.String() != "old backend" {
			t.Fatal("inflight request changed upstream")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("inflight request did not finish")
	}
}

func TestApplicationExceptionsAndResponseInspectionAreIsolated(t *testing.T) {
	g, _ := applicationFixture(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "private-response-marker")
	}))
	defer up.Close()
	c := g.Config()
	for i := range c.Applications {
		c.Applications[i].Upstream = up.URL
		c.Applications[i].Policy.Mode = "enforcing"
		c.Applications[i].Policy.Paranoia = 2
		c.Applications[i].Policy.CustomRules = `SecRule RESPONSE_BODY "@contains private-response-marker" "id:10002,phase:4,deny,status:403,log,msg:'Response boundary'"`
	}
	c.Applications[0].Policy.InspectResponse = true
	c.Applications[0].Policy.ScopedExceptions = []ScopedException{comparisonException()}
	if _, err := g.Apply(c, false); err != nil {
		t.Fatal(err)
	}
	if w := applicationRequest(g, "shop.test", "/", ""); w.Code != 403 {
		t.Fatalf("response inspection missing: %d", w.Code)
	}
	if w := applicationRequest(g, "portal.test", "/", ""); w.Code != 200 {
		t.Fatalf("response policy leaked: %d", w.Code)
	}
	// Use a harmless upstream response to isolate request exception semantics.
	c = g.Config()
	c.Applications[0].Policy.InspectResponse = false
	if _, err := g.Apply(c, false); err != nil {
		t.Fatal(err)
	}
	path := "/search?q=price%20%3C%20100"
	if w := applicationRequest(g, "shop.test", path, ""); w.Code != 200 {
		t.Fatalf("scoped exception did not work: %d", w.Code)
	}
	if w := applicationRequest(g, "portal.test", path, ""); w.Code != 403 {
		t.Fatalf("scoped exception leaked: %d", w.Code)
	}
}

func TestApplicationHTTP2RoutingAndSNIBoundary(t *testing.T) {
	g, _ := applicationFixture(t)
	server := httptest.NewUnstartedServer(g)
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	transport := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "shop.test"}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	for _, host := range []string{"SHOP.TEST.:443", "portal.test", "unknown.test"} {
		r, err := http.NewRequest("GET", server.URL+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Host = host
		r.Header.Set("User-Agent", "OpenWAF HTTP2 routing test")
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		want := 421
		if host == "SHOP.TEST.:443" {
			want = 200
		}
		if response.ProtoMajor != 2 || response.StatusCode != want {
			t.Fatalf("HTTP2 routing %s: %s %d %q", host, response.Proto, response.StatusCode, body)
		}
	}
}

func TestApplicationAdminAuthenticationRevisionAndAudit(t *testing.T) {
	g, _ := applicationFixture(t)
	token := strings.Repeat("a", 64)
	admin := NewAdmin(g, token)
	post := func(path, data, credential, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader(data))
		r.Header.Set("Content-Type", "application/json")
		if credential != "" {
			r.Header.Set("Authorization", "Bearer "+credential)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		admin.ServeHTTP(w, r)
		return w
	}
	create := `{"revision":1,"application_id":"third","name":"Third application","hosts":["third.test"],"upstream":"http://127.0.0.1:3000","reason":"Add application"}`
	if w := post("/api/v1/applications", create, "", ""); w.Code != 401 {
		t.Fatalf("unauthenticated create: %d", w.Code)
	}
	if w := post("/api/v1/applications", create, token, "https://foreign.test"); w.Code != 403 {
		t.Fatalf("foreign origin accepted: %d", w.Code)
	}
	if w := post("/api/v1/applications", create, token, ""); w.Code != 200 {
		t.Fatalf("create failed: %d %s", w.Code, w.Body)
	}
	if g.Config().Applications[2].Policy.Mode != "detection" {
		t.Fatal("new application did not start in detection mode")
	}
	if w := post("/api/v1/applications", create, token, ""); w.Code != 409 {
		t.Fatalf("stale create accepted: %d", w.Code)
	}
	if w := post("/api/v1/applications/third/delete", `{"revision":1,"reason":"Retire application"}`, token, ""); w.Code != 409 {
		t.Fatalf("stale deletion accepted: %d", w.Code)
	}
	if w := post("/api/v1/applications/third/delete", `{"revision":2,"reason":""}`, token, ""); w.Code != 400 {
		t.Fatalf("reasonless deletion accepted: %d", w.Code)
	}
	if w := post("/api/v1/applications/third/delete", `{"revision":2,"reason":"Retire application"}`, token, ""); w.Code != 200 {
		t.Fatalf("delete failed: %d %s", w.Code, w.Body)
	}
	if w := applicationRequest(g, "third.test", "/", ""); w.Code != 421 {
		t.Fatal("removed application still routed")
	}
	records, err := g.audit.Query(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, record := range records {
		if record.Outcome == "success" {
			seen[record.Operation] = true
		}
	}
	for _, operation := range []string{"application.create.request", "application.delete.request", "policy.activate"} {
		if !seen[operation] {
			t.Fatalf("missing durable audit outcome for %s", operation)
		}
	}
}

func TestApplicationConcurrentTrafficAccounting(t *testing.T) {
	g, _ := applicationFixture(t)
	var workers sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := 0; i < 64; i++ {
				host, path, status := "shop.test", "/", 200
				switch i % 4 {
				case 1:
					path, status = "/shop-only", 403
				case 2:
					host, path = "portal.test", "/portal-only"
				case 3:
					host, status = "unknown.test", 421
				}
				if w := applicationRequest(g, host, path, ""); w.Code != status {
					t.Errorf("concurrent routing %s%s: %d, want %d", host, path, w.Code, status)
				}
			}
		}()
	}
	workers.Wait()
	if err := g.flushOverloads(context.Background()); err != nil {
		t.Fatal(err)
	}
	summary := g.Summary()
	for key, want := range map[string]uint64{"requests": 1024, "blocked": 256, "detected": 256, "unrouted_requests": 256} {
		if summary[key] != want {
			t.Fatalf("%s accounting = %v, want %d", key, summary[key], want)
		}
	}
	status := g.StorageStatus()
	if status.CommittedOccurrences != 768 {
		t.Fatalf("durable occurrence loss: %+v", status)
	}
	for _, id := range []string{"shop", "portal"} {
		rows, err := g.eventStore.Query(context.Background(), eventstore.Query{Application: id, Limit: 499})
		if err != nil || len(rows) != 256 {
			t.Fatalf("%s attribution count %d: %v", id, len(rows), err)
		}
	}
}
