package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func reservedBodyControls() TrafficControls {
	return TrafficControls{ClientBodyKiBPerSecond: 160, ClientBodyBurstKiB: 4096,
		ClientBodyReservation: &BodyReservation{Method: "POST", Path: "/upload", KiBPerSecond: 128, BurstKiB: 3072}, bodyKiB: 1024}
}

func TestBodyReservationIsolationAndRefill(t *testing.T) {
	b := &resourceBudget{limits: ResourceLimits{}.defaults()}
	c := reservedBodyControls()
	now := time.Now()
	admit := func(want int, at time.Time) {
		t.Helper()
		r := b.admit("shop", "192.0.2.1", 4, c, 1, at)
		if r.status != want {
			t.Fatalf("status %d, want %d, reason %s", r.status, want, r.reason)
		}
		if r.release != nil {
			r.release()
		}
	}
	admit(0, now)
	admit(429, now)
	c.reservedBody = true
	for range 3 {
		admit(0, now)
	}
	admit(429, now)
	c.bodyKiB = 0
	admit(0, now)
	c.bodyKiB = 1024
	admit(0, now.Add(8*time.Second))
	c.reservedBody = false
	admit(429, now.Add(8*time.Second))
	admit(0, now.Add(32*time.Second))
}

func TestBodyReservationGatewayMatchingAndInspection(t *testing.T) {
	g, _ := applicationFixture(t)
	c := g.Config()
	c.Applications[0].Policy.RequestLimit = 1 << 20
	c.Applications[0].Policy.CustomRules = `SecRule REQUEST_URI "@streq /upload" "id:10001,phase:1,deny,status:403,log,msg:'Reservation still inspected'"`
	controls := reservedBodyControls()
	c.Applications[0].TrafficControls = &controls
	if _, err := g.Apply(c, false); err != nil {
		t.Fatal(err)
	}
	body := `{"data":"` + strings.Repeat("a", (1<<20)-11) + `"}`
	request := func(path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		r.Host = "shop.test"
		r.Header.Set("User-Agent", "Owned reservation test")
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		return w
	}
	if r := request("/general"); r.Code != 200 {
		t.Fatal(r.Code)
	}
	for _, path := range []string{"/other", "/upload/", "/%75pload", "/upload?x=1"} {
		want := 429
		if path == "/upload?x=1" {
			want = 200
		}
		if r := request(path); r.Code != want {
			t.Fatalf("%s returned %d, want %d", path, r.Code, want)
		}
	}
	probe := &unreadBodyProbe{}
	r := httptest.NewRequest(http.MethodPut, "/upload", nil)
	r.Host, r.Body, r.ContentLength = "shop.test", probe, -1
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != 429 || probe.reads != 0 {
		t.Fatal("method or unknown-length bypass", w.Code, probe.reads)
	}
	if r := request("/upload"); r.Code != 403 {
		t.Fatal("reserved route bypassed inspection", r.Code)
	}
	if g.ResourceStatus()["active"] != 0 || g.ResourceStatus()["reserved_buffer_bytes"] != int64(0) {
		t.Fatal("reservation leaked resources")
	}
}

func TestBodyReservationValidation(t *testing.T) {
	for _, path := range []string{"", "//host/path", "/x?y=1", "/x#frag", "/x/../y", "/x%2fy", "/x/", "/x\\y"} {
		c := reservedBodyControls()
		c.ClientBodyReservation.Path = path
		if c.validate() == nil {
			t.Fatal("accepted invalid path", path)
		}
	}
	for _, mutate := range []func(*TrafficControls){
		func(c *TrafficControls) { c.ClientBodyReservation.Method = "GET" },
		func(c *TrafficControls) { c.ClientBodyReservation.KiBPerSecond = 160 },
		func(c *TrafficControls) { c.ClientBodyReservation.BurstKiB = 4096 },
		func(c *TrafficControls) { c.ClientBodyReservation.BurstKiB = 3500 },
	} {
		c := reservedBodyControls()
		mutate(&c)
		if c.validate() == nil && c.validateBuffer(Config{RequestLimit: 1 << 20}) == nil {
			t.Fatal("accepted invalid partition")
		}
	}
}

func TestBodyReservationConfigCloneIsolation(t *testing.T) {
	g, _ := applicationFixture(t)
	c := g.Config()
	controls := reservedBodyControls()
	c.Applications[0].TrafficControls = &controls
	if _, err := g.Apply(c, false); err != nil {
		t.Fatal(err)
	}
	c.Applications[0].TrafficControls.ClientBodyReservation.Path = "/mutated-input"
	snapshot := g.Config()
	if snapshot.Applications[0].TrafficControls.ClientBodyReservation.Path != "/upload" {
		t.Fatal("caller mutated active reservation")
	}
	snapshot.Applications[0].TrafficControls.ClientBodyReservation.Path = "/mutated-output"
	if g.Config().Applications[0].TrafficControls.ClientBodyReservation.Path != "/upload" {
		t.Fatal("config reader mutated active reservation")
	}
}
