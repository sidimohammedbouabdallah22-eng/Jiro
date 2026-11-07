package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func fixture(t *testing.T, handler http.HandlerFunc) (*Gateway, string) {
	t.Helper()
	up := httptest.NewServer(handler)
	t.Cleanup(up.Close)
	path := filepath.Join(t.TempDir(), "policy.json")
	c := Defaults()
	c.Upstream = up.URL
	if err := persist(path, c); err != nil {
		t.Fatal(err)
	}
	g, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close(context.Background()) })
	return g, path
}
func request(g *Gateway, method, path, contentType, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Host = "example.test"
	if r.ContentLength > 0 {
		r.Header.Set("Content-Length", strconv.FormatInt(r.ContentLength, 10))
	}
	r.Header.Set("User-Agent", "OpenWAF integration test")
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	return w
}
func TestCRSRequestInspection(t *testing.T) {
	var reached atomic.Int32
	g, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(append([]byte("upstream:"), b...))
	})
	if w := request(g, "GET", "/hello?name=alice", "", ""); w.Code != 200 {
		t.Fatalf("clean request: %d %s", w.Code, w.Body)
	}
	if len(g.Events()) != 0 {
		t.Fatal("clean traffic generated a security event")
	}
	tests := []struct{ name, method, path, ct, body string }{
		{"query SQLi", "GET", "/?id=" + url.QueryEscape("1' UNION SELECT username,password FROM users--"), "", ""},
		{"encoded XSS", "GET", "/?q=" + url.QueryEscape("<script>alert(1)</script>"), "", ""},
		{"JSON SQLi", "POST", "/", "application/json", `{"id":"1' UNION SELECT username,password FROM users--"}`},
		{"large JSON tail XSS", "POST", "/", "application/json", `{"value":"` + strings.Repeat("a", 8192) + `<script>alert(1)</script>"}`},
		{"large JSON Unicode tail SQLi", "POST", "/", "application/json", `{"value":"` + strings.Repeat("a", 8192) + `é 1' UNION SELECT username,password FROM users--"}`},
		{"form XSS", "POST", "/", "application/x-www-form-urlencoded", "q=" + url.QueryEscape("<script>alert(1)</script>")},
	}
	var mb bytes.Buffer
	mw := multipart.NewWriter(&mb)
	_ = mw.WriteField("q", "<script>alert(1)</script>")
	_ = mw.Close()
	tests = append(tests, struct{ name, method, path, ct, body string }{"multipart XSS", "POST", "/", mw.FormDataContentType(), mb.String()})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := reached.Load()
			w := request(g, tt.method, tt.path, tt.ct, tt.body)
			if w.Code != 403 {
				t.Fatalf("wanted 403; got %d %s", w.Code, w.Body)
			}
			if reached.Load() != before {
				t.Fatal("blocked payload reached upstream")
			}
		})
	}
	found := false
	for _, e := range g.Events() {
		for _, m := range e.Matches {
			if m.ID >= 941000 && m.ID < 943000 {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("no actual CRS SQLi/XSS rule matches recorded")
	}
}
func TestPolicyLifecycle(t *testing.T) {
	var reached atomic.Int32
	g, path := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	})
	c := g.Config()
	c.Mode = "detection"
	c.CustomRules = `SecRule REQUEST_URI "@beginsWith /private" "id:10001,phase:1,deny,status:403,log,msg:'Private route'"`
	c, err := g.Apply(c, false)
	if err != nil {
		t.Fatal(err)
	}
	if w := request(g, "GET", "/private", "", ""); w.Code != 200 {
		t.Fatalf("detection blocked: %d", w.Code)
	}
	if e := g.Events(); len(e) == 0 || e[0].Action != "detected" {
		t.Fatal("detection event missing")
	}
	c.Mode = "enforcing"
	if _, err = g.Apply(c, true); err != nil {
		t.Fatal(err)
	}
	if g.Config().Mode != "detection" {
		t.Fatal("validation changed policy")
	}
	c, err = g.Apply(c, false)
	if err != nil {
		t.Fatal(err)
	}
	if w := request(g, "GET", "/private", "", ""); w.Code != 403 {
		t.Fatalf("custom rule not enforced: %d", w.Code)
	}
	old := c
	c.CustomRules = "SecRule INVALID [ broken"
	if _, err = g.Apply(c, false); err == nil {
		t.Fatal("accepted invalid rule")
	}
	if g.Config().Revision != old.Revision {
		t.Fatal("failed update changed policy")
	}
	c = old
	c.Mode = "disabled"
	c, err = g.Apply(c, false)
	if err != nil {
		t.Fatal(err)
	}
	if w := request(g, "GET", "/private", "", ""); w.Code != 200 {
		t.Fatalf("disabled mode blocked: %d", w.Code)
	}
	if _, err = g.Apply(old, false); err == nil {
		t.Fatal("stale revision accepted")
	}
	loaded, err := load(path)
	if err != nil || loaded.Mode != "disabled" || loaded.Revision != c.Revision {
		t.Fatal("configuration did not persist", err)
	}
	for _, body := range []string{strings.Repeat("x", int(c.RequestLimit)+1)} {
		before := reached.Load()
		w := request(g, "POST", "/", "text/plain", body)
		if w.Code != 413 || reached.Load() != before {
			t.Fatal("oversized body was forwarded")
		}
	}
}
func TestBodyPreservationAndResponseInspection(t *testing.T) {
	g, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if r.URL.Path == "/leak" {
			_, _ = w.Write([]byte("internal-secret-marker"))
			return
		}
		b, _ := io.ReadAll(r.Body)
		_, _ = w.Write(b)
	})
	c := g.Config()
	c.InspectResponse = true
	c.ResponseLimit = 1024
	c.CustomRules = `SecRule RESPONSE_BODY "@contains internal-secret-marker" "id:10002,phase:4,deny,status:403,log,msg:'Leak prevented'"`
	if _, err := g.Apply(c, false); err != nil {
		t.Fatal(err)
	}
	if w := request(g, "POST", "/", "application/json", `{"message":"hello world"}`); w.Code != 200 || w.Body.String() != `{"message":"hello world"}` {
		t.Fatalf("body corrupted: %d %s", w.Code, w.Body)
	}
	if w := request(g, "GET", "/leak", "", ""); w.Code != 403 || strings.Contains(w.Body.String(), "internal-secret-marker") {
		t.Fatal("response secret leaked", w.Code, w.Body)
	}
	if w := request(g, "POST", "/", "application/json", `{"message":"`+strings.Repeat("a", 1025)+`"}`); w.Code != 502 {
		t.Fatalf("oversized response must fail closed: %d", w.Code)
	}
}
func TestManagementBoundaryAndAuthentication(t *testing.T) {
	g, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("application")) })
	token := strings.Repeat("s", 40)
	admin := NewAdmin(g, token)
	call := func(method, path, body, bearer, origin string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://console.test"+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		admin.ServeHTTP(w, r)
		return w
	}
	if w := call("GET", "/api/v1/config", "", "", "", nil); w.Code != 401 {
		t.Fatal("unauthenticated API access", w.Code)
	}
	if w := call("GET", "/api/v1/config", "", token, "", nil); w.Code != 200 {
		t.Fatal("bearer token rejected")
	}
	body, _ := json.Marshal(map[string]string{"token": "  " + token + "\r\n"})
	if w := call("POST", "/api/v1/login", string(body), "", "http://evil.test", nil); w.Code != 403 {
		t.Fatal("cross origin login allowed")
	}
	login := call("POST", "/api/v1/login", string(body), "", "http://console.test", nil)
	if login.Code != 200 {
		t.Fatal("login failed", login.Body)
	}
	cookies := login.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("invalid session cookie")
	}
	if w := call("GET", "/api/v1/events", "", "", "", cookies[0]); w.Code != 200 {
		t.Fatal("session rejected")
	}
	call("POST", "/api/v1/logout", "{}", "", "", cookies[0])
	if w := call("GET", "/api/v1/config", "", "", "", cookies[0]); w.Code != 401 {
		t.Fatal("logout did not revoke session")
	}
	if w := request(g, "GET", "/api/v1/config", "", ""); w.Body.String() != "application" {
		t.Fatal("admin routes exposed on proxy")
	}
	if w := call("GET", "/", "", "", "", nil); w.Code != 200 || !strings.Contains(w.Body.String(), "Security overview") {
		t.Fatal("dashboard missing")
	}
}
func TestConcurrentTrafficDuringReload(t *testing.T) {
	g, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				if w := request(g, "GET", "/", "", ""); w.Code != 200 {
					t.Errorf("request during reload: %d", w.Code)
				}
				_ = g.Events()
				_ = g.Summary()
			}
		}()
	}
	c := g.Config()
	c.Name = "Reloaded application"
	if _, err := g.Apply(c, false); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
}

func TestThresholdExclusionAndFailedPersistence(t *testing.T) {
	g, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	c := g.Config()
	c.InboundThreshold = 3
	var err error
	c, err = g.Apply(c, false)
	if err != nil {
		t.Fatal(err)
	}
	numericHost := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "http://127.0.0.1/", nil)
		r.Header.Set("User-Agent", "Integration test")
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		return w
	}
	if w := numericHost(); w.Code != 403 {
		t.Fatalf("threshold not honored: %d", w.Code)
	}
	c.Exclusions = []int{920350}
	c, err = g.Apply(c, false)
	if err != nil {
		t.Fatal(err)
	}
	if w := numericHost(); w.Code != 200 {
		t.Fatalf("actual CRS exclusion not honored: %d", w.Code)
	}
	old := g.path
	g.path = t.TempDir()
	defer func() { g.path = old }()
	c.Mode = "disabled"
	if _, err = g.Apply(c, false); err == nil {
		t.Fatal("invalid persistence destination accepted")
	}
	if g.Config().Mode == "disabled" || g.Config().Revision != c.Revision {
		t.Fatal("failed persistence changed active policy")
	}
	r := httptest.NewRequest("POST", "http://example.test/", strings.NewReader(strings.Repeat("x", int(c.RequestLimit)+1)))
	r.ContentLength = -1
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != 413 {
		t.Fatalf("unknown-length body limit not enforced: %d", w.Code)
	}
}
