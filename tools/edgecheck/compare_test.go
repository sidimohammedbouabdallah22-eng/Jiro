// Package edgecheck is an isolated dependency-heavy compatibility lab. Its Caddy
// dependencies do not enter the OpenWAF production module or binary.
package edgecheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	_ "github.com/corazawaf/coraza-caddy/v2"
	corazaconf "github.com/corazawaf/coraza-coreruleset/coraza/v3"
	crs "github.com/corazawaf/coraza-coreruleset/crs/v4"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/gateway"
)

type outcome struct {
	Name     string `json:"name"`
	Current  int    `json:"openwaf_status"`
	Caddy    int    `json:"caddy_status"`
	Expected int    `json:"contract_status"`
	Equal    bool   `json:"equal"`
}

func materialize(t *testing.T, root string, bundle fs.FS) {
	t.Helper()
	err := fs.WalkDir(bundle, ".", func(p string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		target := filepath.Join(root, filepath.FromSlash(p))
		if e = os.MkdirAll(filepath.Dir(target), 0700); e != nil {
			return e
		}
		b, e := fs.ReadFile(bundle, p)
		if e != nil {
			return e
		}
		return os.WriteFile(target, b, 0600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestConnectorComparison(t *testing.T) {
	dir := t.TempDir()
	materialize(t, dir, crs.FS)
	materialize(t, dir, corazaconf.FS)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/leak" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "internal-secret-marker")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		b, _ := io.ReadAll(r.Body)
		if len(b) > 0 {
			_, _ = w.Write(b)
		} else {
			_, _ = io.WriteString(w, `{"ok":true}`)
		}
	}))
	defer backend.Close()
	rows := []outcome{}
	for _, variant := range []struct {
		mode     string
		paranoia int
	}{{"enforcing", 1}, {"enforcing", 2}, {"detection", 2}, {"disabled", 2}} {
		mode := variant.mode
		c := gateway.Defaults()
		c.Upstream = backend.URL
		c.Paranoia = variant.paranoia
		c.Mode = mode
		c.RequestLimit = 1024
		c.ResponseLimit = 1024
		c.InspectResponse = true
		c.CustomRules = `SecRule RESPONSE_BODY "@contains internal-secret-marker" "id:10002,phase:4,deny,status:403,log,msg:'Response fixture'"`
		c.ScopedExceptions = []gateway.ScopedException{{ID: "comparison", Path: "/search", Method: "GET", Collection: "ARGS_GET", Parameter: "q", RuleIDs: []int{942131}, Owner: "edgecheck", Reason: "Allow a legitimate price comparison in one search field"}}
		label := fmt.Sprintf("%s PL%d", mode, c.Paranoia)
		policy := filepath.Join(dir, label+".json")
		b, _ := json.Marshal(c)
		if err := os.WriteFile(policy, b, 0600); err != nil {
			t.Fatal(err)
		}
		g, err := gateway.New(policy)
		if err != nil {
			t.Fatal(err)
		}
		current := httptest.NewServer(g)
		directives, err := gateway.Directives(c)
		if err != nil {
			t.Fatal(err)
		}
		// Compare the same Coraza recommended config and CRS 4.30 files, rather
		// than Caddy's release-bundled legacy CRS 4.25 module.
		for _, alias := range []string{"@coraza.conf-recommended", "@crs-setup.conf.example", "@owasp_crs/*.conf"} {
			directives = strings.ReplaceAll(directives, "Include "+alias, "Include "+filepath.ToSlash(filepath.Join(dir, alias)))
		}
		reserve, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := reserve.Addr().String()
		_ = reserve.Close()
		target, _ := url.Parse(backend.URL)
		config := map[string]any{"admin": map[string]any{"disabled": true}, "logging": map[string]any{"logs": map[string]any{"default": map[string]any{"level": "ERROR"}}}, "apps": map[string]any{"http": map[string]any{"servers": map[string]any{"lab": map[string]any{"listen": []string{address}, "automatic_https": map[string]any{"disable": true}, "routes": []any{map[string]any{"handle": []any{map[string]any{"handler": "waf", "directives": directives, "load_owasp_crs": false}, map[string]any{"handler": "reverse_proxy", "upstreams": []any{map[string]any{"dial": target.Host}}}}}}}}}}}
		b, _ = json.Marshal(config)
		if err = caddy.Load(b, true); err != nil {
			current.Close()
			g.Close(context.Background())
			t.Fatal(err)
		}
		client := &http.Client{Timeout: 10 * time.Second}
		cases := []struct {
			name, method, path, body string
			status                   int
			chunked                  bool
		}{
			{"clean GET", "GET", "/", "", 200, false},
			{"clean JSON body", "POST", "/", `{"name":"Alice"}`, 200, false},
			{"SQLi", "GET", "/?q=" + url.QueryEscape("1' UNION SELECT password FROM users--"), "", 403, false},
			{"JSON XSS", "POST", "/", `{"message":"<script>alert(1)</script>"}`, 403, false},
			{"malformed JSON", "POST", "/", `{"broken":`, 400, false},
			{"scoped exception selected field", "GET", "/search?q=" + url.QueryEscape("price < 100"), "", 200, false},
			{"scoped exception other path", "GET", "/other?q=" + url.QueryEscape("price < 100"), "", 403, false},
			{"scoped exception other field", "GET", "/search?other=" + url.QueryEscape("price < 100"), "", 403, false},
			{"chunked JSON XSS", "POST", "/", `{"message":"<script>alert(1)</script>"}`, 403, true},
			{"oversized body", "POST", "/", `{"message":"` + strings.Repeat("a", 1100) + `"}`, 413, false},
			{"response intervention", "GET", "/leak", "", 403, false},
			{"shell command", "GET", "/?q=" + url.QueryEscape("; cat /etc/passwd"), "", 403, false},
		}
		for _, tc := range cases {
			expected := tc.status
			if c.Paranoia == 1 && (tc.name == "scoped exception other path" || tc.name == "scoped exception other field") {
				expected = 200
			}
			if mode != "enforcing" && expected != 413 {
				expected = 200
			}
			statuses := []int{}
			for _, endpoint := range []string{current.URL, "http://" + address} {
				r, _ := http.NewRequest(tc.method, endpoint+tc.path, strings.NewReader(tc.body))
				r.Host = "application.test"
				r.Header.Set("User-Agent", "Mozilla/5.0")
				r.Header.Set("Accept", "application/json")
				r.Header.Set("Accept-Language", "en-US")
				if tc.method == "POST" {
					r.Header.Set("Content-Type", "application/json")
				}
				if tc.chunked {
					r.ContentLength = -1
				}
				resp, err := client.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				statuses = append(statuses, resp.StatusCode)
				if mode == "enforcing" && tc.name == "response intervention" && strings.Contains(string(body), "internal-secret-marker") {
					t.Errorf("%s leaked blocked response", endpoint)
				}
				if tc.name == "clean JSON body" && resp.StatusCode == 200 && string(body) != tc.body {
					t.Errorf("%s changed accepted body", endpoint)
				}
			}
			rows = append(rows, outcome{label + " / " + tc.name, statuses[0], statuses[1], expected, statuses[0] == statuses[1]})
			if statuses[0] != expected {
				t.Errorf("OpenWAF %s: got %d want %d", tc.name, statuses[0], expected)
			}
			caddyExpected := expected
			if mode != "enforcing" && tc.name == "oversized body" {
				caddyExpected = 200
			}
			if statuses[1] != caddyExpected {
				t.Errorf("unexpected Caddy differential for %s/%s: got %d want %d", mode, tc.name, statuses[1], caddyExpected)
			}
			t.Logf("%s / %s: OpenWAF=%d Caddy=%d contract=%d", label, tc.name, statuses[0], statuses[1], expected)
		}
		client.CloseIdleConnections()
		_ = caddy.Stop()
		current.Close()
		g.Close(context.Background())
	}
	if err := os.MkdirAll("../../artifacts", 0755); err != nil {
		t.Fatal(err)
	}
	result := map[string]any{"caddy_connector": "v2.6.2", "coraza": "v3.8.2-0.20261029104012-08aa51147300", "crs": crs.Version, "generated": time.Now().UTC(), "cases": rows, "note": "Focused compatibility probe, not a complete edge qualification. Both use the same extracted CRS and policy compiler."}
	b, _ := json.MarshalIndent(result, "", "  ")
	if err := os.WriteFile("../../artifacts/edge-comparison.json", b, 0644); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("Compared %d connector cases; see artifacts/edge-comparison.json\n", len(rows))
}
