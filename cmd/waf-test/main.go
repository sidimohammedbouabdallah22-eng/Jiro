// waf-test exercises the full local connector against a harmless mock backend.
// Payloads are never executed. No external target or active policy is modified.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/engineinfo"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/gateway"
)

type Case struct {
	Name, Class, Category, Method, Path, ContentType, Body string
	Headers                                                map[string]string
}
type Result struct {
	Case           Case
	Status         int
	Action         string
	BackendReached bool
	BodyPreserved  bool
	Milliseconds   float64
	Matches        []gateway.Match
}
type Scenario struct {
	AttacksObserved                                                                       int
	Name                                                                                  string
	Policy                                                                                gateway.Config
	Benign, BenignBlocked, Attacks, AttacksBlocked, Contextual, ContextualBlocked, Errors int
	Results                                                                               []Result
}
type Load struct {
	Requests, Concurrency, Passed, Failed int
	P50, P95, P99                         float64
	Seconds                               float64
}
type Report struct {
	Generated         time.Time
	Engine, CRS       string
	Scenarios         []Scenario
	Load              Load
	InvariantFailures []string
}

func query(name, class, category, payload string) Case {
	return Case{Name: name, Class: class, Category: category, Method: "GET", Path: "/search?q=" + url.QueryEscape(payload)}
}
func post(name, class, category, ct, body string) Case {
	return Case{Name: name, Class: class, Category: category, Method: "POST", Path: "/submit", ContentType: ct, Body: body}
}
func corpus() []Case {
	cases := []Case{}
	for _, s := range []struct{ name, value string }{
		{"plain search", "summer shoes"}, {"apostrophe in name", "O'Reilly"}, {"surname", "D'Angelo"}, {"Unicode Arabic", "مرحبا بالعالم"}, {"Unicode accents", "café résumé"}, {"emoji", "hello 🌍"}, {"email", "alice+news@example.org"}, {"ampersand", "research & development"}, {"comparison", "price < 100"}, {"math", "2 + 2 = 4"}, {"URL", "https://example.org/products?id=12"}, {"Windows path", `C:\Users\Alice\Documents`}, {"Unix path", "/home/alice/documents"}, {"percent symbol", "save 20% today"}, {"SQL words in prose", "please select from the menu"}, {"hyphenated prose", "well-known product"}, {"JSON-looking search", `{"theme":"dark"}`}, {"empty string", ""}, {"long ordinary text", strings.Repeat("ordinary text ", 150)},
	} {
		cases = append(cases, query(s.name, "benign", "normal input", s.value))
	}
	cases = append(cases,
		Case{Name: "health endpoint", Class: "benign", Category: "normal routing", Method: "GET", Path: "/health"},
		Case{Name: "static asset", Class: "benign", Category: "normal routing", Method: "GET", Path: "/assets/app.js?v=123"},
		post("normal JSON", "benign", "JSON", "application/json", `{"name":"O'Reilly","message":"hello world","count":12}`),
		post("normal form", "benign", "form", "application/x-www-form-urlencoded", "name=Alice&message=hello+world"),
		post("normal XML", "benign", "XML", "application/xml", `<order><name>Alice</name><count>2</count></order>`),
	)
	for _, s := range []struct{ name, category, payload string }{
		{"UNION extraction", "SQLi", "1' UNION SELECT username,password FROM users--"},
		{"boolean SQLi", "SQLi", "' OR '1'='1' --"},
		{"time-based SQLi", "SQLi", "1 AND SLEEP(5)"},
		{"stacked statements", "SQLi", "1; DROP TABLE users--"},
		{"comment-obfuscated UNION", "SQLi", "1 UNION/**/SELECT password FROM users"},
		{"error-based SQLi", "SQLi", "1 AND extractvalue(1,concat(0x7e,version()))"},
		{"script element", "XSS", "<script>alert(1)</script>"},
		{"image event handler", "XSS", `<img src=x onerror=alert(1)>`},
		{"SVG event handler", "XSS", `<svg/onload=alert(1)>`},
		{"javascript URL", "XSS", `javascript:alert(document.cookie)`},
		{"encoded script text", "XSS", `%3Cscript%3Ealert(1)%3C%2Fscript%3E`},
		{"HTML-entity script", "XSS", `<img src=x onerror=&#97;lert(1)>`},
		{"Unix file traversal", "LFI", "../../../../etc/passwd"},
		{"Windows file traversal", "LFI", `..\..\..\windows\win.ini`},
		{"null-byte traversal", "LFI", "../../etc/passwd\x00.jpg"},
		{"shell separator", "RCE", "; cat /etc/passwd"},
		{"shell substitution", "RCE", "$(cat /etc/passwd)"},
		{"shell pipe", "RCE", "| /bin/sh -c id"},
		{"PHP wrapper", "RFI", "php://filter/convert.base64-encode/resource=index.php"},
		{"PHP code", "RCE", "<?php system($_GET['cmd']); ?>"},
		{"Java naming lookup", "RCE", "${jndi:ldap://127.0.0.1/a}"},
	} {
		cases = append(cases, query(s.name, "attack", s.category, s.payload))
	}
	cases = append(cases,
		post("JSON injection", "attack", "SQLi", "application/json", `{"id":"1' UNION SELECT username,password FROM users--"}`),
		post("form injection", "attack", "XSS", "application/x-www-form-urlencoded", "message="+url.QueryEscape("<script>alert(1)</script>")),
		Case{Name: "cookie injection", Class: "attack", Category: "SQLi", Method: "GET", Path: "/", Headers: map[string]string{"Cookie": "search=1' UNION SELECT password FROM users--"}},
		// These are application-dependent probes: CRS is not a URL allowlist or
		// authorization system. Passing a mock backend does not prove exploitation.
		query("cloud metadata URL", "probe", "SSRF", "http://169.254.169.254/latest/meta-data/"),
		query("loopback URL", "probe", "SSRF", "http://127.0.0.1/admin"),
		Case{Name: "admin path without auth", Class: "probe", Category: "authorization", Method: "GET", Path: "/admin"},
		Case{Name: "other user's object", Class: "probe", Category: "authorization", Method: "GET", Path: "/users/2/invoices"},
	)
	for _, s := range []struct{ name, value string }{
		{"SQL tutorial search", "UNION SELECT is used to combine SQL results"},
		{"JavaScript documentation", "<script>alert('hello')</script>"},
		{"rich HTML text", "<p>Hello <strong>world</strong></p>"},
		{"shell documentation", "Run cat /etc/passwd to inspect local accounts"},
		{"relative-path documentation", "../../docs/readme.md"},
		{"JavaScript code snippet", "function greet() { return 'hello'; }"},
		{"SQL query editor", "SELECT name FROM customers WHERE id = 1"},
	} {
		cases = append(cases, query(s.name, "contextual", "legitimate in some applications", s.value))
	}
	cases = append(cases, post("HTML editor JSON", "contextual", "rich text", "application/json", `{"content":"<h1>Hello</h1><p>Welcome</p>"}`), post("SQL editor JSON", "contextual", "developer tool", "application/json", `{"query":"SELECT * FROM users WHERE name = 'Alice'"}`))
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("description", "Quarterly report")
	part, _ := mw.CreateFormFile("document", "report.txt")
	_, _ = part.Write([]byte("Revenue increased this quarter."))
	_ = mw.Close()
	cases = append(cases, post("normal multipart upload", "benign", "multipart", mw.FormDataContentType(), buf.String()))
	buf.Reset()
	mw = multipart.NewWriter(&buf)
	_ = mw.WriteField("message", "<script>alert(1)</script>")
	_ = mw.Close()
	cases = append(cases, post("multipart injection", "attack", "XSS", mw.FormDataContentType(), buf.String()))
	return cases
}

func run() error {
	out := flag.String("out", "artifacts/traffic-report", "Report path without extension")
	loadCount := flag.Int("load", 500, "Number of clean requests in the concurrent smoke check (0–10000)")
	flag.Parse()
	if *loadCount < 0 || *loadCount > 10000 {
		return fmt.Errorf("load must be between 0 and 10000")
	}
	temp, err := os.MkdirTemp("", "openwaf-traffic-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)
	var mu sync.Mutex
	received := map[string][]byte{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		received[r.Header.Get("X-Test-Case")] = b
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	report := Report{Generated: time.Now(), Engine: "Coraza v3.8.1", CRS: "OWASP CRS v4.30.0", InvariantFailures: []string{}}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			switch dep.Path {
			case "github.com/corazawaf/coraza/v3":
				report.Engine = "Coraza " + engineinfo.Version()
			case "github.com/corazawaf/coraza-coreruleset/crs/v4":
				report.CRS = "OWASP CRS " + dep.Version
			}
		}
	}
	for _, level := range []int{1, 2, 3, 4, 0} {
		c := gateway.Defaults()
		c.Upstream = upstream.URL
		c.Paranoia = level
		name := fmt.Sprintf("Enforcing / PL%d", level)
		if level == 0 {
			c.Paranoia = 1
			c.Mode = "detection"
			name = "Detection / PL1"
		}
		data, _ := json.Marshal(c)
		policyPath := filepath.Join(temp, fmt.Sprintf("policy-%d.json", level))
		if err = os.WriteFile(policyPath, data, 0600); err != nil {
			return err
		}
		g, e := gateway.New(policyPath)
		if e != nil {
			return e
		}
		scenario := Scenario{Name: name, Policy: c, Results: []Result{}}
		var completions sync.Map
		front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			g.ServeHTTP(w, r)
			if done, ok := completions.LoadAndDelete(r.Header.Get("X-Test-Case")); ok {
				close(done.(chan struct{}))
			}
		}))
		client := &http.Client{Timeout: 10 * time.Second}
		for i, tc := range corpus() {
			id := fmt.Sprintf("pl%d-case%d", level, i)
			r, _ := http.NewRequest(tc.Method, front.URL+tc.Path, strings.NewReader(tc.Body))
			r.Host = "application.test"
			r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")
			r.Header.Set("X-Test-Case", id)
			r.Header.Set("Accept", "application/json")
			r.Header.Set("Accept-Language", "en-US,en;q=0.9")
			if tc.ContentType != "" {
				r.Header.Set("Content-Type", tc.ContentType)
			}
			for k, v := range tc.Headers {
				r.Header.Set(k, v)
			}
			done := make(chan struct{})
			completions.Store(id, done)
			start := time.Now()
			w, requestErr := client.Do(r)
			if requestErr != nil {
				front.Close()
				g.Close(context.Background())
				return requestErr
			}
			_, readErr := io.Copy(io.Discard, w.Body)
			_ = w.Body.Close()
			if readErr != nil {
				return readErr
			}
			<-done
			duration := float64(time.Since(start).Microseconds()) / 1000
			result := Result{Case: tc, Status: w.StatusCode, Action: "pass", Milliseconds: duration, Matches: []gateway.Match{}}
			mu.Lock()
			b, reached := received[id]
			delete(received, id)
			mu.Unlock()
			result.BackendReached = reached
			result.BodyPreserved = !reached || bytes.Equal(b, []byte(tc.Body))
			for _, evt := range g.Events() {
				if evt.ID == w.Header.Get("X-OpenWAF-Request-ID") {
					result.Action = evt.Action
					result.Matches = evt.Matches
					break
				}
			}
			blocked := w.StatusCode >= 400
			switch tc.Class {
			case "benign":
				scenario.Benign++
				if blocked {
					scenario.BenignBlocked++
				}
			case "attack":
				scenario.Attacks++
				if len(result.Matches) > 0 {
					scenario.AttacksObserved++
				}
				if blocked {
					scenario.AttacksBlocked++
				}
			case "contextual":
				scenario.Contextual++
				if blocked {
					scenario.ContextualBlocked++
				}
			}
			if w.StatusCode >= 500 {
				scenario.Errors++
			}
			if blocked && reached {
				report.InvariantFailures = append(report.InvariantFailures, name+": rejected request reached backend: "+tc.Name)
			}
			if !result.BodyPreserved {
				report.InvariantFailures = append(report.InvariantFailures, name+": accepted body changed: "+tc.Name)
			}
			if c.Mode == "detection" && blocked {
				report.InvariantFailures = append(report.InvariantFailures, name+": detection mode blocked fixture: "+tc.Name)
			}
			scenario.Results = append(scenario.Results, result)
		}
		if level == 1 && *loadCount > 0 {
			samples := make([]float64, *loadCount)
			failed := 0
			var lm sync.Mutex
			var wg sync.WaitGroup
			start := time.Now()
			jobs := make(chan int)
			for worker := 0; worker < 8; worker++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for n := range jobs {
						r, _ := http.NewRequest("GET", front.URL+"/products?color=blue", nil)
						r.Host = "application.test"
						r.Header.Set("User-Agent", "Mozilla/5.0")
						r.Header.Set("X-Test-Case", fmt.Sprintf("load-%d", n))
						st := time.Now()
						w, requestErr := client.Do(r)
						if requestErr == nil {
							_, requestErr = io.Copy(io.Discard, w.Body)
							_ = w.Body.Close()
						}
						samples[n] = float64(time.Since(st).Microseconds()) / 1000
						if requestErr != nil || w.StatusCode != 200 {
							lm.Lock()
							failed++
							lm.Unlock()
						}
					}
				}()
			}
			for n := range samples {
				jobs <- n
			}
			close(jobs)
			wg.Wait()
			seconds := time.Since(start).Seconds()
			sort.Float64s(samples)
			p := func(q float64) float64 { return samples[int(float64(len(samples)-1)*q)] }
			report.Load = Load{*loadCount, 8, *loadCount - failed, failed, p(.50), p(.95), p(.99), seconds}
			if failed > 0 {
				report.InvariantFailures = append(report.InvariantFailures, fmt.Sprintf("clean concurrent traffic: %d failures", failed))
			}
		}
		front.Close()
		client.CloseIdleConnections()
		g.Close(context.Background())
		report.Scenarios = append(report.Scenarios, scenario)
	}
	if err = os.MkdirAll(filepath.Dir(*out), 0755); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(report, "", "  ")
	if err = os.WriteFile(*out+".json", data, 0644); err != nil {
		return err
	}
	if err = writeHTML(*out+".html", report); err != nil {
		return err
	}
	for _, s := range report.Scenarios {
		fmt.Printf("%-20s benign blocked %d/%d | attack fixtures blocked %d/%d, observed %d | contextual blocked %d/%d | server errors %d\n", s.Name, s.BenignBlocked, s.Benign, s.AttacksBlocked, s.Attacks, s.AttacksObserved, s.ContextualBlocked, s.Contextual, s.Errors)
	}
	fmt.Printf("Concurrent clean traffic: %d/%d passed; p50 %.2f ms, p95 %.2f ms, p99 %.2f ms (local smoke check, not a capacity benchmark)\n", report.Load.Passed, report.Load.Requests, report.Load.P50, report.Load.P95, report.Load.P99)
	fmt.Printf("Report: %s.html and %s.json\n", *out, *out)
	if len(report.InvariantFailures) > 0 {
		return fmt.Errorf("connector invariant failures: %v", report.InvariantFailures)
	}
	return nil
}

func writeHTML(path string, r Report) error {
	const page = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>OpenWAF traffic validation</title><style>body{font:14px/1.6 system-ui,sans-serif;background:#f2f6f7;color:#203946;margin:0}main{max-width:1250px;margin:40px auto;padding:0 24px}h1{font-size:32px}h2{margin-top:36px}p{color:#607984}.panel,details{background:white;border:1px solid #dbe5e9;border-radius:8px;padding:18px;margin:14px 0}table{width:100%;border-collapse:collapse;font-size:12px}th,td{text-align:left;border-bottom:1px solid #e6ecef;padding:10px;vertical-align:top}th{background:#edf4f3}code{word-break:break-word;white-space:pre-wrap}summary{cursor:pointer;font-weight:600}.blocked{color:#b13f50}.pass{color:#087e68}.wrap{overflow:auto}.note{border-left:4px solid #138671;padding:10px 18px;background:#e5f3ee}small{color:#6d828c}</style><main><small>OPENWAF / LOCAL VALIDATION</small><h1>Traffic, attacks & false positives</h1><p>{{.Engine}} · {{.CRS}} · {{.Generated}}</p><div class="note">All requests used an isolated policy and a harmless local backend. Payloads were not executed. The active application was not changed. Attack-shaped requests reaching this backend are coverage observations, not proof of exploitation. Contextual cases are legitimate only for particular application features.</div><h2>Results by policy</h2><div class="panel wrap"><table><tr><th>Policy</th><th>Benign blocked</th><th>Attack fixtures blocked / observed</th><th>Contextual blocked</th><th>Server errors</th></tr>{{range .Scenarios}}<tr><td>{{.Name}}</td><td>{{.BenignBlocked}} / {{.Benign}}</td><td>{{.AttacksBlocked}} / {{.Attacks}} blocked; {{.AttacksObserved}} observed</td><td>{{.ContextualBlocked}} / {{.Contextual}}</td><td>{{.Errors}}</td></tr>{{end}}</table></div><h2>Concurrent clean traffic</h2><div class="panel">{{.Load.Passed}} / {{.Load.Requests}} requests passed with {{.Load.Concurrency}} workers. End-to-end p50 {{printf "%.2f" .Load.P50}} ms · p95 {{printf "%.2f" .Load.P95}} ms · p99 {{printf "%.2f" .Load.P99}} ms.<p>This local check sends HTTP requests through a real proxy listener and a real HTTP backend. It is not a production capacity benchmark.</p></div><h2>Connector invariants</h2><div class="panel">{{if .InvariantFailures}}{{range .InvariantFailures}}<p class="blocked">{{.}}</p>{{end}}{{else}}Passed: rejected requests did not reach the backend, accepted bodies were preserved, detection mode did not block these fixtures, and clean concurrent requests succeeded.{{end}}</div><h2>Individual cases and matching rules</h2>{{range .Scenarios}}<details><summary>{{.Name}}</summary><div class="wrap"><table><tr><th>Case</th><th>Class</th><th>Status / backend</th><th>Rules</th><th>Request fixture</th></tr>{{range .Results}}<tr><td>{{.Case.Name}}<br><small>{{.Case.Category}}</small></td><td>{{.Case.Class}}</td><td>{{.Status}}<br>{{if .BackendReached}}Reached backend{{else}}Stopped before backend{{end}}<br>{{printf "%.2f" .Milliseconds}} ms</td><td>{{range .Matches}}<div><b>{{.ID}}</b> {{.Message}}</div>{{end}}</td><td><code>{{.Case.Method}} {{.Case.Path}}{{if .Case.Body}}<br>{{.Case.Body}}{{end}}</code></td></tr>{{end}}</table></div></details>{{end}}<h2>Interpretation</h2><p>Benign cases are expected to pass. Blocked benign cases are false-positive candidates for this synthetic workload. Contextual cases include SQL editors, rich text and code documentation, which need application-specific policy. SSRF and authorization probes are listed separately in the detailed cases; a generic CRS policy cannot replace backend authorization or outbound destination controls. Do not tune by globally raising thresholds just to make fixtures pass.</p></main></html>`
	t, err := template.New("report").Parse(page)
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return t.Execute(f, r)
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
