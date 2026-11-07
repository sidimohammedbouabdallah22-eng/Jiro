// transportcheck drives only an owned loopback-forwarded application fixture.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type testCase struct {
	Host           string            `json:"host"`
	Authority      string            `json:"authority,omitempty"`
	Method         string            `json:"method"`
	Path           string            `json:"path"`
	Body           []byte            `json:"body"`
	Kind           string            `json:"kind"`
	Headers        map[string]string `json:"headers"`
	Expected       int               `json:"expected"`
	ResponseSHA256 string            `json:"response_sha256,omitempty"`
}
type configuration struct {
	Target  string     `json:"target"`
	CA      string     `json:"ca"`
	Seconds int        `json:"seconds"`
	Rate    int        `json:"rate"`
	Cases   []testCase `json:"cases"`
	Large   []testCase `json:"large"`
}
type observation struct {
	Status     int     `json:"status"`
	Correct    bool    `json:"correct"`
	Protocol   int     `json:"protocol"`
	TLS        uint16  `json:"tls"`
	Verified   bool    `json:"verified"`
	Reused     bool    `json:"reused"`
	Resumed    bool    `json:"resumed"`
	Connection int     `json:"connection"`
	Written    float64 `json:"written"`
	FirstByte  float64 `json:"first_byte"`
	ErrorType  string  `json:"error_type,omitempty"`
	LatencyMS  float64 `json:"scheduled_latency_ms"`
}
type connections struct {
	sync.Mutex
	ids map[net.Conn]int
}

func (c *connections) id(conn net.Conn) int {
	c.Lock()
	defer c.Unlock()
	if c.ids == nil {
		c.ids = make(map[net.Conn]int)
	}
	if c.ids[conn] == 0 {
		c.ids[conn] = len(c.ids) + 1
	}
	return c.ids[conn]
}

type generator struct {
	c        configuration
	roots    *x509.CertPool
	requests atomic.Int64
}

func (c *connections) count() int { c.Lock(); defer c.Unlock(); return len(c.ids) }

func timestamp() float64 { return float64(time.Now().UnixNano()) / 1e9 }
func (g *generator) transport(protocol int, fresh bool, version uint16) *http.Transport {
	config := &tls.Config{RootCAs: g.roots, MinVersion: tls.VersionTLS12}
	if version != 0 {
		config.MinVersion = version
		config.MaxVersion = version
	}
	tr := &http.Transport{TLSClientConfig: config, ForceAttemptHTTP2: protocol == 2, DisableKeepAlives: fresh,
		MaxConnsPerHost: 8, MaxIdleConns: 24, MaxIdleConnsPerHost: 8, IdleConnTimeout: 30 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 20 * time.Second,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", g.c.Target)
		}}
	if protocol == 1 {
		config.NextProtos = []string{"http/1.1"}
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	return tr
}
func client(tr *http.Transport) *http.Client {
	return &http.Client{Transport: tr, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func validResponse(c testCase, status int, body []byte) bool {
	if status != c.Expected {
		return false
	}
	if status != 200 && status != 201 {
		return true
	}
	if c.ResponseSHA256 != "" {
		sum := sha256.Sum256(body)
		return hex.EncodeToString(sum[:]) == c.ResponseSHA256
	}
	if c.Host == "probe.capacity.test" || c.Kind == "echo" {
		var value struct {
			Marker string
			Bytes  int
			SHA256 string
		}
		sum := sha256.Sum256(c.Body)
		return json.Unmarshal(body, &value) == nil && value.Marker == "capacity-backend" && value.Bytes == len(c.Body) && value.SHA256 == hex.EncodeToString(sum[:])
	}
	if c.Kind == "dvwa-lookup" {
		return bytes.Contains(body, []byte("First name: admin"))
	}
	if c.Kind == "wordpress-edit" {
		var value struct{ Title struct{ Raw string } }
		return json.Unmarshal(body, &value) == nil && value.Title.Raw == "Capacity reviewed invoice"
	}
	if c.Kind == "upload" {
		var value struct {
			MediaType string `json:"media_type"`
		}
		return json.Unmarshal(body, &value) == nil && value.MediaType == "image"
	}
	var array []json.RawMessage
	return bytes.HasPrefix(bytes.TrimSpace(body), []byte("[")) && json.Unmarshal(body, &array) == nil
}
func (g *generator) request(cl *http.Client, tracker *connections, c testCase, due time.Time) observation {
	obs := observation{}
	var traceMu sync.Mutex
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			traceMu.Lock()
			defer traceMu.Unlock()
			obs.Reused = info.Reused
			obs.Connection = tracker.id(info.Conn)
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			traceMu.Lock()
			defer traceMu.Unlock()
			if info.Err == nil {
				obs.Written = timestamp()
			}
		},
		GotFirstResponseByte: func() { traceMu.Lock(); defer traceMu.Unlock(); obs.FirstByte = timestamp() },
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), c.Method, "https://"+c.Host+c.Path, bytes.NewReader(c.Body))
	if err != nil {
		obs.ErrorType = "invalid_request"
		return obs
	}
	req.Header.Set("User-Agent", "OpenWAF M4 transport qualification")
	if c.Authority != "" {
		req.Host = c.Authority
	}
	req.Header.Set("Content-Type", "application/json")
	for name, value := range c.Headers {
		req.Header.Set(name, value)
	}
	g.requests.Add(1)
	response, err := cl.Do(req)
	if err != nil {
		traceMu.Lock()
		defer traceMu.Unlock()
		obs.ErrorType = fmt.Sprintf("%T", err)
		obs.LatencyMS = float64(time.Since(due)) / float64(time.Millisecond)
		return obs
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	traceMu.Lock()
	defer traceMu.Unlock()
	obs.Status = response.StatusCode
	obs.Protocol = response.ProtoMajor
	if response.TLS != nil {
		obs.TLS = response.TLS.Version
		obs.Verified = len(response.TLS.VerifiedChains) > 0
		obs.Resumed = response.TLS.DidResume
	}
	obs.Correct = err == nil && len(body) <= 2<<20 && validResponse(c, response.StatusCode, body)
	if err != nil {
		obs.ErrorType = fmt.Sprintf("%T", err)
	}
	obs.LatencyMS = float64(time.Since(due)) / float64(time.Millisecond)
	return obs
}

type phase struct {
	Name              string         `json:"name"`
	Started           float64        `json:"started"`
	Finished          float64        `json:"finished"`
	RequestedSeconds  int            `json:"requested_seconds"`
	Rate              int            `json:"rate"`
	Planned           int            `json:"planned"`
	Completed         int            `json:"completed"`
	GeneratorRefusals int            `json:"generator_refusals"`
	Late              int            `json:"scheduler_late_over_100ms"`
	Unexpected        int            `json:"unexpected"`
	NetworkErrors     int            `json:"network_errors"`
	UniqueConnections int            `json:"unique_connections"`
	Reused            int            `json:"reused"`
	P95MS             float64        `json:"p95_ms"`
	P99MS             float64        `json:"p99_ms"`
	Protocols         map[int]int    `json:"protocols"`
	TLSVersions       map[uint16]int `json:"tls_versions"`
	Statuses          map[int]int    `json:"statuses"`
	Passed            bool           `json:"passed"`
}

func percentile(values []float64, fraction float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sort.Float64s(values)
	return values[int(float64(len(values)-1)*fraction)]
}
func (g *generator) phase(name string, protocol int, fresh bool) phase {
	tr := g.transport(protocol, fresh, 0)
	defer tr.CloseIdleConnections()
	cl := client(tr)
	tracker := &connections{}
	p := phase{Name: name, Started: timestamp(), Rate: g.c.Rate, RequestedSeconds: g.c.Seconds, Planned: g.c.Rate * g.c.Seconds,
		Protocols: map[int]int{}, TLSVersions: map[uint16]int{}, Statuses: map[int]int{}}
	type job struct {
		index int
		due   time.Time
	}
	jobs := make(chan job, 32)
	results := make(chan observation, p.Planned)
	var workers sync.WaitGroup
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := range jobs {
				results <- g.request(cl, tracker, g.c.Cases[j.index%len(g.c.Cases)], j.due)
			}
		}()
	}
	start := time.Now()
	for i := 0; i < p.Planned; i++ {
		due := start.Add(time.Duration(float64(i) / float64(p.Rate) * float64(time.Second)))
		if pause := time.Until(due); pause > 0 {
			time.Sleep(pause)
		}
		if time.Since(due) > 100*time.Millisecond {
			p.Late++
		}
		select {
		case jobs <- job{i, due}:
		default:
			p.GeneratorRefusals++
		}
		if i > 0 && i%75 == 0 {
			fmt.Printf("%s: scheduled=%d/%d completed=%d generator_refusals=%d\n", name, i+1, p.Planned, len(results), p.GeneratorRefusals)
		}
	}
	close(jobs)
	workers.Wait()
	close(results)
	latencies := []float64{}
	for result := range results {
		p.Completed++
		p.Protocols[result.Protocol]++
		p.TLSVersions[result.TLS]++
		p.Statuses[result.Status]++
		if result.ErrorType != "" {
			p.NetworkErrors++
		}
		if !result.Correct || !result.Verified || result.Protocol != protocol || result.TLS < tls.VersionTLS12 {
			p.Unexpected++
		}
		if result.Reused {
			p.Reused++
		}
		latencies = append(latencies, result.LatencyMS)
	}
	p.UniqueConnections = tracker.count()
	p.P95MS = percentile(latencies, .95)
	p.P99MS = percentile(latencies, .99)
	p.Passed = p.Completed == p.Planned && p.GeneratorRefusals == 0 && p.Late <= p.Planned/100 && p.NetworkErrors == 0 && p.Unexpected == 0 && p.P95MS <= 2000
	if fresh {
		p.Passed = p.Passed && p.Reused == 0 && p.UniqueConnections == p.Completed
	} else {
		p.Passed = p.Passed && p.Reused > 0 && p.UniqueConnections < p.Completed
	}
	p.Finished = timestamp()
	return p
}

type check struct {
	Name         string        `json:"name"`
	Passed       bool          `json:"passed"`
	Requests     int           `json:"requests"`
	Connections  int           `json:"connections,omitempty"`
	Overlap      int           `json:"overlap,omitempty"`
	Resumed      int           `json:"resumed,omitempty"`
	Observations []observation `json:"observations,omitempty"`
}

func (g *generator) functional(name string, protocol int, version uint16, cases []testCase) check {
	tr := g.transport(protocol, false, version)
	defer tr.CloseIdleConnections()
	tracker := &connections{}
	cl := client(tr)
	result := check{Name: name, Passed: true}
	for _, c := range cases {
		obs := g.request(cl, tracker, c, time.Now())
		result.Requests++
		result.Passed = result.Passed && obs.Correct && obs.Verified && obs.Protocol == protocol && (version == 0 || obs.TLS == version)
	}
	result.Connections = tracker.count()
	return result
}
func (g *generator) multiplex() check {
	tr := g.transport(2, false, 0)
	tr.MaxConnsPerHost = 1
	defer tr.CloseIdleConnections()
	tracker := &connections{}
	cl := client(tr)
	c := testCase{Host: "probe.capacity.test", Method: "GET", Path: "/echo?delay_ms=200", Kind: "echo", Expected: 200}
	warm := g.request(cl, tracker, c, time.Now())
	result := check{Name: "HTTP2 simultaneous streams on one verified TLS connection", Passed: warm.Correct && warm.Protocol == 2 && warm.Verified, Requests: 4}
	start := make(chan struct{})
	out := make(chan observation, 3)
	for i := 0; i < 3; i++ {
		go func() { <-start; out <- g.request(cl, tracker, c, time.Now()) }()
	}
	close(start)
	rows := []observation{}
	for i := 0; i < 3; i++ {
		obs := <-out
		rows = append(rows, obs)
		result.Passed = result.Passed && obs.Correct && obs.Protocol == 2 && obs.Verified && obs.ErrorType == ""
	}
	for _, a := range rows {
		overlap := 0
		for _, b := range rows {
			if a.Written > 0 && b.Written <= a.Written && a.Written < b.FirstByte {
				overlap++
			}
		}
		if overlap > result.Overlap {
			result.Overlap = overlap
		}
	}
	result.Connections = tracker.count()
	result.Passed = result.Passed && result.Connections == 1 && result.Overlap >= 2
	result.Observations = rows
	return result
}
func (g *generator) resumption() check {
	tr := g.transport(1, true, tls.VersionTLS13)
	tr.TLSClientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(8)
	defer tr.CloseIdleConnections()
	cl := client(tr)
	tracker := &connections{}
	result := check{Name: "TLS13 session resumption", Passed: true, Requests: 10}
	resumed := 0
	for i := 0; i < 10; i++ {
		obs := g.request(cl, tracker, g.c.Cases[0], time.Now())
		result.Passed = result.Passed && obs.Correct && obs.Verified && obs.Protocol == 1 && obs.TLS == tls.VersionTLS13
		if obs.Resumed {
			resumed++
		}
	}
	result.Connections = tracker.count()
	result.Passed = result.Passed && resumed > 0 && result.Connections == 10
	result.Resumed = resumed
	return result
}
func (g *generator) certificateChecks() []check {
	results := []check{}
	for _, name := range []string{"Untrusted CA rejected", "Wrong certificate hostname rejected"} {
		config := &tls.Config{RootCAs: g.roots, ServerName: "unmatched.invalid", MinVersion: tls.VersionTLS12}
		if name == "Untrusted CA rejected" {
			config.RootCAs = x509.NewCertPool()
			config.ServerName = "localhost"
		}
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", g.c.Target, config)
		if conn != nil {
			conn.Close()
		}
		var authority x509.UnknownAuthorityError
		var hostname x509.HostnameError
		passed := errors.As(err, &hostname)
		if name == "Untrusted CA rejected" {
			passed = errors.As(err, &authority)
		}
		results = append(results, check{Name: name, Passed: passed})
	}
	return results
}
func validate(c configuration) error {
	host, port, err := net.SplitHostPort(c.Target)
	n, e := strconv.Atoi(port)
	if err != nil || e != nil || host != "127.0.0.1" || n < 1 || n > 65535 || c.Rate != 5 || c.Seconds < 120 || c.Seconds > 600 || len(c.Cases) != 20 || len(c.Large) != 4 {
		return errors.New("requires bounded owned loopback fixture and complete workload")
	}
	for _, item := range append(append([]testCase{}, c.Cases...), c.Large...) {
		if (item.Host != "localhost" && item.Host != "dvwa.capacity.test" && item.Host != "probe.capacity.test") || !strings.HasPrefix(item.Path, "/") || len(item.Path) > 4096 || len(item.Body) > (1<<20)+1 || len(item.Headers) > 16 {
			return errors.New("invalid bounded case")
		}
	}
	return nil
}
func run() error {
	configPath := flag.String("config", "", "Private fixture workload JSON")
	out := flag.String("out", "", "Report JSON")
	flag.Parse()
	file, err := os.Open(*configPath)
	if err != nil {
		return errors.New("cannot open private configuration")
	}
	defer file.Close()
	var c configuration
	decoder := json.NewDecoder(io.LimitReader(file, 4<<20))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&c) != nil || validate(c) != nil {
		return errors.New("invalid private configuration")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(c.CA)) {
		return errors.New("invalid fixture trust anchor")
	}
	g := &generator{c: c, roots: roots}
	cpuStart, err := processCPUSeconds()
	if err != nil {
		return errors.New("generator CPU measurement unavailable")
	}
	result := struct {
		Passed       bool    `json:"passed"`
		Runtime      string  `json:"runtime"`
		OS           string  `json:"os"`
		Architecture string  `json:"architecture"`
		LogicalCPUs  int     `json:"logical_cpus"`
		CPUSeconds   float64 `json:"generator_cpu_seconds"`
		Requests     int64   `json:"http_attempts"`
		Started      float64 `json:"started"`
		Finished     float64 `json:"finished"`
		Phases       []phase `json:"phases"`
		Checks       []check `json:"checks"`
	}{Runtime: runtime.Version(), OS: runtime.GOOS, Architecture: runtime.GOARCH, LogicalCPUs: runtime.NumCPU()}
	result.Started = timestamp()
	for _, mode := range []struct {
		name     string
		protocol int
		fresh    bool
	}{{"TLS HTTP1 fresh connections", 1, true}, {"TLS HTTP1 persistent connections", 1, false}, {"TLS HTTP2 persistent connections", 2, false}} {
		p := g.phase(mode.name, mode.protocol, mode.fresh)
		result.Phases = append(result.Phases, p)
		fmt.Printf("%s: completed=%d passed=%t p95=%.1f ms connections=%d reused=%d\n", p.Name, p.Completed, p.Passed, p.P95MS, p.UniqueConnections, p.Reused)
		if !p.Passed {
			break
		}
	}
	if len(result.Phases) == 3 && result.Phases[2].Passed {
		result.Checks = append(result.Checks, g.functional("TLS12 complete mixed corpus", 1, tls.VersionTLS12, c.Cases))
		result.Checks = append(result.Checks, g.functional("HTTP1 large body verdicts", 1, 0, c.Large), g.functional("HTTP2 large body verdicts", 2, 0, c.Large), g.multiplex(), g.resumption())
		mismatch := []testCase{{Host: "localhost", Authority: "dvwa.capacity.test", Method: "GET", Path: "/", Expected: 421}}
		result.Checks = append(result.Checks, g.functional("HTTP1 SNI authority mismatch rejected", 1, 0, mismatch), g.functional("HTTP2 SNI authority mismatch rejected", 2, 0, mismatch))
		result.Checks = append(result.Checks, g.certificateChecks()...)
	}
	result.Requests = g.requests.Load()
	result.Finished = timestamp()
	cpuEnd, cpuErr := processCPUSeconds()
	result.CPUSeconds = cpuEnd - cpuStart
	result.Passed = cpuErr == nil && len(result.Phases) == 3 && len(result.Checks) == 9
	for _, p := range result.Phases {
		result.Passed = result.Passed && p.Passed
	}
	for _, c := range result.Checks {
		result.Passed = result.Passed && c.Passed
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	if os.WriteFile(*out, append(data, '\n'), 0600) != nil {
		return errors.New("cannot write report")
	}
	if !result.Passed {
		return errors.New("transport qualification failed; inspect bounded report")
	}
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
