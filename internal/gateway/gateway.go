package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/gofrs/flock"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/accounts"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/adminaudit"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/certificates"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/eventstore"
)

type runtime struct {
	pool         *upstreamRuntime
	traffic      TrafficControls
	applications map[string]*runtime
	hosts        map[string]*runtime
	config       Config
	waf          coraza.WAF
	target       *url.URL
}
type Match struct {
	ID      int      `json:"id"`
	Message string   `json:"message"`
	Tags    []string `json:"tags"`
	Targets []string `json:"targets"`
	Phase   int      `json:"phase"`
}
type Event struct {
	UpstreamErrorClass string    `json:"upstream_error_class,omitempty"`
	UpstreamBackend    string    `json:"upstream_backend,omitempty"`
	Host               string    `json:"host,omitempty"`
	PeerIP             string    `json:"peer_ip,omitempty"`
	ProxyConfigSHA256  string    `json:"proxy_config_sha256,omitempty"`
	Occurrences        uint64    `json:"occurrences,omitempty"`
	Aggregated         bool      `json:"aggregated,omitempty"`
	LastSeen           time.Time `json:"last_seen,omitempty"`
	DeliveryIncomplete bool      `json:"delivery_incomplete,omitempty"`
	Sequence           int64     `json:"sequence,omitempty"`
	Truncated          bool      `json:"truncated,omitempty"`
	PolicyRevision     uint64    `json:"policy_revision"`
	ApplicationID      string    `json:"application_id"`
	UpstreamAttempted  bool      `json:"upstream_attempted"`
	ID                 string    `json:"id"`
	Time               time.Time `json:"time"`
	IP                 string    `json:"ip"`
	Method             string    `json:"method"`
	Path               string    `json:"path"`
	Action             string    `json:"action"`
	Status             int       `json:"status"`
	Reason             string    `json:"reason"`
	Matches            []Match   `json:"matches"`
	Duration           float64   `json:"duration_ms"`
}
type Bucket struct {
	Minute   int64  `json:"minute"`
	Requests uint64 `json:"requests"`
	Blocked  uint64 `json:"blocked"`
}
type Gateway struct {
	auditExporter                            *adminaudit.Exporter
	accounts                                 *accounts.Store
	proxyTrust                               *proxyTrust
	certificates                             atomic.Pointer[certificates.Manager]
	audit                                    *adminaudit.Journal
	eventStore                               *eventstore.Store
	budget                                   *resourceBudget
	engineFactory                            func(Config) (coraza.WAF, error)
	active                                   atomic.Pointer[runtime]
	update                                   sync.Mutex
	lifecycle                                sync.RWMutex
	path                                     string
	historyDir                               string
	lease                                    *flock.Flock
	closeOnce                                sync.Once
	closeDone                                chan struct{}
	closed                                   atomic.Bool
	requests                                 sync.WaitGroup
	shutdown                                 context.Context
	cancelRequests                           context.CancelFunc
	overloadID                               atomic.Uint64
	rollupMu, rollupFlush                    sync.Mutex
	rollups                                  map[rejectionKey]Event
	rollupStop, rollupDone                   chan struct{}
	persistenceFailures                      atomic.Uint64
	securitySeen, overloaded                 uint64
	unrouted                                 uint64
	rateLimited                              uint64
	writePolicy                              func(string, Config) error
	started                                  time.Time
	transport                                *http.Transport
	mu                                       sync.Mutex
	events                                   []Event
	buckets                                  [60]Bucket
	total, blocked, detected, upstreamErrors uint64
}

// Options supplies trusted in-process dependencies. EngineFactory is a test-lab
// seam; it is never populated from an API request, policy file or CLI flag.
type Options struct {
	AuditExport       eventstore.ExportOptions
	TrustedProxies    []string
	AuditPath         string
	DisableAudit      bool
	EngineFactory     func(Config) (coraza.WAF, error)
	Resources         ResourceLimits
	EventStore        eventstore.Options
	DisableEventStore bool
}

func New(path string) (*Gateway, error) { return NewWithOptions(path, Options{}) }
func NewWithOptions(path string, options Options) (*Gateway, error) {
	proxyTrust, err := newProxyTrust(options.TrustedProxies)
	if err != nil {
		return nil, err
	}
	options.Resources = options.Resources.defaults()
	if err := options.Resources.validate(); err != nil {
		return nil, err
	}
	if options.EngineFactory == nil {
		options.EngineFactory = compile
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	lease := flock.New(path + ".lock")
	locked, err := lease.TryLock()
	if err != nil {
		_ = lease.Close()
		return nil, err
	}
	if !locked {
		_ = lease.Close()
		return nil, errors.New("another OpenWAF process owns this policy file")
	}
	success := false
	defer func() {
		if !success {
			_ = lease.Close()
		}
	}()
	_, statErr := os.Stat(path)
	missing := errors.Is(statErr, os.ErrNotExist)
	c, err := load(path)
	if err != nil {
		return nil, err
	}
	if err := validateAdmissionShares(c, options.Resources); err != nil {
		return nil, err
	}
	deployment, err := buildRuntime(c, options.EngineFactory)
	if err != nil {
		return nil, fmt.Errorf("compile initial policy: %w", err)
	}
	defer func() {
		if !success {
			closeRuntime(deployment)
		}
	}()
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.ResponseHeaderTimeout = 30 * time.Second
	tr.IdleConnTimeout = upstreamIdleTimeout
	tr.DisableCompression = true
	g := &Gateway{proxyTrust: proxyTrust, engineFactory: options.EngineFactory, path: path, historyDir: path + ".history", lease: lease, writePolicy: persist, started: time.Now(), transport: tr, events: []Event{}, closeDone: make(chan struct{})}
	g.accounts, err = accounts.Open(path + ".accounts.json")
	if err != nil {
		return nil, fmt.Errorf("open administration accounts: %w", err)
	}
	if err = g.accounts.CheckApplications(c.SchemaVersion, applicationIDs(c)); err != nil {
		return nil, err
	}
	g.shutdown, g.cancelRequests = context.WithCancel(context.Background())
	defer func() {
		if !success {
			g.cancelRequests()
		}
	}()
	g.budget = &resourceBudget{limits: options.Resources}
	g.budget.configureApplications(c)
	tr.MaxConnsPerHost = options.Resources.MaxConcurrent
	tr.MaxIdleConns = options.Resources.MaxConcurrent
	tr.MaxIdleConnsPerHost = min(16, options.Resources.MaxConcurrent)
	if err = g.initializeHistory(c, missing); err != nil {
		return nil, err
	}
	g.active.Store(deployment)
	if missing {
		if err = persist(path, c); err != nil {
			return nil, err
		}
	}
	if !options.DisableEventStore {
		if options.EventStore.Path == "" {
			options.EventStore.Path = path + ".events.db"
		}
		g.eventStore, err = eventstore.Open(options.EventStore)
		if err != nil {
			return nil, fmt.Errorf("open durable security events: %w", err)
		}
		rows, queryErr := g.eventStore.Query(context.Background(), eventstore.Query{Limit: 500})
		if queryErr != nil {
			_ = g.eventStore.Close(context.Background())
			return nil, queryErr
		}
		for _, row := range rows {
			var evt Event
			if err = json.Unmarshal(row.Data, &evt); err != nil {
				_ = g.eventStore.Close(context.Background())
				return nil, fmt.Errorf("decode stored security event: %w", err)
			}
			evt.Sequence = row.Sequence
			g.events = append(g.events, evt)
		}
	}
	if !options.DisableAudit {
		if options.AuditPath == "" {
			options.AuditPath = path + ".audit.jsonl"
		}
		g.audit, err = adminaudit.Open(options.AuditPath)
		if err != nil {
			if g.eventStore != nil {
				_ = g.eventStore.Close(context.Background())
			}
			return nil, fmt.Errorf("open administration audit: %w", err)
		}
		g.auditExporter, err = adminaudit.NewExporter(g.audit, options.AuditExport)
		if err != nil {
			_ = g.audit.Close()
			if g.eventStore != nil {
				_ = g.eventStore.Close(context.Background())
			}
			return nil, fmt.Errorf("open audit export: %w", err)
		}
	} else if options.AuditExport.URL != "" {
		if g.eventStore != nil {
			_ = g.eventStore.Close(context.Background())
		}
		return nil, errors.New("audit export requires administration auditing")
	}
	success = true
	g.startOverloadWorker()
	return g, nil
}

func (g *Gateway) Config() Config {
	return g.active.Load().config.clone()
}

// Apply builds a full replacement before touching durable or active state.
func (g *Gateway) Apply(c Config, validateOnly bool) (Config, error) {
	return g.ApplyWithMetadata(c, validateOnly, "local", "Policy updated")
}
func (g *Gateway) ApplyWithMetadata(c Config, validateOnly bool, actor, reason string) (Config, error) {
	if !g.update.TryLock() {
		return Config{}, errors.New("another policy operation is in progress; retry")
	}
	defer g.update.Unlock()
	return g.applyLocked(c, validateOnly, actor, reason, 0)
}
func (g *Gateway) applyLocked(c Config, validateOnly bool, actor, reason string, restoredFrom uint64) (Config, error) {
	if g.closed.Load() {
		return Config{}, errors.New("gateway is closed")
	}
	c = c.clone()
	if len(actor) > 100 || len(reason) > 500 {
		return Config{}, errors.New("change actor/reason exceeds length limits")
	}
	if err := g.accounts.CheckApplications(c.SchemaVersion, applicationIDs(c)); err != nil {
		return Config{}, err
	}
	current := g.active.Load()
	if err := validateAdmissionShares(c, g.budget.limits); err != nil {
		return Config{}, err
	}
	if c.Revision != current.config.Revision {
		return Config{}, errors.New("configuration changed; reload before saving")
	}
	if current.config.SchemaVersion == 2 && c.SchemaVersion == 1 && restoredFrom == 0 {
		return Config{}, errors.New("returning to legacy catch-all requires an explicit history rollback or checkpoint restore")
	}
	recorded, err := g.readSnapshot(current.config.Revision)
	if err != nil || recorded.SHA256 != policyDigest(current.config) {
		return Config{}, errors.New("active revision history failed integrity verification")
	}
	next, err := buildRuntime(c, g.engineFactory)
	if err != nil {
		return Config{}, err
	}
	published := false
	defer func() {
		if !published {
			closeRuntime(next)
		}
	}()
	manager := g.certificates.Load()
	if validateOnly {
		if manager != nil {
			if err = manager.ValidateApplicationNames(c.ApplicationHosts()); err != nil {
				return Config{}, err
			}
		}
		return c, nil
	}
	if _, err := os.Stat(g.path); err != nil {
		return Config{}, err
	}
	disk, err := load(g.path)
	if err != nil {
		return Config{}, err
	}
	if policyDigest(disk) != policyDigest(current.config) {
		return Config{}, errors.New("active policy file changed outside OpenWAF; restore it before saving")
	}
	c.Revision, err = g.nextRevision()
	if err != nil {
		return Config{}, err
	}
	next.config = c.clone()
	for _, app := range next.applications {
		app.config.Revision = c.Revision
	}
	intent, err := g.RecordAudit(adminaudit.Record{Operation: "policy.activate", Actor: actor, Outcome: "intent", Revision: c.Revision, Resource: policyDigest(c)})
	if err != nil {
		return Config{}, err
	}
	outcome := "failed"
	defer func() {
		_, _ = g.RecordAudit(adminaudit.Record{Correlation: intent.Correlation, Operation: "policy.activate", Actor: actor, Outcome: outcome, Revision: c.Revision, Resource: policyDigest(c)})
	}()
	activate := func() error {
		if err := g.prepareSnapshot(c, current.config.Revision, restoredFrom, actor, reason); err != nil {
			return err
		}
		if err := g.writePolicy(g.path, c); err != nil {
			return err
		}
		g.lifecycle.Lock()
		g.active.Store(next)
		g.budget.configureApplications(c)
		closeRuntime(current)
		g.lifecycle.Unlock()
		published = true
		return nil
	}
	if manager != nil {
		err = manager.WithApplicationNames(c.ApplicationHosts(), activate)
	} else {
		err = activate()
	}
	if err != nil {
		return Config{}, err
	}
	outcome = "success"
	return c.clone(), nil
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.lifecycle.RLock()
	if g.closed.Load() {
		g.lifecycle.RUnlock()
		http.Error(w, "Gateway is shutting down", http.StatusServiceUnavailable)
		return
	}
	deployment := g.active.Load()
	// Add while holding lifecycle's read lock: Close prevents new additions
	// before waiting, including requests rejected by admission.
	g.requests.Add(1)
	defer g.requests.Done()
	identity := g.proxyTrust.resolve(r)
	rt, authority, routeStatus := deployment.selectApplication(r)
	if routeStatus != 0 {
		g.lifecycle.RUnlock()
		reason := "Request does not match an application hostname"
		if routeStatus == http.StatusBadRequest {
			reason = "Invalid application request authority"
		}
		evt := Event{ID: fmt.Sprintf("route-%d-%d", time.Now().UnixNano(), g.overloadID.Add(1)), Time: time.Now(), PolicyRevision: deployment.config.Revision, Host: authority, IP: identity.IP, Method: r.Method, Path: r.URL.EscapedPath(), Action: "unrouted", Status: routeStatus, Reason: reason, Matches: []Match{}}
		if identity.Forwarded {
			evt.PeerIP = identity.PeerIP
		}
		if len(g.proxyTrust.networks) > 0 {
			evt.ProxyConfigSHA256 = g.proxyTrust.configHash
		}
		g.recordOverload(evt)
		http.Error(w, reason, routeStatus)
		return
	}
	if authority != "" {
		r = r.Clone(r.Context())
		r.Host = authority
	}
	weight := bodyReservation(r, rt.config)
	admissionStart := time.Now()
	clientContext := r.Context()
	ctx, cancel := context.WithTimeout(clientContext, g.budget.limits.RequestTimeout)
	defer cancel()
	stopShutdown := context.AfterFunc(g.shutdown, cancel)
	defer stopShutdown()
	r = r.WithContext(ctx)
	admission := admissionResult{}
	if deployment.config.SchemaVersion == 2 {
		traffic := rt.traffic
		// Charge declared body bytes before buffering or inspecting. Unknown
		// lengths reserve the full envelope so chunking cannot bypass the rate.
		traffic.bodyKiB = int((requestBodySize(r, rt.config) + 1023) / 1024)
		traffic.reservedBody = traffic.ClientBodyReservation != nil && traffic.ClientBodyReservation.Method == r.Method && traffic.ClientBodyReservation.Path == r.URL.EscapedPath()
		if traffic.AdmissionWaitMS > 0 {
			// Never hold lifecycle across a wait: shutdown and policy activation
			// must remain able to wake/cancel waiters and close old runtimes.
			g.lifecycle.RUnlock()
			admission = g.budget.admitWaiting(ctx, rt.config.ApplicationID, identity.IP, weight, traffic, len(deployment.config.Applications))
			g.lifecycle.RLock()
			if g.closed.Load() || g.active.Load() != deployment {
				if admission.release != nil {
					admission.release()
				}
				admission = admissionResult{status: 503, reason: "Policy or shutdown changed during admission", retry: 1}
			}
		} else {
			admission = g.budget.admit(rt.config.ApplicationID, identity.IP, weight, traffic, len(deployment.config.Applications), time.Now())
		}
	} else if g.budget.acquire(weight) {
		admission.release = func() { g.budget.release(weight) }
	} else {
		admission = admissionResult{status: 503, reason: "Process inspection capacity exhausted", retry: 1}
	}
	if admission.status != 0 {
		g.lifecycle.RUnlock()
		evt := Event{ID: fmt.Sprintf("overload-%d-%d", time.Now().UnixNano(), g.overloadID.Add(1)), Time: time.Now(), IP: identity.IP, PolicyRevision: rt.config.Revision, ApplicationID: rt.config.ApplicationID, Method: r.Method, Path: r.URL.EscapedPath(), Action: "overloaded", Status: 503, Reason: "Process inspection capacity exhausted", Matches: []Match{}}
		evt.Host = authority
		if identity.Forwarded {
			evt.PeerIP = identity.PeerIP
		}
		if len(g.proxyTrust.networks) > 0 {
			evt.ProxyConfigSHA256 = g.proxyTrust.configHash
		}
		evt.Status = admission.status
		evt.Reason = admission.reason
		evt.Duration = float64(time.Since(admissionStart).Microseconds()) / 1000
		if admission.status == 429 {
			evt.Action = "rate_limited"
		}
		g.recordOverload(evt)
		w.Header().Set("Retry-After", fmt.Sprint(admission.retry))
		http.Error(w, evt.Reason, admission.status)
		return
	}
	defer admission.release()
	bodyDeadline := time.Now().Add(g.budget.limits.BodyReadTimeout)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(bodyDeadline) {
		bodyDeadline = deadline
	}
	_ = http.NewResponseController(w).SetReadDeadline(bodyDeadline)
	tx := rt.waf.NewTransaction()
	g.lifecycle.RUnlock()
	start := admissionStart
	evt := Event{PolicyRevision: rt.config.Revision, ApplicationID: rt.config.ApplicationID, Time: start, IP: identity.IP, Method: r.Method, Path: r.URL.EscapedPath(), Action: "pass", Status: 200, Matches: []Match{}}
	evt.Host = authority
	if identity.Forwarded {
		evt.PeerIP = identity.PeerIP
	}
	if len(g.proxyTrust.networks) > 0 {
		evt.ProxyConfigSHA256 = g.proxyTrust.configHash
	}
	evt.ID = tx.ID()
	defer func() {
		panicValue := recover()
		if panicValue != nil {
			evt.Action = "error"
			evt.Reason = "Request processing aborted"
			if err, ok := panicValue.(error); ok && errors.Is(err, http.ErrAbortHandler) {
				evt.DeliveryIncomplete = true
				evt.Reason = "Response delivery interrupted after headers were sent"
				if errors.Is(r.Context().Err(), context.Canceled) {
					evt.Action = "cancelled"
					evt.Reason = "Client or gateway cancelled response delivery"
				}
			}
		}
		tx.ProcessLogging()
		for _, m := range tx.MatchedRules() {
			if len(evt.Matches) >= 24 {
				evt.Truncated = true
				break
			}
			// CRS initialization rules can match with a message and nolog.
			// Honor the engine's log flag instead of counting those as threats.
			if logged, ok := m.(interface{ Log() bool }); ok && !logged.Log() {
				continue
			}
			if m.Message() != "" {
				targets := []string{}
				seen := map[string]bool{}
				for _, data := range m.MatchedDatas() {
					name := data.Variable().Name()
					if data.Key() != "" {
						name += ":" + data.Key()
					}
					if !seen[name] && len(targets) < 32 {
						targets = append(targets, name)
						seen[name] = true
					}
				}
				evt.Matches = append(evt.Matches, Match{ID: m.Rule().ID(), Message: ruleLabel(m.Rule().Raw()), Tags: append([]string{}, m.Rule().Tags()...), Targets: targets, Phase: int(m.Rule().Phase())})
			}
		}
		if evt.Action == "pass" && len(evt.Matches) > 0 {
			evt.Action = "detected"
			evt.Reason = "Rules matched in detection mode or below the blocking threshold"
		}
		evt.Duration = float64(time.Since(start).Microseconds()) / 1000
		g.record(evt)
		_ = tx.Close()
		if panicValue != nil {
			panic(panicValue)
		}
	}()
	reject := func(status int, reason string) {
		evt.Action = "blocked"
		evt.Status = status
		evt.Reason = reason
		w.Header().Set("X-OpenWAF-Request-ID", evt.ID)
		http.Error(w, reason, status)
	}
	interrupted := func(it *types.Interruption) bool {
		if it == nil {
			return false
		}
		status := it.Status
		if status < 400 || status > 599 {
			status = 403
		}
		reject(status, "Request blocked by security policy")
		return true
	}

	if identity.Invalid {
		reject(http.StatusBadRequest, "Invalid forwarding headers from configured proxy")
		return
	}
	// The hard proxy body limit applies in every mode. Never forward a truncated body.
	if strings.Contains(r.RequestURI, "#") {
		reject(http.StatusBadRequest, "URL fragments are not allowed in an HTTP request target")
		return
	}
	if r.Method == http.MethodConnect {
		reject(http.StatusMethodNotAllowed, "CONNECT tunnelling is not supported by this application gateway")
		return
	}
	if upgrade := strings.TrimSpace(r.Header.Get("Upgrade")); len(r.Header.Values("Upgrade")) > 1 || (upgrade != "" && !strings.EqualFold(upgrade, "websocket")) {
		reject(http.StatusBadRequest, "Only WebSocket protocol upgrades are supported")
		return
	}
	if r.ContentLength > rt.config.RequestLimit {
		reject(413, "Request body exceeds configured limit")
		return
	}
	var body []byte
	if r.Body != nil {
		readLimit := rt.config.RequestLimit
		if r.ContentLength >= 0 {
			readLimit = min(readLimit, r.ContentLength)
		}
		var err error
		body, err = io.ReadAll(io.LimitReader(r.Body, readLimit+1))
		_ = r.Body.Close()
		if err != nil {
			reject(400, "Could not read request body")
			return
		}
		if int64(len(body)) > rt.config.RequestLimit {
			reject(413, "Request body exceeds configured limit")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		// The inspected buffer can be reopened if net/http proves that a stale
		// pooled connection failed before writing any bytes. Its normal retry
		// rules still forbid replaying a POST after an ambiguous upstream write.
		r.GetBody = nil
		_, idempotencyKey := r.Header["Idempotency-Key"]
		_, legacyIdempotencyKey := r.Header["X-Idempotency-Key"]
		if !idempotencyKey && !legacyIdempotencyKey {
			r.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(body)), nil
			}
		}
		// An untrusted idempotency header must not opt a body-bearing mutation
		// into net/http's broader replay rules. Forward the header unchanged for
		// applications that implement it, but disable transport replay for it.
		if r.ContentLength >= 0 && int64(len(body)) != r.ContentLength {
			reject(400, "Request body does not match its framing")
			return
		}
	}
	// The downstream body is complete. Keeping its deadline armed lets
	// net/http's background disconnect read cancel a valid slow upstream.
	// The request context continues to enforce the overall request timeout.
	_ = http.NewResponseController(w).SetReadDeadline(time.Time{})
	// Trailer values arrive after the body, outside the supported Coraza
	// request-header phase. Reject rather than forward uninspected fields.
	if len(r.Trailer) > 0 || len(r.Header.Values("Trailer")) > 0 {
		reject(http.StatusBadRequest, "Request trailers are not supported")
		return
	}
	if !tx.IsRuleEngineOff() {
		tx.ProcessConnection(identity.IP, identity.Port, "", 0)
		rawURI := r.RequestURI
		if rawURI == "" {
			rawURI = r.URL.String()
		}
		tx.ProcessURI(rawURI, r.Method, r.Proto)
		if r.Host != "" {
			tx.SetServerName(r.Host)
			tx.AddRequestHeader("Host", r.Host)
		}
		for k, vs := range r.Header {
			for _, v := range vs {
				tx.AddRequestHeader(k, v)
			}
		}
		for _, te := range r.TransferEncoding {
			tx.AddRequestHeader("Transfer-Encoding", te)
		}
		if interrupted(tx.ProcessRequestHeaders()) {
			return
		}
		if tx.IsRequestBodyAccessible() && len(body) > 0 {
			it, _, e := tx.WriteRequestBody(body)
			if e != nil {
				reject(400, "Request body inspection failed")
				return
			}
			if interrupted(it) {
				return
			}
		}
		it, e := tx.ProcessRequestBody()
		if e != nil {
			reject(400, "Request body inspection failed")
			return
		}
		if interrupted(it) {
			return
		}
	}
	target := rt.target
	var transport http.RoundTripper = g.transport
	if rt.pool != nil {
		selected := rt.pool.selectBackend(time.Now())
		if selected == nil {
			evt.Action = "error"
			evt.Status = 503
			evt.Reason = "No upstream backend is currently available"
			w.Header().Set("Retry-After", "1")
			http.Error(w, evt.Reason, 503)
			return
		}
		defer selected.finish(nil)
		target, transport = selected.backend.target, selected
		evt.UpstreamBackend = selected.backend.config.ID
	}
	// A request owns its proxy/transaction. Configuration swaps cannot alter it.
	rp := &httputil.ReverseProxy{Transport: transport, FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			evt.UpstreamAttempted = true
			pr.SetURL(target)
			pr.Out.Host = target.Host
			if deployment.config.SchemaVersion == 2 {
				// Exact application routing has already validated/canonicalized
				// this authority. Preserve it for virtual hosts and canonical
				// redirects; the fixed target still controls dialing and TLS SNI.
				pr.Out.Host = pr.In.Host
			}
			pr.SetXForwarded()
			stripConsoleCookies(pr.Out.Header)
			writeForwardedIdentity(pr.Out.Header, identity, pr.In.Host)
			if rt.config.InspectResponse && !tx.IsRuleEngineOff() {
				pr.Out.Header.Set("Accept-Encoding", "identity")
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, e error) {
			if errors.Is(r.Context().Err(), context.Canceled) {
				evt.Action = "cancelled"
				if clientContext.Err() == nil {
					evt.Status = http.StatusServiceUnavailable
					evt.Reason = "Gateway is shutting down"
					http.Error(w, evt.Reason, evt.Status)
					return
				}
				evt.Status = 499
				evt.Reason = "Client cancelled request"
				return
			}
			if evt.Action != "blocked" {
				evt.Action = "error"
				evt.UpstreamErrorClass = upstreamErrorClass(e)
				evt.Reason = "Upstream connection or response inspection failed"
				evt.Status = 502
			}
			http.Error(w, evt.Reason, evt.Status)
		},
	}
	rp.ModifyResponse = func(resp *http.Response) error {
		stripConsoleSetCookies(resp.Header)
		evt.Status = resp.StatusCode
		if tx.IsRuleEngineOff() {
			return nil
		}
		for k, vs := range resp.Header {
			for _, v := range vs {
				tx.AddResponseHeader(k, v)
			}
		}
		fail := func(it *types.Interruption) error {
			status := it.Status
			if status < 400 || status > 599 {
				status = 403
			}
			evt.Action = "blocked"
			evt.Status = status
			evt.Reason = "Response blocked by security policy"
			_ = resp.Body.Close()
			return errors.New("response interrupted")
		}
		if it := tx.ProcessResponseHeaders(resp.StatusCode, resp.Proto); it != nil {
			return fail(it)
		}
		if resp.StatusCode != 101 && r.Method != "HEAD" && tx.IsResponseBodyAccessible() && tx.IsResponseBodyProcessable() {
			if enc := resp.Header.Get("Content-Encoding"); enc != "" && !strings.EqualFold(enc, "identity") {
				_ = resp.Body.Close()
				return errors.New("encoded response cannot be inspected")
			}
			b, e := io.ReadAll(io.LimitReader(resp.Body, rt.config.ResponseLimit+1))
			_ = resp.Body.Close()
			if e != nil {
				return e
			}
			if int64(len(b)) > rt.config.ResponseLimit {
				return errors.New("response inspection limit exceeded")
			}
			it, _, e := tx.WriteResponseBody(b)
			if e != nil {
				return e
			}
			if it != nil {
				return fail(it)
			}
			resp.Body = io.NopCloser(bytes.NewReader(b))
		}
		it, e := tx.ProcessResponseBody()
		if e != nil {
			return e
		}
		if it != nil {
			return fail(it)
		}
		return nil
	}
	w.Header().Set("X-OpenWAF-Request-ID", evt.ID)
	rp.ServeHTTP(w, r)
	if r.Context().Err() != nil && evt.Status == http.StatusSwitchingProtocols {
		evt.Action = "cancelled"
		evt.Reason = "Upgraded connection ended after cancellation"
	}
}

// Persist only bounded categories: upstream errors may contain credentials,
// URLs or untrusted response text and must never be copied into an event.
func upstreamErrorClass(err error) string {
	var timeout net.Error
	switch {
	case errors.As(err, &timeout) && timeout.Timeout():
		return "timeout"
	case errors.Is(err, syscall.EPIPE):
		return "write_closed"
	case errors.Is(err, syscall.ECONNRESET):
		return "connection_reset"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection_refused"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "unexpected_eof"
	case errors.Is(err, io.EOF):
		return "eof"
	case errors.Is(err, net.ErrClosed):
		return "connection_closed"
	default:
		return "other"
	}
}

func (g *Gateway) record(e Event) {
	g.mu.Lock()
	g.total++
	minute := time.Now().Unix() / 60
	b := &g.buckets[minute%60]
	if b.Minute != minute {
		*b = Bucket{Minute: minute}
	}
	b.Requests++
	if e.Action == "blocked" {
		g.blocked++
		b.Blocked++
	}
	if e.Action == "detected" {
		g.detected++
	}
	if e.Action == "error" {
		g.upstreamErrors++
	}
	if e.Action != "pass" {
		g.securitySeen++
	}
	g.mu.Unlock()
	if e.Action != "pass" {
		_ = g.persistEvent(context.Background(), e)
	}
}
func (g *Gateway) Events() []Event {
	g.mu.Lock()
	defer g.mu.Unlock()
	maxAge := 7 * 24 * time.Hour
	if g.eventStore != nil {
		maxAge = time.Duration(g.eventStore.Status().RetentionDays * 24 * float64(time.Hour))
	}
	items := []Event{}
	for _, e := range g.events {
		if time.Since(e.Time) <= maxAge {
			items = append(items, e)
		}
	}
	return items
}
func (g *Gateway) Summary() map[string]any {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now().Unix() / 60
	series := make([]Bucket, 0, 60)
	for m := now - 59; m <= now; m++ {
		b := g.buckets[m%60]
		if b.Minute != m {
			b = Bucket{Minute: m}
		}
		series = append(series, b)
	}
	return map[string]any{"requests": g.total, "blocked": g.blocked, "detected": g.detected, "errors": g.upstreamErrors, "security_occurrences": g.securitySeen, "overload_requests": g.overloaded, "rate_limited_requests": g.rateLimited, "unrouted_requests": g.unrouted, "event_persistence_errors": g.persistenceFailures.Load(), "series": series, "started": g.started, "uptime_seconds": int(time.Since(g.started).Seconds())}
}
func closeWAF(waf coraza.WAF) {
	if c, ok := waf.(experimental.WAFCloser); ok {
		_ = c.Close()
	}
}
func (g *Gateway) Close(ctx context.Context) {
	g.closeOnce.Do(func() {
		g.update.Lock()
		defer g.update.Unlock()
		g.lifecycle.Lock()
		g.closed.Store(true)
		g.cancelRequests()
		closeRuntime(g.active.Load())
		g.transport.CloseIdleConnections()
		g.lifecycle.Unlock()
		// The cleanup owns a fresh flush deadline. Reusing a caller's expired
		// deadline could declare shutdown finished with queued events unwritten.
		go func() {
			g.requests.Wait()
			close(g.rollupStop)
			<-g.rollupDone
			defer close(g.closeDone)
			flushContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if g.eventStore != nil {
				if err := g.eventStore.Close(flushContext); err != nil {
					log.Printf("Security event shutdown did not fully flush: %v", err)
				}
			}
			if g.auditExporter != nil {
				if status := g.auditExporter.Status(); status.Enabled && !status.Paused {
					deliveryContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					_ = g.auditExporter.Wait(deliveryContext)
					cancel()
				}
				g.auditExporter.Close()
			}
			if g.audit != nil {
				_ = g.audit.Close()
			}
			if g.lease != nil {
				_ = g.lease.Close()
			}
		}()
	})
	select {
	case <-g.closeDone:
	case <-ctx.Done():
		log.Print("Gateway shutdown deadline reached; draining transactions and events in background")
	}
}
