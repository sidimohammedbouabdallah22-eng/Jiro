package gateway

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	crs "github.com/corazawaf/coraza-coreruleset/crs/v4"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/adminaudit"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/engineinfo"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/eventstore"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/ui"
	"io"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

type session struct {
	strong     bool
	verifiedAt time.Time
	method     string
	expires    time.Time
	username   string
	version    uint64
}
type Admin struct {
	gateway        *Gateway
	token          [32]byte
	mu             sync.Mutex
	sessions       map[[32]byte]session
	failures       int
	window         time.Time
	passwordSlots  chan struct{}
	enrollments    map[[32]byte]mfaEnrollment
	authentication *authenticationRuntime
	oidcPending    map[[32]byte]oidcTransaction
	externalSlots  chan struct{}
	passkeyPending map[[32]byte]passkeyCeremony
}

func NewAdmin(g *Gateway, token string) http.Handler { return newAdmin(g, token, nil) }
func NewAdminWithAuthentication(g *Gateway, token string, config AuthenticationConfig) (http.Handler, error) {
	runtime, err := newAuthenticationRuntime(config)
	if err != nil {
		return nil, err
	}
	return newAdmin(g, token, runtime), nil
}
func newAdmin(g *Gateway, token string, authentication *authenticationRuntime) http.Handler {
	a := &Admin{gateway: g, token: sha256.Sum256([]byte(token)), sessions: map[[32]byte]session{}, passwordSlots: make(chan struct{}, 2), enrollments: map[[32]byte]mfaEnrollment{}, authentication: authentication, oidcPending: map[[32]byte]oidcTransaction{}, externalSlots: make(chan struct{}, 2), passkeyPending: map[[32]byte]passkeyCeremony{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/login/passkey/begin", a.beginPasskeyLogin)
	mux.HandleFunc("POST /api/v1/login/passkey/finish", a.finishPasskeyLogin)
	mux.HandleFunc("GET /api/v1/me/passkeys", a.listPasskeys)
	mux.HandleFunc("POST /api/v1/me/passkeys/begin", a.beginPasskeyRegistration)
	mux.HandleFunc("POST /api/v1/me/passkeys/finish", a.finishPasskeyRegistration)
	mux.HandleFunc("POST /api/v1/me/passkeys/revoke", a.removePasskey)
	mux.HandleFunc("POST /api/v1/accounts/passkeys-reset", a.recoverPasskeys)
	mux.HandleFunc("GET /api/v1/auth/options", a.authenticationOptions)
	mux.HandleFunc("POST /api/v1/login/oidc", a.beginOIDC)
	mux.HandleFunc("GET /auth/oidc/callback", a.finishOIDC)
	mux.HandleFunc("POST /api/v1/accounts/oidc", a.bindOIDC)
	mux.HandleFunc("GET /api/v1/upstreams", a.upstreamStatus)
	mux.HandleFunc("GET /api/v1/me", func(w http.ResponseWriter, r *http.Request) { p, _ := a.identity(r); reply(w, 200, p) })
	mux.HandleFunc("GET /api/v1/accounts", func(w http.ResponseWriter, r *http.Request) { reply(w, 200, g.accounts.List()) })
	mux.HandleFunc("POST /api/v1/accounts", a.saveAccount)
	mux.HandleFunc("POST /api/v1/me/password", a.changePassword)
	mux.HandleFunc("GET /api/v1/tokens", a.listTokens)
	mux.HandleFunc("POST /api/v1/tokens", a.createToken)
	mux.HandleFunc("POST /api/v1/tokens/{id}/revoke", a.revokeToken)
	mux.HandleFunc("POST /api/v1/me/mfa/setup", a.setupMFA)
	mux.HandleFunc("POST /api/v1/me/mfa/enable", a.enableMFA)
	mux.HandleFunc("POST /api/v1/me/mfa/disable", a.disableMFA)
	mux.HandleFunc("POST /api/v1/accounts/mfa-reset", a.resetMFA)
	mux.HandleFunc("GET /api/v1/security-policy", a.getSecurityPolicy)
	mux.HandleFunc("POST /api/v1/security-policy", a.saveSecurityPolicy)
	mux.HandleFunc("POST /api/v1/applications", a.createApplication)
	mux.HandleFunc("GET /api/v1/applications", func(w http.ResponseWriter, r *http.Request) {
		c := g.Config()
		reply(w, 200, map[string]any{"schema_version": c.SchemaVersion, "revision": c.Revision, "applications": a.visibleConfig(r, c).ApplicationList()})
	})
	mux.HandleFunc("POST /api/v1/applications/{application}/delete", a.deleteApplication)
	mux.HandleFunc("GET /api/v1/certificates", func(w http.ResponseWriter, r *http.Request) { reply(w, 200, g.CertificateStatus()) })
	mux.HandleFunc("POST /api/v1/certificates/reload", func(w http.ResponseWriter, r *http.Request) {
		var request struct{}
		if err := decode(w, r, &request); err != nil {
			problem(w, 400, "Expected an empty JSON object")
			return
		}
		manager := g.certificates.Load()
		if manager == nil {
			problem(w, 409, "TLS certificate management is not configured")
			return
		}
		if err := manager.Reload(); err != nil {
			problem(w, 503, err.Error())
			return
		}
		reply(w, 200, g.CertificateStatus())
	})
	mux.HandleFunc("GET /api/v1/audit", func(w http.ResponseWriter, r *http.Request) {
		before, limit := uint64(0), 100
		var err error
		if value := r.URL.Query().Get("before"); value != "" {
			before, err = strconv.ParseUint(value, 10, 64)
		}
		if err != nil {
			problem(w, 400, "Invalid audit cursor")
			return
		}
		if value := r.URL.Query().Get("limit"); value != "" {
			limit, err = strconv.Atoi(value)
		}
		if err != nil || limit < 1 || limit > 100 {
			problem(w, 400, "Audit limit must be 1..100")
			return
		}
		if g.audit == nil {
			problem(w, 503, "Administration auditing is disabled")
			return
		}
		items, err := g.audit.Query(before, limit)
		if err != nil {
			problem(w, 503, "Could not read administration audit")
			return
		}
		reply(w, 200, map[string]any{"items": items, "status": g.AuditStatus()})
	})
	mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		health := g.Health()
		status := http.StatusOK
		if !health.Ready {
			status = http.StatusServiceUnavailable
		}
		reply(w, status, health)
	})
	mux.HandleFunc("GET /api/v1/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = io.WriteString(w, g.metricsText())
	})
	mux.HandleFunc("POST /api/v1/login", a.login)
	mux.HandleFunc("POST /api/v1/logout", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		if c, e := r.Cookie("openwaf_session"); e == nil {
			delete(a.sessions, sha256.Sum256([]byte(c.Value)))
		}
		a.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "openwaf_session", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		reply(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		version := engineinfo.Version()
		configuration := g.Config()
		reply(w, 200, map[string]any{"engine": "Coraza", "engine_version": version, "crs_version": crs.Version, "revision": configuration.Revision, "applications": configuration.applicationSummaries(), "summary": g.Summary(), "resources": g.ResourceStatus(), "storage": g.StorageStatus(), "audit": g.AuditStatus(), "audit_export": g.AuditExportStatus(), "certificate": g.CertificateStatus(), "client_identity": g.ProxyStatus()})
	})
	mux.HandleFunc("GET /api/v1/config", func(w http.ResponseWriter, r *http.Request) { reply(w, 200, a.visibleConfig(r, g.Config())) })
	for _, route := range []string{"PUT /api/v1/config", "POST /api/v1/config/validate"} {
		mux.HandleFunc(route, func(w http.ResponseWriter, r *http.Request) {
			var c Config
			if err := decode(w, r, &c); err != nil {
				problem(w, 400, err.Error())
				return
			}
			updated, err := a.applyVisibleConfig(r, c, strings.HasSuffix(r.URL.Path, "/validate"), "Policy updated through API")
			if err != nil {
				status := 400
				if strings.Contains(err.Error(), "configuration changed") || strings.Contains(err.Error(), "in progress") {
					status = 409
				}
				problem(w, status, err.Error())
				return
			}
			reply(w, 200, a.visibleConfig(r, updated))
		})
	}
	mux.HandleFunc("POST /api/v1/config/apply", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Config Config `json:"config"`
			Reason string `json:"reason"`
		}
		if err := decode(w, r, &req); err != nil {
			problem(w, 400, err.Error())
			return
		}
		if strings.TrimSpace(req.Reason) == "" {
			problem(w, 400, "A change reason is required")
			return
		}
		c, err := a.applyVisibleConfig(r, req.Config, false, req.Reason)
		if err != nil {
			policyProblem(w, err)
			return
		}
		reply(w, 200, a.visibleConfig(r, c))
	})
	mux.HandleFunc("GET /api/v1/config/history", func(w http.ResponseWriter, r *http.Request) {
		history, err := g.History()
		if err != nil {
			problem(w, 500, "Could not verify policy history")
			return
		}
		reply(w, 200, history)
	})
	mux.HandleFunc("GET /api/v1/config/history/{revision}", func(w http.ResponseWriter, r *http.Request) {
		revision, err := strconv.ParseUint(r.PathValue("revision"), 10, 64)
		if err != nil {
			problem(w, 400, "Invalid revision")
			return
		}
		snapshot, err := g.Snapshot(revision)
		if err != nil {
			problem(w, 404, "Committed revision unavailable or failed integrity verification")
			return
		}
		reply(w, 200, snapshot)
	})
	mux.HandleFunc("POST /api/v1/config/rollback", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Revision uint64 `json:"revision"`
			Target   uint64 `json:"target_revision"`
			Reason   string `json:"reason"`
		}
		if err := decode(w, r, &req); err != nil {
			problem(w, 400, err.Error())
			return
		}
		c, err := g.Rollback(req.Revision, req.Target, a.actor(r), req.Reason)
		if err != nil {
			policyProblem(w, err)
			return
		}
		reply(w, 200, c)
	})
	mux.HandleFunc("GET /api/v1/events", func(w http.ResponseWriter, r *http.Request) {
		p, _ := a.identity(r)
		events := g.Events()
		if p.Access != nil {
			values := r.URL.Query()["application"]
			if len(values) != 1 || !slices.Contains(p.Access.IDs, values[0]) {
				problem(w, 403, "Select an assigned application")
				return
			}
			filtered := []Event{}
			for _, event := range events {
				if event.ApplicationID == values[0] {
					filtered = append(filtered, event)
				}
			}
			events = filtered
		}
		reply(w, 200, events)
	})
	mux.HandleFunc("GET /api/v1/events/search", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		before := int64(0)
		limit := 100
		var err error
		if q.Get("before") != "" {
			before, err = strconv.ParseInt(q.Get("before"), 10, 64)
			if err != nil || before < 0 {
				problem(w, 400, "Invalid event cursor")
				return
			}
		}
		if q.Get("limit") != "" {
			limit, err = strconv.Atoi(q.Get("limit"))
			if err != nil || limit < 1 || limit > 499 {
				problem(w, 400, "Event page limit must be between 1 and 499")
				return
			}
		}
		if len(q.Get("q")) > 128 {
			problem(w, 400, "Search is limited to 128 bytes")
			return
		}
		if app := q.Get("application"); app != "" && !identifier.MatchString(app) {
			problem(w, 400, "Invalid application ID")
			return
		}
		p, _ := a.identity(r)
		if p.Access != nil && (len(q["application"]) != 1 || !slices.Contains(p.Access.IDs, q.Get("application"))) {
			problem(w, 403, "Select an assigned application")
			return
		}
		page, err := g.QueryEvents(r.Context(), eventstore.Query{Before: before, Limit: limit, Action: q.Get("action"), Search: q.Get("q"), Application: q.Get("application")})
		if err != nil {
			problem(w, 503, "Security event storage query failed")
			return
		}
		reply(w, 200, page)
	})
	mux.Handle("/", ui.Handler())
	admission := make(chan struct{}, 16)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case admission <- struct{}{}:
			defer func() { <-admission }()
		default:
			problem(w, 503, "Management request capacity exhausted")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		// Keep permission checks and audit attribution on one request identity.
		// Later requests observe account revocation and version changes.
		if strings.HasPrefix(r.URL.Path, "/api/") {
			p, ok := a.identity(r)
			r = r.WithContext(context.WithValue(r.Context(), principalContextKey{}, requestPrincipal{principal: p, valid: ok}))
		}
		if strings.HasPrefix(r.URL.Path, "/api/") && r.Method != "GET" && r.Method != "HEAD" {
			actor := "unauthenticated"
			if a.authorized(r) {
				actor = a.actor(r)
			}
			intent, err := g.RecordAudit(adminaudit.Record{Operation: auditOperation(r), Actor: actor, Outcome: "intent", Revision: g.Config().Revision})
			if err != nil {
				problem(w, 503, "Administration audit unavailable; change refused")
				return
			}
			response := &auditResponse{ResponseWriter: w}
			w = response
			defer func() {
				outcome := "failed"
				if response.status >= 200 && response.status < 300 {
					outcome = "success"
					if r.URL.Path == "/api/v1/login" || r.URL.Path == "/api/v1/login/passkey/finish" {
						actor = "administrator"
						if response.actor != "" {
							actor = response.actor
						}
					}
				}
				if _, err := g.RecordAudit(adminaudit.Record{Correlation: intent.Correlation, Operation: intent.Operation, Actor: actor, Outcome: outcome, Status: response.status, Revision: g.Config().Revision}); err != nil {
					log.Print("Administration audit outcome commit failed; inspect audit health")
				}
			}()
			if origin := r.Header.Get("Origin"); origin != "" {
				u, e := url.Parse(origin)
				scheme := "http"
				if r.TLS != nil {
					scheme = "https"
				}
				if e != nil || u.Host != r.Host || u.Scheme != scheme {
					problem(w, 403, "Cross-origin request denied")
					return
				}
			}
			if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
				problem(w, 415, "Content-Type must be application/json")
				return
			}
		}
		if strings.HasPrefix(r.URL.Path, "/api/") && !publicAuthenticationPath(r.URL.Path) && !a.authorized(r) {
			problem(w, 401, "Sign in required")
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") && !publicAuthenticationPath(r.URL.Path) {
			p, _ := a.identity(r)
			if !principalAllows(p, r.Method, r.URL.Path) {
				problem(w, 403, "Your role does not allow this operation")
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}
func (a *Admin) actor(r *http.Request) string {
	if p, ok := a.identity(r); ok && p.Automation != "" {
		return "automation " + p.Automation
	}
	if p, ok := a.identity(r); ok && !p.Bootstrap {
		return "account " + p.Username
	}
	if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		return "administrator API token"
	}
	if cookie, err := r.Cookie("openwaf_session"); err == nil {
		sum := sha256.Sum256([]byte(cookie.Value))
		return "administrator session " + hex.EncodeToString(sum[:6])
	}
	return "administrator"
}
func policyProblem(w http.ResponseWriter, err error) {
	status := 400
	if strings.Contains(err.Error(), "configuration changed") || strings.Contains(err.Error(), "in progress") {
		status = 409
	}
	problem(w, status, err.Error())
}
func (a *Admin) authorized(r *http.Request) bool {
	_, ok := a.identity(r)
	return ok
}
func (a *Admin) login(w http.ResponseWriter, r *http.Request) {
	if a.credentialLimited() {
		w.Header().Set("Retry-After", "60")
		problem(w, 429, "Too many sign-in attempts; retry in one minute")
		return
	}
	var req struct {
		Token    string `json:"token"`
		Username string `json:"username"`
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if err := decode(w, r, &req); err != nil {
		problem(w, 400, "Invalid sign-in request")
		return
	}
	p := principal{Role: "administrator", Bootstrap: true}
	valid := false
	if req.Username != "" || req.Password != "" {
		if req.Token != "" || len(req.Username) > 64 || len(req.Password) < 1 || len(req.Password) > 256 {
			problem(w, 400, "Invalid sign-in fields")
			return
		}
		select {
		case a.passwordSlots <- struct{}{}:
			defer func() { <-a.passwordSlots }()
		default:
			problem(w, 429, "Password verification capacity exhausted")
			return
		}
		if !a.gateway.update.TryLock() {
			problem(w, 409, "Another administration operation is in progress")
			return
		}
		defer a.gateway.update.Unlock()
		if a.gateway.closed.Load() {
			problem(w, 503, "Gateway is closed")
			return
		}
		account, err := a.gateway.accounts.Authenticate(req.Username, req.Password, req.Code, time.Now())
		valid = err == nil
		p = principal{Username: account.Username, Role: account.Role, Version: account.Version, MFAEnabled: account.MFAEnabled}
	} else {
		sum := sha256.Sum256([]byte(strings.TrimSpace(req.Token)))
		valid = subtle.ConstantTimeCompare(sum[:], a.token[:]) == 1
	}
	if !valid {
		a.failedCredential()
		problem(w, 401, "Invalid sign-in credentials")
		return
	}
	if a.issueSession(w, r, p, p.MFAEnabled, time.Now(), "local", time.Time{}) {
		reply(w, 200, map[string]bool{"ok": true})
	}
}
func (a *Admin) issueSession(w http.ResponseWriter, r *http.Request, p principal, strong bool, verifiedAt time.Time, method string, limit time.Time) bool {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		problem(w, 500, "Could not create session")
		return false
	}
	value := hex.EncodeToString(b)
	key := sha256.Sum256([]byte(value))
	expires := time.Now().Add(8 * time.Hour)
	if !limit.IsZero() && limit.Before(expires) {
		expires = limit
	}
	a.mu.Lock()
	if previous, err := r.Cookie("openwaf_session"); err == nil {
		key := sha256.Sum256([]byte(previous.Value))
		delete(a.sessions, key)
		delete(a.enrollments, key)
	}
	for k, s := range a.sessions {
		if time.Now().After(s.expires) {
			delete(a.sessions, k)
		}
	}
	if len(a.sessions) >= 100 {
		a.mu.Unlock()
		problem(w, 429, "Session limit reached")
		return false
	}
	a.sessions[key] = session{expires: expires, username: p.Username, version: p.Version, strong: strong, verifiedAt: verifiedAt, method: method}
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "openwaf_session", Value: value, Path: "/", Expires: expires, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
	if response, ok := w.(*auditResponse); ok && !p.Bootstrap {
		response.actor = "account " + p.Username
	}
	return true
}
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("expected one JSON value")
		}
		return err
	}
	return nil
}
func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func problem(w http.ResponseWriter, status int, message string) {
	reply(w, status, map[string]string{"error": message})
}
