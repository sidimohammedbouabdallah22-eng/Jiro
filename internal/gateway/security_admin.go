package gateway

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/accounts"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/adminaudit"
)

func principalAllows(p principal, method, path string) bool {
	if p.EnrollmentRequired {
		return ((method == "GET" || method == "HEAD") && (path == "/api/v1/me" || path == "/api/v1/me/passkeys")) || (method == "POST" && slices.Contains([]string{"/api/v1/logout", "/api/v1/me/mfa/setup", "/api/v1/me/mfa/enable", "/api/v1/me/passkeys/begin", "/api/v1/me/passkeys/finish"}, path))
	}
	if p.Access != nil && !applicationRouteAllowed(method, path) {
		return false
	}
	if p.Automation == "" {
		return roleAllows(p.Role, method, path)
	}
	if method == "GET" || method == "HEAD" {
		if path == "/api/v1/me" {
			return true
		}
		for scope, paths := range map[string][]string{
			"monitoring:read": {"/api/v1/status", "/api/v1/health", "/api/v1/metrics"},
			"events:read":     {"/api/v1/events", "/api/v1/events/search"},
			"audit:read":      {"/api/v1/audit"},
			"policy:read":     {"/api/v1/config", "/api/v1/applications", "/api/v1/config/history", "/api/v1/upstreams"},
		} {
			if slices.Contains(p.Scopes, scope) && slices.Contains(paths, path) {
				return true
			}
		}
		if slices.Contains(p.Scopes, "policy:read") && strings.HasPrefix(path, "/api/v1/config/history/") {
			return roleAllows("viewer", method, path)
		}
		return false
	}
	if slices.Contains(p.Scopes, "policy:write") {
		if method == "PUT" && path == "/api/v1/config" {
			return true
		}
		if method == "POST" && slices.Contains([]string{"/api/v1/config/apply", "/api/v1/config/validate", "/api/v1/config/rollback", "/api/v1/applications"}, path) {
			return true
		}
		if strings.HasPrefix(path, "/api/v1/applications/") {
			return roleAllows("operator", method, path)
		}
	}
	return method == "POST" && path == "/api/v1/certificates/reload" && slices.Contains(p.Scopes, "certificates:reload")
}

// Security mutations share the policy/shutdown lease and require a durable audit intent.
func (a *Admin) securityMutation(r *http.Request, operation, resource string, apply func() error) error {
	if !a.gateway.update.TryLock() {
		return errors.New("another administration operation is in progress; retry")
	}
	defer a.gateway.update.Unlock()
	if a.gateway.closed.Load() {
		return errors.New("gateway is closed")
	}
	intent, err := a.gateway.RecordAudit(adminaudit.Record{Operation: operation, Actor: a.actor(r), Outcome: "intent", Resource: clip(resource, 128)})
	if err != nil {
		return fmt.Errorf("security audit unavailable: %w", err)
	}
	err = apply()
	outcome := "success"
	if err != nil {
		outcome = "failed"
	}
	_, _ = a.gateway.RecordAudit(adminaudit.Record{Operation: operation, Actor: a.actor(r), Outcome: outcome, Resource: clip(resource, 128), Correlation: intent.Correlation})
	return err
}

func (a *Admin) listTokens(w http.ResponseWriter, r *http.Request) {
	d := a.gateway.accounts.List()
	reply(w, 200, map[string]any{"revision": d.Revision, "items": d.Tokens, "available_scopes": accounts.Scopes})
}

func (a *Admin) createToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Revision      uint64                      `json:"revision"`
		Owner         string                      `json:"owner"`
		Name          string                      `json:"name"`
		Scopes        []string                    `json:"scopes"`
		LifetimeHours int                         `json:"lifetime_hours"`
		Reason        string                      `json:"reason"`
		Access        *accounts.ApplicationAccess `json:"access"`
	}
	if err := decode(w, r, &req); err != nil || strings.TrimSpace(req.Reason) == "" || len(req.Reason) > 500 || req.LifetimeHours < 1 || req.LifetimeHours > 2160 {
		problem(w, 400, "Use an owner, explicit scopes, a 1..2160 hour lifetime and a change reason")
		return
	}
	var token accounts.Token
	var secret string
	err := a.securityMutation(r, "automation.create", req.Owner+" "+req.Name, func() error {
		if req.Access != nil && a.gateway.Config().SchemaVersion != 2 {
			return errors.New("application tokens require schema-2 routing")
		}
		if err := accounts.ValidateAssignedIDs(req.Access, applicationIDs(a.gateway.Config())); err != nil {
			return err
		}
		now := time.Now()
		var err error
		token, secret, err = a.gateway.accounts.CreateScopedToken(req.Revision, req.Owner, req.Name, req.Scopes, now.Add(time.Duration(req.LifetimeHours)*time.Hour), now, a.actor(r), req.Reason, req.Access)
		if err == nil {
			_, _ = a.gateway.RecordAudit(adminaudit.Record{Operation: "automation.issued", Actor: a.actor(r), Outcome: "success", Resource: token.ID + " owner=" + token.Owner})
		}
		return err
	})
	if err != nil {
		accountProblem(w, err.Error())
		return
	}
	reply(w, 201, map[string]any{"token": token, "secret": secret})
}

func (a *Admin) revokeToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Revision uint64 `json:"revision"`
		Reason   string `json:"reason"`
	}
	if err := decode(w, r, &req); err != nil || strings.TrimSpace(req.Reason) == "" || len(req.Reason) > 90 {
		problem(w, 400, "A revision and change reason are required")
		return
	}
	err := a.securityMutation(r, "automation.revoke", r.PathValue("id")+" "+req.Reason, func() error {
		_, err := a.gateway.accounts.RevokeToken(req.Revision, r.PathValue("id"))
		return err
	})
	if err != nil {
		accountProblem(w, err.Error())
		return
	}
	reply(w, 200, map[string]bool{"ok": true})
}

type mfaEnrollment struct {
	secret   string
	username string
	version  uint64
	expires  time.Time
}

// MFA credential operations use the same bounded verification slots and failure throttle as login.
func (a *Admin) mfaRequest(w http.ResponseWriter, r *http.Request) (principal, string, string, [32]byte, bool) {
	p, _ := a.identity(r)
	var req struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if p.Bootstrap || p.Automation != "" {
		problem(w, 403, "Use a named local account session")
		return p, "", "", [32]byte{}, false
	}
	if err := decode(w, r, &req); err != nil || len(req.Password) < 1 || len(req.Password) > 256 || len(req.Code) > 6 {
		problem(w, 400, "Invalid password or authenticator code")
		return p, "", "", [32]byte{}, false
	}
	cookie, err := r.Cookie("openwaf_session")
	if err != nil {
		problem(w, 401, "Sign in required")
		return p, "", "", [32]byte{}, false
	}
	if a.credentialLimited() {
		w.Header().Set("Retry-After", "60")
		problem(w, 429, "Too many credential checks; retry in one minute")
		return p, "", "", [32]byte{}, false
	}
	return p, req.Password, req.Code, sha256.Sum256([]byte(cookie.Value)), true
}

func (a *Admin) setupMFA(w http.ResponseWriter, r *http.Request)   { a.manageMFA(w, r, "setup") }
func (a *Admin) enableMFA(w http.ResponseWriter, r *http.Request)  { a.manageMFA(w, r, "enable") }
func (a *Admin) disableMFA(w http.ResponseWriter, r *http.Request) { a.manageMFA(w, r, "disable") }

func (a *Admin) manageMFA(w http.ResponseWriter, r *http.Request, operation string) {
	p, password, code, key, ok := a.mfaRequest(w, r)
	if !ok {
		return
	}
	if operation == "disable" && p.Role == "administrator" && p.PasskeyCount == 0 && a.gateway.accounts.RequiresAdminMFA() {
		problem(w, 409, "Administrator MFA is required by deployment policy")
		return
	}
	select {
	case a.passwordSlots <- struct{}{}:
		defer func() { <-a.passwordSlots }()
	default:
		problem(w, 429, "Password operation capacity exhausted")
		return
	}
	account, valid := a.gateway.accounts.Verify(p.Username, password)
	if !valid || account.Version != p.Version {
		a.failedCredential()
		problem(w, 401, "Credential verification failed")
		return
	}
	if operation == "setup" {
		if account.MFAEnabled {
			problem(w, 409, "Disable the existing authenticator before enrolling another")
			return
		}
		secret, err := accounts.NewMFASecret()
		if err != nil {
			problem(w, 500, "Could not create authenticator secret")
			return
		}
		a.mu.Lock()
		for k, enrollment := range a.enrollments {
			if time.Now().After(enrollment.expires) {
				delete(a.enrollments, k)
			}
		}
		if len(a.enrollments) >= 100 {
			a.mu.Unlock()
			problem(w, 429, "Enrollment capacity exhausted")
			return
		}
		a.enrollments[key] = mfaEnrollment{secret: secret, username: p.Username, version: p.Version, expires: time.Now().Add(10 * time.Minute)}
		a.mu.Unlock()
		uri := "otpauth://totp/" + url.PathEscape("OpenWAF:"+p.Username) + "?" + url.Values{"secret": {secret}, "issuer": {"OpenWAF"}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}.Encode()
		reply(w, 200, map[string]string{"secret": secret, "uri": uri})
		return
	}
	var secret string
	if operation == "enable" {
		a.mu.Lock()
		enrollment, exists := a.enrollments[key]
		a.mu.Unlock()
		if !exists || enrollment.username != p.Username || enrollment.version != p.Version || !time.Now().Before(enrollment.expires) {
			problem(w, 409, "Start a new authenticator enrollment")
			return
		}
		secret = enrollment.secret
	}
	err := a.securityMutation(r, "account.mfa."+operation, p.Username, func() error {
		if operation == "disable" {
			if !account.MFAEnabled {
				return errors.New("authenticator is already disabled")
			}
			current, err := a.gateway.accounts.Authenticate(p.Username, password, code, time.Now())
			if err != nil || current.Version != p.Version {
				return errors.New("credential verification failed")
			}
		}
		_, err := a.gateway.accounts.SetMFA(p.Username, p.Version, secret, code, time.Now(), a.actor(r), "Authenticator "+operation)
		return err
	})
	if err != nil {
		a.failedCredential()
		accountProblem(w, err.Error())
		return
	}
	a.mu.Lock()
	delete(a.enrollments, key)
	a.mu.Unlock()
	reply(w, 200, map[string]bool{"ok": true})
}

func (a *Admin) resetMFA(w http.ResponseWriter, r *http.Request) {
	p, _ := a.identity(r)
	if !p.Bootstrap {
		problem(w, 403, "Authenticator recovery requires the bootstrap recovery credential")
		return
	}
	var req struct {
		Revision uint64 `json:"revision"`
		Username string `json:"username"`
		Reason   string `json:"reason"`
	}
	if err := decode(w, r, &req); err != nil || strings.TrimSpace(req.Reason) == "" || len(req.Reason) > 500 {
		problem(w, 400, "A revision, username and recovery reason are required")
		return
	}
	err := a.securityMutation(r, "account.mfa.recover", req.Username, func() error {
		d := a.gateway.accounts.List()
		if d.Revision != req.Revision {
			return errors.New("account revision changed; reload before saving")
		}
		for _, account := range d.Accounts {
			if account.Username == req.Username {
				_, err := a.gateway.accounts.RecoverMFA(account.Username, account.Version, time.Now(), a.actor(r), req.Reason)
				return err
			}
		}
		return errors.New("account unavailable")
	})
	if err != nil {
		accountProblem(w, err.Error())
		return
	}
	reply(w, 200, map[string]bool{"ok": true})
}
