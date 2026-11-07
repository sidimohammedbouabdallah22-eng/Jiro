package gateway

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/accounts"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/adminaudit"
)

type principal struct {
	PasskeyCount       int                         `json:"passkey_count,omitempty"`
	Strong             bool                        `json:"strong_authentication,omitempty"`
	VerifiedAt         time.Time                   `json:"-"`
	Method             string                      `json:"authentication_method,omitempty"`
	Username           string                      `json:"username"`
	Role               string                      `json:"role"`
	Bootstrap          bool                        `json:"bootstrap"`
	Version            uint64                      `json:"-"`
	Automation         string                      `json:"automation_id,omitempty"`
	Scopes             []string                    `json:"scopes,omitempty"`
	MFAEnabled         bool                        `json:"mfa_enabled,omitempty"`
	Access             *accounts.ApplicationAccess `json:"access,omitempty"`
	EnrollmentRequired bool                        `json:"mfa_enrollment_required,omitempty"`
	RequireAdminMFA    bool                        `json:"require_admin_mfa,omitempty"`
}

type principalContextKey struct{}
type requestPrincipal struct {
	principal principal
	valid     bool
}

func (a *Admin) identity(r *http.Request) (principal, bool) {
	if cached, ok := r.Context().Value(principalContextKey{}).(requestPrincipal); ok {
		return cached.principal, cached.valid
	}
	return a.liveIdentity(r)
}

func (a *Admin) liveIdentity(r *http.Request) (principal, bool) {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		value := strings.TrimPrefix(h, "Bearer ")
		sum := sha256.Sum256([]byte(value))
		if subtle.ConstantTimeCompare(sum[:], a.token[:]) == 1 {
			return principal{Username: "bootstrap", Role: "administrator", Bootstrap: true}, true
		}
		token, ok := a.gateway.accounts.VerifyToken(value, time.Now())
		return principal{Username: token.Owner, Role: "automation", Automation: token.ID, Scopes: token.Scopes, Access: token.Access}, ok
	}
	cookie, err := r.Cookie("openwaf_session")
	if err != nil {
		return principal{}, false
	}
	key := sha256.Sum256([]byte(cookie.Value))
	a.mu.Lock()
	s, ok := a.sessions[key]
	if !ok || !time.Now().Before(s.expires) {
		delete(a.sessions, key)
		a.mu.Unlock()
		return principal{}, false
	}
	a.mu.Unlock()
	if s.username == "" {
		return principal{Username: "bootstrap", Role: "administrator", Bootstrap: true}, true
	}
	account, ok := a.gateway.accounts.Current(s.username, s.version)
	required := a.gateway.accounts.RequiresAdminMFA()
	return principal{Username: account.Username, Role: account.Role, Version: account.Version, MFAEnabled: account.MFAEnabled, PasskeyCount: account.PasskeyCount, Access: account.Access, RequireAdminMFA: required, Strong: s.strong, VerifiedAt: s.verifiedAt, Method: s.method, EnrollmentRequired: required && account.Role == "administrator" && !s.strong}, ok
}

func roleAllows(role, method, path string) bool {
	if role == "administrator" {
		return true
	}
	if role != "operator" && role != "viewer" {
		return false
	}
	if method == "GET" || method == "HEAD" {
		switch path {
		case "/api/v1/me", "/api/v1/me/passkeys", "/api/v1/config", "/api/v1/config/history", "/api/v1/status", "/api/v1/events", "/api/v1/events/search", "/api/v1/audit", "/api/v1/certificates", "/api/v1/health", "/api/v1/metrics", "/api/v1/applications", "/api/v1/upstreams":
			return true
		}
		if strings.HasPrefix(path, "/api/v1/config/history/") {
			_, err := strconv.ParseUint(strings.TrimPrefix(path, "/api/v1/config/history/"), 10, 64)
			return err == nil
		}
		return false
	}
	if method == "POST" && (path == "/api/v1/logout" || path == "/api/v1/me/password" || path == "/api/v1/me/mfa/setup" || path == "/api/v1/me/mfa/enable" || path == "/api/v1/me/mfa/disable" || path == "/api/v1/me/passkeys/begin" || path == "/api/v1/me/passkeys/finish" || path == "/api/v1/me/passkeys/revoke") {
		return true
	}
	if role != "operator" {
		return false
	}
	if method == "PUT" {
		return path == "/api/v1/config"
	}
	if method != "POST" {
		return false
	}
	switch path {
	case "/api/v1/config/apply", "/api/v1/config/validate", "/api/v1/config/rollback", "/api/v1/applications":
		return true
	}
	parts := strings.Split(strings.TrimPrefix(path, "/api/v1/applications/"), "/")
	return strings.HasPrefix(path, "/api/v1/applications/") && len(parts) == 2 && parts[1] == "delete"
}

func (a *Admin) saveAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Revision     uint64                      `json:"revision"`
		Username     string                      `json:"username"`
		Role         string                      `json:"role"`
		Disabled     bool                        `json:"disabled"`
		Password     string                      `json:"password"`
		Reason       string                      `json:"reason"`
		Access       *accounts.ApplicationAccess `json:"access"`
		UpdateAccess bool                        `json:"update_access"`
	}
	if err := decode(w, r, &req); err != nil {
		problem(w, 400, "Invalid account request")
		return
	}
	if strings.TrimSpace(req.Reason) == "" || len(req.Reason) > 500 {
		problem(w, 400, "A change reason of at most 500 bytes is required")
		return
	}
	select {
	case a.passwordSlots <- struct{}{}:
		defer func() { <-a.passwordSlots }()
	default:
		problem(w, 429, "Password operation capacity exhausted")
		return
	}
	updated, err := a.commitAccount(r, req.Revision, req.Username, req.Role, req.Disabled, req.Password, req.Reason, accountAccessChange{update: req.UpdateAccess || req.Access != nil, access: req.Access})
	if err != nil {
		accountProblem(w, err.Error())
		return
	}
	reply(w, 200, updated)
}

func accountProblem(w http.ResponseWriter, message string) {
	status := 400
	if strings.Contains(message, "revision changed") || strings.Contains(message, "in progress") {
		status = 409
	}
	if strings.Contains(message, "audit unavailable") || strings.Contains(message, "gateway is closed") || strings.Contains(message, "durability is uncertain") {
		status = 503
	}
	problem(w, status, message)
}

func (a *Admin) changePassword(w http.ResponseWriter, r *http.Request) {
	p, _ := a.identity(r)
	if p.Bootstrap {
		problem(w, 409, "Bootstrap credentials are rotated through the server credential source")
		return
	}
	var req struct {
		CurrentPassword string `json:"current_password"`
		Password        string `json:"password"`
		Code            string `json:"code"`
	}
	if err := decode(w, r, &req); err != nil || len(req.CurrentPassword) > 256 || len(req.Password) < 15 || len(req.Password) > 256 {
		problem(w, 400, "Use the current password and a new 15..256 byte password")
		return
	}
	if a.credentialLimited() {
		w.Header().Set("Retry-After", "60")
		problem(w, 429, "Too many credential checks; retry in one minute")
		return
	}
	select {
	case a.passwordSlots <- struct{}{}:
		defer func() { <-a.passwordSlots }()
	default:
		problem(w, 429, "Password operation capacity exhausted")
		return
	}
	if !a.gateway.update.TryLock() {
		problem(w, 409, "Another administration operation is in progress")
		return
	}
	if a.gateway.closed.Load() {
		a.gateway.update.Unlock()
		problem(w, 503, "Gateway is closed")
		return
	}
	account, err := a.gateway.accounts.Authenticate(p.Username, req.CurrentPassword, req.Code, time.Now())
	a.gateway.update.Unlock()
	if err != nil || account.Version != p.Version {
		a.failedCredential()
		problem(w, 401, "Current password verification failed")
		return
	}
	d := a.gateway.accounts.List()
	for _, current := range d.Accounts {
		if current.Username == p.Username && current.Version == p.Version {
			if _, err := a.commitAccount(r, d.Revision, p.Username, current.Role, false, req.Password, "Self-service password change"); err != nil {
				accountProblem(w, err.Error())
				return
			}
			reply(w, 200, map[string]bool{"ok": true})
			return
		}
	}
	problem(w, 409, "Account changed; sign in again")
}

func (a *Admin) credentialLimited() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if time.Since(a.window) > time.Minute {
		a.window = time.Now()
		a.failures = 0
	}
	return a.failures >= 10
}

func (a *Admin) failedCredential() { a.mu.Lock(); a.failures++; a.mu.Unlock() }

func (a *Admin) commitAccount(r *http.Request, revision uint64, username, role string, disabled bool, password, reason string, changes ...accountAccessChange) (accounts.Document, error) {
	if !a.gateway.update.TryLock() {
		return accounts.Document{}, errors.New("another administration operation is in progress; retry")
	}
	defer a.gateway.update.Unlock()
	if a.gateway.closed.Load() {
		return accounts.Document{}, errors.New("gateway is closed")
	}
	actor := a.actor(r)
	resource := clip(fmt.Sprintf("%s role=%s disabled=%t password_changed=%t", clip(username, 64), clip(role, 16), disabled, password != ""), 128)
	if len(changes) > 0 && changes[0].update {
		data, _ := json.Marshal(struct {
			Role     string
			Disabled bool
			Access   *accounts.ApplicationAccess
		}{role, disabled, changes[0].access})
		sum := sha256.Sum256(data)
		resource = clip(username, 64) + " grant=" + base64.RawURLEncoding.EncodeToString(sum[:])
	}
	intent, err := a.gateway.RecordAudit(adminaudit.Record{Operation: "account.activate", Actor: actor, Outcome: "intent", Revision: revision + 1, Resource: resource})
	if err != nil {
		return accounts.Document{}, fmt.Errorf("account audit unavailable: %w", err)
	}
	var updated accounts.Document
	if len(changes) > 0 && changes[0].update {
		access := changes[0].access
		if access != nil && a.gateway.Config().SchemaVersion != 2 {
			return accounts.Document{}, errors.New("application access requires schema-2 routing")
		}
		if err = accounts.ValidateAssignedIDs(access, applicationIDs(a.gateway.Config())); err == nil {
			updated, err = a.gateway.accounts.SaveAccess(revision, username, role, disabled, password, actor, reason, access)
		}
	} else {
		updated, err = a.gateway.accounts.Save(revision, username, role, disabled, password, actor, reason)
	}
	outcome := "failed"
	if err == nil {
		outcome = "success"
		a.mu.Lock()
		for key, session := range a.sessions {
			if session.username == username {
				delete(a.sessions, key)
			}
		}
		a.mu.Unlock()
	}
	_, _ = a.gateway.RecordAudit(adminaudit.Record{Operation: "account.activate", Actor: actor, Outcome: outcome, Revision: revision + 1, Resource: resource, Correlation: intent.Correlation})
	return updated, err
}
