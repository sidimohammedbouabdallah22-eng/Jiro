package gateway

import (
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/accounts"
)

type accountAccessChange struct {
	update bool
	access *accounts.ApplicationAccess
}

func applicationIDs(c Config) []string {
	ids := []string{}
	for _, app := range c.ApplicationList() {
		ids = append(ids, app.ApplicationID)
	}
	return ids
}

func applicationRouteAllowed(method, path string) bool {
	if method == "GET" || method == "HEAD" {
		return slices.Contains([]string{"/api/v1/me", "/api/v1/me/passkeys", "/api/v1/config", "/api/v1/applications", "/api/v1/events", "/api/v1/events/search", "/api/v1/upstreams"}, path)
	}
	return method == "POST" && slices.Contains([]string{"/api/v1/config/apply", "/api/v1/config/validate", "/api/v1/logout", "/api/v1/me/password", "/api/v1/me/mfa/setup", "/api/v1/me/mfa/enable", "/api/v1/me/mfa/disable", "/api/v1/me/passkeys/begin", "/api/v1/me/passkeys/finish", "/api/v1/me/passkeys/revoke"}, path)
}

func (a *Admin) visibleConfig(r *http.Request, c Config) Config {
	p, _ := a.identity(r)
	if p.Access == nil {
		return c
	}
	apps := []Application{}
	for _, app := range c.Applications {
		if slices.Contains(p.Access.IDs, app.ApplicationID) {
			apps = append(apps, app)
		}
	}
	c.Applications = apps
	c.syncPrimary()
	return c
}

func (a *Admin) applyVisibleConfig(r *http.Request, requested Config, validateOnly bool, reason string) (Config, error) {
	p, _ := a.identity(r)
	if p.Access == nil {
		return a.gateway.ApplyWithMetadata(requested, validateOnly, a.actor(r), reason)
	}
	g := a.gateway
	if !g.update.TryLock() {
		return Config{}, errors.New("another policy operation is in progress; retry")
	}
	defer g.update.Unlock()
	if fresh, valid := a.liveIdentity(r); !valid || !principalAllows(fresh, r.Method, r.URL.Path) {
		return Config{}, errors.New("authorization changed; sign in again")
	}
	current := g.Config()
	if requested.Revision != current.Revision {
		return Config{}, errors.New("configuration changed; reload before saving")
	}
	visible := a.visibleConfig(r, current)
	if requested.SchemaVersion != 2 || len(requested.Applications) != len(visible.Applications) {
		return Config{}, errors.New("submit exactly the assigned application policies")
	}
	seen := map[string]bool{}
	for _, app := range requested.Applications {
		if !slices.Contains(p.Access.IDs, app.ApplicationID) || seen[app.ApplicationID] {
			return Config{}, errors.New("application is outside your assignment")
		}
		seen[app.ApplicationID] = true
		found := false
		for i, existing := range current.Applications {
			if existing.ApplicationID != app.ApplicationID {
				continue
			}
			if !reflect.DeepEqual(app.Hosts, existing.Hosts) || app.Upstream != existing.Upstream || !reflect.DeepEqual(app.Pool, existing.Pool) {
				return Config{}, errors.New("shared routing changes require deployment-wide access")
			}
			current.Applications[i] = app
			found = true
		}
		if !found {
			return Config{}, errors.New("application is unavailable")
		}
	}
	updated, err := g.applyLocked(current, validateOnly, a.actor(r), reason, 0)
	if err != nil {
		return Config{}, errors.New("assigned policy failed complete-deployment validation or activation")
	}
	return updated, nil
}

func (a *Admin) getSecurityPolicy(w http.ResponseWriter, r *http.Request) {
	d := a.gateway.accounts.List()
	reply(w, 200, map[string]any{"revision": d.Revision, "require_admin_mfa": d.RequireAdminMFA})
}

func (a *Admin) saveSecurityPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Revision uint64 `json:"revision"`
		Required bool   `json:"require_admin_mfa"`
		Password string `json:"password"`
		Code     string `json:"code"`
		Reason   string `json:"reason"`
	}
	if err := decode(w, r, &req); err != nil || strings.TrimSpace(req.Reason) == "" || len(req.Reason) > 90 || len(req.Password) > 256 || len(req.Code) > 6 {
		problem(w, 400, "Use a revision, security policy and reason of at most 90 bytes")
		return
	}
	p, _ := a.identity(r)
	strongStepUp := p.Strong && p.Method != "local" && time.Since(p.VerifiedAt) < 2*time.Minute
	if !p.Bootstrap {
		if !p.MFAEnabled && !strongStepUp {
			problem(w, 403, "Enroll your authenticator before changing deployment MFA policy")
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
	}
	err := a.securityMutation(r, "security.mfa-policy", fmt.Sprintf("required=%t %s", req.Required, req.Reason), func() error {
		if a.gateway.accounts.List().Revision != req.Revision {
			return errors.New("account revision changed; reload before saving")
		}
		if !p.Bootstrap && !strongStepUp {
			account, err := a.gateway.accounts.Authenticate(p.Username, req.Password, req.Code, time.Now())
			if err != nil || account.Version != p.Version {
				a.failedCredential()
				return errors.New("credential verification failed")
			}
		}
		_, err := a.gateway.accounts.SetMFAPolicy(a.gateway.accounts.List().Revision, req.Required)
		return err
	})
	if err != nil {
		accountProblem(w, err.Error())
		return
	}
	a.getSecurityPolicy(w, r)
}
