package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/accounts"
)

func TestRequiredAdministratorMFAEnrollmentAndRecovery(t *testing.T) {
	g, _ := applicationFixture(t)
	root := strings.Repeat("q", 64)
	h := NewAdmin(g, root)
	const password = "a long enforcement test password"
	for _, name := range []string{"ready", "newadmin"} {
		if _, err := g.accounts.Save(g.accounts.List().Revision, name, "administrator", false, password, "test", "Administrator fixture"); err != nil {
			t.Fatal(err)
		}
	}
	login := func(name, code string) *http.Cookie {
		w := securityCall(h, "POST", "/api/v1/login", map[string]string{"username": name, "password": password, "code": code}, "", nil)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
		return w.Result().Cookies()[0]
	}
	old := login("newadmin", "")
	now := time.Now()
	_, bearer, err := g.accounts.CreateToken(g.accounts.List().Revision, "newadmin", "before enforcement", []string{"monitoring:read"}, now.Add(time.Hour), now, "test", "Fixture")
	if err != nil {
		t.Fatal(err)
	}
	setPolicy := func(required bool) int {
		return securityCall(h, "POST", "/api/v1/security-policy", map[string]any{"revision": g.accounts.List().Revision, "require_admin_mfa": required, "reason": "Enforcement test"}, root, nil).Code
	}
	if got := setPolicy(true); got != 400 {
		t.Fatal("enabled without an enrolled administrator", got)
	}
	secret, _ := accounts.NewMFASecret()
	ready, _ := g.accounts.Verify("ready", password)
	readyAt := time.Now()
	if _, err := g.accounts.SetMFA("ready", ready.Version, secret, testAuthenticatorCode(secret, readyAt.Unix()/30-1), readyAt, "test", "Ready administrator"); err != nil {
		t.Fatal(err)
	}
	if got := setPolicy(true); got != 200 {
		t.Fatal("enable enforcement", got)
	}
	for path, want := range map[string]int{"/api/v1/me": 200, "/api/v1/config": 403, "/api/v1/accounts": 403, "/api/v1/security-policy": 403} {
		if w := securityCall(h, "GET", path, nil, "", old); w.Code != want {
			t.Fatalf("%s=%d want %d", path, w.Code, want)
		}
	}
	if w := securityCall(h, "GET", "/api/v1/health", nil, bearer, nil); w.Code != 401 {
		t.Fatal("unenrolled administrator token bypassed MFA policy")
	}
	limited := login("newadmin", "")
	w := securityCall(h, "POST", "/api/v1/me/mfa/setup", map[string]string{"password": password}, "", limited)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	var enrollment struct {
		Secret string `json:"secret"`
	}
	json.Unmarshal(w.Body.Bytes(), &enrollment)
	waitForAuthenticatorWindow(t)
	w = securityCall(h, "POST", "/api/v1/me/mfa/enable", map[string]string{"password": password, "code": testAuthenticatorCode(enrollment.Secret, time.Now().Unix()/30-1)}, "", limited)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	full := login("newadmin", testAuthenticatorCode(enrollment.Secret, time.Now().Unix()/30))
	if w := securityCall(h, "GET", "/api/v1/config", nil, "", full); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if w := securityCall(h, "POST", "/api/v1/me/mfa/disable", map[string]string{"password": password, "code": testAuthenticatorCode(enrollment.Secret, time.Now().Unix()/30+1)}, "", full); w.Code != 409 {
		t.Fatal("disabled required MFA", w.Code, w.Body)
	}
	w = securityCall(h, "POST", "/api/v1/security-policy", map[string]any{"revision": g.accounts.List().Revision, "require_admin_mfa": false, "reason": "Missing step-up"}, "", full)
	if w.Code == 200 || !g.accounts.RequiresAdminMFA() {
		t.Fatal("policy changed without password and fresh OTP")
	}
	for _, name := range []string{"ready", "newadmin"} {
		w := securityCall(h, "POST", "/api/v1/accounts/mfa-reset", map[string]any{"revision": g.accounts.List().Revision, "username": name, "reason": "Lost authenticator recovery"}, root, nil)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
	}
	if !g.accounts.RequiresAdminMFA() {
		t.Fatal("recovery silently disabled MFA policy")
	}
	limited = login("newadmin", "")
	if w := securityCall(h, "GET", "/api/v1/config", nil, "", limited); w.Code != 403 {
		t.Fatal("recovery issued full password-only administration")
	}
	if got := setPolicy(false); got != 200 {
		t.Fatal("bootstrap could not recover policy", got)
	}
	if w := securityCall(h, "GET", "/api/v1/config", nil, "", limited); w.Code != 200 {
		t.Fatal("explicit policy disable failed")
	}
}

func TestAssignedApplicationsFilterReadsAndMergeWrites(t *testing.T) {
	g, _ := applicationFixture(t)
	root := strings.Repeat("a", 64)
	h := NewAdmin(g, root)
	const password = "a long application access password"
	if _, err := g.accounts.Save(1, "admin", "administrator", false, password, "test", "Fixture administrator"); err != nil {
		t.Fatal(err)
	}
	created := securityCall(h, "POST", "/api/v1/accounts", map[string]any{"revision": g.accounts.List().Revision, "username": "scoped", "role": "operator", "password": password, "reason": "Shop access", "access": map[string]any{"application_ids": []string{"shop"}}}, root, nil)
	if created.Code != 200 {
		t.Fatal(created.Code, created.Body)
	}
	w := securityCall(h, "POST", "/api/v1/login", map[string]string{"username": "scoped", "password": password}, "", nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	cookie := w.Result().Cookies()[0]
	w = securityCall(h, "GET", "/api/v1/config", nil, "", cookie)
	var c Config
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &c) != nil || len(c.Applications) != 1 || c.Applications[0].ApplicationID != "shop" {
		t.Fatal("unfiltered configuration", w.Code, w.Body)
	}
	for _, path := range []string{"/api/v1/status", "/api/v1/health", "/api/v1/metrics", "/api/v1/config/history", "/api/v1/config/history/1", "/api/v1/audit", "/api/v1/certificates", "/api/v1/accounts"} {
		if w := securityCall(h, "GET", path, nil, "", cookie); w.Code != 403 {
			t.Fatal(path, w.Code)
		}
	}
	for _, path := range []string{"/api/v1/applications", "/api/v1/applications/portal/delete", "/api/v1/config/rollback"} {
		if w := securityCall(h, "POST", path, map[string]any{}, "", cookie); w.Code != 403 {
			t.Fatal(path, w.Code)
		}
	}
	if w := securityCall(h, "PUT", "/api/v1/config", c, "", cookie); w.Code != 403 {
		t.Fatal("scoped user reached raw PUT")
	}
	portalBefore, _ := json.Marshal(g.Config().Applications[1])
	c.Applications[0].Name = "Scoped operator change"
	w = securityCall(h, "POST", "/api/v1/config/apply", map[string]any{"config": c, "reason": "Tune assigned application"}, "", cookie)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	portalAfter, _ := json.Marshal(g.Config().Applications[1])
	if string(portalBefore) != string(portalAfter) || strings.Contains(w.Body.String(), "portal") {
		t.Fatal("unassigned application changed or leaked")
	}
	json.Unmarshal(w.Body.Bytes(), &c)
	c.Applications[0].Upstream = "http://127.0.0.1:1"
	if w := securityCall(h, "POST", "/api/v1/config/apply", map[string]any{"config": c, "reason": "Change shared routing"}, "", cookie); w.Code != 400 {
		t.Fatal("scoped routing change accepted", w.Code, w.Body)
	}
	applicationRequest(g, "shop.test", "/shop-only", "")
	applicationRequest(g, "portal.test", "/portal-only", "")
	if err := g.FlushEvents(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/v1/events", "/api/v1/events?application=portal", "/api/v1/events/search", "/api/v1/events/search?application=portal", "/api/v1/events/search?application=shop&application=portal"} {
		if w := securityCall(h, "GET", path, nil, "", cookie); w.Code != 403 {
			t.Fatal("cross-application query allowed", path, w.Code)
		}
	}
	w = securityCall(h, "GET", "/api/v1/events/search?application=shop", nil, "", cookie)
	if w.Code != 200 || strings.Contains(w.Body.String(), "portal") {
		t.Fatal("event isolation", w.Code, w.Body)
	}
	now := time.Now()
	_, token, err := g.accounts.CreateToken(g.accounts.List().Revision, "scoped", "shop reader", []string{"policy:read", "events:read"}, now.Add(time.Hour), now, "test", "Scoped automation")
	if err != nil {
		t.Fatal(err)
	}
	if w := securityCall(h, "GET", "/api/v1/config", nil, token, nil); w.Code != 200 || strings.Contains(w.Body.String(), "portal") {
		t.Fatal("token escaped owner assignment", w.Code, w.Body)
	}
	if w := securityCall(h, "GET", "/api/v1/events/search?application=portal", nil, token, nil); w.Code != 403 {
		t.Fatal("token queried other application")
	}
	global := g.Config()
	global.Applications = global.Applications[1:]
	if _, err := g.Apply(global, false); err == nil {
		t.Fatal("deleted application while its assignments were present")
	}
	if _, err := g.accounts.SaveAccess(g.accounts.List().Revision, "scoped", "operator", false, "", "test", "Remove assignment", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Apply(global, false); err == nil {
		t.Fatal("retained token assignment was ignored")
	}
	if _, err := g.accounts.RevokeToken(g.accounts.List().Revision, g.accounts.List().Tokens[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Apply(global, false); err != nil {
		t.Fatal("removed grants still pin application", err)
	}
}

func TestLegacyRoutingRefusesApplicationTokenBeforePublication(t *testing.T) {
	g, err := New(filepath.Join(t.TempDir(), "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close(context.Background())
	if _, err := g.accounts.Save(1, "admin", "administrator", false, "a legacy routing test password", "test", "Administrator fixture"); err != nil {
		t.Fatal(err)
	}
	root := strings.Repeat("l", 64)
	h := NewAdmin(g, root)
	w := securityCall(h, "POST", "/api/v1/tokens", map[string]any{"revision": g.accounts.List().Revision, "owner": "admin", "name": "legacy assignment", "scopes": []string{"policy:read"}, "lifetime_hours": 1, "reason": "Assignment attempt", "access": map[string]any{"application_ids": []string{g.Config().ApplicationID}}}, root, nil)
	if w.Code != 400 || len(g.accounts.List().Tokens) != 0 || g.accounts.List().Schema != 1 {
		t.Fatal("legacy token assignment was published", w.Code, w.Body)
	}
}

func TestScopedPolicyWriteRechecksRevokedRequestIdentity(t *testing.T) {
	for _, kind := range []string{"session", "automation"} {
		t.Run(kind, func(t *testing.T) {
			g, _ := applicationFixture(t)
			const password = "a long scoped concurrency password"
			if _, err := g.accounts.Save(1, "admin", "administrator", false, password, "test", "Fixture"); err != nil {
				t.Fatal(err)
			}
			d, err := g.accounts.SaveAccess(g.accounts.List().Revision, "scoped", "operator", false, password, "test", "Shop grant", &accounts.ApplicationAccess{IDs: []string{"shop"}})
			if err != nil {
				t.Fatal(err)
			}
			a := &Admin{gateway: g, sessions: map[[32]byte]session{}}
			r := httptest.NewRequest("POST", "/api/v1/config/apply", nil)
			if kind == "session" {
				cookie := &http.Cookie{Name: "openwaf_session", Value: "concurrency-test-session"}
				r.AddCookie(cookie)
				a.sessions[sha256.Sum256([]byte(cookie.Value))] = session{username: "scoped", version: d.Accounts[1].Version, expires: time.Now().Add(time.Hour)}
			} else {
				now := time.Now()
				_, token, err := g.accounts.CreateToken(g.accounts.List().Revision, "scoped", "writer", []string{"policy:write"}, now.Add(time.Hour), now, "test", "In-flight grant")
				if err != nil {
					t.Fatal(err)
				}
				r.Header.Set("Authorization", "Bearer "+token)
			}
			p, ok := a.identity(r)
			if !ok {
				t.Fatal("fixture identity failed")
			}
			r = r.WithContext(context.WithValue(r.Context(), principalContextKey{}, requestPrincipal{principal: p, valid: true}))
			requested := a.visibleConfig(r, g.Config())
			requested.Applications[0].Name = "Should never activate"
			if kind == "session" {
				if _, err := g.accounts.SaveAccess(g.accounts.List().Revision, "scoped", "operator", false, "", "test", "Reassign application", &accounts.ApplicationAccess{IDs: []string{"portal"}}); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := g.accounts.RevokeToken(g.accounts.List().Revision, g.accounts.List().Tokens[0].ID); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := a.applyVisibleConfig(r, requested, false, "Cached permission must be rechecked"); err == nil {
				t.Fatal("revoked cached identity changed policy")
			}
			if g.Config().Applications[0].Name == "Should never activate" {
				t.Fatal("revoked write reached activation")
			}
		})
	}
}
