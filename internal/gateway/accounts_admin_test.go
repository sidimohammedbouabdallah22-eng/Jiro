package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAccountRolesSessionRevocationAndPasswordChanges(t *testing.T) {
	g, _ := applicationFixture(t)
	token := strings.Repeat("t", 64)
	handler := NewAdmin(g, token)
	const password = "test password long enough for local accounts"
	call := func(method, path string, data any, cookie *http.Cookie, bootstrap bool) *httptest.ResponseRecorder {
		encoded, _ := json.Marshal(data)
		r := httptest.NewRequest(method, path, strings.NewReader(string(encoded)))
		r.Header.Set("Content-Type", "application/json")
		if bootstrap {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	for _, role := range []string{"administrator", "operator", "viewer"} {
		d := g.accounts.List()
		w := call("POST", "/api/v1/accounts", map[string]any{"revision": d.Revision, "username": role, "role": role, "password": password, "reason": "Create test role"}, nil, true)
		if w.Code != 200 {
			t.Fatalf("create %s: %d %s", role, w.Code, w.Body)
		}
	}
	login := func(username, password string) *http.Cookie {
		w := call("POST", "/api/v1/login", map[string]string{"username": username, "password": password}, nil, false)
		if w.Code != 200 {
			t.Fatalf("login %s: %d %s", username, w.Code, w.Body)
		}
		cookies := w.Result().Cookies()
		if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
			t.Fatal("unsafe session cookie")
		}
		return cookies[0]
	}
	viewer, operator := login("viewer", password), login("operator", password)
	for _, path := range []string{"/api/v1/config", "/api/v1/events", "/api/v1/health", "/api/v1/audit", "/api/v1/config/history/1"} {
		if w := call("GET", path, nil, viewer, false); w.Code != 200 {
			t.Fatalf("viewer read %s: %d", path, w.Code)
		}
	}
	for _, path := range []string{"/api/v1/config/apply", "/api/v1/config/rollback", "/api/v1/config/validate", "/api/v1/applications", "/api/v1/applications/shop/delete", "/api/v1/accounts", "/api/v1/certificates/reload"} {
		if w := call("POST", path, map[string]any{}, viewer, false); w.Code != 403 {
			t.Fatalf("viewer mutation %s: %d", path, w.Code)
		}
	}
	if w := call("PUT", "/api/v1/config", g.Config(), viewer, false); w.Code != 403 {
		t.Fatal("viewer used alternate config entry point")
	}
	for _, path := range []string{"/api/v1/accounts", "/api/v1/certificates/reload"} {
		if w := call("POST", path, map[string]any{}, operator, false); w.Code != 403 {
			t.Fatalf("operator elevated through %s: %d", path, w.Code)
		}
	}
	if w := call("GET", "/api/v1/accounts", nil, viewer, false); w.Code != 403 {
		t.Fatal("viewer listed account directory")
	}
	c := g.Config()
	c.Applications[0].Name = "Operator changed application"
	if w := call("POST", "/api/v1/config/apply", map[string]any{"config": c, "reason": "Operator policy change"}, operator, false); w.Code != 200 {
		t.Fatalf("operator cannot change policy: %d %s", w.Code, w.Body)
	}
	d := g.accounts.List()
	if w := call("POST", "/api/v1/accounts", map[string]any{"revision": d.Revision, "username": "operator", "role": "viewer", "reason": "Demote operator"}, nil, true); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if w := call("GET", "/api/v1/me", nil, operator, false); w.Code != 401 {
		t.Fatal("role change did not revoke old session")
	}
	newPassword := "a different long local password"
	if w := call("POST", "/api/v1/me/password", map[string]string{"current_password": password, "password": newPassword}, viewer, false); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if w := call("GET", "/api/v1/me", nil, viewer, false); w.Code != 401 {
		t.Fatal("password change did not revoke current session")
	}
	viewer = login("viewer", newPassword)
	if w := call("POST", "/api/v1/login", map[string]string{"username": "viewer", "password": password}, nil, false); w.Code != 401 {
		t.Fatal("old password still authenticated")
	}
	d = g.accounts.List()
	if w := call("POST", "/api/v1/accounts", map[string]any{"revision": d.Revision, "username": "viewer", "role": "viewer", "disabled": true, "reason": "Disable viewer"}, nil, true); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if w := call("GET", "/api/v1/me", nil, viewer, false); w.Code != 401 {
		t.Fatal("disabled account session survived")
	}
	entries, err := g.audit.Query(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range entries {
		if entry.Operation == "policy.activate" && entry.Actor == "account operator" && entry.Outcome == "success" {
			found = true
		}
	}
	if !found {
		t.Fatal("policy change did not attribute the individual account")
	}
	encoded, _ := json.Marshal(entries)
	if strings.Contains(string(encoded), password) || strings.Contains(string(encoded), newPassword) {
		t.Fatal("audit exposed passwords")
	}
}

func TestRoleMatrixDeniesUnknownCapabilities(t *testing.T) {
	for _, role := range []string{"viewer", "operator", "unknown"} {
		for _, method := range []string{"GET", "POST", "PUT", "DELETE"} {
			if roleAllows(role, method, "/api/v1/future-administrator-operation") {
				t.Fatal("role inherited an unspecified capability")
			}
		}
	}
}

func TestAccountActivationSerializesWithPolicyAndShutdown(t *testing.T) {
	g, _ := applicationFixture(t)
	token := strings.Repeat("x", 64)
	handler := NewAdmin(g, token)
	call := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/v1/accounts", strings.NewReader(`{"revision":1,"username":"admin","role":"administrator","disabled":false,"password":"a long administrator password","reason":"Test serialization"}`))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	g.update.Lock()
	w := call()
	g.update.Unlock()
	if w.Code != 409 || len(g.accounts.List().Accounts) != 0 {
		t.Fatalf("account activation bypassed policy/shutdown lock: %d %s", w.Code, w.Body)
	}
	g.Close(context.Background())
	if w = call(); w.Code != 503 || len(g.accounts.List().Accounts) != 0 {
		t.Fatalf("closed gateway accepted account mutation: %d", w.Code)
	}
}

func TestCredentialThrottleIncludesPasswordChanges(t *testing.T) {
	g, _ := applicationFixture(t)
	d, err := g.accounts.Save(1, "admin", "administrator", false, "a long correct administrator password", "test", "Bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	a := &Admin{gateway: g, passwordSlots: make(chan struct{}, 2)}
	p := principal{Username: "admin", Role: "administrator", Version: d.Accounts[0].Version}
	request := func() *http.Request {
		r := httptest.NewRequest("POST", "/api/v1/me/password", strings.NewReader(`{"current_password":"incorrect","password":"a replacement long password"}`))
		return r.WithContext(context.WithValue(r.Context(), principalContextKey{}, requestPrincipal{principal: p, valid: true}))
	}
	for i := 0; i < 10; i++ {
		w := httptest.NewRecorder()
		a.changePassword(w, request())
		if w.Code != 401 {
			t.Fatalf("failed password check %d: %d", i, w.Code)
		}
	}
	w := httptest.NewRecorder()
	a.changePassword(w, request())
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatal("password-change guesses bypassed throttle", w.Code)
	}
	w = httptest.NewRecorder()
	a.login(w, httptest.NewRequest("POST", "/api/v1/login", strings.NewReader(`{"token":"unused"}`)))
	if w.Code != 429 {
		t.Fatal("sign-in did not share the credential failure window", w.Code)
	}
	if len(a.passwordSlots) != 0 {
		t.Fatal("failed password checks leaked execution slots")
	}
}

func TestRequestPrincipalKeepsAuditIdentityDuringRevocation(t *testing.T) {
	g, _ := applicationFixture(t)
	a := &Admin{gateway: g}
	r := httptest.NewRequest("POST", "/api/v1/config/apply", nil)
	r = r.WithContext(context.WithValue(r.Context(), principalContextKey{}, requestPrincipal{principal: principal{Username: "operator", Role: "operator", Version: 2}, valid: true}))
	if a.actor(r) != "account operator" {
		t.Fatal("request attribution lost the authenticated account")
	}
	// A later request resolves afresh and has no valid session here.
	if _, ok := a.identity(httptest.NewRequest("GET", "/api/v1/me", nil)); ok {
		t.Fatal("request identity leaked into a later request")
	}
}
