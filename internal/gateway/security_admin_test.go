package gateway

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func securityCall(handler http.Handler, method, path string, data any, bearer string, cookie *http.Cookie) *httptest.ResponseRecorder {
	encoded, _ := json.Marshal(data)
	r := httptest.NewRequest(method, path, strings.NewReader(string(encoded)))
	r.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func TestAutomationScopeBoundaryAndAPIRevocation(t *testing.T) {
	for _, test := range []struct {
		scope, method, path string
		allowed             bool
	}{
		{"monitoring:read", "GET", "/api/v1/metrics", true},
		{"monitoring:read", "GET", "/api/v1/config", false},
		{"events:read", "HEAD", "/api/v1/events/search", true},
		{"events:read", "GET", "/api/v1/audit", false},
		{"policy:read", "GET", "/api/v1/config/history/1", true},
		{"policy:read", "POST", "/api/v1/config/validate", false},
		{"policy:write", "PUT", "/api/v1/config", true},
		{"policy:write", "POST", "/api/v1/config/rollback", true},
		{"policy:write", "POST", "/api/v1/applications/shop/delete", true},
		{"policy:write", "GET", "/api/v1/accounts", false},
		{"policy:write", "POST", "/api/v1/tokens", false},
		{"policy:write", "POST", "/api/v1/me/password", false},
		{"policy:write", "POST", "/api/v1/me/mfa/setup", false},
		{"policy:write", "POST", "/api/v1/accounts/mfa-reset", false},
		{"certificates:reload", "POST", "/api/v1/certificates/reload", true},
		{"certificates:reload", "POST", "/api/v1/unknown", false},
	} {
		p := principal{Role: "automation", Automation: "test", Scopes: []string{test.scope}}
		if got := principalAllows(p, test.method, test.path); got != test.allowed {
			t.Errorf("%+v got %t", test, got)
		}
	}
	g, _ := applicationFixture(t)
	bootstrap := strings.Repeat("x", 64)
	h := NewAdmin(g, bootstrap)
	_, err := g.accounts.Save(1, "admin", "administrator", false, "a long security test password", "test", "Fixture")
	if err != nil {
		t.Fatal(err)
	}
	w := securityCall(h, "POST", "/api/v1/tokens", map[string]any{"revision": g.accounts.List().Revision, "owner": "admin", "name": "monitor", "scopes": []string{"monitoring:read"}, "lifetime_hours": 24, "reason": "Monitoring integration"}, bootstrap, nil)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body)
	}
	var issued struct {
		Secret string `json:"secret"`
		Token  struct {
			ID string `json:"id"`
		} `json:"token"`
	}
	json.Unmarshal(w.Body.Bytes(), &issued)
	for path, want := range map[string]int{"/api/v1/health": 200, "/api/v1/config": 403, "/api/v1/tokens": 403, "/api/v1/accounts": 403} {
		if got := securityCall(h, "GET", path, nil, issued.Secret, nil); got.Code != want {
			t.Fatalf("%s: %d %s", path, got.Code, got.Body)
		}
	}
	if w := securityCall(h, "GET", "/api/v1/tokens", nil, bootstrap, nil); strings.Contains(w.Body.String(), issued.Secret) || strings.Contains(w.Body.String(), "\"hash\"") {
		t.Fatal("list exposed credential")
	}
	if w := securityCall(h, "POST", "/api/v1/login", map[string]string{"token": issued.Secret}, "", nil); w.Code != 401 {
		t.Fatal("automation exchanged for full session", w.Code)
	}
	if w := securityCall(h, "POST", "/api/v1/tokens/"+issued.Token.ID+"/revoke", map[string]any{"revision": g.accounts.List().Revision, "reason": "Revoke integration"}, bootstrap, nil); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if w := securityCall(h, "GET", "/api/v1/health", nil, issued.Secret, nil); w.Code != 401 {
		t.Fatal("revoked bearer survived", w.Code)
	}
	items, err := g.audit.Query(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(items)
	if strings.Contains(string(encoded), issued.Secret) {
		t.Fatal("audit leaked bearer")
	}
}

func testAuthenticatorCode(secret string, step int64) string {
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[offset:offset+4])&0x7fffffff)%1000000)
}

// API handlers use the real clock. Reserve time for password verification before
// submitting a previous-window code so the fixture cannot cross two windows.
func waitForAuthenticatorWindow(t *testing.T) {
	t.Helper()
	now := time.Now()
	remaining := time.Until(now.Truncate(30 * time.Second).Add(30 * time.Second))
	if remaining < 5*time.Second {
		time.Sleep(remaining + 50*time.Millisecond)
	}
}

func TestMFASessionEnrollmentLoginDisableAndRecovery(t *testing.T) {
	g, _ := applicationFixture(t)
	bootstrap := strings.Repeat("r", 64)
	h := NewAdmin(g, bootstrap)
	const password = "a long security test password"
	if _, err := g.accounts.Save(1, "admin", "administrator", false, password, "test", "Fixture"); err != nil {
		t.Fatal(err)
	}
	login := func(code string) *httptest.ResponseRecorder {
		return securityCall(h, "POST", "/api/v1/login", map[string]string{"username": "admin", "password": password, "code": code}, "", nil)
	}
	w := login("")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	cookie := w.Result().Cookies()[0]
	w = securityCall(h, "POST", "/api/v1/me/mfa/setup", map[string]string{"password": password}, "", cookie)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	var enrollment struct {
		Secret string `json:"secret"`
	}
	json.Unmarshal(w.Body.Bytes(), &enrollment)
	// Confirm in the previous accepted window, leaving the current code for login.
	waitForAuthenticatorWindow(t)
	code := testAuthenticatorCode(enrollment.Secret, time.Now().Unix()/30-1)
	w = securityCall(h, "POST", "/api/v1/me/mfa/enable", map[string]string{"password": password, "code": code}, "", cookie)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if w := securityCall(h, "GET", "/api/v1/me", nil, "", cookie); w.Code != 401 {
		t.Fatal("enrollment retained old session")
	}
	if w := login(""); w.Code != 401 {
		t.Fatal("password bypassed MFA")
	}
	code = testAuthenticatorCode(enrollment.Secret, time.Now().Unix()/30)
	w = login(code)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	cookie = w.Result().Cookies()[0]
	if w := login(code); w.Code != 401 {
		t.Fatal("OTP replay created second session")
	}
	if w := securityCall(h, "POST", "/api/v1/accounts/mfa-reset", map[string]any{"revision": g.accounts.List().Revision, "username": "admin", "reason": "Recovery"}, "", cookie); w.Code != 403 {
		t.Fatal("ordinary admin session bypassed MFA recovery")
	}
	if w := securityCall(h, "GET", "/api/v1/accounts", nil, bootstrap, nil); strings.Contains(w.Body.String(), enrollment.Secret) {
		t.Fatal("account list exposed MFA secret")
	}
	code = testAuthenticatorCode(enrollment.Secret, time.Now().Unix()/30+1)
	w = securityCall(h, "POST", "/api/v1/me/mfa/disable", map[string]string{"password": password, "code": code}, "", cookie)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if w := securityCall(h, "GET", "/api/v1/me", nil, "", cookie); w.Code != 401 {
		t.Fatal("MFA disable retained old session")
	}
	if w := login(""); w.Code != 200 {
		t.Fatal("password login after explicit disable failed", w.Code, w.Body)
	}
	a := g.accounts.List().Accounts[0]
	if _, err := g.accounts.SetMFA(a.Username, a.Version, enrollment.Secret, testAuthenticatorCode(enrollment.Secret, time.Now().Unix()/30), time.Now(), "test", "Recovery fixture"); err != nil {
		t.Fatal(err)
	}
	w = securityCall(h, "POST", "/api/v1/accounts/mfa-reset", map[string]any{"revision": g.accounts.List().Revision, "username": "admin", "reason": "Lost authenticator recovery"}, bootstrap, nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if w := login(""); w.Code != 200 {
		t.Fatal("bootstrap recovery failed", w.Code, w.Body)
	}
}
