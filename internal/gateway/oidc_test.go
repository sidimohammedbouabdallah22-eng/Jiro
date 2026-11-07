package gateway

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

func TestOIDCCodePKCEBindingClaimsAndLocalRevocation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var mutex sync.Mutex
	flows := map[string]url.Values{}
	mode := "valid"
	var issuer *httptest.Server
	issuer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{"issuer": issuer.URL, "authorization_endpoint": issuer.URL + "/authorize", "token_endpoint": issuer.URL + "/token", "jwks_uri": issuer.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/keys":
			json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "fixture", Algorithm: "RS256", Use: "sig"}}})
		case "/authorize":
			q := r.URL.Query()
			if q.Get("code_challenge_method") != "S256" {
				t.Error("PKCE S256 was not requested")
			}
			code := fmt.Sprint(time.Now().UnixNano())
			mutex.Lock()
			flows[code] = q
			mutex.Unlock()
			http.Redirect(w, r, q.Get("redirect_uri")+"?"+url.Values{"code": {code}, "state": {q.Get("state")}}.Encode(), 303)
		case "/token":
			r.ParseForm()
			mutex.Lock()
			q := flows[r.Form.Get("code")]
			delete(flows, r.Form.Get("code"))
			currentMode := mode
			mutex.Unlock()
			sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if q == nil || base64.RawURLEncoding.EncodeToString(sum[:]) != q.Get("code_challenge") {
				w.WriteHeader(400)
				io.WriteString(w, `{"error":"invalid_grant"}`)
				return
			}
			claims := map[string]any{"iss": issuer.URL, "sub": "subject-123", "aud": "fixture-client", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": q.Get("nonce"), "auth_time": time.Now().Unix(), "acr": "fixture-mfa"}
			switch currentMode {
			case "nonce":
				claims["nonce"] = "wrong"
			case "audience":
				claims["aud"] = "other-client"
			case "issuer":
				claims["iss"] = "https://other.invalid"
			case "expired":
				claims["exp"] = time.Now().Add(-time.Hour).Unix()
			case "assurance":
				claims["acr"] = "password-only"
			case "unmapped":
				claims["sub"] = "unmapped-subject"
			case "auth-time":
				claims["auth_time"] = time.Now().Add(-time.Hour).Unix()
			case "authorized-party":
				claims["azp"] = "another-client"
			}
			signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "fixture"))
			data, _ := json.Marshal(claims)
			signed, _ := signer.Sign(data)
			raw, _ := signed.CompactSerialize()
			json.NewEncoder(w).Encode(map[string]any{"access_token": "fixture-access", "token_type": "Bearer", "id_token": raw})
		default:
			http.NotFound(w, r)
		}
	}))
	defer issuer.Close()
	g, _ := applicationFixture(t)
	password := "a long federation fixture password"
	if _, err := g.accounts.Save(1, "admin", "administrator", false, password, "test", "Fixture administrator"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.accounts.BindOIDC(g.accounts.List().Revision, "admin", issuer.URL, "subject-123", "test", "Explicit issuer/subject grant", false); err != nil {
		t.Fatal(err)
	}
	if _, err := g.accounts.SetMFA("admin", g.accounts.List().Accounts[0].Version, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "287082", time.Unix(59, 0), "test", "Require local MFA"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.accounts.SetMFAPolicy(g.accounts.List().Revision, true); err != nil {
		t.Fatal(err)
	}
	front := httptest.NewUnstartedServer(nil)
	origin := "http://" + front.Listener.Addr().String()
	handler, err := NewAdminWithAuthentication(g, strings.Repeat("o", 64), AuthenticationConfig{Origin: origin, OIDC: &OIDCConfig{Issuer: issuer.URL, ClientID: "fixture-client", RequiredACR: "fixture-mfa"}})
	if err != nil {
		t.Fatal(err)
	}
	front.Config.Handler = handler
	front.Start()
	defer front.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	flow := func() (string, *http.Response) {
		resp, err := client.Post(origin+"/api/v1/login/oidc", "application/json", strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		var start map[string]string
		json.NewDecoder(resp.Body).Decode(&start)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatal("begin", resp.StatusCode, start)
		}
		auth, err := client.Get(start["url"])
		if err != nil {
			t.Fatal(err)
		}
		auth.Body.Close()
		callback := auth.Header.Get("Location")
		mutex.Lock()
		currentMode := mode
		mutex.Unlock()
		callbackClient := client
		if currentMode == "cookie" {
			callbackClient = &http.Client{CheckRedirect: client.CheckRedirect}
		}
		if currentMode == "state" {
			parsed, _ := url.Parse(callback)
			query := parsed.Query()
			query.Set("state", strings.Repeat("a", 64))
			parsed.RawQuery = query.Encode()
			callback = parsed.String()
		}
		result, err := callbackClient.Get(callback)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, result.Body)
		result.Body.Close()
		return callback, result
	}
	for _, bad := range []string{"nonce", "audience", "issuer", "expired", "assurance", "unmapped", "auth-time", "authorized-party", "cookie", "state"} {
		mutex.Lock()
		mode = bad
		mutex.Unlock()
		_, response := flow()
		if response.StatusCode != 401 {
			t.Fatalf("%s accepted with %d", bad, response.StatusCode)
		}
	}
	mutex.Lock()
	mode = "valid"
	mutex.Unlock()
	callback, response := flow()
	if response.StatusCode != 303 {
		t.Fatal("valid flow failed", response.StatusCode)
	}
	me, err := client.Get(origin + "/api/v1/me")
	if err != nil {
		t.Fatal(err)
	}
	var identity principal
	json.NewDecoder(me.Body).Decode(&identity)
	me.Body.Close()
	if me.StatusCode != 200 || identity.Username != "admin" || identity.Method != "oidc" || !identity.Strong {
		t.Fatal("invalid federated principal", me.StatusCode, identity)
	}
	replay, _ := client.Get(callback)
	replay.Body.Close()
	if replay.StatusCode != 401 {
		t.Fatal("callback replay accepted")
	}
	if _, err := g.accounts.BindOIDC(g.accounts.List().Revision, "admin", issuer.URL, "subject-123", "test", "Unlink IdP subject", true); err != nil {
		t.Fatal(err)
	}
	me, _ = client.Get(origin + "/api/v1/me")
	me.Body.Close()
	if me.StatusCode != 401 {
		t.Fatal("unlinked identity retained session")
	}
}
