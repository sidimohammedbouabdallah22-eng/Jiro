package gateway

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/accounts"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/adminaudit"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/credentials"
	"golang.org/x/oauth2"
)

type OIDCConfig struct {
	Issuer           string `json:"issuer"`
	ClientID         string `json:"client_id"`
	ClientSecretFile string `json:"client_secret_file,omitempty"`
	RequiredACR      string `json:"required_acr,omitempty"`
}

type AuthenticationConfig struct {
	Origin      string      `json:"origin"`
	PasskeyRPID string      `json:"passkey_rp_id,omitempty"`
	OIDC        *OIDCConfig `json:"oidc,omitempty"`
	httpClient  *http.Client
}

func LoadAuthenticationConfig(path string) (AuthenticationConfig, error) {
	if path == "" {
		return AuthenticationConfig{}, nil
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return AuthenticationConfig{}, errors.New("authentication config must be a regular file at most 64 KiB")
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 64<<10 {
		return AuthenticationConfig{}, errors.New("authentication config unavailable or oversized")
	}
	var config AuthenticationConfig
	if err = strictDocument(data, &config); err != nil {
		return config, errors.New("invalid authentication configuration")
	}
	return config, nil
}

type authenticationRuntime struct {
	config   AuthenticationConfig
	client   *http.Client
	secret   string
	mu       sync.Mutex
	provider *oidc.Provider
	oauth    *oauth2.Config
	passkeys *webauthn.WebAuthn
}

type boundedAuthTransport struct{ base http.RoundTripper }

func (t boundedAuthTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(r)
	if resp != nil {
		resp.Body = http.MaxBytesReader(nil, resp.Body, 128<<10)
	}
	return resp, err
}

func secureOrLoopback(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.ForceQuery {
		return false
	}
	return u.Scheme == "https" || (u.Scheme == "http" && (u.Hostname() == "localhost" || net.ParseIP(u.Hostname()).IsLoopback()))
}

func newAuthenticationRuntime(config AuthenticationConfig) (*authenticationRuntime, error) {
	if config.Origin == "" && config.OIDC == nil && config.PasskeyRPID == "" {
		return nil, nil
	}
	u, err := url.Parse(config.Origin)
	if !secureOrLoopback(config.Origin) || err != nil || u.Path != "" {
		return nil, errors.New("authentication origin must be an exact HTTPS origin or explicit loopback HTTP origin")
	}
	if config.OIDC != nil && (!secureOrLoopback(config.OIDC.Issuer) || config.OIDC.ClientID == "" || len(config.OIDC.ClientID) > 255 || len(config.OIDC.RequiredACR) > 255) {
		return nil, errors.New("invalid OIDC issuer, client ID or assurance requirement")
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: boundedAuthTransport{base: http.DefaultTransport.(*http.Transport).Clone()}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("identity provider redirect refused") }}
	if config.httpClient != nil {
		client = config.httpClient
	}
	runtime := &authenticationRuntime{config: config, client: client}
	if config.OIDC != nil {
		runtime.secret, err = credentials.Value("OPENWAF_OIDC_CLIENT_SECRET", config.OIDC.ClientSecretFile)
		if err != nil {
			return nil, err
		}
	}
	if config.PasskeyRPID != "" {
		if config.PasskeyRPID != u.Hostname() || net.ParseIP(config.PasskeyRPID) != nil {
			return nil, errors.New("passkey RP ID must match the configured DNS hostname; use localhost for loopback")
		}
		runtime.passkeys, err = webauthn.New(&webauthn.Config{RPID: config.PasskeyRPID, RPOrigins: []string{config.Origin}, RPDisplayName: "OpenWAF", AttestationPreference: protocol.PreferNoAttestation, AuthenticatorSelection: protocol.AuthenticatorSelection{UserVerification: protocol.VerificationRequired, ResidentKey: protocol.ResidentKeyRequirementPreferred}})
		if err != nil {
			return nil, errors.New("invalid passkey relying-party configuration")
		}
	}
	return runtime, nil
}

func publicAuthenticationPath(path string) bool {
	return path == "/api/v1/login" || path == "/api/v1/auth/options" || path == "/api/v1/login/oidc" || path == "/api/v1/login/passkey/begin" || path == "/api/v1/login/passkey/finish"
}

func (a *Admin) authenticationOptions(w http.ResponseWriter, r *http.Request) {
	options := map[string]any{"oidc": false, "passkeys": false}
	if a.authentication != nil {
		options["origin"] = a.authentication.config.Origin
		options["oidc"] = a.authentication.config.OIDC != nil
		options["passkeys"] = a.authentication.config.PasskeyRPID != ""
	}
	reply(w, 200, options)
}

func (a *Admin) configuredOrigin(r *http.Request) bool {
	if a.authentication == nil {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme+"://"+r.Host == a.authentication.config.Origin
}

func randomAuthValue() (string, error) {
	data := make([]byte, 32)
	_, err := rand.Read(data)
	return hex.EncodeToString(data), err
}

type oidcTransaction struct {
	cookie   [32]byte
	nonce    string
	verifier string
	expires  time.Time
}

func (a *Admin) initializeOIDC(ctx context.Context) error {
	runtime := a.authentication
	if !runtime.mu.TryLock() {
		return errors.New("identity provider initialization in progress")
	}
	defer runtime.mu.Unlock()
	if runtime.provider != nil {
		return nil
	}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, runtime.client), runtime.config.OIDC.Issuer)
	if err != nil {
		return errors.New("identity provider discovery unavailable")
	}
	endpoint := provider.Endpoint()
	var metadata struct {
		Keys string `json:"jwks_uri"`
	}
	if provider.Claims(&metadata) != nil || !secureOrLoopback(metadata.Keys) || !secureOrLoopback(endpoint.AuthURL) || !secureOrLoopback(endpoint.TokenURL) {
		return errors.New("identity provider endpoints require HTTPS or literal loopback")
	}
	runtime.provider = provider
	runtime.oauth = &oauth2.Config{ClientID: runtime.config.OIDC.ClientID, ClientSecret: runtime.secret, RedirectURL: runtime.config.Origin + "/auth/oidc/callback", Endpoint: endpoint, Scopes: []string{oidc.ScopeOpenID}}
	return nil
}

func (a *Admin) beginOIDC(w http.ResponseWriter, r *http.Request) {
	if !a.configuredOrigin(r) || a.authentication.config.OIDC == nil {
		problem(w, 409, "OIDC is unavailable at this console origin")
		return
	}
	var empty struct{}
	if err := decode(w, r, &empty); err != nil {
		problem(w, 400, "Expected an empty JSON object")
		return
	}
	select {
	case a.externalSlots <- struct{}{}:
		defer func() { <-a.externalSlots }()
	default:
		problem(w, 429, "External authentication capacity exhausted")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := a.initializeOIDC(ctx); err != nil {
		problem(w, 503, err.Error())
		return
	}
	state, e1 := randomAuthValue()
	cookie, e2 := randomAuthValue()
	nonce, e3 := randomAuthValue()
	if e1 != nil || e2 != nil || e3 != nil {
		problem(w, 500, "Could not create authentication transaction")
		return
	}
	a.mu.Lock()
	for key, pending := range a.oidcPending {
		if time.Now().After(pending.expires) {
			delete(a.oidcPending, key)
		}
	}
	if len(a.oidcPending) >= 100 {
		a.mu.Unlock()
		problem(w, 429, "Authentication transaction limit reached")
		return
	}
	verifier := oauth2.GenerateVerifier()
	a.oidcPending[sha256.Sum256([]byte(state))] = oidcTransaction{cookie: sha256.Sum256([]byte(cookie)), nonce: nonce, verifier: verifier, expires: time.Now().Add(5 * time.Minute)}
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "openwaf_oidc", Value: cookie, Path: "/auth/oidc/callback", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode, MaxAge: 300})
	options := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce), oauth2.SetAuthURLParam("max_age", "0")}
	if acr := a.authentication.config.OIDC.RequiredACR; acr != "" {
		options = append(options, oauth2.SetAuthURLParam("acr_values", acr))
	}
	reply(w, 200, map[string]string{"url": a.authentication.oauth.AuthCodeURL(state, options...)})
}

func (a *Admin) finishOIDC(w http.ResponseWriter, r *http.Request) {
	if !a.configuredOrigin(r) || a.authentication.config.OIDC == nil {
		problem(w, 403, "Authentication origin is unavailable")
		return
	}
	q := r.URL.Query()
	if len(q["state"]) != 1 || len(q["code"]) != 1 || len(q.Get("state")) != 64 || len(q.Get("code")) > 4096 || q.Get("code") == "" {
		problem(w, 401, "Invalid authentication response")
		return
	}
	cookie, err := r.Cookie("openwaf_oidc")
	if err != nil {
		problem(w, 401, "Authentication transaction cookie missing")
		return
	}
	key := sha256.Sum256([]byte(q.Get("state")))
	cookieHash := sha256.Sum256([]byte(cookie.Value))
	a.mu.Lock()
	pending, ok := a.oidcPending[key]
	valid := ok && time.Now().Before(pending.expires) && subtle.ConstantTimeCompare(cookieHash[:], pending.cookie[:]) == 1
	if valid {
		delete(a.oidcPending, key)
	}
	a.mu.Unlock()
	if !valid {
		problem(w, 401, "Invalid or expired authentication transaction")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "openwaf_oidc", Path: "/auth/oidc/callback", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil})
	intent, err := a.gateway.RecordAudit(adminaudit.Record{Operation: "session.oidc", Actor: "unauthenticated", Outcome: "intent"})
	if err != nil {
		problem(w, 503, "Administration audit unavailable")
		return
	}
	outcome := "failed"
	actor := "unauthenticated"
	defer func() {
		_, _ = a.gateway.RecordAudit(adminaudit.Record{Operation: "session.oidc", Actor: actor, Outcome: outcome, Correlation: intent.Correlation})
	}()
	select {
	case a.externalSlots <- struct{}{}:
		defer func() { <-a.externalSlots }()
	default:
		problem(w, 429, "External authentication capacity exhausted")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	ctx = oidc.ClientContext(ctx, a.authentication.client)
	ctx = context.WithValue(ctx, oauth2.HTTPClient, a.authentication.client)
	if err := a.initializeOIDC(ctx); err != nil {
		problem(w, 503, err.Error())
		return
	}
	if values := q["iss"]; len(values) > 0 && (len(values) != 1 || values[0] != a.authentication.config.OIDC.Issuer) {
		problem(w, 401, "Issuer response mismatch")
		return
	}
	token, err := a.authentication.oauth.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(pending.verifier))
	if err != nil {
		problem(w, 401, "Identity provider exchange failed")
		return
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || len(raw) > 64<<10 {
		problem(w, 401, "Identity token unavailable")
		return
	}
	idToken, err := a.authentication.provider.Verifier(&oidc.Config{ClientID: a.authentication.config.OIDC.ClientID}).Verify(ctx, raw)
	if err != nil || idToken.Nonce != pending.nonce {
		problem(w, 401, "Identity token verification failed")
		return
	}
	if idToken.AccessTokenHash != "" && idToken.VerifyAccessToken(token.AccessToken) != nil {
		problem(w, 401, "Identity token binding failed")
		return
	}
	var claims struct {
		ACR             string `json:"acr"`
		AuthTime        int64  `json:"auth_time"`
		AuthorizedParty string `json:"azp"`
	}
	if err = idToken.Claims(&claims); err != nil || (claims.AuthorizedParty != "" && claims.AuthorizedParty != a.authentication.config.OIDC.ClientID) || (len(idToken.Audience) > 1 && claims.AuthorizedParty != a.authentication.config.OIDC.ClientID) {
		problem(w, 401, "Invalid identity claims")
		return
	}
	strong := false
	verifiedAt := time.Unix(claims.AuthTime, 0)
	if required := a.authentication.config.OIDC.RequiredACR; required != "" {
		if claims.ACR != required || claims.AuthTime == 0 || verifiedAt.Before(time.Now().Add(-5*time.Minute)) || verifiedAt.After(time.Now().Add(time.Minute)) {
			problem(w, 401, "Required identity assurance was not verified")
			return
		}
		strong = true
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
	account, ok := a.gateway.accounts.OIDCAccount(a.authentication.config.OIDC.Issuer, idToken.Subject)
	if !ok || (account.MFAEnabled && !strong) {
		problem(w, 401, "Identity is not authorized for this local account")
		return
	}
	p := principal{Username: account.Username, Role: account.Role, Version: account.Version}
	limit := time.Now().Add(15 * time.Minute)
	if idToken.Expiry.Before(limit) {
		limit = idToken.Expiry
	}
	actor = "account " + account.Username
	if !a.issueSession(w, r, p, strong, verifiedAt, "oidc", limit) {
		return
	}
	outcome = "success"
	http.Redirect(w, r, a.authentication.config.Origin+"/", http.StatusSeeOther)
}

func (a *Admin) bindOIDC(w http.ResponseWriter, r *http.Request) {
	if a.authentication == nil || a.authentication.config.OIDC == nil {
		problem(w, 409, "Configure an OIDC provider on the server first")
		return
	}
	var req struct {
		Revision uint64 `json:"revision"`
		Username string `json:"username"`
		Subject  string `json:"subject"`
		Remove   bool   `json:"remove"`
		Reason   string `json:"reason"`
	}
	if err := decode(w, r, &req); err != nil || !accounts.ValidReason(req.Reason) {
		problem(w, 400, "Use a local account, immutable subject and change reason")
		return
	}
	err := a.securityMutation(r, "account.oidc.bind", req.Username, func() error {
		_, err := a.gateway.accounts.BindOIDC(req.Revision, req.Username, a.authentication.config.OIDC.Issuer, req.Subject, a.actor(r), req.Reason, req.Remove)
		return err
	})
	if err != nil {
		accountProblem(w, err.Error())
		return
	}
	reply(w, 200, a.gateway.accounts.List())
}
