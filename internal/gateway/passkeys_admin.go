package gateway

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/accounts"
)

type passkeyCeremony struct {
	user    accounts.PasskeyIdentity
	session webauthn.SessionData
	cookie  [32]byte
	purpose string
	expires time.Time
}

func (a *Admin) saveCeremony(w http.ResponseWriter, r *http.Request, user accounts.PasskeyIdentity, session *webauthn.SessionData, purpose string) (string, error) {
	id, err := randomAuthValue()
	if err != nil {
		return "", err
	}
	cookieValue := ""
	if purpose == "register" {
		cookie, err := r.Cookie("openwaf_session")
		if err != nil {
			return "", err
		}
		cookieValue = cookie.Value
	} else {
		cookieValue, err = randomAuthValue()
		if err != nil {
			return "", err
		}
		http.SetCookie(w, &http.Cookie{Name: "openwaf_passkey", Value: cookieValue, Path: "/api/v1/login/passkey", MaxAge: 120, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for key, pending := range a.passkeyPending {
		if time.Now().After(pending.expires) {
			delete(a.passkeyPending, key)
		}
	}
	if len(a.passkeyPending) >= 100 {
		return "", errors.New("passkey ceremony capacity exhausted")
	}
	a.passkeyPending[sha256.Sum256([]byte(id))] = passkeyCeremony{user: user, session: *session, cookie: sha256.Sum256([]byte(cookieValue)), purpose: purpose, expires: time.Now().Add(2 * time.Minute)}
	return id, nil
}

func (a *Admin) takeCeremony(r *http.Request, id, purpose string) (passkeyCeremony, bool) {
	if len(id) != 64 {
		return passkeyCeremony{}, false
	}
	name := "openwaf_session"
	if purpose == "login" {
		name = "openwaf_passkey"
	}
	cookie, err := r.Cookie(name)
	if err != nil {
		return passkeyCeremony{}, false
	}
	hash := sha256.Sum256([]byte(cookie.Value))
	key := sha256.Sum256([]byte(id))
	a.mu.Lock()
	defer a.mu.Unlock()
	pending, ok := a.passkeyPending[key]
	valid := ok && pending.purpose == purpose && time.Now().Before(pending.expires) && subtle.ConstantTimeCompare(hash[:], pending.cookie[:]) == 1
	if valid {
		delete(a.passkeyPending, key)
	}
	return pending, valid
}

func (a *Admin) passkeysAvailable(w http.ResponseWriter, r *http.Request) bool {
	if !a.configuredOrigin(r) || a.authentication.passkeys == nil {
		problem(w, 409, "Use the configured passkey console origin")
		return false
	}
	return true
}

func (a *Admin) beginPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	if !a.passkeysAvailable(w, r) {
		return
	}
	p, _ := a.identity(r)
	if p.Bootstrap {
		problem(w, 403, "Use a named account for passkeys")
		return
	}
	var req struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if err := decode(w, r, &req); err != nil || len(req.Password) > 256 || len(req.Code) > 6 {
		problem(w, 400, "Invalid credential confirmation")
		return
	}
	if a.credentialLimited() {
		problem(w, 429, "Too many credential checks")
		return
	}
	select {
	case a.passwordSlots <- struct{}{}:
		defer func() { <-a.passwordSlots }()
	default:
		problem(w, 429, "Authentication capacity exhausted")
		return
	}
	var user accounts.PasskeyIdentity
	err := a.securityMutation(r, "passkey.enrollment.begin", p.Username, func() error {
		if !(p.Strong && time.Since(p.VerifiedAt) < 2*time.Minute) {
			if p.PasskeyCount > 0 {
				return errors.New("sign in with a passkey again before changing passkeys")
			}
			account, err := a.gateway.accounts.Authenticate(p.Username, req.Password, req.Code, time.Now())
			if err != nil || account.Version != p.Version {
				a.failedCredential()
				return errors.New("credential confirmation failed")
			}
		}
		var err error
		user, err = a.gateway.accounts.PreparePasskeyUser(p.Username, p.Version, a.authentication.config.PasskeyRPID)
		return err
	})
	if err != nil {
		accountProblem(w, err.Error())
		return
	}
	exclusions := []protocol.CredentialDescriptor{}
	for _, credential := range user.Credentials {
		exclusions = append(exclusions, credential.Descriptor())
	}
	options, session, err := a.authentication.passkeys.BeginRegistration(user, webauthn.WithExclusions(exclusions))
	if err != nil {
		problem(w, 400, "Could not begin passkey enrollment")
		return
	}
	id, err := a.saveCeremony(w, r, user, session, "register")
	if err != nil {
		problem(w, 429, "Passkey ceremony capacity exhausted")
		return
	}
	reply(w, 200, map[string]any{"ceremony_id": id, "options": options})
}

func (a *Admin) finishPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	if !a.passkeysAvailable(w, r) {
		return
	}
	var req struct {
		ID       string          `json:"ceremony_id"`
		Name     string          `json:"name"`
		Response json.RawMessage `json:"response"`
	}
	if err := decode(w, r, &req); err != nil || strings.TrimSpace(req.Name) == "" || len(req.Name) > 80 {
		problem(w, 400, "Use a passkey name and registration response")
		return
	}
	p, _ := a.identity(r)
	pending, ok := a.takeCeremony(r, req.ID, "register")
	if !ok || pending.user.Username != p.Username || pending.user.Version != p.Version {
		problem(w, 401, "Invalid or expired passkey ceremony")
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(req.Response)
	if err != nil {
		problem(w, 400, "Invalid passkey response")
		return
	}
	select {
	case a.passwordSlots <- struct{}{}:
		defer func() { <-a.passwordSlots }()
	default:
		problem(w, 429, "Authentication capacity exhausted")
		return
	}
	credential, err := a.authentication.passkeys.CreateCredential(pending.user, pending.session, parsed)
	if err != nil || !credential.Flags.UserVerified {
		a.failedCredential()
		problem(w, 401, "Passkey enrollment verification failed")
		return
	}
	err = a.securityMutation(r, "passkey.enrollment.confirm", p.Username, func() error {
		_, err := a.gateway.accounts.AddPasskey(p.Username, p.Version, req.Name, *credential, a.actor(r), a.authentication.config.PasskeyRPID)
		return err
	})
	if err != nil {
		accountProblem(w, err.Error())
		return
	}
	reply(w, 200, map[string]bool{"ok": true})
}

func (a *Admin) beginPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	if !a.passkeysAvailable(w, r) {
		return
	}
	var req struct {
		Username string `json:"username"`
	}
	if err := decode(w, r, &req); err != nil || len(req.Username) > 64 {
		problem(w, 400, "Invalid username")
		return
	}
	if a.credentialLimited() {
		problem(w, 429, "Too many sign-in attempts")
		return
	}
	user, ok := a.gateway.accounts.PasskeyUser(req.Username, a.authentication.config.PasskeyRPID)
	if !ok || len(user.Credentials) == 0 {
		a.failedCredential()
		problem(w, 401, "Passkey sign-in is unavailable")
		return
	}
	options, session, err := a.authentication.passkeys.BeginLogin(user, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		problem(w, 400, "Could not begin passkey sign-in")
		return
	}
	id, err := a.saveCeremony(w, r, user, session, "login")
	if err != nil {
		problem(w, 429, "Passkey ceremony capacity exhausted")
		return
	}
	reply(w, 200, map[string]any{"ceremony_id": id, "options": options})
}

func (a *Admin) finishPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	if !a.passkeysAvailable(w, r) {
		return
	}
	var req struct {
		ID       string          `json:"ceremony_id"`
		Response json.RawMessage `json:"response"`
	}
	if err := decode(w, r, &req); err != nil {
		problem(w, 400, "Invalid passkey assertion")
		return
	}
	if a.credentialLimited() {
		problem(w, 429, "Too many sign-in attempts")
		return
	}
	pending, ok := a.takeCeremony(r, req.ID, "login")
	if !ok {
		problem(w, 401, "Invalid or expired passkey ceremony")
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(req.Response)
	if err != nil {
		problem(w, 400, "Invalid passkey assertion")
		return
	}
	select {
	case a.passwordSlots <- struct{}{}:
		defer func() { <-a.passwordSlots }()
	default:
		problem(w, 429, "Authentication capacity exhausted")
		return
	}
	credential, err := a.authentication.passkeys.ValidateLogin(pending.user, pending.session, parsed)
	if err != nil || credential.Authenticator.CloneWarning || !credential.Flags.UserVerified {
		a.failedCredential()
		problem(w, 401, "Passkey signature, origin or counter verification failed")
		return
	}
	var before webauthn.Credential
	for _, candidate := range pending.user.Credentials {
		if bytes.Equal(candidate.ID, credential.ID) {
			before = candidate
		}
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
	account, err := a.gateway.accounts.CommitPasskeyLogin(pending.user.Username, pending.user.Version, before, *credential)
	if err != nil {
		problem(w, 401, "Passkey account or counter changed; start a new sign-in")
		return
	}
	p := principal{Username: account.Username, Role: account.Role, Version: account.Version}
	if a.issueSession(w, r, p, true, time.Now(), "passkey", time.Time{}) {
		reply(w, 200, map[string]bool{"ok": true})
	}
}

func (a *Admin) listPasskeys(w http.ResponseWriter, r *http.Request) {
	p, _ := a.identity(r)
	if p.Bootstrap {
		problem(w, 403, "Use a named account")
		return
	}
	reply(w, 200, map[string]any{"items": a.gateway.accounts.PasskeyMetadata(p.Username)})
}

func (a *Admin) removePasskey(w http.ResponseWriter, r *http.Request) {
	p, _ := a.identity(r)
	if p.Bootstrap || !p.Strong || time.Since(p.VerifiedAt) > 2*time.Minute {
		problem(w, 403, "Sign in with a passkey or verified MFA again before revoking a passkey")
		return
	}
	var req struct {
		ID     string `json:"id"`
		Reason string `json:"reason"`
	}
	if err := decode(w, r, &req); err != nil || !accounts.ValidReason(req.Reason) {
		problem(w, 400, "A passkey ID and reason are required")
		return
	}
	err := a.securityMutation(r, "passkey.revoke", p.Username, func() error {
		_, err := a.gateway.accounts.RemovePasskey(p.Username, p.Version, req.ID, a.actor(r), false)
		return err
	})
	if err != nil {
		accountProblem(w, err.Error())
		return
	}
	reply(w, 200, map[string]bool{"ok": true})
}

func (a *Admin) recoverPasskeys(w http.ResponseWriter, r *http.Request) {
	p, _ := a.identity(r)
	if !p.Bootstrap {
		problem(w, 403, "Passkey recovery requires the bootstrap credential")
		return
	}
	var req struct {
		Username string `json:"username"`
		Revision uint64 `json:"revision"`
		Reason   string `json:"reason"`
	}
	if err := decode(w, r, &req); err != nil || !accounts.ValidReason(req.Reason) {
		problem(w, 400, "A username, revision and recovery reason are required")
		return
	}
	err := a.securityMutation(r, "passkey.recover", req.Username, func() error {
		d := a.gateway.accounts.List()
		if d.Revision != req.Revision {
			return errors.New("account revision changed; reload before saving")
		}
		for _, account := range d.Accounts {
			if account.Username == req.Username {
				_, err := a.gateway.accounts.RemovePasskey(account.Username, account.Version, "", a.actor(r), true)
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
