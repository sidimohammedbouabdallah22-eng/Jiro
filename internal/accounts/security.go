package accounts

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // RFC 6238 authenticator interoperability.
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"
)

type Token struct {
	Access       *ApplicationAccess `json:"access,omitempty"`
	CreatedBy    string             `json:"created_by"`
	Reason       string             `json:"reason"`
	ID           string             `json:"id"`
	Name         string             `json:"name"`
	Owner        string             `json:"owner"`
	OwnerVersion uint64             `json:"owner_version"`
	Scopes       []string           `json:"scopes"`
	Created      time.Time          `json:"created"`
	Expires      time.Time          `json:"expires"`
	Hash         string             `json:"hash,omitempty"`
}

var Scopes = []string{"monitoring:read", "events:read", "audit:read", "policy:read", "policy:write", "certificates:reload"}

var errPublicationUncertain = errors.New("credential publication durability is uncertain; restart required")

func ScopeAllowed(role, scope string) bool {
	if !slices.Contains(Scopes, scope) {
		return false
	}
	if role == "administrator" {
		return true
	}
	if scope == "certificates:reload" {
		return false
	}
	if scope == "policy:write" {
		return role == "operator"
	}
	return role == "operator" || role == "viewer"
}

func publicAccount(a Account) Account {
	a.PasskeyCount = len(a.Passkeys)
	a.Passkeys = nil
	a.WebAuthnID = nil
	a.Access = cloneAccess(a.Access)
	a.OIDC = slices.Clone(a.OIDC)
	a.Hash, a.Salt, a.MFASecret, a.MFALastStep = "", "", "", 0
	return a
}

func publicDocument(d Document) Document {
	d.Accounts = append([]Account{}, d.Accounts...)
	for i, a := range d.Accounts {
		d.Accounts[i] = publicAccount(a)
	}
	d.Tokens = slices.Clone(d.Tokens)
	for i := range d.Tokens {
		d.Tokens[i].Access = cloneAccess(d.Tokens[i].Access)
		d.Tokens[i].Hash = ""
		d.Tokens[i].Scopes = slices.Clone(d.Tokens[i].Scopes)
	}
	return d
}

func validateSecurity(d Document) error {
	if err := validatePasskeys(d); err != nil {
		return err
	}
	bindings := map[string]bool{}
	for _, account := range d.Accounts {
		if len(account.OIDC) > 2 || (len(account.OIDC) > 0 && d.Schema < 4) {
			return errors.New("invalid OIDC binding count or schema")
		}
		for _, binding := range account.OIDC {
			key := binding.Issuer + "\x00" + binding.Subject
			if binding.Issuer == "" || len(binding.Issuer) > 2048 || binding.Subject == "" || len(binding.Subject) > 255 || bindings[key] {
				return errors.New("invalid or duplicate OIDC subject binding")
			}
			bindings[key] = true
		}
	}

	if err := validateAuthorization(d); err != nil {
		return err
	}
	if len(d.Tokens) > 64 || (d.Schema == 1 && len(d.Tokens) != 0) {
		return errors.New("invalid automation token count or schema")
	}
	for _, a := range d.Accounts {
		key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(a.MFASecret)
		if a.MFAEnabled != (a.MFASecret != "") || (a.MFAEnabled && (d.Schema < 2 || err != nil || len(key) != 20)) || a.MFALastStep < 0 || (!a.MFAEnabled && a.MFALastStep != 0) {
			return errors.New("invalid authenticator state")
		}
	}
	ids := map[string]bool{}
	for _, t := range d.Tokens {
		id, ie := hex.DecodeString(t.ID)
		hash, he := hex.DecodeString(t.Hash)
		if len(t.CreatedBy) > 100 || len(t.Reason) > 500 || strings.TrimSpace(t.Reason) == "" || ie != nil || len(id) != 16 || he != nil || len(hash) != 32 || ids[t.ID] || !usernamePattern.MatchString(t.Owner) || t.OwnerVersion == 0 || t.OwnerVersion > d.Revision || len(strings.TrimSpace(t.Name)) == 0 || len(t.Name) > 80 || len(t.Scopes) < 1 || len(t.Scopes) > len(Scopes) || t.Created.IsZero() || !t.Expires.After(t.Created) || t.Expires.Sub(t.Created) > 90*24*time.Hour {
			return errors.New("invalid automation token record")
		}
		seen := map[string]bool{}
		for _, scope := range t.Scopes {
			if !slices.Contains(Scopes, scope) || seen[scope] {
				return errors.New("invalid automation scope")
			}
			seen[scope] = true
		}
		ids[t.ID] = true
	}
	return nil
}

// Caller holds the identity-store lock. Publication never changes in-memory state on failure.
func (s *Store) publish(d Document) (Document, error) {
	if s.uncertain {
		return Document{}, errPublicationUncertain
	}
	if d.Revision == 0 || s.document.Revision == ^uint64(0) {
		return Document{}, errors.New("account revision exhausted")
	}
	if err := validate(d); err != nil {
		return Document{}, err
	}
	_, digest, err := read(s.path)
	if (s.digest == "" && !errors.Is(err, os.ErrNotExist)) || (s.digest != "" && (err != nil || digest != s.digest)) {
		return Document{}, errors.New("account file changed outside OpenWAF")
	}
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return Document{}, err
	}
	data = append(data, '\n')
	limit := MaxBytes
	if d.Schema < 4 {
		limit = LegacyMaxBytes
	}
	if len(data) > limit {
		return Document{}, errors.New("account store exceeds its credential-format byte limit")
	}
	if err = s.write(s.path, data); err != nil {
		if errors.Is(err, errPublicationUncertain) {
			s.uncertain = true
		}
		return Document{}, err
	}
	sum := sha256.Sum256(data)
	s.document, s.digest = d, hex.EncodeToString(sum[:])
	return publicDocument(d), nil
}

func (s *Store) CreateToken(revision uint64, owner, name string, scopes []string, expires, now time.Time, actor, reason string) (Token, string, error) {
	return s.CreateScopedToken(revision, owner, name, scopes, expires, now, actor, reason, nil)
}
func (s *Store) CreateScopedToken(revision uint64, owner, name string, scopes []string, expires, now time.Time, actor, reason string, access *ApplicationAccess) (Token, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if revision != s.document.Revision {
		return Token{}, "", errors.New("account revision changed; reload before saving")
	}
	if len(s.document.Tokens) >= 64 || expires.Sub(now) < time.Hour || expires.Sub(now) > 90*24*time.Hour {
		return Token{}, "", errors.New("tokens require an available slot and expiry between one hour and 90 days")
	}
	var account Account
	for _, a := range s.document.Accounts {
		if a.Username == owner && !a.Disabled {
			account = a
		}
	}
	if account.Username == "" {
		return Token{}, "", errors.New("token owner must be an enabled local account")
	}
	if s.document.RequireAdminMFA && account.Role == "administrator" && !readyAccount(account) {
		return Token{}, "", errors.New("administrator owner must enroll MFA before using automation")
	}
	if access == nil {
		access = account.Access
	}
	if !accessSubset(access, account.Access) {
		return Token{}, "", errors.New("token applications exceed owner access")
	}
	for _, scope := range scopes {
		if !ScopeAllowed(account.Role, scope) {
			return Token{}, "", errors.New("scope exceeds owner permissions")
		}
	}
	id, secret := make([]byte, 16), make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return Token{}, "", err
	}
	if _, err := rand.Read(secret); err != nil {
		return Token{}, "", err
	}
	value := "owaf_" + hex.EncodeToString(id) + "." + hex.EncodeToString(secret)
	sum := sha256.Sum256([]byte(value))
	t := Token{Access: cloneAccess(access), CreatedBy: actor, Reason: reason, ID: hex.EncodeToString(id), Name: strings.TrimSpace(name), Owner: owner, OwnerVersion: account.Version, Scopes: slices.Clone(scopes), Created: now.UTC(), Expires: expires.UTC(), Hash: hex.EncodeToString(sum[:])}
	d := s.document
	d.Schema, d.Revision = max(d.Schema, 2), d.Revision+1
	if access != nil {
		d.Schema = max(d.Schema, 3)
	}
	d.Tokens = append(slices.Clone(d.Tokens), t)
	if _, err := s.publish(d); err != nil {
		return Token{}, "", err
	}
	t.Hash = ""
	t.Access = cloneAccess(t.Access)
	t.Scopes = slices.Clone(t.Scopes)
	return t, value, nil
}

func (s *Store) RevokeToken(revision uint64, id string) (Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if revision != s.document.Revision {
		return Document{}, errors.New("account revision changed; reload before saving")
	}
	d := s.document
	d.Tokens = slices.Clone(d.Tokens)
	index := slices.IndexFunc(d.Tokens, func(t Token) bool { return t.ID == id })
	if index < 0 {
		return Document{}, errors.New("automation token does not exist")
	}
	d.Tokens = slices.Delete(d.Tokens, index, index+1)
	d.Revision++
	return s.publish(d)
}

func (s *Store) VerifyToken(value string, now time.Time) (Token, bool) {
	if len(value) != 102 || !strings.HasPrefix(value, "owaf_") || value[37] != '.' {
		return Token{}, false
	}
	id := value[5:37]
	sum := sha256.Sum256([]byte(value))
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.uncertain {
		return Token{}, false
	}
	for _, t := range s.document.Tokens {
		if t.ID != id {
			continue
		}
		hash, _ := hex.DecodeString(t.Hash)
		if subtle.ConstantTimeCompare(sum[:], hash) != 1 || !now.Before(t.Expires) {
			return Token{}, false
		}
		for _, a := range s.document.Accounts {
			if a.Username == t.Owner && a.Version == t.OwnerVersion && !a.Disabled {
				if s.document.RequireAdminMFA && a.Role == "administrator" && !readyAccount(a) {
					return Token{}, false
				}
				if !accessSubset(t.Access, a.Access) {
					return Token{}, false
				}
				t.Access = cloneAccess(t.Access)
				for _, scope := range t.Scopes {
					if !ScopeAllowed(a.Role, scope) {
						return Token{}, false
					}
				}
				t.Hash, t.Scopes = "", slices.Clone(t.Scopes)
				return t, true
			}
		}
	}
	return Token{}, false
}

func NewMFASecret() (string, error) {
	key := make([]byte, 20)
	_, err := rand.Read(key)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key), err
}

func totp(secret string, step int64, digits int) string {
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 15
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	modulus := uint32(1000000)
	if digits == 8 {
		modulus = 100000000
	}
	return fmt.Sprintf("%0*d", digits, value%modulus)
}

func matchOTP(secret, code string, now time.Time, last int64) (int64, bool) {
	if len(code) != 6 {
		return 0, false
	}
	for _, ch := range code {
		if ch < '0' || ch > '9' {
			return 0, false
		}
	}
	step := now.Unix() / 30
	for _, candidate := range []int64{step, step - 1, step + 1} {
		if candidate > last && subtle.ConstantTimeCompare([]byte(totp(secret, candidate, 6)), []byte(code)) == 1 {
			return candidate, true
		}
	}
	return 0, false
}

// Authenticate consumes an accepted OTP durably before issuing any session.
func (s *Store) Authenticate(username, password, code string, now time.Time) (Account, error) {
	a, ok := s.Verify(username, password)
	if !ok {
		return Account{}, errors.New("invalid sign-in credentials")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.uncertain {
		return Account{}, errPublicationUncertain
	}
	for i, current := range s.document.Accounts {
		if current.Username != a.Username || current.Version != a.Version || current.Disabled {
			continue
		}
		if !current.MFAEnabled {
			return publicAccount(current), nil
		}
		step, ok := matchOTP(current.MFASecret, code, now, current.MFALastStep)
		if !ok {
			return Account{}, errors.New("invalid sign-in credentials")
		}
		d := s.document
		d.Accounts = slices.Clone(d.Accounts)
		d.Revision++
		d.Accounts[i].MFALastStep = step
		if _, err := s.publish(d); err != nil {
			return Account{}, err
		}
		return publicAccount(current), nil
	}
	return Account{}, errors.New("invalid sign-in credentials")
}

func (s *Store) SetMFA(username string, version uint64, secret, code string, now time.Time, actor, reason string) (Document, error) {
	return s.setMFA(username, version, secret, code, now, actor, reason, false)
}
func (s *Store) RecoverMFA(username string, version uint64, now time.Time, actor, reason string) (Document, error) {
	return s.setMFA(username, version, "", "", now, actor, reason, true)
}
func (s *Store) setMFA(username string, version uint64, secret, code string, now time.Time, actor, reason string, recovery bool) (Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, a := range s.document.Accounts {
		if a.Username != username || a.Version != version || a.Disabled {
			continue
		}
		if secret == "" && s.document.RequireAdminMFA && a.Role == "administrator" && len(a.Passkeys) == 0 && !recovery {
			return Document{}, errors.New("administrator MFA is required by deployment policy")
		}
		if a.MFAEnabled && secret != "" {
			return Document{}, errors.New("disable the existing authenticator before enrolling another")
		}
		step := int64(0)
		if secret != "" {
			var ok bool
			step, ok = matchOTP(secret, code, now, 0)
			if !ok {
				return Document{}, errors.New("invalid authenticator code")
			}
		}
		d := s.document
		d.Schema, d.Revision = max(d.Schema, 2), d.Revision+1
		d.Accounts = slices.Clone(d.Accounts)
		d.Accounts[i].MFASecret, d.Accounts[i].MFAEnabled, d.Accounts[i].MFALastStep = secret, secret != "", step
		d.Accounts[i].Version = d.Revision
		d.Accounts[i].ChangedBy, d.Accounts[i].Reason = actor, reason
		return s.publish(d)
	}
	return Document{}, errors.New("account revision changed; sign in again")
}
