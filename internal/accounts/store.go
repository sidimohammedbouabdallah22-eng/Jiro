// Package accounts stores bounded local identities independently of policy rollback.
package accounts

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

const MaxBytes = 256 << 10
const LegacyMaxBytes = 64 << 10
const iterations = 600000

var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

type ApplicationAccess struct {
	IDs []string `json:"application_ids"`
}

type Account struct {
	WebAuthnID   []byte             `json:"webauthn_id,omitempty"`
	Passkeys     []Passkey          `json:"passkeys,omitempty"`
	PasskeyCount int                `json:"passkey_count,omitempty"`
	OIDC         []OIDCBinding      `json:"oidc,omitempty"`
	Access       *ApplicationAccess `json:"access,omitempty"`
	ChangedBy    string             `json:"changed_by,omitempty"`
	Reason       string             `json:"reason,omitempty"`
	Username     string             `json:"username"`
	Role         string             `json:"role"`
	Disabled     bool               `json:"disabled"`
	Version      uint64             `json:"version"`
	Salt         string             `json:"salt,omitempty"`
	Hash         string             `json:"hash,omitempty"`
	MFAEnabled   bool               `json:"mfa_enabled,omitempty"`
	MFASecret    string             `json:"mfa_secret,omitempty"`
	MFALastStep  int64              `json:"mfa_last_step,omitempty"`
}
type Document struct {
	RequireAdminMFA bool      `json:"require_admin_mfa,omitempty"`
	Schema          int       `json:"schema"`
	Revision        uint64    `json:"revision"`
	Accounts        []Account `json:"accounts"`
	Tokens          []Token   `json:"tokens,omitempty"`
}
type Metadata struct {
	Schema   int    `json:"schema"`
	Revision uint64 `json:"revision"`
	Count    int    `json:"count"`
	SHA256   string `json:"sha256"`
}
type Store struct {
	mu        sync.RWMutex
	path      string
	document  Document
	digest    string
	write     func(string, []byte) error
	uncertain bool
}

func validRole(role string) bool {
	return role == "administrator" || role == "operator" || role == "viewer"
}
func validate(d Document) error {
	if (d.Schema < 1 || d.Schema > 4) || d.Revision == 0 || len(d.Accounts) < 1 || len(d.Accounts) > 32 {
		return errors.New("invalid account store version or account count")
	}
	names := map[string]bool{}
	admins := 0
	for _, a := range d.Accounts {
		salt, se := hex.DecodeString(a.Salt)
		hash, he := hex.DecodeString(a.Hash)
		if !usernamePattern.MatchString(a.Username) || names[a.Username] || !validRole(a.Role) || a.Version == 0 || a.Version > d.Revision || se != nil || he != nil || len(salt) != 32 || len(hash) != 32 || len(a.ChangedBy) > 100 || len(a.Reason) > 500 {
			return errors.New("invalid account record")
		}
		names[a.Username] = true
		if a.Role == "administrator" && !a.Disabled {
			admins++
		}
	}
	if admins == 0 {
		return errors.New("at least one enabled administrator is required")
	}
	return validateSecurity(d)
}
func read(path string) (Document, string, error) {
	var d Document
	info, err := os.Lstat(path)
	if err != nil {
		return d, "", err
	}
	if !info.Mode().IsRegular() || info.Size() > MaxBytes {
		return d, "", errors.New("accounts must be a regular file at most 256 KiB")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return d, "", err
	}
	if len(data) > MaxBytes {
		return d, "", errors.New("account file exceeds limit")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&d); err != nil {
		return d, "", err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return d, "", errors.New("expected one accounts object")
	}
	if d.Schema < 4 && len(data) > LegacyMaxBytes {
		return d, "", errors.New("legacy account file exceeds 64 KiB")
	}
	if err = validate(d); err != nil {
		return d, "", err
	}
	sum := sha256.Sum256(data)
	return d, hex.EncodeToString(sum[:]), nil
}
func Inspect(path string) (Metadata, error) {
	d, sum, err := read(path)
	return Metadata{Schema: d.Schema, Revision: d.Revision, Count: len(d.Accounts), SHA256: sum}, err
}
func Open(path string) (*Store, error) {
	s := &Store{path: path, document: Document{Schema: 1, Revision: 1, Accounts: []Account{}}, write: writeAtomic}
	d, sum, err := read(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	s.document, s.digest = d, sum
	return s, nil
}
func writeAtomic(path string, data []byte) error {
	return writeAtomicWithPublish(path, data, publishDurable)
}

// The publish seam exercises real synced writes at process-crash boundaries.
func writeAtomicWithPublish(path string, data []byte, publish func(string, string) error) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".accounts-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return publish(f.Name(), path)
}
func (s *Store) List() Document {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return publicDocument(s.document)
}
func (s *Store) Current(username string, version uint64) (Account, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.uncertain {
		return Account{}, false
	}
	for _, a := range s.document.Accounts {
		if a.Username == username && a.Version == version && !a.Disabled {
			return publicAccount(a), true
		}
	}
	return Account{}, false
}
func (s *Store) Verify(username, password string) (Account, bool) {
	s.mu.RLock()
	var selected Account
	if s.uncertain {
		s.mu.RUnlock()
		return Account{}, false
	}
	for _, a := range s.document.Accounts {
		if a.Username == username {
			selected = a
			break
		}
	}
	s.mu.RUnlock()
	// Unknown and disabled names use the same fixed-cost derivation.
	salt, _ := hex.DecodeString(selected.Salt)
	hash, _ := hex.DecodeString(selected.Hash)
	if len(salt) != 32 {
		salt = make([]byte, 32)
	}
	if len(hash) != 32 {
		hash = make([]byte, 32)
	}
	derived, err := pbkdf2.Key(sha256.New, password, salt, iterations, 32)
	ok := err == nil && subtle.ConstantTimeCompare(derived, hash) == 1 && selected.Username != "" && !selected.Disabled
	return publicAccount(selected), ok
}
func (s *Store) Save(revision uint64, username, role string, disabled bool, password, actor, reason string) (Document, error) {
	return s.save(revision, username, role, disabled, password, actor, reason, nil, false)
}
func (s *Store) SaveAccess(revision uint64, username, role string, disabled bool, password, actor, reason string, access *ApplicationAccess) (Document, error) {
	return s.save(revision, username, role, disabled, password, actor, reason, access, true)
}
func (s *Store) save(revision uint64, username, role string, disabled bool, password, actor, reason string, access *ApplicationAccess, updateAccess bool) (Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if revision != s.document.Revision {
		return Document{}, errors.New("account revision changed; reload before saving")
	}
	if !usernamePattern.MatchString(username) || !validRole(role) || len(actor) > 100 || len(reason) > 500 || strings.TrimSpace(reason) == "" || (password != "" && (len(password) < 15 || len(password) > 256)) {
		return Document{}, errors.New("use a lowercase username, valid role and a 15..256 byte password")
	}
	if s.document.Revision == ^uint64(0) {
		return Document{}, errors.New("account revision exhausted")
	}
	d := s.document
	d.Accounts = append([]Account{}, d.Accounts...)
	d.Revision++
	index := -1
	for i, a := range d.Accounts {
		if a.Username == username {
			index = i
			break
		}
	}
	if index < 0 {
		if len(d.Accounts) >= 32 || password == "" {
			return Document{}, errors.New("new accounts require a password and an available account slot")
		}
		index = len(d.Accounts)
		d.Accounts = append(d.Accounts, Account{Username: username})
	}
	a := &d.Accounts[index]
	if updateAccess {
		a.Access = cloneAccess(access)
		if access != nil {
			d.Schema = max(d.Schema, 3)
		}
	}
	a.Role, a.Disabled, a.Version = role, disabled, d.Revision
	a.ChangedBy, a.Reason = actor, reason
	if password != "" {
		salt := make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return Document{}, err
		}
		hash, err := pbkdf2.Key(sha256.New, password, salt, iterations, 32)
		if err != nil {
			return Document{}, err
		}
		a.Salt = hex.EncodeToString(salt)
		a.Hash = hex.EncodeToString(hash)
	}
	if s.document.RequireAdminMFA && readyAdministrator(s.document) && !readyAdministrator(d) {
		return Document{}, errors.New("retain an enabled MFA-enrolled administrator")
	}
	return s.publish(d)
}
