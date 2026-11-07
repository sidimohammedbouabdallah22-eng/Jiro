package accounts

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

type Passkey struct {
	RPID       string              `json:"rp_id"`
	Name       string              `json:"name"`
	Created    time.Time           `json:"created"`
	Credential webauthn.Credential `json:"credential"`
}

type PasskeyIdentity struct {
	Username    string
	Version     uint64
	Handle      []byte
	Credentials []webauthn.Credential
}

func (u PasskeyIdentity) WebAuthnID() []byte                         { return u.Handle }
func (u PasskeyIdentity) WebAuthnName() string                       { return u.Username }
func (u PasskeyIdentity) WebAuthnDisplayName() string                { return u.Username }
func (u PasskeyIdentity) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

func readyAccount(a Account) bool { return a.MFAEnabled || len(a.Passkeys) > 0 }

func validatePasskeys(d Document) error {
	ids, handles := map[string]bool{}, map[string]bool{}
	for _, a := range d.Accounts {
		if a.PasskeyCount != 0 || len(a.Passkeys) > 4 || (len(a.WebAuthnID) != 0 && len(a.WebAuthnID) != 32) || (len(a.Passkeys) > 0 && len(a.WebAuthnID) != 32) || ((len(a.WebAuthnID) > 0 || len(a.Passkeys) > 0) && d.Schema < 4) {
			return errors.New("invalid passkey count, handle or schema")
		}
		if len(a.WebAuthnID) > 0 {
			handle := string(a.WebAuthnID)
			if handles[handle] {
				return errors.New("duplicate passkey user handle")
			}
			handles[handle] = true
		}
		for _, key := range a.Passkeys {
			data, err := json.Marshal(key.Credential)
			id := string(key.Credential.ID)
			if key.RPID == "" || len(key.RPID) > 253 || err != nil || len(data) > 12<<10 || strings.TrimSpace(key.Name) == "" || len(key.Name) > 80 || key.Created.IsZero() || len(id) == 0 || len(id) > 1024 || ids[id] || len(key.Credential.PublicKey) == 0 || len(key.Credential.PublicKey) > 4096 || !key.Credential.Flags.UserVerified {
				return errors.New("invalid or duplicate passkey record")
			}
			ids[id] = true
		}
	}
	return nil
}

func identityFor(a Account, rpid string) PasskeyIdentity {
	u := PasskeyIdentity{Username: a.Username, Version: a.Version, Handle: slices.Clone(a.WebAuthnID)}
	for _, key := range a.Passkeys {
		if key.RPID != rpid {
			continue
		}
		u.Credentials = append(u.Credentials, cloneCredential(key.Credential))
	}
	return u
}

func cloneCredential(credential webauthn.Credential) webauthn.Credential {
	data, _ := json.Marshal(credential)
	var cloned webauthn.Credential
	json.Unmarshal(data, &cloned)
	return cloned
}

func (s *Store) PasskeyUser(username, rpid string) (PasskeyIdentity, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.uncertain {
		return PasskeyIdentity{}, false
	}
	for _, a := range s.document.Accounts {
		if a.Username == username && !a.Disabled {
			return identityFor(a, rpid), true
		}
	}
	return PasskeyIdentity{}, false
}

func (s *Store) PreparePasskeyUser(username string, version uint64, rpid string) (PasskeyIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, a := range s.document.Accounts {
		if a.Username != username || a.Version != version || a.Disabled {
			continue
		}
		if len(a.Passkeys) >= 4 {
			return PasskeyIdentity{}, errors.New("passkey limit reached")
		}
		if len(a.WebAuthnID) == 0 {
			d := s.document
			d.Schema, d.Revision = 4, d.Revision+1
			d.Accounts = slices.Clone(d.Accounts)
			handle := make([]byte, 32)
			if _, err := rand.Read(handle); err != nil {
				return PasskeyIdentity{}, err
			}
			d.Accounts[i].WebAuthnID = handle
			if _, err := s.publish(d); err != nil {
				return PasskeyIdentity{}, err
			}
			a = d.Accounts[i]
		}
		return identityFor(a, rpid), nil
	}
	return PasskeyIdentity{}, errors.New("account revision changed; sign in again")
}

func (s *Store) AddPasskey(username string, version uint64, name string, key webauthn.Credential, actor, rpid string) (Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, a := range s.document.Accounts {
		if a.Username != username || a.Version != version || a.Disabled {
			continue
		}
		d := s.document
		d.Schema, d.Revision = 4, d.Revision+1
		d.Accounts = slices.Clone(d.Accounts)
		d.Accounts[i].Passkeys = append(slices.Clone(a.Passkeys), Passkey{RPID: rpid, Name: name, Credential: cloneCredential(key), Created: time.Now().UTC()})
		d.Accounts[i].Version = d.Revision
		d.Accounts[i].ChangedBy, d.Accounts[i].Reason = actor, "Passkey enrollment confirmed"
		return s.publish(d)
	}
	return Document{}, errors.New("account revision changed; sign in again")
}

func (s *Store) CommitPasskeyLogin(username string, version uint64, before webauthn.Credential, after webauthn.Credential) (Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if after.Authenticator.CloneWarning || !after.Flags.UserVerified {
		return Account{}, errors.New("passkey verification rejected")
	}
	for i, a := range s.document.Accounts {
		if a.Username != username || a.Version != version || a.Disabled {
			continue
		}
		for j, key := range a.Passkeys {
			if !bytes.Equal(key.Credential.ID, after.ID) || !bytes.Equal(before.ID, after.ID) {
				continue
			}
			if key.Credential.Authenticator.SignCount != before.Authenticator.SignCount {
				return Account{}, errors.New("passkey counter changed; start a new sign-in")
			}
			d := s.document
			d.Revision++
			d.Accounts = slices.Clone(d.Accounts)
			d.Accounts[i].Passkeys = slices.Clone(a.Passkeys)
			d.Accounts[i].Passkeys[j].Credential = cloneCredential(after)
			if _, err := s.publish(d); err != nil {
				return Account{}, err
			}
			return publicAccount(d.Accounts[i]), nil
		}
	}
	return Account{}, errors.New("passkey account changed; sign in again")
}

func (s *Store) RemovePasskey(username string, version uint64, id, actor string, recovery bool) (Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, a := range s.document.Accounts {
		if a.Username != username || a.Version != version || a.Disabled {
			continue
		}
		d := s.document
		d.Revision++
		d.Accounts = slices.Clone(d.Accounts)
		d.Accounts[i].Passkeys = slices.Clone(a.Passkeys)
		if recovery {
			d.Accounts[i].Passkeys = nil
		} else {
			index := slices.IndexFunc(a.Passkeys, func(key Passkey) bool { return base64.RawURLEncoding.EncodeToString(key.Credential.ID) == id })
			if index < 0 {
				return Document{}, errors.New("passkey is unavailable")
			}
			d.Accounts[i].Passkeys = slices.Delete(d.Accounts[i].Passkeys, index, index+1)
		}
		if !recovery && d.RequireAdminMFA && readyAdministrator(s.document) && !readyAdministrator(d) {
			return Document{}, errors.New("retain an enabled administrator with a local authenticator")
		}
		d.Accounts[i].Version = d.Revision
		d.Accounts[i].ChangedBy, d.Accounts[i].Reason = actor, "Passkey revocation"
		return s.publish(d)
	}
	return Document{}, errors.New("account revision changed; sign in again")
}

func (s *Store) PasskeyMetadata(username string) []map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := []map[string]any{}
	for _, a := range s.document.Accounts {
		if a.Username == username {
			for _, key := range a.Passkeys {
				items = append(items, map[string]any{"id": base64.RawURLEncoding.EncodeToString(key.Credential.ID), "name": key.Name, "created": key.Created, "rp_id": key.RPID})
			}
		}
	}
	return items
}
