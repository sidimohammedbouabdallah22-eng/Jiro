package accounts

import (
	"errors"
	"slices"
	"strings"
)

type OIDCBinding struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
}

func (s *Store) BindOIDC(revision uint64, username, issuer, subject, actor, reason string, remove bool) (Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if revision != s.document.Revision {
		return Document{}, errors.New("account revision changed; reload before saving")
	}
	if issuer == "" || len(issuer) > 2048 || strings.TrimSpace(subject) == "" || len(subject) > 255 || !ValidReason(reason) {
		return Document{}, errors.New("use an issuer, immutable subject and change reason")
	}
	for _, account := range s.document.Accounts {
		for _, binding := range account.OIDC {
			if binding.Issuer == issuer && binding.Subject == subject && account.Username != username {
				return Document{}, errors.New("OIDC subject is already bound to another account")
			}
		}
	}
	for i, account := range s.document.Accounts {
		if account.Username != username {
			continue
		}
		d := s.document
		d.Accounts = slices.Clone(d.Accounts)
		bindings := slices.Clone(account.OIDC)
		index := slices.IndexFunc(bindings, func(b OIDCBinding) bool { return b.Issuer == issuer && b.Subject == subject })
		if remove {
			if index < 0 {
				return Document{}, errors.New("OIDC binding is unavailable")
			}
			bindings = slices.Delete(bindings, index, index+1)
		} else {
			if index >= 0 {
				return Document{}, errors.New("OIDC subject is already bound")
			}
			if len(bindings) >= 2 {
				return Document{}, errors.New("account OIDC binding limit reached")
			}
			bindings = append(bindings, OIDCBinding{Issuer: issuer, Subject: subject})
		}
		d.Schema, d.Revision = 4, d.Revision+1
		d.Accounts[i].OIDC = bindings
		d.Accounts[i].Version = d.Revision
		d.Accounts[i].ChangedBy, d.Accounts[i].Reason = actor, reason
		return s.publish(d)
	}
	return Document{}, errors.New("local account is unavailable")
}

func (s *Store) OIDCAccount(issuer, subject string) (Account, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.uncertain {
		return Account{}, false
	}
	for _, account := range s.document.Accounts {
		if account.Disabled {
			continue
		}
		for _, binding := range account.OIDC {
			if binding.Issuer == issuer && binding.Subject == subject {
				return publicAccount(account), true
			}
		}
	}
	return Account{}, false
}

func ValidReason(reason string) bool { return strings.TrimSpace(reason) != "" && len(reason) <= 500 }
