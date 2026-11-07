package accounts

import (
	"errors"
	"regexp"
	"slices"
)

var applicationIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func cloneAccess(access *ApplicationAccess) *ApplicationAccess {
	if access == nil {
		return nil
	}
	return &ApplicationAccess{IDs: slices.Clone(access.IDs)}
}

func validateAccess(access *ApplicationAccess) error {
	if access == nil {
		return nil
	}
	if len(access.IDs) < 1 || len(access.IDs) > 8 {
		return errors.New("select one through eight application IDs")
	}
	seen := map[string]bool{}
	for _, id := range access.IDs {
		if !applicationIDPattern.MatchString(id) || seen[id] {
			return errors.New("invalid or duplicate application assignment")
		}
		seen[id] = true
	}
	return nil
}

func accessSubset(child, parent *ApplicationAccess) bool {
	if parent == nil {
		return true
	}
	if child == nil {
		return false
	}
	for _, id := range child.IDs {
		if !slices.Contains(parent.IDs, id) {
			return false
		}
	}
	return true
}

func validateAuthorization(d Document) error {
	if d.RequireAdminMFA && d.Schema < 3 {
		return errors.New("MFA enforcement requires credential schema 3")
	}
	for _, a := range d.Accounts {
		if err := validateAccess(a.Access); err != nil {
			return err
		}
		if a.Access != nil && (d.Schema < 3 || a.Role == "administrator") {
			return errors.New("application assignments require schema 3 and a non-administrator role")
		}
	}
	for _, t := range d.Tokens {
		if err := validateAccess(t.Access); err != nil {
			return err
		}
		if t.Access != nil {
			if d.Schema < 3 {
				return errors.New("token application assignments require credential schema 3")
			}
			for _, scope := range t.Scopes {
				if !slices.Contains([]string{"policy:read", "policy:write", "events:read"}, scope) {
					return errors.New("application tokens support policy and event scopes")
				}
			}
		}
	}
	return nil
}

func readyAdministrator(d Document) bool {
	for _, a := range d.Accounts {
		if a.Role == "administrator" && !a.Disabled && readyAccount(a) {
			return true
		}
	}
	return false
}

func (s *Store) RequiresAdminMFA() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.document.RequireAdminMFA
}

func (s *Store) SetMFAPolicy(revision uint64, required bool) (Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if revision != s.document.Revision {
		return Document{}, errors.New("account revision changed; reload before saving")
	}
	if required && !readyAdministrator(s.document) {
		return Document{}, errors.New("enroll an enabled administrator before requiring MFA")
	}
	d := s.document
	d.Schema, d.Revision, d.RequireAdminMFA = max(d.Schema, 3), d.Revision+1, required
	return s.publish(d)
}

// References pin application IDs until an operator explicitly removes their grants.
func (s *Store) CheckApplications(schema int, ids []string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	check := func(access *ApplicationAccess) error {
		if access == nil {
			return nil
		}
		if schema != 2 {
			return errors.New("application access requires explicit schema-2 application routing")
		}
		for _, id := range access.IDs {
			if !slices.Contains(ids, id) {
				return errors.New("remove account and token assignments before removing an application")
			}
		}
		return nil
	}
	for _, a := range s.document.Accounts {
		if err := check(a.Access); err != nil {
			return err
		}
	}
	for _, t := range s.document.Tokens {
		if err := check(t.Access); err != nil {
			return err
		}
	}
	return nil
}

func ValidateAssignedIDs(access *ApplicationAccess, ids []string) error {
	if err := validateAccess(access); err != nil {
		return err
	}
	if access != nil {
		for _, id := range access.IDs {
			if !slices.Contains(ids, id) {
				return errors.New("assigned application is unavailable")
			}
		}
	}
	return nil
}
