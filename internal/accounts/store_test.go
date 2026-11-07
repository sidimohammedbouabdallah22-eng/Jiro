package accounts

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAccountsDurabilityValidationAndSessionVersions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	password := "a long test password for admin"
	d, err := s.Save(1, "admin", "administrator", false, password, "test", "Bootstrap administrator")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(d.Accounts[0].Hash, password) || d.Accounts[0].Hash != "" || d.Accounts[0].Salt != "" {
		t.Fatal("public account data exposed a hash")
	}
	a, ok := s.Verify("admin", password)
	if !ok {
		t.Fatal("password verification failed")
	}
	if _, ok := s.Verify("admin", "incorrect"); ok {
		t.Fatal("incorrect password accepted")
	}
	if _, err = s.Save(d.Revision, "admin", "viewer", false, "", "test", "Demote last administrator"); err == nil {
		t.Fatal("last administrator demoted")
	}
	d, err = s.Save(d.Revision, "viewer", "viewer", false, password, "test", "Add viewer")
	if err != nil {
		t.Fatal(err)
	}
	viewer, ok := s.Verify("viewer", password)
	if !ok {
		t.Fatal("viewer did not authenticate")
	}
	d, err = s.Save(d.Revision, "viewer", "viewer", true, "", "test", "Disable viewer")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Current("viewer", viewer.Version); ok {
		t.Fatal("disabled account session survived")
	}
	if _, ok := s.Verify("viewer", password); ok {
		t.Fatal("disabled account authenticated")
	}
	if _, ok := s.Current("admin", a.Version); !ok {
		t.Fatal("unrelated account change revoked administrator")
	}
	restarted, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := restarted.Verify("admin", password); !ok {
		t.Fatal("account did not survive restart")
	}
	if _, err := s.Save(1, "other", "viewer", false, password, "test", "Stale update"); err == nil {
		t.Fatal("stale account write accepted")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), password) {
		t.Fatal("plaintext password persisted")
	}
}

func TestAccountFailedCommitKeepsPreviousIdentity(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.Save(1, "admin", "administrator", false, "a long administrator password", "test", "Bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	s.write = func(string, []byte) error { return errors.New("disk unavailable") }
	if _, err = s.Save(d.Revision, "admin", "administrator", false, "a different long password", "test", "Change password"); err == nil {
		t.Fatal("failed commit accepted")
	}
	if _, ok := s.Verify("admin", "a long administrator password"); !ok {
		t.Fatal("failed password change modified active identity")
	}
}

func TestOversizedEncodedAccountStoreCannotBePublished(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.Save(1, "admin", "administrator", false, "a long administrator password", "test", "Bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	// Valid field byte lengths can expand considerably when encoded as JSON.
	base := s.document.Accounts[0]
	for i := 0; i < 31; i++ {
		copy := base
		copy.Username = fmt.Sprintf("user%d", i)
		copy.Role = "viewer"
		copy.Reason = strings.Repeat("\x01", 500)
		s.document.Accounts = append(s.document.Accounts, copy)
	}
	if _, err := s.Save(d.Revision, "admin", "administrator", false, "", "test", "Try oversized document"); err == nil {
		t.Fatal("oversized account document committed")
	}
	if metadata, err := Inspect(s.path); err != nil || metadata.Count != 1 {
		t.Fatal("oversized write damaged prior accounts", err)
	}
}
