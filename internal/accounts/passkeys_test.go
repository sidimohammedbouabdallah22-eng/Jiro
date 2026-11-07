package accounts

import (
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

func TestPasskeyPublicationCounterAndRecovery(t *testing.T) {
	s, path := securityFixture(t)
	user, err := s.PreparePasskeyUser("admin", s.List().Accounts[0].Version, "localhost")
	if err != nil || len(user.Handle) != 32 {
		t.Fatal(user, err)
	}
	key := webauthn.Credential{ID: []byte("test-key"), PublicKey: []byte("test-public-key")}
	key.Flags.UserVerified = true
	if _, err := s.AddPasskey("admin", user.Version, "Test key", key, "test", "localhost"); err != nil {
		t.Fatal(err)
	}
	user, _ = s.PasskeyUser("admin", "localhost")
	user.Credentials[0].PublicKey[0] = 'X'
	user, _ = s.PasskeyUser("admin", "localhost")
	if string(user.Credentials[0].PublicKey) != "test-public-key" {
		t.Fatal("credential aliases store")
	}
	before := user.Credentials[0]
	after := cloneCredential(before)
	after.Authenticator.SignCount = 1
	write := s.write
	s.write = func(string, []byte) error { return errors.New("injected publication failure") }
	if _, err := s.CommitPasskeyLogin("admin", user.Version, before, after); err == nil {
		t.Fatal("accepted failed counter publication")
	}
	s.write = write
	if _, err := s.CommitPasskeyLogin("admin", user.Version, before, after); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitPasskeyLogin("admin", user.Version, before, after); err == nil {
		t.Fatal("accepted stale counter")
	}
	before = cloneCredential(after)
	after.Authenticator.CloneWarning = true
	if _, err := s.CommitPasskeyLogin("admin", user.Version, before, after); err == nil {
		t.Fatal("accepted clone warning")
	}
	if _, err := s.SetMFAPolicy(s.List().Revision, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RemovePasskey("admin", user.Version, base64.RawURLEncoding.EncodeToString(key.ID), "admin", false); err == nil {
		t.Fatal("removed last ready administrator")
	}
	if _, err := s.RemovePasskey("admin", user.Version, "", "bootstrap", true); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil || !reopened.RequiresAdminMFA() || reopened.List().Schema != 4 {
		t.Fatal("recovery weakened policy or schema", err)
	}
	if _, ok := reopened.Current("admin", user.Version); ok {
		t.Fatal("revoked account version remained usable")
	}
}

func TestFederatedSchemaSurvivesLegacyMutations(t *testing.T) {
	s, path := securityFixture(t)
	if _, err := s.Save(s.List().Revision, "backup", "administrator", false, "a second long administrator password", "test", "Retain administrator"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BindOIDC(s.List().Revision, "admin", "https://issuer.test", "subject", "test", "Bind identity", false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveAccess(s.List().Revision, "admin", "operator", false, "", "test", "Assign application", &ApplicationAccess{IDs: []string{"shop"}}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, _, err := s.CreateScopedToken(s.List().Revision, "admin", "reader", []string{"policy:read"}, now.Add(time.Hour), now, "test", "Assign token", &ApplicationAccess{IDs: []string{"shop"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetMFAPolicy(s.List().Revision, false); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil || reopened.List().Schema != 4 {
		t.Fatal("schema downgraded", err)
	}
	if _, ok := reopened.OIDCAccount("https://issuer.test", "subject"); !ok {
		t.Fatal("binding lost")
	}
	if _, err := reopened.Save(reopened.List().Revision, "other", "viewer", false, "another long test password", "test", "Second account"); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.BindOIDC(reopened.List().Revision, "other", "https://issuer.test", "subject", "test", "Duplicate identity", false); err == nil {
		t.Fatal("duplicate binding accepted")
	}
}
