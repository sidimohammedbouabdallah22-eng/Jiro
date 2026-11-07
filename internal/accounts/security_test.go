package accounts

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func securityFixture(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "accounts.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Save(1, "admin", "administrator", false, "a long security test password", "test", "Fixture administrator"); err != nil {
		t.Fatal(err)
	}
	return s, path
}

func TestAutomationExpiryRevocationOwnershipAndPublication(t *testing.T) {
	s, path := securityFixture(t)
	now := time.Now().UTC()
	token, secret, err := s.CreateToken(s.List().Revision, "admin", "monitor", []string{"monitoring:read"}, now.Add(time.Hour), now, "test", "Credential test")
	if err != nil {
		t.Fatal(err)
	}
	if token.Hash != "" || len(secret) != 102 {
		t.Fatal("unsafe issue response")
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), secret) {
		t.Fatal("persisted bearer secret")
	}
	if _, ok := s.VerifyToken(secret, now); !ok {
		t.Fatal("issued token rejected")
	}
	if _, ok := s.VerifyToken(secret, now.Add(time.Hour)); ok {
		t.Fatal("expired token accepted")
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.VerifyToken(secret, now); !ok {
		t.Fatal("token lost on reopen")
	}
	reopened.write = func(string, []byte) error { return errors.New("injected write failure") }
	if _, err := reopened.RevokeToken(reopened.List().Revision, token.ID); err == nil {
		t.Fatal("write failure concealed")
	}
	if _, ok := reopened.VerifyToken(secret, now); !ok {
		t.Fatal("failed revocation changed memory")
	}
	reopened.write = writeAtomic
	if _, err := reopened.RevokeToken(reopened.List().Revision, token.ID); err != nil {
		t.Fatal(err)
	}
	reopened, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.VerifyToken(secret, now); ok {
		t.Fatal("revoked token accepted")
	}
	_, secret, err = reopened.CreateToken(reopened.List().Revision, "admin", "deploy", []string{"policy:write"}, now.Add(time.Hour), now, "test", "Credential test")
	if err != nil {
		t.Fatal(err)
	}
	d := reopened.List()
	if _, err := reopened.Save(d.Revision, "admin", "administrator", false, "another long security password", "test", "Password rotation"); err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.VerifyToken(secret, now); ok {
		t.Fatal("owner password change retained token")
	}
	if _, _, err := reopened.CreateToken(reopened.List().Revision, "admin", "bad", []string{"accounts:write"}, now.Add(time.Hour), now, "test", "Credential test"); err == nil {
		t.Fatal("unknown scope accepted")
	}
	if _, err := reopened.Save(reopened.List().Revision, "viewer", "viewer", false, "a long security test password", "test", "Viewer owner"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reopened.CreateToken(reopened.List().Revision, "viewer", "bad", []string{"policy:write"}, now.Add(time.Hour), now, "test", "Credential test"); err == nil {
		t.Fatal("viewer delegated policy write")
	}
}

func TestTOTPRFC6238Vectors(t *testing.T) {
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	for _, test := range []struct {
		seconds int64
		want    string
	}{{59, "94287082"}, {1111111109, "07081804"}, {1111111111, "14050471"}, {1234567890, "89005924"}, {2000000000, "69279037"}, {20000000000, "65353130"}} {
		if got := totp(secret, test.seconds/30, 8); got != test.want {
			t.Fatalf("%d: %s want %s", test.seconds, got, test.want)
		}
	}
}

func TestMFAReplayConcurrencyDurabilityAndRedaction(t *testing.T) {
	s, path := securityFixture(t)
	now := time.Unix(1800000010, 0)
	secret, err := NewMFASecret()
	if err != nil {
		t.Fatal(err)
	}
	account := s.List().Accounts[0]
	d, err := s.SetMFA("admin", account.Version, secret, totp(secret, now.Unix()/30, 6), now, "test", "Enroll test authenticator")
	if err != nil {
		t.Fatal(err)
	}
	if d.Schema != 2 || !d.Accounts[0].MFAEnabled || d.Accounts[0].MFASecret != "" || d.Accounts[0].MFALastStep != 0 {
		t.Fatal("unsafe MFA metadata")
	}
	if _, ok := s.Current("admin", account.Version); ok {
		t.Fatal("enrollment retained old session")
	}
	if _, err := s.Authenticate("admin", "a long security test password", "", now); err == nil {
		t.Fatal("MFA bypassed")
	}
	if _, err := s.Authenticate("admin", "a long security test password", totp(secret, now.Unix()/30, 6), now); err == nil {
		t.Fatal("enrollment code replayed")
	}
	now = now.Add(30 * time.Second)
	code := totp(secret, now.Unix()/30, 6)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Go(func() { _, err := s.Authenticate("admin", "a long security test password", code, now); results <- err })
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("accepted %d copies of OTP", successes)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate("admin", "a long security test password", code, now); err == nil {
		t.Fatal("restart reset replay protection")
	}
	now = now.Add(30 * time.Second)
	s.write = func(string, []byte) error { return errors.New("injected write failure") }
	if _, err := s.Authenticate("admin", "a long security test password", totp(secret, now.Unix()/30, 6), now); err == nil {
		t.Fatal("session admitted before durable OTP publication")
	}
	s.write = writeAtomic
	if _, err := s.Authenticate("admin", "a long security test password", totp(secret, now.Unix()/30, 6), now); err != nil {
		t.Fatal(err)
	}
}

func TestUncertainCredentialPublicationRefusesAuthentication(t *testing.T) {
	s, _ := securityFixture(t)
	now := time.Now()
	token, secret, err := s.CreateToken(s.List().Revision, "admin", "monitor", []string{"monitoring:read"}, now.Add(time.Hour), now, "test", "Uncertain publication test")
	if err != nil {
		t.Fatal(err)
	}
	s.write = func(string, []byte) error { return errPublicationUncertain }
	if _, err := s.RevokeToken(s.List().Revision, token.ID); err == nil {
		t.Fatal("uncertain revocation acknowledged")
	}
	if _, ok := s.VerifyToken(secret, now); ok {
		t.Fatal("uncertain store accepted token")
	}
	if _, ok := s.Current("admin", s.List().Accounts[0].Version); ok {
		t.Fatal("uncertain store accepted session")
	}
	if _, err := s.Authenticate("admin", "a long security test password", "", now); err == nil {
		t.Fatal("uncertain store accepted login")
	}
}
