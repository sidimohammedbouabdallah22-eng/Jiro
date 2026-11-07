package operations

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/accounts"
)

func TestSecurityCredentialsBackupRestoreAndDowngradeGuards(t *testing.T) {
	ctx := context.Background()
	p := simpleState(t, false)
	s, err := accounts.Open(p.Policy + ".accounts.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Save(1, "admin", "administrator", false, "a long credential backup password", "test", "Backup fixture"); err != nil {
		t.Fatal(err)
	}
	const mfaSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	if _, err := s.SetMFA("admin", s.List().Accounts[0].Version, mfaSecret, "287082", time.Unix(59, 0), "test", "Backup authenticator fixture"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	_, secret, err := s.CreateToken(s.List().Revision, "admin", "monitor", []string{"monitoring:read"}, now.Add(time.Hour), now, "test", "Credential recovery fixture")
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := filepath.Join(t.TempDir(), "checkpoint")
	manifest, err := Backup(ctx, BackupOptions{Paths: p, Destination: checkpoint})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.State.Accounts == nil || manifest.State.Accounts.Schema != 2 {
		t.Fatal("backup omitted credential schema")
	}
	old := CurrentCapabilities()
	old.AccountSchemas = nil
	if err := supports(manifest.State, old); err == nil {
		t.Fatal("format-1 candidate accepted credential schema 2")
	}
	if err := supports(manifest.State, CurrentCapabilities()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeToken(s.List().Revision, s.List().Tokens[0].ID); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "restored")
	if _, err := Restore(ctx, checkpoint, destination); err != nil {
		t.Fatal(err)
	}
	restored, err := accounts.Open(pathsUnder(destination, manifest.Paths).Accounts)
	if err != nil {
		t.Fatal(err)
	}
	// Selecting an older credential checkpoint revives its then-valid token.
	if _, ok := restored.VerifyToken(secret, now); !ok {
		t.Fatal("checkpoint token was not preserved")
	}
	if !restored.List().Accounts[0].MFAEnabled {
		t.Fatal("checkpoint lost MFA requirement")
	}
	if _, err := restored.Authenticate("admin", "a long credential backup password", "287082", time.Unix(59, 0)); err == nil {
		t.Fatal("checkpoint lost accepted OTP watermark")
	}
	if candidate := os.Getenv("OPENWAF_RECOVERY_CANDIDATE"); candidate != "" {
		if report, err := UpgradeCheck(ctx, checkpoint, candidate); err != nil || !report.Compatible {
			t.Fatalf("current candidate: %+v %v", report, err)
		}
	}
	if previous := os.Getenv("OPENWAF_SECURITY_PREVIOUS"); previous != "" {
		if _, err := UpgradeCheck(ctx, checkpoint, previous); err == nil {
			t.Fatal("actual pre-MFA/token binary accepted new credential state")
		}
	}
}
