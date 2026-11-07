package operations

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/accounts"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/gateway"
)

func TestRequiredMFAAndApplicationAssignmentsSurviveRecovery(t *testing.T) {
	ctx := context.Background()
	p := simpleState(t, false)
	g, err := gateway.New(p.Policy)
	if err != nil {
		t.Fatal(err)
	}
	c := g.Config()
	app := gateway.ApplicationFromConfig(c, []string{"application.test"})
	_, err = g.Apply(gateway.Config{SchemaVersion: 2, Revision: c.Revision, Applications: []gateway.Application{app}}, false)
	g.Close(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s, err := accounts.Open(p.Policy + ".accounts.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Save(1, "admin", "administrator", false, "a long enforcement recovery password", "test", "Fixture"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetMFA("admin", s.List().Accounts[0].Version, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "287082", time.Unix(59, 0), "test", "Enroll"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetMFAPolicy(s.List().Revision, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveAccess(s.List().Revision, "operator", "operator", false, "a long assigned operator password", "test", "Assignment", &accounts.ApplicationAccess{IDs: []string{app.ApplicationID}}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	_, token, err := s.CreateToken(s.List().Revision, "operator", "assigned", []string{"policy:read"}, now.Add(time.Hour), now, "test", "Recovery fixture")
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := filepath.Join(t.TempDir(), "checkpoint")
	manifest, err := Backup(ctx, BackupOptions{Paths: p, Destination: checkpoint})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.State.Accounts.Schema != 3 {
		t.Fatal("credential schema was not retained")
	}
	old := CurrentCapabilities()
	old.AccountSchemas = []int{1, 2}
	if err := supports(manifest.State, old); err == nil {
		t.Fatal("schema-2 candidate accepted enforcement and ACL state")
	}
	if previous := os.Getenv("OPENWAF_AUTHORIZATION_PREVIOUS"); previous != "" {
		if _, err := UpgradeCheck(ctx, checkpoint, previous); err == nil {
			t.Fatal("actual pre-enforcement executable accepted schema 3")
		}
	}
	if candidate := os.Getenv("OPENWAF_RECOVERY_CANDIDATE"); candidate != "" {
		if _, err := UpgradeCheck(ctx, checkpoint, candidate); err != nil {
			t.Fatal(err)
		}
	}
	destination := filepath.Join(t.TempDir(), "restored")
	if _, err := Restore(ctx, checkpoint, destination); err != nil {
		t.Fatal(err)
	}
	restored, err := accounts.Open(pathsUnder(destination, manifest.Paths).Accounts)
	if err != nil {
		t.Fatal(err)
	}
	verified, ok := restored.VerifyToken(token, now)
	if !restored.RequiresAdminMFA() || !ok || verified.Access == nil || verified.Access.IDs[0] != app.ApplicationID {
		t.Fatal("restoration changed enforcement or application grants")
	}
}
