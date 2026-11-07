package operations

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/accounts"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/gateway"
)

func TestControlsAndAccountsCheckpointCompatibility(t *testing.T) {
	ctx := context.Background()
	p := simpleState(t, false)
	before := filepath.Join(t.TempDir(), "before-controls")
	if _, err := Backup(ctx, BackupOptions{Paths: p, Destination: before}); err != nil {
		t.Fatal(err)
	}
	g, err := gateway.New(p.Policy)
	if err != nil {
		t.Fatal(err)
	}
	legacy := g.Config()
	app := gateway.ApplicationFromConfig(legacy, []string{"shop.test"})
	app.TrafficControls = &gateway.TrafficControls{RequestsPerSecond: 5, Burst: 10, MaxClientConcurrent: 2}
	c, err := g.Apply(gateway.Config{SchemaVersion: 2, Revision: legacy.Revision, Applications: []gateway.Application{app}}, false)
	if err != nil {
		g.Close(ctx)
		t.Fatal(err)
	}
	if _, err = g.Rollback(c.Revision, legacy.Revision, "test", "Keep traffic controls in committed history"); err != nil {
		g.Close(ctx)
		t.Fatal(err)
	}
	g.Close(ctx)
	s, err := accounts.Open(p.Policy + ".accounts.json")
	if err != nil {
		t.Fatal(err)
	}
	const password = "a long offline recovery test password"
	if _, err = s.Save(1, "admin", "administrator", false, password, "test", "Recovery fixture"); err != nil {
		t.Fatal(err)
	}
	checkpoint := filepath.Join(t.TempDir(), "checkpoint")
	manifest, err := Backup(ctx, BackupOptions{Paths: p, Destination: checkpoint})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Paths.Accounts == "" || manifest.State.Accounts == nil || !manifest.State.Policy.TrafficControls {
		t.Fatal("recovery set omitted identity or historical rate requirements")
	}
	old := CurrentCapabilities()
	old.TrafficControls = 0
	if err := supports(manifest.State, old); err == nil {
		t.Fatal("candidate without rate controls accepted rate-bearing history")
	}
	old = CurrentCapabilities()
	old.AccountsFormat = 0
	if err := supports(manifest.State, old); err == nil {
		t.Fatal("candidate without accounts accepted identity state")
	}
	destination := filepath.Join(t.TempDir(), "restored")
	if _, err := Restore(ctx, checkpoint, destination); err != nil {
		t.Fatal(err)
	}
	restored, err := accounts.Open(pathsUnder(destination, manifest.Paths).Accounts)
	if err != nil {
		t.Fatal(err)
	}
	if account, ok := restored.Verify("admin", password); !ok || account.Role != "administrator" {
		t.Fatal("restored credentials lost")
	}
	if candidate := os.Getenv("OPENWAF_RECOVERY_CANDIDATE"); candidate != "" {
		if report, err := UpgradeCheck(ctx, checkpoint, candidate); err != nil || !report.Compatible {
			t.Fatalf("candidate did not preserve accounts/rate history: %+v %v", report, err)
		}
	}
	if previous := os.Getenv("OPENWAF_CONTROLS_PREVIOUS"); previous != "" {
		if _, err := UpgradeCheck(ctx, checkpoint, previous); err == nil {
			t.Fatal("prior binary accepted accounts/rate history")
		}
		if report, err := UpgradeCheck(ctx, before, previous); err != nil || !report.Compatible {
			t.Fatalf("pre-controls checkpoint failed prior binary: %+v %v", report, err)
		}
	}
}
