package operations

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/gateway"
)

func TestApplicationCheckpointAndHistoricalDowngradeGuard(t *testing.T) {
	ctx := context.Background()
	p := simpleState(t, false)
	preMigration := filepath.Join(t.TempDir(), "before-migration")
	if _, err := Backup(ctx, BackupOptions{Paths: p, Destination: preMigration}); err != nil {
		t.Fatal(err)
	}
	g, err := gateway.New(p.Policy)
	if err != nil {
		t.Fatal(err)
	}
	legacy := g.Config()
	app := gateway.ApplicationFromConfig(legacy, []string{"shop.test"})
	second := gateway.ApplicationFromConfig(legacy, []string{"portal.test"})
	second.ApplicationID, second.Name = "portal", "Portal"
	second.Policy.Mode = "detection"
	c, err := g.Apply(gateway.Config{SchemaVersion: 2, Revision: legacy.Revision, Applications: []gateway.Application{app, second}}, false)
	if err != nil {
		g.Close(ctx)
		t.Fatal(err)
	}
	g.Close(ctx)
	checkpoint := filepath.Join(t.TempDir(), "applications")
	manifest, err := Backup(ctx, BackupOptions{Paths: p, Destination: checkpoint})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(manifest.State.Policy.PolicySchemas, []int{1, 2}) || len(manifest.State.Policy.ApplicationIDs) != 2 {
		t.Fatal("deployment requirements missing from checkpoint")
	}
	old := CurrentCapabilities()
	old.PolicySchemas = []int{1}
	if err := supports(manifest.State, old); err == nil {
		t.Fatal("schema-1 reader accepted deployment checkpoint")
	}
	if err := supports(manifest.State, CurrentCapabilities()); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "restored")
	if _, err := Restore(ctx, checkpoint, destination); err != nil {
		t.Fatal(err)
	}
	restoredPaths := pathsUnder(destination, manifest.Paths)
	restored, err := gateway.New(restoredPaths.Policy)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(restored.Config().Applications, c.Applications) {
		restored.Close(ctx)
		t.Fatal("restore changed application policies")
	}
	if _, err := restored.Rollback(c.Revision, legacy.Revision, "test", "Restore legacy policy explicitly"); err != nil {
		restored.Close(ctx)
		t.Fatal(err)
	}
	restored.Close(ctx)
	rolled, err := Inspect(ctx, restoredPaths, true)
	if err != nil {
		t.Fatal(err)
	}
	if rolled.Policy.Schema != 1 || !reflect.DeepEqual(rolled.Policy.PolicySchemas, []int{1, 2}) {
		t.Fatal("legacy rollback lost schema-2 history requirements")
	}
	if err := supports(rolled, old); err == nil {
		t.Fatal("schema-1 reader accepted incompatible committed ancestors")
	}
	before, err := Verify(ctx, preMigration)
	if err != nil {
		t.Fatal(err)
	}
	if err := supports(before.State, old); err != nil {
		t.Fatal("pre-migration checkpoint became incompatible", err)
	}
	if candidate := os.Getenv("OPENWAF_RECOVERY_CANDIDATE"); candidate != "" {
		report, err := UpgradeCheck(ctx, checkpoint, candidate)
		if err != nil || !report.Compatible {
			t.Fatalf("actual candidate rejected applications: %+v %v", report, err)
		}
	}
	if previous := os.Getenv("OPENWAF_APPLICATIONS_PREVIOUS"); previous != "" {
		if _, err := UpgradeCheck(ctx, checkpoint, previous); err == nil {
			t.Fatal("actual previous binary accepted schema 2")
		}
		if report, err := UpgradeCheck(ctx, preMigration, previous); err != nil || !report.Compatible {
			t.Fatalf("actual previous binary rejected pre-migration checkpoint: %+v %v", report, err)
		}
	}
}
