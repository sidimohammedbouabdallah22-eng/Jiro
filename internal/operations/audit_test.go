package operations

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestAuditCheckpointPreservationAndCompatibility(t *testing.T) {
	ctx := context.Background()
	paths := simpleState(t, false)
	checkpoint := filepath.Join(t.TempDir(), "checkpoint")
	manifest, err := Backup(ctx, BackupOptions{Paths: paths, Destination: checkpoint})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.State.Audit == nil || manifest.State.Audit.Records != 2 || manifest.Paths.Audit == "" {
		t.Fatal("default administration journal omitted")
	}
	caps := CurrentCapabilities()
	caps.AuditFormat = 0
	if supports(manifest.State, caps) == nil {
		t.Fatal("candidate without audit support accepted")
	}
	restored := filepath.Join(t.TempDir(), "restored")
	if _, err = Restore(ctx, checkpoint, restored); err != nil {
		t.Fatal(err)
	}
	p := pathsUnder(restored, manifest.Paths)
	if err = prepareProbe(restored, p); err != nil {
		t.Fatal(err)
	}
	report, err := Probe(ctx, p)
	if err != nil || report.After.Audit == nil || *report.After.Audit != *manifest.State.Audit {
		t.Fatalf("audit changed during rehearsal: %v", err)
	}
	if err = os.WriteFile(p.Audit, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Inspect(ctx, p, false); err == nil {
		t.Fatal("corrupt restored audit accepted")
	}
}
