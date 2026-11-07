package operations

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/adminaudit"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/eventcollector"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/eventstore"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/gateway"
)

func TestAuditExportCheckpointReplayAndDowngradeGuard(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	root := t.TempDir()
	token := strings.Repeat("e", 64)
	collector, err := eventcollector.Open(eventcollector.Options{Path: filepath.Join(root, "independent-audit.db"), Token: token})
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	server := httptest.NewServer(collector)
	defer server.Close()
	p := simpleState(t, false)
	options := gateway.Options{AuditExport: eventstore.ExportOptions{URL: server.URL + "/v1/events", Token: token}}
	g, err := gateway.NewWithOptions(p.Policy, options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.RecordAudit(adminaudit.Record{Operation: "qualification", Actor: "test", Outcome: "success"}); err != nil {
		t.Fatal(err)
	}
	if err := g.WaitAuditExport(ctx); err != nil {
		t.Fatal(err)
	}
	source := g.AuditExportStatus().SourceID
	g.Close(ctx)
	backup := filepath.Join(t.TempDir(), "checkpoint")
	manifest, err := Backup(ctx, BackupOptions{Paths: p, Destination: backup})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.State.Audit.ExportDestinationSHA256 == "" {
		t.Fatal("backup lost the audit export binding")
	}
	old := CurrentCapabilities()
	old.AuditExport = 0
	if err := supports(manifest.State, old); err == nil {
		t.Fatal("older candidate accepted bound audit export")
	}
	if candidate := os.Getenv("OPENWAF_RECOVERY_CANDIDATE"); candidate != "" {
		if report, err := UpgradeCheck(ctx, backup, candidate); err != nil || !report.Compatible {
			t.Fatalf("offline probe did not preserve paused audit export: %+v %v", report, err)
		}
	}
	destination := filepath.Join(t.TempDir(), "restored")
	if _, err = Restore(ctx, backup, destination); err != nil {
		t.Fatal(err)
	}
	restored, err := gateway.NewWithOptions(pathsUnder(destination, manifest.Paths).Policy, options)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close(ctx)
	if err := restored.WaitAuditExport(ctx); err != nil {
		t.Fatal(err)
	}
	if restored.AuditExportStatus().SourceID != source {
		t.Fatal("restore changed the audit receipt identity")
	}
	totals, err := collector.SourceTotals(ctx, source)
	if err != nil || totals.Records != manifest.State.Audit.Records {
		t.Fatal("checkpoint replay inflated or lost audit receipts", totals, err)
	}
}
