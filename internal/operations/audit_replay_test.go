package operations

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/adminaudit"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/eventcollector"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/eventstore"
)

func TestReadOnlyAuditArchiveReplay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	root := t.TempDir()
	path := filepath.Join(root, "archive.jsonl")
	token := strings.Repeat("a", 64)
	j, err := adminaudit.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.Append(adminaudit.Record{Operation: "archived.activity", Actor: "test", Outcome: "success"}); err != nil {
		t.Fatal(err)
	}
	collector, err := eventcollector.Open(eventcollector.Options{Path: filepath.Join(root, "collector.db"), Token: token})
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	server := httptest.NewServer(collector)
	defer server.Close()
	options := eventstore.ExportOptions{URL: server.URL + "/v1/events", Token: token}
	if _, err := ReplayAudit(ctx, path, options); err == nil {
		t.Fatal("export bypassed the active journal lease")
	}
	j.Close()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(path, 0600)
	status, err := ReplayAudit(ctx, path, options)
	if err != nil || status.Acknowledged != 1 {
		t.Fatal("read-only replay failed", status, err)
	}
	if _, err := ReplayAudit(ctx, path, options); err != nil {
		t.Fatal("replay retry failed", err)
	}
	totals, err := collector.SourceTotals(ctx, status.SourceID)
	if err != nil || totals.Records != 1 {
		t.Fatal("archive replay inflated receipts", totals, err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("replay rewrote the original archive")
	}
	if admin := os.Getenv("OPENWAF_RECOVERY_ADMIN"); admin != "" {
		credential := filepath.Join(root, "collector-token")
		if err := os.WriteFile(credential, []byte(token), 0600); err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(ctx, admin, "audit-export", "-audit-file", path, "-export-url", options.URL, "-export-token-file", credential)
		command.Env = append(os.Environ(), "OPENWAF_AUDIT_EXPORT_TOKEN=")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("audit replay CLI failed: %s %v", output, err)
		} else if bytes.Contains(output, []byte(token)) {
			t.Fatal("replay CLI printed the credential")
		}
	}
}
