package operations

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/eventcollector"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/eventstore"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/gateway"
)

func simpleState(t *testing.T, legacy bool) Paths {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "policy.json")
	g, err := gateway.NewWithOptions(path, gateway.Options{DisableEventStore: legacy})
	if err != nil {
		t.Fatal(err)
	}
	c := g.Config()
	c.Name = "Recovery fixture"
	if _, err = g.Apply(c, false); err != nil {
		t.Fatal(err)
	}
	g.Close(context.Background())
	paths := Paths{Policy: path, Events: path + ".events.db"}
	if legacy {
		db, e := sql.Open("sqlite", paths.Events)
		if e != nil {
			t.Fatal(e)
		}
		_, e = db.Exec(`PRAGMA journal_mode=DELETE; CREATE TABLE events(seq INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT NOT NULL UNIQUE,time_ns INTEGER NOT NULL,action TEXT NOT NULL,ip TEXT NOT NULL,path TEXT NOT NULL,size INTEGER NOT NULL,data BLOB NOT NULL); CREATE INDEX events_time ON events(time_ns); CREATE INDEX events_action ON events(action,seq); PRAGMA user_version=1;`)
		if e != nil {
			db.Close()
			t.Fatal(e)
		}
		for i := 0; i < 8; i++ {
			encoded, _ := json.Marshal(map[string]any{"id": fmt.Sprintf("legacy-%d", i), "time": time.Now().UTC(), "action": "blocked", "status": 403, "method": "GET", "path": "/", "ip": "192.0.2.1", "policy_revision": 2, "application_id": "primary", "matches": []any{}})
			data := string(encoded)
			if _, e = db.Exec("INSERT INTO events(id,time_ns,action,ip,path,size,data) VALUES(?,?,?,?,?,?,?)", fmt.Sprintf("legacy-%d", i), time.Now().UnixNano(), "blocked", "192.0.2.1", "/", len(data)+256, []byte(data)); e != nil {
				db.Close()
				t.Fatal(e)
			}
		}
		db.Close()
	}
	return paths
}
func TestBackupRestoreVerificationAndNoOverwrite(t *testing.T) {
	ctx := context.Background()
	paths := simpleState(t, false)
	orphan := filepath.Join(paths.Policy+".history", "00000000000000000099.json")
	if err := os.WriteFile(orphan, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(t.TempDir(), "private-token")
	if err := os.WriteFile(token, []byte(strings.Repeat("s", 64)), 0600); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(t.TempDir(), "snapshot")
	manifest, err := Backup(ctx, BackupOptions{Paths: paths, Destination: backup, Credential: token})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.State.Policy.Orphans != 1 || manifest.Credential == "" {
		t.Fatal("recovery metadata missing")
	}
	if _, err = Verify(ctx, backup); err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(t.TempDir(), "restored")
	if _, err = Restore(ctx, backup, restored); err != nil {
		t.Fatal(err)
	}
	if _, err = Restore(ctx, backup, restored); err == nil {
		t.Fatal("existing destination was overwritten")
	}
	restoredPaths := pathsUnder(restored, manifest.Paths)
	g, err := gateway.NewWithOptions(restoredPaths.Policy, gateway.Options{EventStore: eventstore.Options{Path: restoredPaths.Events}})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close(ctx)
	c := g.Config()
	c.Name = "After restore"
	c, err = g.Apply(c, false)
	if err != nil || c.Revision != 100 {
		t.Fatalf("orphan reservation lost: %d %v", c.Revision, err)
	}
	if _, err = Verify(ctx, backup); err != nil {
		t.Fatal("using restored state changed backup", err)
	}
}
func TestLiveLeasesAndTamperingAreRefused(t *testing.T) {
	ctx := context.Background()
	p := simpleState(t, false)
	g, err := gateway.NewWithOptions(p.Policy, gateway.Options{EventStore: eventstore.Options{Path: p.Events}})
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "live-backup")
	if _, err = Backup(ctx, BackupOptions{Paths: p, Destination: out}); err == nil {
		g.Close(ctx)
		t.Fatal("live policy was backed up")
	}
	g.Close(ctx)
	s, err := eventstore.Open(eventstore.Options{Path: p.Events})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Backup(ctx, BackupOptions{Paths: p, Destination: out}); err == nil {
		s.Close(ctx)
		t.Fatal("live sender database was backed up")
	}
	s.Close(ctx)
	if _, err = Backup(ctx, BackupOptions{Paths: p, Destination: out}); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(out, "state/policy.json")
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(file, append(data, ' '), 0600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "must-not-exist")
	if _, err = Restore(ctx, out, destination); err == nil {
		t.Fatal("tampered backup restored")
	}
	if _, err = os.Stat(destination); !os.IsNotExist(err) {
		t.Fatal("failed restore published a destination")
	}
}
func TestUnsafeMembersAndInterruptedCopyAreRefused(t *testing.T) {
	ctx := context.Background()
	p := simpleState(t, false)
	backup := filepath.Join(t.TempDir(), "snapshot")
	if _, err := Backup(ctx, BackupOptions{Paths: p, Destination: backup}); err != nil {
		t.Fatal(err)
	}
	extra := filepath.Join(backup, "extra.txt")
	os.WriteFile(extra, []byte("unlisted"), 0600)
	if _, err := Verify(ctx, backup); err == nil {
		t.Fatal("unlisted file accepted")
	}
	os.Remove(extra)
	data, err := os.ReadFile(filepath.Join(backup, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err = json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	m.Files[0].Path = "../escape"
	data, _ = json.Marshal(m)
	os.WriteFile(filepath.Join(backup, "manifest.json"), data, 0600)
	if _, err = Verify(ctx, backup); err == nil {
		t.Fatal("traversal member accepted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	out := filepath.Join(t.TempDir(), "interrupted")
	if _, err = Backup(cancelled, BackupOptions{Paths: p, Destination: out}); err == nil {
		t.Fatal("cancelled backup published")
	}
	if _, err = os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("partial backup published")
	}
}

type profileRunner struct {
	legacy bool
	called *bool
}

func (p profileRunner) capabilities(context.Context) (Capabilities, error) {
	c := CurrentCapabilities()
	if p.legacy {
		c.SenderMax = 1
	}
	return c, nil
}
func (p profileRunner) probe(ctx context.Context, paths Paths) error {
	if p.called != nil {
		*p.called = true
	}
	if p.legacy {
		_, err := Inspect(ctx, paths, true)
		return err
	}
	_, err := Probe(ctx, paths)
	return err
}
func TestSchemaUpgradeAndBackupBasedRollback(t *testing.T) {
	ctx := context.Background()
	paths := simpleState(t, true)
	backup := filepath.Join(t.TempDir(), "v1-checkpoint")
	m, err := Backup(ctx, BackupOptions{Paths: paths, Destination: backup})
	if err != nil {
		t.Fatal(err)
	}
	report, err := checkWith(ctx, backup, profileRunner{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Before.Events.Schema != 1 || report.After.Events.Schema != 2 || report.Before.Events.Digest != report.After.Events.Digest {
		t.Fatal("migration did not preserve data")
	}
	upgrade := filepath.Join(t.TempDir(), "upgrade")
	if _, err = Restore(ctx, backup, upgrade); err != nil {
		t.Fatal(err)
	}
	up := pathsUnder(upgrade, m.Paths)
	if err = prepareProbe(upgrade, up); err != nil {
		t.Fatal(err)
	}
	if _, err = Probe(ctx, up); err != nil {
		t.Fatal(err)
	}
	post := filepath.Join(t.TempDir(), "post-upgrade")
	if _, err = Backup(ctx, BackupOptions{Paths: up, Destination: post}); err != nil {
		t.Fatal(err)
	}
	called := false
	if _, err = checkWith(ctx, post, profileRunner{legacy: true, called: &called}); err == nil || called {
		t.Fatal("downgrade was not rejected before opening migrated state")
	}
	if report, err = checkWith(ctx, backup, profileRunner{legacy: true}); err != nil || !report.Compatible {
		t.Fatalf("restored v1 is not readable by legacy profile: %+v %v", report, err)
	}
	if after, err := Verify(ctx, backup); err != nil || after.State.Events.Schema != 1 {
		t.Fatal("upgrade rehearsal modified its rollback checkpoint")
	}
}

func TestCoordinatedRestoreReplaysPendingExportsWithoutInflatingCollector(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	token := "recovery-test-private-collector-token-32"
	collectorPath := filepath.Join(root, "receiver.db")
	receiver, err := eventcollector.Open(eventcollector.Options{Path: collectorPath, Token: token})
	if err != nil {
		t.Fatal(err)
	}
	var current atomic.Pointer[eventcollector.Collector]
	current.Store(receiver)
	var good atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := current.Load()
		rec := httptest.NewRecorder()
		c.ServeHTTP(rec, r)
		if !good.Load() {
			http.Error(w, "lost acknowledgement", 503)
			return
		}
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		w.Write(rec.Body.Bytes())
	}))
	defer server.Close()
	defer func() { current.Load().Close() }()
	policy := filepath.Join(root, "policy.json")
	eventPath := policy + ".events.db"
	options := gateway.Options{EventStore: eventstore.Options{Path: eventPath, MaxRows: 1, Export: eventstore.ExportOptions{URL: server.URL + "/v1/events", Token: token, RetryMin: 5 * time.Millisecond, RetryMax: 30 * time.Millisecond}}}
	g, err := gateway.NewWithOptions(policy, options)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		r := httptest.NewRequest("GET", fmt.Sprintf("/?q=%%3Cscript%%3Ealert(%d)%%3C/script%%3E", i), nil)
		r.Host = "application.test"
		r.Header.Set("User-Agent", "OpenWAF recovery test")
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		if w.Code != 403 {
			g.Close(ctx)
			t.Fatalf("fixture not blocked: %d", w.Code)
		}
	}
	source := g.StorageStatus().Export.SourceID
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		totals, e := receiver.SourceTotals(ctx, source)
		if e == nil && totals.Records == 4 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	g.Close(ctx)
	// Policy is stopped, but the collector still holds its maintenance lease.
	paths := Paths{Policy: policy, Events: eventPath, Collector: collectorPath}
	backup := filepath.Join(t.TempDir(), "coordinated")
	if _, err = Backup(ctx, BackupOptions{Paths: paths, Destination: backup}); err == nil {
		t.Fatal("running collector was copied")
	}
	receiver.Close()
	m, err := Backup(ctx, BackupOptions{Paths: paths, Destination: backup})
	if err != nil {
		t.Fatal(err)
	}
	if m.Scope != "coordinated" || m.State.Events.OutboxRows != 4 || m.State.Events.Rows != 1 {
		t.Fatalf("wrong recovery coverage: %+v", m.State)
	}
	if checked, e := checkWith(ctx, backup, profileRunner{}); e != nil || !checked.Compatible {
		t.Fatalf("coordinated upgrade rehearsal failed: %+v %v", checked, e)
	}
	restored := filepath.Join(t.TempDir(), "restored")
	if _, err = Restore(ctx, backup, restored); err != nil {
		t.Fatal(err)
	}
	p := pathsUnder(restored, m.Paths)
	replacement, err := eventcollector.Open(eventcollector.Options{Path: p.Collector, Token: token})
	if err != nil {
		t.Fatal(err)
	}
	current.Store(replacement)
	good.Store(true)
	options.EventStore.Path = p.Events
	g, err = gateway.NewWithOptions(p.Policy, options)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close(ctx)
	wait, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err = g.WaitEventExport(wait); err != nil {
		t.Fatal(err)
	}
	totals, err := replacement.SourceTotals(ctx, source)
	if err != nil || totals.Records != 4 || totals.Occurrences != 4 || g.StorageStatus().Export.Acked != 4 {
		t.Fatalf("restore replay lost/inflated receipts: %+v %v", totals, err)
	}
	g.Close(ctx)
	replacement.Close()
	db, e := sql.Open("sqlite", p.Collector)
	if e != nil {
		t.Fatal(e)
	}
	_, e = db.Exec("DELETE FROM collected_events WHERE id=(SELECT id FROM collected_events LIMIT 1); UPDATE collector_totals SET records=records-1,occurrences=occurrences-1")
	db.Close()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Backup(ctx, BackupOptions{Paths: p, Destination: filepath.Join(t.TempDir(), "stale-collector")}); e == nil || !strings.Contains(e.Error(), "checkpoints do not reconcile") {
		t.Fatalf("stale acknowledged collector accepted: %v", e)
	}
}

func TestActualCandidateRehearsal(t *testing.T) {
	candidate := os.Getenv("OPENWAF_RECOVERY_CANDIDATE")
	if candidate == "" {
		t.Skip("set OPENWAF_RECOVERY_CANDIDATE to a newly built waf-server")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	p := simpleState(t, true)
	backup := filepath.Join(t.TempDir(), "checkpoint")
	if _, err := Backup(ctx, BackupOptions{Paths: p, Destination: backup, Binary: candidate}); err != nil {
		t.Fatal(err)
	}
	report, err := UpgradeCheck(ctx, backup, candidate)
	if err != nil || !report.Compatible {
		t.Fatalf("real candidate failed: %+v %v", report, err)
	}
	restored := filepath.Join(t.TempDir(), "rollback")
	rollback, err := Rollback(ctx, backup, restored, "")
	if err != nil || !rollback.Prepared {
		t.Fatalf("bundled binary rollback failed: %+v %v", rollback, err)
	}
}

func TestCommandLineRecoveryProcedure(t *testing.T) {
	admin := os.Getenv("OPENWAF_RECOVERY_ADMIN")
	candidate := os.Getenv("OPENWAF_RECOVERY_CANDIDATE")
	if admin == "" || candidate == "" {
		t.Skip("set admin and candidate executable paths")
	}
	p := simpleState(t, true)
	backup := filepath.Join(t.TempDir(), "checkpoint")
	token := filepath.Join(t.TempDir(), "token")
	secret := "private-fixture-credential-must-not-appear-in-output"
	os.WriteFile(token, []byte(secret), 0600)
	invoke := func(args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		command := exec.CommandContext(ctx, admin, args...)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("CLI %v: %v %s", args, err, output)
		}
		var reply struct {
			OK bool `json:"ok"`
		}
		if err = json.Unmarshal(output, &reply); err != nil || !reply.OK {
			t.Fatalf("CLI did not return a successful structured result: %s", output)
		}
		if strings.Contains(string(output), secret) {
			t.Fatal("CLI disclosed credential content")
		}
	}
	invoke("backup", "-config", p.Policy, "-event-db", p.Events, "-out", backup, "-binary", candidate, "-admin-token-file", token)
	invoke("verify", "-backup", backup)
	invoke("upgrade-check", "-backup", backup, "-candidate", candidate)
	invoke("restore", "-backup", backup, "-out", filepath.Join(t.TempDir(), "restored"))
	invoke("rollback", "-backup", backup, "-out", filepath.Join(t.TempDir(), "rolled-back"))
	badDestination := filepath.Join(t.TempDir(), "must-not-exist")
	command := exec.Command(admin, "restore", "-backup", backup, "-out", badDestination, "-candidate", candidate)
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("irrelevant candidate flag was silently ignored: %s", output)
	}
	if _, err := os.Stat(badDestination); !os.IsNotExist(err) {
		t.Fatal("rejected CLI invocation created recovery state")
	}
}

func TestExecutableLegacyReaderRollbackDrill(t *testing.T) {
	legacy := os.Getenv("OPENWAF_RECOVERY_LEGACY")
	candidate := os.Getenv("OPENWAF_RECOVERY_CANDIDATE")
	if legacy == "" || candidate == "" {
		t.Skip("set actual candidate and test-only schema-1 reader executable paths")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	p := simpleState(t, true)
	backup := filepath.Join(t.TempDir(), "before-upgrade")
	manifest, err := Backup(ctx, BackupOptions{Paths: p, Destination: backup, Binary: legacy})
	if err != nil {
		t.Fatal(err)
	}
	report, err := UpgradeCheck(ctx, backup, candidate)
	if err != nil || report.After.Events.Schema != 2 {
		t.Fatalf("actual candidate did not qualify migration: %+v %v", report, err)
	}
	upgraded := filepath.Join(t.TempDir(), "migrated")
	if _, err = Restore(ctx, backup, upgraded); err != nil {
		t.Fatal(err)
	}
	up := pathsUnder(upgraded, manifest.Paths)
	if err = prepareProbe(upgraded, up); err != nil {
		t.Fatal(err)
	}
	if err = (executable{path: candidate}).probe(ctx, up); err != nil {
		t.Fatal(err)
	}
	migratedBackup := filepath.Join(t.TempDir(), "after-upgrade")
	if _, err = Backup(ctx, BackupOptions{Paths: up, Destination: migratedBackup}); err != nil {
		t.Fatal(err)
	}
	if _, err = UpgradeCheck(ctx, migratedBackup, legacy); err == nil {
		t.Fatal("actual schema-1 executable accepted a schema-2 recovery set")
	}
	rollback := filepath.Join(t.TempDir(), "rolled-back")
	prepared, err := Rollback(ctx, backup, rollback, "")
	if err != nil || !prepared.Prepared {
		t.Fatalf("executable rollback rehearsal failed: %+v %v", prepared, err)
	}
	state, err := Inspect(ctx, prepared.Paths, true)
	if err != nil || state.Events.Schema != 1 || state.Events.Digest != manifest.State.Events.Digest {
		t.Fatal("rollback did not preserve the original schema-1 records")
	}
}

func TestProbeCannotOperateDirectlyOnOriginalState(t *testing.T) {
	paths := simpleState(t, true)
	before, err := Inspect(context.Background(), paths, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Probe(context.Background(), paths); err == nil {
		t.Fatal("probe modified unmarked original state")
	}
	after, err := Inspect(context.Background(), paths, false)
	if err != nil || !stateEqual(before, after) {
		t.Fatal("refused probe changed original state")
	}
}

func TestUnknownSchemaAndRecoverySidecarsAreRefused(t *testing.T) {
	paths := simpleState(t, false)
	db, err := sql.Open("sqlite", paths.Events)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("PRAGMA user_version=99"); err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()
	before, _, err := hashFile(context.Background(), paths.Events)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "future-schema")
	if _, err = Backup(context.Background(), BackupOptions{Paths: paths, Destination: out}); err == nil {
		t.Fatal("newer schema accepted")
	}
	after, _, err := hashFile(context.Background(), paths.Events)
	if err != nil || before != after {
		t.Fatal("schema refusal changed source database")
	}
	paths = simpleState(t, false)
	if err = os.WriteFile(paths.Events+"-journal", []byte("recovery required"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Backup(context.Background(), BackupOptions{Paths: paths, Destination: filepath.Join(t.TempDir(), "dirty")}); err == nil {
		t.Fatal("nonempty journal was ignored")
	}
}

func TestSymlinkBackupMemberIsRefused(t *testing.T) {
	paths := simpleState(t, false)
	backup := filepath.Join(t.TempDir(), "snapshot")
	if _, err := Backup(context.Background(), BackupOptions{Paths: paths, Destination: backup}); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("external"), 0600); err != nil {
		t.Fatal(err)
	}
	member := filepath.Join(backup, "state", "events.db")
	if err := os.Remove(member); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, member); err != nil {
		t.Skip("symlink creation unavailable on this host")
	}
	if _, err := Verify(context.Background(), backup); err == nil {
		t.Fatal("symlink member accepted")
	}
}

func TestBackupCrashHelper(t *testing.T) {
	input := os.Getenv("OPENWAF_BACKUP_CRASH_INPUT")
	if input == "" {
		t.Skip("subprocess helper")
	}
	data, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	var options BackupOptions
	if err = json.Unmarshal(data, &options); err != nil {
		t.Fatal(err)
	}
	options.copyCheckpoint = func(count int) {
		if count == 1 {
			if err := os.WriteFile(input+".ready", []byte("partially copied"), 0600); err != nil {
				t.Fatal(err)
			}
			for {
				time.Sleep(time.Hour)
			}
		}
	}
	if _, err = Backup(context.Background(), options); err != nil {
		t.Fatal(err)
	}
}

func TestKilledBackupNeverPublishesPartialCheckpoint(t *testing.T) {
	paths := simpleState(t, false)
	before, err := Inspect(context.Background(), paths, false)
	if err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	destination := filepath.Join(parent, "checkpoint")
	options := BackupOptions{Paths: paths, Destination: destination}
	data, _ := json.Marshal(options)
	input := filepath.Join(t.TempDir(), "input.json")
	if err = os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestBackupCrashHelper$", "-test.v")
	command.Env = append(os.Environ(), "OPENWAF_BACKUP_CRASH_INPUT="+input)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			command.Process.Kill()
			command.Wait()
		}
	}()
	deadline := time.Now().Add(15 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		if _, e := os.Stat(input + ".ready"); e == nil {
			ready = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		command.Process.Kill()
		command.Wait()
		waited = true
		t.Fatalf("child did not reach copy checkpoint: %s", output.String())
	}
	if err = command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	command.Wait()
	waited = true
	if _, err = os.Stat(destination); !os.IsNotExist(err) {
		t.Fatal("killed backup published a destination")
	}
	after, err := Inspect(context.Background(), paths, false)
	if err != nil || !stateEqual(before, after) {
		t.Fatal("interrupted backup changed original state")
	}
	if _, err = Backup(context.Background(), options); err != nil {
		t.Fatalf("retry after interrupted backup failed: %v", err)
	}
	if _, err = Verify(context.Background(), destination); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentRestoresPublishOnlyOneDestination(t *testing.T) {
	p := simpleState(t, false)
	backup := filepath.Join(t.TempDir(), "checkpoint")
	if _, err := Backup(context.Background(), BackupOptions{Paths: p, Destination: backup}); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "winner")
	var wg sync.WaitGroup
	results := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := Restore(context.Background(), backup, destination); results <- err }()
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("published %d competing restores", success)
	}
	if _, err := Verify(context.Background(), destination); err != nil {
		t.Fatal(err)
	}
}
