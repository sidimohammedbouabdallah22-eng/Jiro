package gateway

import (
	"bytes"
	"context"
	"database/sql"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestPolicyCrashHelper(t *testing.T) {
	path := os.Getenv("OPENWAF_CRASH_POLICY_PATH")
	if path == "" {
		t.Skip("subprocess helper")
	}
	g, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	g.writePolicy = func(_ string, _ Config) error {
		if err := os.WriteFile(path+".ready", []byte("prepared, not committed"), 0600); err != nil {
			return err
		}
		for {
			time.Sleep(time.Hour)
		}
	}
	c := g.Config()
	c.Mode = "detection"
	if _, err = g.Apply(c, false); err != nil {
		t.Fatal(err)
	}
}
func TestForcedPolicyCrashKeepsCommittedRevision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	cmd := exec.Command(os.Args[0], "-test.run=^TestPolicyCrashHelper$", "-test.v")
	cmd.Env = append(os.Environ(), "OPENWAF_CRASH_POLICY_PATH="+path)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	deadline := time.Now().Add(15 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path + ".ready"); err == nil {
			ready = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		waited = true
		t.Fatalf("helper not ready: %s", output.String())
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	waited = true
	g, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close(context.Background())
	if g.Config().Mode != "enforcing" || g.Config().Revision != 1 {
		t.Fatalf("uncommitted config active: %+v", g.Config())
	}
	history, err := g.History()
	if err != nil || len(history) != 1 {
		t.Fatalf("orphan visible: %+v %v", history, err)
	}
	c := g.Config()
	c.Mode = "detection"
	c, err = g.Apply(c, false)
	if err != nil || c.Revision != 3 {
		t.Fatalf("orphan revision reused: %d %v", c.Revision, err)
	}
}

func TestLockedEventDatabaseDoesNotDisableInspection(t *testing.T) {
	g, path := fixture(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("healthy")) })
	db, err := sql.Open("sqlite", path+".events.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err = db.Exec("BEGIN EXCLUSIVE"); err != nil {
		t.Fatal(err)
	}
	locked := true
	defer func() {
		if locked {
			db.Exec("ROLLBACK")
		}
	}()
	decision := make(chan int, 1)
	go func() { decision <- request(g, "GET", "/?q=%3Cscript%3Ealert(1)%3C/script%3E", "", "").Code }()
	deadline := time.Now().Add(3 * time.Second)
	for g.StorageStatus().WriteRetries == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if g.StorageStatus().WriteRetries == 0 {
		t.Fatal("temporary writer lock was not retried")
	}
	if w := request(g, "GET", "/", "", ""); w.Code != 200 {
		t.Fatalf("clean request failed during disk lock: %d", w.Code)
	}
	select {
	case <-decision:
		t.Fatal("event was discarded instead of waiting for its durable commit")
	default:
	}
	if _, err = db.Exec("ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	locked = false
	select {
	case code := <-decision:
		if code != 403 {
			t.Fatalf("inspection failed: %d", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("event did not commit after lock release")
	}
	if w := request(g, "GET", "/recovered?q=%3Cscript%3Ealert(1)%3C/script%3E", "", ""); w.Code != 403 {
		t.Fatal("inspection did not recover")
	}
	_ = g.FlushEvents(context.Background())
	if g.StorageStatus().Stored == 0 || !g.StorageStatus().Healthy {
		t.Fatal("writer did not resume after unlock")
	}
}
