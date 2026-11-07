package eventstore

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDatabaseFullReportsLossAndRecovers(t *testing.T) {
	s := openTest(t, Options{Path: filepath.Join(t.TempDir(), "events.db"), MaxBytes: 4 << 20})
	if _, err := s.db.Exec("CREATE TABLE filler(data BLOB)"); err != nil {
		t.Fatal(err)
	}
	full := false
	for i := 0; i < 1200; i++ {
		if _, err := s.db.Exec("INSERT INTO filler VALUES(zeroblob(4000))"); err != nil {
			if !strings.Contains(strings.ToLower(err.Error()), "full") {
				t.Fatal(err)
			}
			full = true
			break
		}
	}
	if !full {
		t.Fatal("failed to reach SQLite's physical page cap")
	}
	if !s.Enqueue(Record{ID: "cannot-fit", Time: time.Now(), Data: []byte(strings.Repeat("x", MaxRecordBytes))}) {
		t.Fatal("enqueue")
	}
	if err := s.Flush(context.Background()); err == nil {
		t.Fatal("physical disk-budget failure hidden")
	}
	if status := s.Status(); status.Healthy || status.WriteFailed != 1 || !strings.Contains(strings.ToLower(status.LastError), "full") {
		t.Fatalf("full database health: %+v", status)
	}
	if _, err := s.db.Exec("DROP TABLE filler"); err != nil {
		t.Fatal(err)
	}
	s.Enqueue(Record{ID: "recovered", Time: time.Now(), Action: "blocked", Data: []byte(`{}`)})
	// Lifetime loss counters intentionally keep Flush/Healthy degraded.
	_ = s.Flush(context.Background())
	rows, err := s.Query(context.Background(), Query{Limit: 10})
	if err != nil || len(rows) != 1 || rows[0].ID != "recovered" {
		t.Fatalf("writer did not recover: %+v %v", rows, err)
	}
	if s.Status().WriteFailed != 1 || s.Status().Healthy {
		t.Fatal("historical loss disappeared")
	}
}

// This subprocess is only entered by TestForcedCrashRollsBackHotJournal.
func TestEventCrashHelper(t *testing.T) {
	path := os.Getenv("OPENWAF_CRASH_EVENT_PATH")
	if path == "" {
		t.Skip("subprocess helper")
	}
	s, err := Open(Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		if !s.Enqueue(Record{ID: fmt.Sprintf("committed-%02d", i), Time: time.Now(), Action: "blocked", Data: []byte(`{"committed":true}`)}) {
			t.Fatal("enqueue")
		}
	}
	if err = s.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("PRAGMA cache_size=16"); err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec("INSERT INTO events(id,time_ns,action,ip,path,size,data) VALUES(?,?,?,?,?,?,?)", "uncommitted", time.Now().UnixNano(), "blocked", "", "/", 2, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	// Force dirty pages and a real rollback journal before notifying the parent.
	for i := 0; i < 100; i++ {
		if _, err = tx.Exec("INSERT INTO events(id,time_ns,action,ip,path,size,data) VALUES(?,?,?,?,?,?,?)", fmt.Sprintf("dirty-%d", i), time.Now().UnixNano(), "blocked", "", "/", 16000, []byte(strings.Repeat("x", 16000))); err != nil {
			t.Fatal(err)
		}
	}
	if err = os.WriteFile(path+".ready", []byte("transaction open"), 0600); err != nil {
		t.Fatal(err)
	}
	for {
		time.Sleep(time.Hour)
	}
}

func TestForcedCrashRollsBackHotJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.db")
	cmd := exec.Command(os.Args[0], "-test.run=^TestEventCrashHelper$", "-test.v")
	cmd.Env = append(os.Environ(), "OPENWAF_CRASH_EVENT_PATH="+path)
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
		t.Fatalf("crash helper not ready: %s", output.String())
	}
	if info, err := os.Stat(path + "-journal"); err != nil || info.Size() == 0 {
		t.Fatalf("rollback journal not present: %v", err)
	}
	journal, err := os.Open(path + "-journal")
	if err != nil {
		t.Fatal(err)
	}
	header := make([]byte, 8)
	_, err = journal.Read(header)
	journal.Close()
	if err != nil || bytes.Equal(header, make([]byte, 8)) {
		t.Fatalf("journal was not made hot before crash: %x %v", header, err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	waited = true
	s := openTest(t, Options{Path: path})
	rows, err := s.Query(context.Background(), Query{Limit: 100})
	if err != nil || len(rows) != 50 {
		t.Fatalf("recovery: %d events, %v", len(rows), err)
	}
	for _, r := range rows {
		if !strings.HasPrefix(r.ID, "committed-") {
			t.Fatalf("uncommitted transaction survived: %s", r.ID)
		}
	}
}

func TestTimedOutCloseStillClosesDatabaseAfterDrain(t *testing.T) {
	s := openTest(t, Options{Path: filepath.Join(t.TempDir(), "events.db")})
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !s.Enqueue(Record{ID: "last", Time: time.Now(), Data: []byte(`{}`)}) {
		conn.Close()
		t.Fatal("enqueue")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	err = s.Close(ctx)
	cancel()
	conn.Close()
	if err == nil {
		t.Fatal("close unexpectedly finished behind held connection")
	}
	select {
	case <-s.done:
	case <-time.After(4 * time.Second):
		t.Fatal("worker did not finish after timeout")
	}
	if err = s.db.Ping(); err == nil {
		t.Fatal("database handle leaked after timeout")
	}
	reopened := openTest(t, Options{Path: s.opts.Path})
	rows, err := reopened.Query(context.Background(), Query{Limit: 10})
	if err != nil || len(rows) != 1 {
		t.Fatalf("final queued record lost: %d %v", len(rows), err)
	}
}
