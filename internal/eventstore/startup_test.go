package eventstore

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestStartupSchemaTransactionRollbackAndDiagnostics(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE event_totals(singleton INTEGER PRIMARY KEY CHECK(singleton=1),records INTEGER NOT NULL,occurrences INTEGER NOT NULL,enqueued INTEGER NOT NULL,enqueued_occurrences INTEGER NOT NULL,acked INTEGER NOT NULL,acked_occurrences INTEGER NOT NULL);
CREATE TRIGGER stalled_initialization BEFORE INSERT ON event_totals BEGIN SELECT sum(x) FROM (WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<1000000000) SELECT x FROM n); END;`)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()
	started := time.Now()
	store, err := Open(Options{Path: path, StartupTimeout: time.Second})
	if err == nil {
		store.Close(context.Background())
		t.Fatal("injected startup stall did not time out")
	}
	if !strings.Contains(err.Error(), "schema transaction") || time.Since(started) > 5*time.Second {
		t.Fatalf("missing stage or unbounded startup: %v", err)
	}
	t.Log(err)
	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	var version, events int
	if err = db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='events'").Scan(&events); err != nil {
		t.Fatal(err)
	}
	if version != 0 || events != 0 {
		t.Fatalf("timed-out schema setup committed partial state: version=%d events=%d", version, events)
	}
	if _, err = db.Exec("DROP TRIGGER stalled_initialization"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	store, err = Open(Options{Path: path})
	if err != nil {
		t.Fatal("startup did not recover after removing the fault", err)
	}
	defer store.Close(context.Background())
	if store.Status().StartupMilliseconds <= 0 || store.opts.CommitTimeout != 5*time.Second || store.opts.StartupTimeout != 30*time.Second {
		t.Fatal("startup and commit budgets are not independent")
	}
}

func TestStartupUnderContention(t *testing.T) {
	root := t.TempDir()
	var mu sync.Mutex
	var elapsed []float64
	var workers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for run := 0; run < 8; run++ {
				path := filepath.Join(root, fmt.Sprintf("%d-%d.db", worker, run))
				s, err := Open(Options{Path: path})
				if err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				elapsed = append(elapsed, s.Status().StartupMilliseconds)
				mu.Unlock()
				if err = s.Append(context.Background(), Record{ID: "acknowledged", Time: time.Now(), Data: []byte(`{"id":"acknowledged"}`)}); err != nil {
					t.Error(err)
				}
				if err = s.Close(context.Background()); err != nil {
					t.Error(err)
					return
				}
				s, err = Open(Options{Path: path})
				if err != nil {
					t.Error(err)
					return
				}
				rows, err := s.Query(context.Background(), Query{Limit: 1})
				if err != nil || len(rows) != 1 {
					t.Error("acknowledged data lost on reopen", err)
				}
				mu.Lock()
				elapsed = append(elapsed, s.Status().StartupMilliseconds)
				mu.Unlock()
				s.Close(context.Background())
			}
		}()
	}
	workers.Wait()
	sort.Float64s(elapsed)
	if len(elapsed) != 128 {
		t.Fatalf("completed %d of 128 startup/reopen operations", len(elapsed))
	}
	t.Logf("128 startup/reopen operations, 8 workers: p50=%.2fms p95=%.2fms max=%.2fms", elapsed[64], elapsed[121], elapsed[127])
}
