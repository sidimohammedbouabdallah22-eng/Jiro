package eventstore

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openTest(t *testing.T, o Options) *Store {
	t.Helper()
	s, e := Open(o)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = s.Close(context.Background()) })
	return s
}
func flushTest(t *testing.T, s *Store) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if e := s.Flush(ctx); e != nil {
		t.Fatal(e)
	}
}
func TestPersistenceCursorLiteralSearchAndRetention(t *testing.T) {
	o := Options{Path: filepath.Join(t.TempDir(), "events.db"), MaxRows: 3, MaxAge: time.Hour}
	s := openTest(t, o)
	for i := 0; i < 5; i++ {
		if !s.Enqueue(Record{ID: fmt.Sprint(i), Time: time.Now(), Action: "blocked", Path: fmt.Sprintf("/item/%d_%%", i), Data: []byte(`{"rule":941100}`)}) {
			t.Fatal("enqueue")
		}
	}
	s.Enqueue(Record{ID: "old", Time: time.Now().Add(-2 * time.Hour), Data: []byte(`{}`)})
	flushTest(t, s)
	rows, e := s.Query(context.Background(), Query{Limit: 2, Search: "_%"})
	if e != nil || len(rows) != 2 || rows[0].ID != "4" {
		t.Fatalf("query: %v %v", rows, e)
	}
	next, e := s.Query(context.Background(), Query{Limit: 2, Before: rows[1].Sequence})
	if e != nil || len(next) != 1 || next[0].ID != "2" {
		t.Fatalf("cursor: %v %v", next, e)
	}
	if e = s.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	reopened := openTest(t, o)
	rows, e = reopened.Query(context.Background(), Query{Limit: 10, Action: "blocked"})
	if e != nil || len(rows) != 3 {
		t.Fatalf("restart: %v %v", rows, e)
	}
}
func TestDiskBudgetAndCorruptStartup(t *testing.T) {
	o := Options{Path: filepath.Join(t.TempDir(), "events.db"), MaxBytes: 4 << 20, MaxRows: 10000}
	s := openTest(t, o)
	for i := 0; i < 400; i++ {
		if !s.Enqueue(Record{ID: fmt.Sprint(i), Time: time.Now(), Action: "blocked", Data: []byte(strings.Repeat("x", 16000))}) {
			t.Fatal("unexpected queue loss")
		}
		if i%16 == 0 {
			flushTest(t, s)
		}
	}
	flushTest(t, s)
	st := s.Status()
	if !st.Healthy || st.Stored >= 400 || st.PayloadBytes > o.MaxBytes/2 || st.Pending != 0 {
		t.Fatalf("budget: %+v", st)
	}
	info, e := os.Stat(o.Path)
	if e != nil || info.Size() > o.MaxBytes {
		t.Fatalf("disk cap: %v %v", info, e)
	}
	bad := filepath.Join(t.TempDir(), "bad.db")
	if e = os.WriteFile(bad, []byte("corrupted database"), 0600); e != nil {
		t.Fatal(e)
	}
	if db, e := Open(Options{Path: bad}); e == nil {
		db.Close(context.Background())
		t.Fatal("corruption accepted")
	}
}
func TestQueueLossAndWriterFailureAreObservable(t *testing.T) {
	s := openTest(t, Options{Path: filepath.Join(t.TempDir(), "events.db"), QueueSize: 1})
	// Hold the only SQL connection so the worker cannot drain its next batch.
	conn, e := s.db.Conn(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 100; i++ {
		s.Enqueue(Record{ID: fmt.Sprint(i), Time: time.Now(), Data: []byte(`{}`)})
	}
	conn.Close()
	flushTest(t, s)
	if s.Status().QueueDropped == 0 || s.Status().Healthy {
		t.Fatal("queue loss hidden")
	}
	if _, e = s.db.Exec("PRAGMA query_only=ON"); e != nil {
		t.Fatal(e)
	}
	s.Enqueue(Record{ID: "failure", Time: time.Now(), Data: []byte(`{}`)})
	if e = s.Flush(context.Background()); e == nil {
		t.Fatal("writer error hidden")
	}
	if s.Status().WriteFailed == 0 || s.Status().Healthy {
		t.Fatalf("failure health: %+v", s.Status())
	}
}

func TestCloseDrainsAndReopenAppliesReducedRetention(t *testing.T) {
	o := Options{Path: filepath.Join(t.TempDir(), "events.db"), MaxRows: 100}
	s := openTest(t, o)
	for i := 0; i < 50; i++ {
		if !s.Enqueue(Record{ID: fmt.Sprint(i), Time: time.Now(), Data: []byte(`{}`)}) {
			t.Fatal("enqueue")
		}
	}
	if e := s.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	s = openTest(t, o)
	if s.Status().Stored != 50 {
		t.Fatal("shutdown did not drain events")
	}
	s.Close(context.Background())
	o.MaxRows = 3
	s = openTest(t, o)
	if s.Status().Stored != 3 {
		t.Fatal("reopen ignored reduced retention")
	}
	// A duplicate ID must not evict another retained event at the row limit.
	s.Enqueue(Record{ID: "49", Time: time.Now(), Data: []byte(`{}`)})
	flushTest(t, s)
	if s.Status().Stored != 3 {
		t.Fatal("duplicate evicted a retained event")
	}
}
