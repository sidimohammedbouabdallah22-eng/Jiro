package eventstore

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestIngestAndExportCheckpointShareSlowCommit(t *testing.T) {
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer receiver.Close()
	path := filepath.Join(t.TempDir(), "events.db")
	seed := openTest(t, exportOptions(path, receiver.URL))
	appendTest(t, seed, "seed")
	if err := seed.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Reopen paused so this test controls the already-received checkpoint.
	// Queue membership and the exact durable-commit count prove coalescing.
	// Allow real fsync/scheduler latency under parallel test load; a sub-second
	// wall-clock race would test host speed instead of the shared-writer contract.
	s := openTest(t, Options{Path: path, CommitTimeout: 5 * time.Second})
	batch, err := s.loadExport(context.Background())
	if err != nil || len(batch.Events) != 1 {
		t.Fatalf("load pending batch: %+v %v", batch, err)
	}
	var commits atomic.Int32
	primerEntered := make(chan struct{})
	release := make(chan struct{})
	releasePrimer := sync.OnceFunc(func() { close(release) })
	defer releasePrimer()
	first := true
	s.writeMu.Lock()
	s.commit = func(tx *sql.Tx) error {
		if first {
			first = false
			close(primerEntered)
			<-release
			return tx.Commit()
		}
		commits.Add(1)
		time.Sleep(450 * time.Millisecond)
		return tx.Commit()
	}
	s.writeMu.Unlock()
	// Hold a priming barrier at commit while both real producers enqueue.
	// Scheduler timing must not decide whether they share the ten-ms window.
	primerDone := make(chan error, 1)
	if err := s.send(context.Background(), item{barrier: primerDone}); err != nil {
		t.Fatal(err)
	}
	<-primerEntered
	checkpointDone := make(chan error, 1)
	go func() { checkpointDone <- s.ackExport(context.Background(), batch) }()
	appendDone := make(chan error, 1)
	go func() {
		appendDone <- s.Append(context.Background(), Record{ID: "next", Time: time.Now(), Action: "blocked", Data: []byte(`{"id":"next"}`)})
	}()
	deadline := time.Now().Add(time.Second)
	for len(s.queue) < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(s.queue) != 2 {
		t.Fatal("both checkpoint and ingestion must enter the shared writer queue")
	}
	releasePrimer()
	if err := <-primerDone; err != nil {
		t.Fatal(err)
	}
	appendErr, checkpointErr := <-appendDone, <-checkpointDone
	if appendErr != nil || checkpointErr != nil {
		t.Fatalf("slow commit exceeded acknowledgement budget: ingest=%v checkpoint=%v commits=%d", appendErr, checkpointErr, commits.Load())
	}
	if got := commits.Load(); got != 1 {
		t.Fatalf("ingestion and checkpoint used %d durable commits, want one", got)
	}
	if status := s.Status(); status.IngestTimeouts != 0 || status.Export.Acked != 1 || status.Export.Pending != 1 || status.CommittedRecords != 2 {
		t.Fatalf("combined transaction accounting %+v", status)
	}
	s.writeMu.Lock()
	s.commit = (*sql.Tx).Commit
	s.writeMu.Unlock()
	if err := s.ackExport(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	if status := s.Status(); status.Export.Acked != 1 || status.Export.AckedOccurrences != 2 || status.Export.Pending != 1 {
		t.Fatalf("replayed checkpoint inflated counters %+v", status)
	}
}

func TestCombinedCheckpointRollbackPreservesPendingReceipt(t *testing.T) {
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer receiver.Close()
	path := filepath.Join(t.TempDir(), "events.db")
	seed := openTest(t, exportOptions(path, receiver.URL))
	appendTest(t, seed, "seed")
	if err := seed.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := openTest(t, Options{Path: path})
	checkpoint, err := s.loadExport(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s.writeMu.Lock()
	s.commit = func(*sql.Tx) error { return errors.New("injected commit failure") }
	s.writeMu.Unlock()
	ack := make(chan error, 1)
	s.pending.Add(1)
	if err := s.send(context.Background(), item{record: &Record{ID: "next", Time: time.Now(), Action: "blocked", Data: []byte(`{"id":"next"}`)}, checkpoint: []exportReceipt{{sequence: checkpoint.Events[0].Sequence, id: "seed"}}, ack: ack}); err != nil {
		s.pending.Add(-1)
		t.Fatal(err)
	}
	if err := <-ack; err == nil {
		t.Fatal("failed transaction was acknowledged")
	}
	if status := s.Status(); status.Pending != 0 || status.CommittedRecords != 1 || status.Export.Acked != 0 || status.Export.Pending != 1 {
		t.Fatalf("failed transaction changed accounting %+v", status)
	}
	rows, err := s.Query(context.Background(), Query{Limit: 10})
	if err != nil || len(rows) != 1 || rows[0].ID != "seed" {
		t.Fatalf("failed transaction changed retained events %+v %v", rows, err)
	}
	pending, err := s.loadExport(context.Background())
	if err != nil || len(pending.Events) != 1 || pending.Events[0].ID != "seed" {
		t.Fatalf("failed transaction removed the pending receipt %+v %v", pending, err)
	}
	s.writeMu.Lock()
	s.commit = (*sql.Tx).Commit
	s.writeMu.Unlock()
	if err := s.ackExport(context.Background(), checkpoint); err != nil {
		t.Fatal(err)
	}
	appendTest(t, s, "next")
	if status := s.Status(); status.CommittedRecords != 2 || status.Export.Acked != 1 || status.Export.Pending != 1 {
		t.Fatalf("retry did not preserve receipts %+v", status)
	}
}
