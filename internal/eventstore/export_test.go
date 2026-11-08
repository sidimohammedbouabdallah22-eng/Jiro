package eventstore

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
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func appendTest(t *testing.T, s *Store, id string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Append(ctx, Record{ID: id, Time: time.Now(), Action: "blocked", Data: []byte(`{"rule":941100}`), Occurrences: 2}); err != nil {
		t.Fatal(err)
	}
}

func TestEmptyExportReadFailureRecoversWithoutCollectorAcknowledgement(t *testing.T) {
	s := openTest(t, exportOptions(filepath.Join(t.TempDir(), "events.db"), "http://127.0.0.1:1/events"))
	connection, err := s.db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	await(t, func() bool { return s.ExportStatus().Failures > 0 })
	if s.ExportStatus().Healthy {
		t.Fatal("outbox read failure did not affect export health")
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	await(t, func() bool { return s.ExportStatus().Healthy })
	status := s.ExportStatus()
	if status.Failures == 0 || status.LastError != "" || status.Pending != 0 || status.Attempts != 0 || status.Acked != 0 || !status.LastSuccess.IsZero() {
		t.Fatalf("read recovery changed delivery history: %+v", status)
	}
}

func TestAcknowledgedCollectorCommitWithFailedLocalCheckpointRetries(t *testing.T) {
	received := make(chan struct{}, 1)
	release := make(chan struct{})
	var first atomic.Bool
	first.Store(true)
	var calls atomic.Int32
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b ExportBatch
		json.NewDecoder(r.Body).Decode(&b)
		calls.Add(1)
		if first.Swap(false) {
			received <- struct{}{}
			<-release
		}
		ack := ExportAck{BatchID: b.BatchID}
		for _, e := range b.Events {
			ack.IDs = append(ack.IDs, e.ID)
		}
		json.NewEncoder(w).Encode(ack)
	}))
	defer collector.Close()
	path := filepath.Join(t.TempDir(), "events.db")
	s := openTest(t, exportOptions(path, collector.URL))
	appendTest(t, s, "one")
	select {
	case <-received:
	case <-time.After(5 * time.Second):
		t.Fatal("collector did not receive batch")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		close(release)
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec("BEGIN EXCLUSIVE"); err != nil {
		close(release)
		t.Fatal(err)
	}
	close(release)
	await(t, func() bool { return s.ExportStatus().Failures > 0 })
	// A queued checkpoint may outlive its caller's acknowledgement deadline.
	// Keep the lock until the writer has actually rolled back the transaction.
	await(t, func() bool { return s.Status().LastError != "" })
	if s.ExportStatus().Pending != 1 || s.ExportStatus().Acked != 0 {
		t.Fatal("failed local checkpoint lost pending delivery")
	}
	if _, err = db.Exec("ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = s.WaitExport(ctx); err != nil {
		t.Fatal(err)
	}
	if calls.Load() < 2 || s.ExportStatus().Acked != 1 {
		t.Fatal("collector-committed event was not safely retried")
	}
}

func TestExportCrashHelper(t *testing.T) {
	path := os.Getenv("OPENWAF_CRASH_EXPORT_PATH")
	if path == "" {
		t.Skip("subprocess helper")
	}
	s, err := Open(exportOptions(path, os.Getenv("OPENWAF_CRASH_EXPORT_URL")))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		appendTest(t, s, fmt.Sprint(i))
	}
	if err = os.WriteFile(path+".ready", []byte("committed with pending exports"), 0600); err != nil {
		t.Fatal(err)
	}
	for {
		time.Sleep(time.Hour)
	}
}

func TestForcedExportCrashReplaysUnacknowledgedIDs(t *testing.T) {
	var good atomic.Bool
	var mu sync.Mutex
	received := map[string]bool{}
	var duplicates atomic.Int32
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b ExportBatch
		json.NewDecoder(r.Body).Decode(&b)
		ack := ExportAck{BatchID: b.BatchID}
		mu.Lock()
		for _, e := range b.Events {
			key := b.SourceID + "/" + e.ID
			if received[key] {
				duplicates.Add(1)
			}
			received[key] = true
			ack.IDs = append(ack.IDs, e.ID)
		}
		mu.Unlock()
		if !good.Load() {
			ack.BatchID = "acknowledgement-lost"
		}
		json.NewEncoder(w).Encode(ack)
	}))
	defer collector.Close()
	path := filepath.Join(t.TempDir(), "events.db")
	cmd := exec.Command(os.Args[0], "-test.run=^TestExportCrashHelper$", "-test.v")
	cmd.Env = append(os.Environ(), "OPENWAF_CRASH_EXPORT_PATH="+path, "OPENWAF_CRASH_EXPORT_URL="+collector.URL)
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
	await(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(received) > 0 })
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	waited = true
	good.Store(true)
	s := openTest(t, exportOptions(path, collector.URL))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.WaitExport(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	count := len(received)
	mu.Unlock()
	if count != 40 || duplicates.Load() == 0 || s.ExportStatus().Acked != 40 || s.ExportStatus().AckedOccurrences != 80 {
		t.Fatalf("crash replay: received=%d duplicates=%d export=%+v", count, duplicates.Load(), s.ExportStatus())
	}
}
func await(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition did not become true")
}
func exportOptions(path, url string) Options {
	return Options{Path: path, MaxRows: 2, Export: ExportOptions{URL: url, Token: "test-export-secret", RetryMin: 5 * time.Millisecond, RetryMax: 30 * time.Millisecond}}
}

func TestAppendBackpressureDoesNotDiscardConcurrentEvents(t *testing.T) {
	s := openTest(t, Options{Path: filepath.Join(t.TempDir(), "events.db"), QueueSize: 1})
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for worker := 0; worker < 32; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				err := s.Append(ctx, Record{ID: fmt.Sprintf("%d-%d", worker, i), Time: time.Now(), Data: []byte(`{}`)})
				cancel()
				if err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	status := s.Status()
	if !status.Healthy || status.CommittedRecords != 640 || status.CommittedOccurrences != 640 || status.QueueDropped != 0 || status.Pending != 0 {
		t.Fatalf("lost records: %+v", status)
	}
}

func TestCompletedCommitIsNotReportedLostAtDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ack := make(chan error, 1)
	ack <- nil
	if err, uncertain := awaitCommit(ctx, ack); err != nil || uncertain {
		t.Fatal("completed durable commit misclassified as timeout")
	}
}

func TestOutboxSurvivesRetentionPauseAndRestart(t *testing.T) {
	var down atomic.Bool
	down.Store(true)
	var mu sync.Mutex
	received := map[string]bool{}
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			http.Error(w, "offline", 503)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-export-secret" {
			http.Error(w, "auth", 401)
			return
		}
		var b ExportBatch
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			http.Error(w, "json", 400)
			return
		}
		ack := ExportAck{BatchID: b.BatchID}
		mu.Lock()
		for _, e := range b.Events {
			received[e.ID] = true
			ack.IDs = append(ack.IDs, e.ID)
		}
		mu.Unlock()
		json.NewEncoder(w).Encode(ack)
	}))
	defer collector.Close()
	options := exportOptions(filepath.Join(t.TempDir(), "events.db"), collector.URL)
	s := openTest(t, options)
	for i := 0; i < 40; i++ {
		appendTest(t, s, fmt.Sprint(i))
	}
	await(t, func() bool { return s.ExportStatus().Failures > 0 })
	if status := s.Status(); status.Stored != 2 || status.Export.Pending != 40 || status.Export.EnqueuedOccurrences != 80 {
		t.Fatalf("outbox evicted with history: %+v", status)
	}
	source := s.ExportStatus().SourceID
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	changed := options
	changed.Export.URL = collector.URL + "/different"
	if other, err := Open(changed); err == nil {
		other.Close(context.Background())
		t.Fatal("destination change stranded pending deliveries")
	}
	paused := options
	paused.Export.URL = ""
	s = openTest(t, paused)
	appendTest(t, s, "paused")
	if !s.ExportStatus().Paused || s.ExportStatus().Pending != 41 {
		t.Fatal("paused export lost backlog")
	}
	s.Close(context.Background())
	down.Store(false)
	s = openTest(t, options)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.WaitExport(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	count := len(received)
	mu.Unlock()
	if count != 41 || s.ExportStatus().Acked != 41 || s.ExportStatus().AckedOccurrences != 82 || s.ExportStatus().SourceID != source {
		t.Fatalf("restart delivery mismatch: %d %+v", count, s.ExportStatus())
	}
}

func TestLostAcknowledgementRetriesWithoutLosingIDs(t *testing.T) {
	var requests atomic.Int32
	var duplicates atomic.Int32
	var mu sync.Mutex
	received := map[string]bool{}
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b ExportBatch
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			http.Error(w, "json", 400)
			return
		}
		ack := ExportAck{BatchID: b.BatchID}
		mu.Lock()
		for _, e := range b.Events {
			if received[e.ID] {
				duplicates.Add(1)
			}
			received[e.ID] = true
			ack.IDs = append(ack.IDs, e.ID)
		}
		mu.Unlock()
		if requests.Add(1) == 1 {
			ack.BatchID = "wrong-batch"
		}
		json.NewEncoder(w).Encode(ack)
	}))
	defer collector.Close()
	s := openTest(t, exportOptions(filepath.Join(t.TempDir(), "events.db"), collector.URL))
	for i := 0; i < 20; i++ {
		appendTest(t, s, fmt.Sprint(i))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.WaitExport(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	count := len(received)
	mu.Unlock()
	if count != 20 || duplicates.Load() == 0 || s.ExportStatus().Failures == 0 || s.ExportStatus().Acked != 20 || !s.Status().Healthy {
		t.Fatalf("retry/ack mismatch: %d %+v", count, s.Status())
	}
}

func TestOutboxCapacityNeverEvictsUnacknowledgedDeliveries(t *testing.T) {
	var down atomic.Bool
	down.Store(true)
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			http.Error(w, "offline", 503)
			return
		}
		var b ExportBatch
		json.NewDecoder(r.Body).Decode(&b)
		ack := ExportAck{BatchID: b.BatchID}
		for _, e := range b.Events {
			ack.IDs = append(ack.IDs, e.ID)
		}
		json.NewEncoder(w).Encode(ack)
	}))
	defer collector.Close()
	o := exportOptions(filepath.Join(t.TempDir(), "events.db"), collector.URL)
	o.Export.MaxRows = 2
	s := openTest(t, o)
	appendTest(t, s, "first")
	appendTest(t, s, "second")
	if err := s.Append(context.Background(), Record{ID: "cannot-fit", Time: time.Now(), Data: []byte(`{}`)}); err == nil {
		t.Fatal("full outbox accepted untracked event")
	}
	if s.ExportStatus().Pending != 2 || s.Status().WriteFailed != 1 || s.Status().CommittedRecords != 2 {
		t.Fatalf("full outbox changed committed data: %+v", s.Status())
	}
	down.Store(false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.WaitExport(ctx); err != nil {
		t.Fatal(err)
	}
	if s.ExportStatus().Acked != 2 {
		t.Fatal("unacknowledged entries were evicted")
	}
}

func TestExportRedirectDoesNotLeakAuthorization(t *testing.T) {
	var leaked atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer redirect.Close()
	s := openTest(t, exportOptions(filepath.Join(t.TempDir(), "events.db"), redirect.URL))
	appendTest(t, s, "one")
	await(t, func() bool { return s.ExportStatus().Failures > 0 })
	if leaked.Load() != 0 || s.ExportStatus().Pending != 1 {
		t.Fatal("redirect followed or pending delivery discarded")
	}
}
