package eventstore

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestExportHealthRecoversAfterLateCommittedCheckpointWithoutNewTraffic(t *testing.T) {
	received, allowAck := make(chan struct{}), make(chan struct{})
	committed, publishCommit := make(chan struct{}), make(chan struct{})
	var ackOnce, commitOnce sync.Once
	var calls atomic.Int32
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch ExportBatch
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Error(err)
			return
		}
		if calls.Add(1) == 1 {
			close(received)
			<-allowAck
		}
		ack := ExportAck{BatchID: batch.BatchID}
		for _, event := range batch.Events {
			ack.IDs = append(ack.IDs, event.ID)
		}
		_ = json.NewEncoder(w).Encode(ack)
	}))
	defer collector.Close()
	defer ackOnce.Do(func() { close(allowAck) })
	defer commitOnce.Do(func() { close(publishCommit) })
	s := openTest(t, exportOptions(filepath.Join(t.TempDir(), "events.db"), collector.URL))
	appendTest(t, s, "late-checkpoint")
	select {
	case <-received:
	case <-time.After(5 * time.Second):
		t.Fatal("receiver did not receive event")
	}
	s.writeMu.Lock()
	original := s.commit
	var held atomic.Bool
	s.commit = func(tx *sql.Tx) error {
		err := original(tx)
		if err == nil && held.CompareAndSwap(false, true) {
			close(committed)
			<-publishCommit
		}
		return err
	}
	s.writeMu.Unlock()
	ackOnce.Do(func() { close(allowAck) })
	select {
	case <-committed:
	case <-time.After(5 * time.Second):
		t.Fatal("checkpoint did not commit")
	}
	await(t, func() bool { return s.ExportStatus().Failures > 0 })
	if status := s.ExportStatus(); status.Healthy || status.Pending != 1 || status.Acked != 0 {
		t.Fatal("unpublished checkpoint was treated as fully drained", status)
	}
	publishedAt := time.Now().UTC()
	commitOnce.Do(func() { close(publishCommit) })
	await(t, func() bool {
		status := s.ExportStatus()
		return status.Pending == 0 && status.Acked == 1 && status.Healthy
	})
	status := s.ExportStatus()
	if status.Failures == 0 || calls.Load() != 1 || status.LastSuccess.IsZero() || !status.LastSuccess.Before(publishedAt) {
		t.Fatal("late checkpoint lost history, replayed, or fabricated new receiver contact", status, calls.Load())
	}
}
