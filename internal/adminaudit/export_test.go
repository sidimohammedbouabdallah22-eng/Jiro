package adminaudit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/eventcollector"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/eventstore"
)

func TestAuditExportOutageLostAckReplayAndBinding(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, "receiver.db")
	token := strings.Repeat("a", 64)
	collector, err := eventcollector.Open(eventcollector.Options{Path: dbPath, Token: token})
	if err != nil {
		t.Fatal(err)
	}
	var outage atomic.Bool
	outage.Store(true)
	var loseAck atomic.Bool
	loseAck.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if outage.Load() {
			http.Error(w, "unavailable", 503)
			return
		}
		response := httptest.NewRecorder()
		collector.ServeHTTP(response, r)
		if response.Code == 200 && loseAck.CompareAndSwap(true, false) {
			http.Error(w, "ack lost after commit", 503)
			return
		}
		for key, values := range response.Header() {
			w.Header()[key] = values
		}
		w.WriteHeader(response.Code)
		w.Write(response.Body.Bytes())
	}))
	defer server.Close()
	journal, err := Open(filepath.Join(root, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	for i := 0; i < 70; i++ {
		if _, err := journal.Append(Record{Operation: "policy.activate", Actor: "test", Outcome: "success"}); err != nil {
			t.Fatal(err)
		}
	}
	options := eventstore.ExportOptions{URL: server.URL + "/v1/events", Token: token, RetryMin: 10 * time.Millisecond, RetryMax: 30 * time.Millisecond}
	exporter, err := NewExporter(journal, options)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for exporter.Status().Failures == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if status := exporter.Status(); status.Healthy || status.Pending != 71 {
		t.Fatal("audit outage was hidden", status)
	}
	outage.Store(false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	err = exporter.Wait(ctx)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	status := exporter.Status()
	if status.Acknowledged != 71 || status.Pending != 0 || loseAck.Load() {
		t.Fatal("incomplete delivery", status)
	}
	exporter.Close()
	collector.Close()
	// Reopen the independent receiver and replay the full local journal.
	collector, err = eventcollector.Open(eventcollector.Options{Path: dbPath, Token: token})
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	exporter, err = NewExporter(journal, options)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	err = exporter.Wait(ctx)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	meta := journal.Status().Metadata
	totals, err := collector.SourceTotals(context.Background(), status.SourceID)
	if err != nil || totals.Records != meta.Records || totals.Occurrences != meta.Records {
		t.Fatal("audit replay inflated receipts", totals, err)
	}
	exporter.Close()
	if other, err := NewExporter(journal, eventstore.ExportOptions{URL: server.URL + "/different", Token: token}); err == nil {
		other.Close()
		t.Fatal("journal export destination changed silently")
	}
	paused, err := NewExporter(journal, eventstore.ExportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if status := paused.Status(); !status.Paused || status.Healthy || status.Pending != meta.Records {
		t.Fatal("disabled bound export did not remain visible", status)
	}
	paused.Close()
	// Verify the independent copy retains the original canonical hash chain.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query("SELECT data FROM collected_events WHERE source_id=? ORDER BY sequence", status.SourceID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	previous := ""
	count := uint64(0)
	for rows.Next() {
		var data []byte
		if err = rows.Scan(&data); err != nil {
			t.Fatal(err)
		}
		var record Record
		if err = json.Unmarshal(data, &record); err != nil {
			t.Fatal(err)
		}
		count++
		if record.Sequence != count || record.Previous != previous || record.Hash != digest(record) {
			t.Fatal("independent audit chain is invalid")
		}
		previous = record.Hash
	}
	if rows.Err() != nil || count != meta.Records || previous != meta.LastHash {
		t.Fatal("independent audit copy is incomplete")
	}
}

func TestAuditExportRejectsIncompleteAcknowledgement(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch eventstore.ExportBatch
		json.NewDecoder(r.Body).Decode(&batch)
		json.NewEncoder(w).Encode(eventstore.ExportAck{BatchID: batch.BatchID, IDs: []string{}})
	}))
	defer server.Close()
	j, err := Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	e, err := NewExporter(j, eventstore.ExportOptions{URL: server.URL, Token: strings.Repeat("t", 32), RetryMin: 10 * time.Millisecond, RetryMax: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := e.Wait(ctx); err == nil || e.Status().Acknowledged != 0 || e.Status().Failures == 0 {
		t.Fatal("incomplete acknowledgement advanced audit delivery")
	}
	if strings.Contains(e.Status().LastError, strings.Repeat("t", 32)) {
		t.Fatal("audit error exposed the collector credential")
	}
	if j.Status().ExportDestinationSHA256 == "" {
		t.Fatal("export binding was not committed")
	}
	// Binding is a digest of the destination, without the secret credential.
	sum := sha256.Sum256([]byte(server.URL))
	if j.Status().ExportDestinationSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("wrong destination binding")
	}
}
