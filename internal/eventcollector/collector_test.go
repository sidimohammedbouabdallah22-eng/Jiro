package eventcollector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/eventstore"
)

const testToken = "reference-collector-test-token-32-characters"

func batchFor(ids ...string) eventstore.ExportBatch {
	b := eventstore.ExportBatch{SchemaVersion: 1, SourceID: strings.Repeat("a", 32)}
	h := sha256.New()
	h.Write([]byte(b.SourceID))
	for i, id := range ids {
		b.Events = append(b.Events, eventstore.ExportEvent{Sequence: int64(i + 1), ID: id, Occurrences: 3, Event: json.RawMessage(fmt.Sprintf(`{"id":%q,"occurrences":3}`, id))})
		h.Write([]byte{0})
		h.Write([]byte(id))
	}
	b.BatchID = hex.EncodeToString(h.Sum(nil))
	return b
}

type gateReader struct {
	reader           io.Reader
	entered, proceed chan struct{}
	once             sync.Once
}

func (g *gateReader) Read(b []byte) (int, error) {
	g.once.Do(func() { close(g.entered); <-g.proceed })
	return g.reader.Read(b)
}
func TestCloseDrainsActiveBatchBeforeDatabaseRestart(t *testing.T) {
	o := Options{Path: filepath.Join(t.TempDir(), "collector.db"), Token: testToken}
	c, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	data, _ := json.Marshal(batchFor("one"))
	body := &gateReader{reader: bytes.NewReader(data), entered: make(chan struct{}), proceed: make(chan struct{})}
	r := httptest.NewRequest("POST", "/v1/events", body)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()
	handled := make(chan struct{})
	go func() { defer close(handled); c.ServeHTTP(w, r) }()
	<-body.entered
	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	select {
	case <-closed:
		close(body.proceed)
		t.Fatal("collector closed its database during an active request")
	case <-time.After(20 * time.Millisecond):
	}
	close(body.proceed)
	<-handled
	if err = <-closed; err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 {
		t.Fatalf("active commit failed during close: %d", w.Code)
	}
	replacement, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	totals, err := replacement.Totals(context.Background())
	if err != nil || totals.Records != 1 {
		t.Fatalf("restart lost final commit: %+v %v", totals, err)
	}
}
func send(t *testing.T, c *Collector, b eventstore.ExportBatch, token string) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/events", bytes.NewReader(data))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	c.ServeHTTP(w, r)
	return w
}
func TestDurableDeduplicationAndImmutableIdentity(t *testing.T) {
	o := Options{Path: filepath.Join(t.TempDir(), "collector.db"), Token: testToken}
	c, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { c.Close() }()
	b := batchFor("one", "two")
	if w := send(t, c, b, "bad"); w.Code != 401 {
		t.Fatal("unauthenticated batch accepted")
	}
	for i := 0; i < 2; i++ {
		w := send(t, c, b, testToken)
		if w.Code != 200 {
			t.Fatalf("batch rejected: %d %s", w.Code, w.Body.String())
		}
		var ack eventstore.ExportAck
		if err = json.Unmarshal(w.Body.Bytes(), &ack); err != nil || ack.BatchID != b.BatchID || len(ack.IDs) != 2 {
			t.Fatal("incorrect acknowledgement")
		}
	}
	totals, err := c.Totals(context.Background())
	if err != nil || totals.Records != 2 || totals.Occurrences != 6 {
		t.Fatalf("duplicates inflated totals: %+v %v", totals, err)
	}
	b.Events[0].Event = json.RawMessage(`{"id":"one","occurrences":3,"changed":true}`)
	if w := send(t, c, b, testToken); w.Code != 409 {
		t.Fatalf("immutable ID overwritten: %d", w.Code)
	}
	c.Close()
	c, err = Open(o)
	if err != nil {
		t.Fatal(err)
	}
	totals, err = c.Totals(context.Background())
	if err != nil || totals.Records != 2 || totals.Occurrences != 6 {
		t.Fatal("collector restart lost committed data")
	}
}
func TestCollectorDoesNotAcknowledgeFailedCommit(t *testing.T) {
	c, err := Open(Options{Path: filepath.Join(t.TempDir(), "collector.db"), Token: testToken, MaxBytes: 4 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err = c.db.Exec("CREATE TABLE filler(data BLOB)"); err != nil {
		t.Fatal(err)
	}
	full := false
	for i := 0; i < 1200; i++ {
		if _, err = c.db.Exec("INSERT INTO filler VALUES(zeroblob(4000))"); err != nil {
			if !strings.Contains(strings.ToLower(err.Error()), "full") {
				t.Fatal(err)
			}
			full = true
			break
		}
	}
	if !full {
		t.Fatal("disk quota was not exhausted")
	}
	large := batchFor("one")
	large.Events[0].Event = json.RawMessage(fmt.Sprintf(`{"id":"one","occurrences":3,"message":%q}`, strings.Repeat("x", 15000)))
	if w := send(t, c, large, testToken); w.Code != 503 || strings.Contains(w.Body.String(), "acked_ids") {
		t.Fatalf("uncommitted record acknowledged: %d %s", w.Code, w.Body.String())
	}
	if _, err = c.db.Exec("DROP TABLE filler"); err != nil {
		t.Fatal(err)
	}
	if w := send(t, c, large, testToken); w.Code != 200 {
		t.Fatalf("collector did not recover: %d", w.Code)
	}
}
func TestInvalidBatchDoesNotCommit(t *testing.T) {
	c, err := Open(Options{Path: filepath.Join(t.TempDir(), "collector.db"), Token: testToken})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	b := batchFor("one")
	b.BatchID = "incorrect"
	if w := send(t, c, b, testToken); w.Code != 400 {
		t.Fatal("invalid batch identity accepted")
	}
	totals, err := c.Totals(context.Background())
	if err != nil || totals.Records != 0 {
		t.Fatal("invalid batch committed")
	}
}
