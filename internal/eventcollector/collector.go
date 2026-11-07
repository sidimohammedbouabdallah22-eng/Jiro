// Package eventcollector implements the reference acknowledged-export receiver.
// It acknowledges only after a FULL-synchronous, idempotent SQLite commit.
package eventcollector

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gofrs/flock"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/eventstore"
)

const applicationID = 0x4f574543

type Options struct {
	Path, Token    string
	MaxBytes       int64
	StartupTimeout time.Duration
}
type Collector struct {
	lease      *flock.Flock
	closeOnce  sync.Once
	closeError error
	db         *sql.DB
	token      [32]byte
	admission  chan struct{}
	lifecycle  sync.RWMutex
	closed     bool
	requests   sync.WaitGroup
}
type Totals struct {
	Records     uint64 `json:"records"`
	Occurrences uint64 `json:"occurrences"`
}

func Open(o Options) (_ *Collector, resultErr error) {
	started := time.Now()
	stage := "validation"
	defer func() {
		if resultErr != nil {
			resultErr = fmt.Errorf("collector database startup stage %s after %s: %w", stage, time.Since(started).Round(time.Millisecond), resultErr)
		}
	}()
	if o.StartupTimeout == 0 {
		o.StartupTimeout = eventstore.DefaultStartupTimeout
	}
	if o.StartupTimeout < time.Second || o.StartupTimeout > 2*time.Minute {
		return nil, errors.New("storage startup timeout must be 1s..2m")
	}
	if o.MaxBytes == 0 {
		o.MaxBytes = 256 << 20
	}
	if o.Path == "" || len(o.Token) < 32 || len(o.Token) > 4096 || strings.ContainsAny(o.Token, "\r\n") || o.MaxBytes < 4<<20 || o.MaxBytes > 1<<30 {
		return nil, errors.New("invalid collector path, token or disk budget")
	}
	if err := os.MkdirAll(filepath.Dir(o.Path), 0700); err != nil {
		return nil, err
	}
	lease := flock.New(o.Path + ".lock")
	stage = "lease"
	locked, err := lease.TryLock()
	if err != nil || !locked {
		lease.Close()
		if err != nil {
			return nil, fmt.Errorf("acquire collector database lease: %w", err)
		}
		return nil, errors.New("collector database is owned by another process or maintenance operation")
	}
	leaseOwned := false
	defer func() {
		if !leaseOwned {
			lease.Close()
		}
	}()
	file, err := os.OpenFile(o.Path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	file.Close()
	db, err := sql.Open("sqlite", o.Path)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			db.Close()
		}
	}()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), o.StartupTimeout)
	defer cancel()
	var appID int
	stage = "database identity"
	if err = db.QueryRowContext(ctx, "PRAGMA application_id").Scan(&appID); err != nil {
		return nil, err
	}
	var tables int
	if err = db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").Scan(&tables); err != nil {
		return nil, err
	}
	if appID != applicationID && (appID != 0 || tables != 0) {
		return nil, errors.New("database is not an OpenWAF reference collector database")
	}
	var version int
	if err = db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return nil, err
	}
	if version > 1 {
		return nil, errors.New("collector database uses a newer schema")
	}
	for _, pragma := range []string{"PRAGMA busy_timeout=100", "PRAGMA journal_mode=DELETE", "PRAGMA synchronous=FULL", "PRAGMA cache_size=-2048", fmt.Sprintf("PRAGMA max_page_count=%d", o.MaxBytes/4096)} {
		stage = pragma
		if _, err = db.ExecContext(ctx, pragma); err != nil {
			return nil, err
		}
	}
	var pageSize, pages int64
	var check string
	stage = "page budget"
	if err = db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize); err != nil {
		return nil, err
	}
	if err = db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages); err != nil {
		return nil, err
	}
	if pageSize != 4096 || pages*4096 > o.MaxBytes {
		return nil, errors.New("collector database exceeds the configured page/disk budget")
	}
	stage = "integrity check"
	if err = db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&check); err != nil || check != "ok" {
		return nil, errors.New("collector database integrity check failed")
	}
	stage = "schema transaction"
	if _, err = db.ExecContext(ctx, fmt.Sprintf(`BEGIN; CREATE TABLE IF NOT EXISTS collected_events(source_id TEXT NOT NULL,id TEXT NOT NULL,sequence INTEGER NOT NULL,occurrences INTEGER NOT NULL,data BLOB NOT NULL,digest TEXT NOT NULL,PRIMARY KEY(source_id,id)); CREATE TABLE IF NOT EXISTS collector_totals(singleton INTEGER PRIMARY KEY CHECK(singleton=1),records INTEGER NOT NULL,occurrences INTEGER NOT NULL); INSERT OR IGNORE INTO collector_totals VALUES(1,0,0); PRAGMA application_id=%d; PRAGMA user_version=1; COMMIT;`, applicationID)); err != nil {
		return nil, err
	}
	success = true
	leaseOwned = true
	return &Collector{db: db, lease: lease, token: sha256.Sum256([]byte(o.Token)), admission: make(chan struct{}, 8)}, nil
}
func (c *Collector) Close() error {
	c.closeOnce.Do(func() {
		c.lifecycle.Lock()
		c.closed = true
		c.lifecycle.Unlock()
		c.requests.Wait()
		c.closeError = c.db.Close()
		_ = c.lease.Close()
	})
	return c.closeError
}
func (c *Collector) Totals(ctx context.Context) (Totals, error) {
	var totals Totals
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	err := c.db.QueryRowContext(ctx, "SELECT records,occurrences FROM collector_totals WHERE singleton=1").Scan(&totals.Records, &totals.Occurrences)
	return totals, err
}
func (c *Collector) SourceTotals(ctx context.Context, source string) (Totals, error) {
	var totals Totals
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	err := c.db.QueryRowContext(ctx, "SELECT count(*),coalesce(sum(occurrences),0) FROM collected_events WHERE source_id=?", source).Scan(&totals.Records, &totals.Occurrences)
	return totals, err
}

func (c *Collector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.lifecycle.RLock()
	if c.closed {
		c.lifecycle.RUnlock()
		http.Error(w, "Collector restarting", 503)
		return
	}
	c.requests.Add(1)
	c.lifecycle.RUnlock()
	defer c.requests.Done()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != "POST" || r.URL.Path != "/v1/events" {
		http.NotFound(w, r)
		return
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	sum := sha256.Sum256([]byte(token))
	if !ok || subtle.ConstantTimeCompare(sum[:], c.token[:]) != 1 {
		http.Error(w, "Authentication required", 401)
		return
	}
	select {
	case c.admission <- struct{}{}:
		defer func() { <-c.admission }()
	default:
		w.Header().Set("Retry-After", "1")
		http.Error(w, "Collector busy", 503)
		return
	}
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		http.Error(w, "JSON required", 415)
		return
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	var batch eventstore.ExportBatch
	if err := decoder.Decode(&batch); err != nil {
		http.Error(w, "Invalid or oversized export batch", 400)
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		http.Error(w, "Trailing JSON", 400)
		return
	}
	if err := validate(batch); err != nil {
		http.Error(w, "Invalid export batch", 400)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := c.commit(ctx, batch); err != nil {
		if errors.Is(err, errCollision) {
			http.Error(w, "An event ID already has different content", 409)
		} else {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "Collector could not commit batch", 503)
		}
		return
	}
	ack := eventstore.ExportAck{BatchID: batch.BatchID, IDs: make([]string, 0, len(batch.Events))}
	for _, e := range batch.Events {
		ack.IDs = append(ack.IDs, e.ID)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ack)
}
func validate(b eventstore.ExportBatch) error {
	source, err := hex.DecodeString(b.SourceID)
	if err != nil || len(source) != 16 || len(b.SourceID) != 32 || b.SchemaVersion != 1 || len(b.Events) < 1 || len(b.Events) > 32 {
		return errors.New("invalid envelope")
	}
	h := sha256.New()
	h.Write([]byte(b.SourceID))
	ids := map[string]bool{}
	for _, e := range b.Events {
		if e.ID == "" || len(e.ID) > 128 || ids[e.ID] || e.Sequence < 1 || e.Occurrences < 1 || e.Occurrences > 1<<62 || len(e.Event) > eventstore.MaxRecordBytes || !json.Valid(e.Event) {
			return errors.New("invalid event")
		}
		ids[e.ID] = true
		h.Write([]byte{0})
		h.Write([]byte(e.ID))
		var metadata struct {
			ID          string `json:"id"`
			Occurrences uint64 `json:"occurrences"`
		}
		if err = json.Unmarshal(e.Event, &metadata); err != nil || metadata.ID != e.ID || (metadata.Occurrences != 0 && metadata.Occurrences != e.Occurrences) {
			return errors.New("event identity/count mismatch")
		}
	}
	if hex.EncodeToString(h.Sum(nil)) != b.BatchID {
		return errors.New("batch identity mismatch")
	}
	return nil
}

var errCollision = errors.New("event identity collision")

func (c *Collector) commit(ctx context.Context, b eventstore.ExportBatch) error {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var records, occurrences uint64
	for _, e := range b.Events {
		hash := sha256.New()
		hash.Write(e.Event)
		fmt.Fprintf(hash, "\x00%d", e.Occurrences)
		digest := hex.EncodeToString(hash.Sum(nil))
		var existing string
		err = tx.QueryRowContext(ctx, "SELECT digest FROM collected_events WHERE source_id=? AND id=?", b.SourceID, e.ID).Scan(&existing)
		if err == nil {
			if existing != digest {
				return errCollision
			}
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO collected_events VALUES(?,?,?,?,?,?)", b.SourceID, e.ID, e.Sequence, e.Occurrences, []byte(e.Event), digest); err != nil {
			return err
		}
		records++
		occurrences += e.Occurrences
	}
	if _, err = tx.ExecContext(ctx, "UPDATE collector_totals SET records=records+?,occurrences=occurrences+? WHERE singleton=1", records, occurrences); err != nil {
		return err
	}
	return tx.Commit()
}
