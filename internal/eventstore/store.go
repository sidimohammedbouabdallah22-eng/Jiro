// Package eventstore provides bounded, acknowledged SQLite group commits and
// a transactional export outbox. Append applies bounded backpressure; storage
// failures and uncertain acknowledgements remain observable.
package eventstore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gofrs/flock"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

const MaxRecordBytes = 16 << 10
const DefaultStartupTimeout = 30 * time.Second

type Options struct {
	Path           string
	MaxBytes       int64
	MaxRows        int
	MaxAge         time.Duration
	QueueSize      int
	Export         ExportOptions
	CommitTimeout  time.Duration
	StartupTimeout time.Duration
}

func (o Options) defaults() Options {
	if o.StartupTimeout == 0 {
		o.StartupTimeout = DefaultStartupTimeout
	}
	if o.MaxBytes == 0 {
		o.MaxBytes = 64 << 20
	}
	if o.MaxRows == 0 {
		o.MaxRows = 10000
	}
	if o.MaxAge == 0 {
		o.MaxAge = 7 * 24 * time.Hour
	}
	if o.QueueSize == 0 {
		o.QueueSize = 256
	}
	if o.CommitTimeout == 0 {
		o.CommitTimeout = 5 * time.Second
	}
	return o
}

type Record struct {
	Sequence         int64
	ID               string
	Time             time.Time
	Action, IP, Path string
	Data             []byte
	Occurrences      uint64
}
type Query struct {
	Application    string
	Before         int64
	Limit          int
	Action, Search string
}
type Status struct {
	StartupMilliseconds   float64      `json:"startup_ms"`
	Enabled               bool         `json:"enabled"`
	Healthy               bool         `json:"healthy"`
	Queued                int          `json:"queued"`
	QueueCapacity         int          `json:"queue_capacity"`
	Pending               int64        `json:"pending_writes"`
	Stored                int64        `json:"stored"`
	PayloadBytes          int64        `json:"payload_bytes"`
	MaxBytes              int64        `json:"max_database_bytes"`
	MaxRows               int          `json:"max_rows"`
	RetentionDays         float64      `json:"retention_days"`
	QueueDropped          uint64       `json:"queue_dropped"`
	WriteFailed           uint64       `json:"write_failed"`
	LastError             string       `json:"last_error,omitempty"`
	LastCommit            time.Time    `json:"last_commit,omitempty"`
	CommittedRecords      uint64       `json:"committed_records"`
	CommittedOccurrences  uint64       `json:"committed_occurrences"`
	IngestTimeouts        uint64       `json:"ingest_timeouts"`
	WriteRetries          uint64       `json:"write_retries"`
	MaxCommitMilliseconds float64      `json:"max_commit_ms"`
	Export                ExportStatus `json:"export"`
}
type item struct {
	record     *Record
	barrier    chan error
	ack        chan error
	checkpoint []exportReceipt
}
type exportReceipt struct {
	sequence int64
	id       string
}
type Store struct {
	startupMilliseconds                                                            float64
	lease                                                                          *flock.Flock
	db                                                                             *sql.DB
	opts                                                                           Options
	queue                                                                          chan item
	done                                                                           chan struct{}
	mu                                                                             sync.Mutex
	closed                                                                         bool
	senders                                                                        sync.WaitGroup
	closing                                                                        chan struct{}
	healthMu                                                                       sync.Mutex
	lastError                                                                      string
	lastCommit                                                                     time.Time
	dropped, failed                                                                atomic.Uint64
	rows, bytes                                                                    atomic.Int64
	pending                                                                        atomic.Int64
	now                                                                            func() time.Time
	writeMu                                                                        sync.Mutex
	commit                                                                         func(*sql.Tx) error
	ingestTimeouts                                                                 atomic.Uint64
	writeRetries                                                                   atomic.Uint64
	maxCommitMicroseconds                                                          atomic.Int64
	committedRecords, committedOccurrences                                         atomic.Uint64
	exportBound                                                                    bool
	exportDestination, exportSource                                                string
	exportCancel                                                                   context.CancelFunc
	exportDone                                                                     chan struct{}
	exportRows, exportBytes                                                        atomic.Int64
	exportEnqueued, exportEnqueuedOccurrences, exportAcked, exportAckedOccurrences atomic.Uint64
	exportMu                                                                       sync.Mutex
	exportError                                                                    string
	exportSuccess                                                                  time.Time
	exportAttempts, exportFailures                                                 atomic.Uint64
}

func Open(options Options) (_ *Store, resultErr error) {
	started := time.Now()
	stage := "validation"
	defer func() {
		if resultErr != nil {
			resultErr = fmt.Errorf("event database startup stage %s after %s: %w", stage, time.Since(started).Round(time.Millisecond), resultErr)
		}
	}()
	o := options.defaults()
	if o.StartupTimeout < time.Second || o.StartupTimeout > 2*time.Minute {
		return nil, errors.New("storage startup timeout must be 1s..2m")
	}
	if err := o.Export.validate(); err != nil {
		return nil, err
	}
	if o.Path == "" || o.MaxBytes < 4<<20 || o.MaxBytes > 1<<30 || o.MaxRows < 1 || o.MaxRows > 100000 || o.MaxAge < time.Minute || o.MaxAge > 365*24*time.Hour || o.QueueSize < 1 || o.QueueSize > 4096 || o.CommitTimeout < 100*time.Millisecond || o.CommitTimeout > 30*time.Second {
		return nil, errors.New("invalid event-store limits")
	}
	if err := os.MkdirAll(filepath.Dir(o.Path), 0700); err != nil {
		return nil, err
	}
	stage = "lease"
	lease := flock.New(o.Path + ".lock")
	locked, err := lease.TryLock()
	if err != nil || !locked {
		lease.Close()
		if err != nil {
			return nil, fmt.Errorf("acquire event database lease: %w", err)
		}
		return nil, errors.New("event database is owned by another process or maintenance operation")
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
	_ = file.Close()
	db, err := sql.Open("sqlite", o.Path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	success := false
	defer func() {
		if !success {
			_ = db.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), o.StartupTimeout)
	defer cancel()
	// DELETE journaling avoids a WAL that could grow behind a pinned reader.
	// The rollback journal can temporarily add approximately one database's size.
	for _, pragma := range []string{"PRAGMA busy_timeout=100", "PRAGMA journal_mode=DELETE", "PRAGMA synchronous=FULL", "PRAGMA cache_size=-2048", "PRAGMA temp_store=MEMORY", fmt.Sprintf("PRAGMA max_page_count=%d", o.MaxBytes/4096)} {
		stage = pragma
		if _, err = db.ExecContext(ctx, pragma); err != nil {
			return nil, err
		}
	}
	var pageSize, version int
	var integrity string
	stage = "page size"
	if err = db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize); err != nil {
		return nil, err
	}
	if pageSize != 4096 {
		return nil, errors.New("event database must use 4096-byte pages")
	}
	stage = "schema version"
	if err = db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return nil, err
	}
	if version > 2 {
		return nil, errors.New("event database has a newer unsupported schema")
	}
	stage = "integrity check"
	if err = db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&integrity); err != nil || integrity != "ok" {
		return nil, fmt.Errorf("event database integrity check failed: %v", err)
	}
	stage = "schema transaction"
	if err = initializeSchema(ctx, db, version); err != nil {
		return nil, err
	}
	stage = "page budget"
	var pages int64
	if err = db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages); err != nil {
		return nil, err
	}
	if pages*4096 > o.MaxBytes {
		return nil, errors.New("existing event database exceeds the configured disk budget")
	}
	s := &Store{db: db, lease: lease, opts: o, queue: make(chan item, o.QueueSize), done: make(chan struct{}), closing: make(chan struct{}), now: time.Now, commit: (*sql.Tx).Commit}
	stage = "export initialization"
	if err = s.initializeExport(ctx); err != nil {
		return nil, err
	}
	stage = "retention reconciliation"
	if err = s.writeBatchWithTimeout(ctx, nil, o.StartupTimeout); err != nil {
		return nil, err
	}
	success = true
	s.startupMilliseconds = float64(time.Since(started).Microseconds()) / 1000
	leaseOwned = true
	exportContext, cancelExport := context.WithCancel(context.Background())
	s.exportCancel = cancelExport
	s.exportDone = make(chan struct{})
	if o.Export.URL != "" {
		go s.runExport(exportContext)
	} else {
		close(s.exportDone)
	}
	go s.run()
	return s, nil
}

func initializeSchema(ctx context.Context, db *sql.DB, version int) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT NOT NULL UNIQUE,time_ns INTEGER NOT NULL,action TEXT NOT NULL,ip TEXT NOT NULL,path TEXT NOT NULL,size INTEGER NOT NULL,data BLOB NOT NULL); CREATE INDEX IF NOT EXISTS events_time ON events(time_ns); CREATE INDEX IF NOT EXISTS events_action ON events(action,seq); CREATE TABLE IF NOT EXISTS event_totals(singleton INTEGER PRIMARY KEY CHECK(singleton=1),records INTEGER NOT NULL,occurrences INTEGER NOT NULL,enqueued INTEGER NOT NULL,enqueued_occurrences INTEGER NOT NULL,acked INTEGER NOT NULL,acked_occurrences INTEGER NOT NULL); INSERT OR IGNORE INTO event_totals VALUES(1,0,0,0,0,0,0); CREATE TABLE IF NOT EXISTS export_outbox(seq INTEGER PRIMARY KEY,id TEXT NOT NULL UNIQUE,occurrences INTEGER NOT NULL,size INTEGER NOT NULL,data BLOB NOT NULL); CREATE TABLE IF NOT EXISTS export_settings(singleton INTEGER PRIMARY KEY CHECK(singleton=1),destination TEXT NOT NULL,source_id TEXT NOT NULL);`)
	if err != nil {
		return err
	}
	if version < 2 {
		if _, err = tx.ExecContext(ctx, "PRAGMA user_version=2"); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Append waits for a FULL-synchronous batch commit, using bounded backpressure
// instead of discarding a record when the memory queue is full. A deadline after
// enqueue is an uncertain acknowledgement: the record may still commit later.
func (s *Store) Append(ctx context.Context, r Record) error {
	ctx, cancel := context.WithTimeout(ctx, s.opts.CommitTimeout)
	defer cancel()
	if len(r.Data) > MaxRecordBytes || !json.Valid(r.Data) || r.Time.Before(s.now().Add(-s.opts.MaxAge)) || r.ID == "" || len(r.ID) > 128 || len(r.Path) > 2048 || len(r.IP) > 64 || len(r.Action) > 32 {
		return errors.New("invalid event record")
	}
	r.Data = append([]byte(nil), r.Data...)
	ack := make(chan error, 1)
	s.pending.Add(1)
	if err := s.send(ctx, item{record: &r, ack: ack}); err != nil {
		s.pending.Add(-1)
		s.ingestTimeouts.Add(1)
		return err
	}
	err, uncertain := awaitCommit(ctx, ack)
	if uncertain {
		s.ingestTimeouts.Add(1)
	}
	return err
}

// A scheduler pause can make both a completed commit and its deadline ready.
// Prefer the actual commit result instead of randomly reporting a lost ack.
func awaitCommit(ctx context.Context, ack <-chan error) (error, bool) {
	select {
	case err := <-ack:
		return err, false
	default:
	}
	select {
	case err := <-ack:
		return err, false
	case <-ctx.Done():
		select {
		case err := <-ack:
			return err, false
		default:
			return ctx.Err(), true
		}
	}
}

func (s *Store) send(ctx context.Context, it item) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("event store is closing")
	}
	s.senders.Add(1)
	s.mu.Unlock()
	defer s.senders.Done()
	select {
	case s.queue <- it:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-s.closing:
		return errors.New("event store is closing")
	}
}

func (s *Store) Enqueue(r Record) bool {
	if len(r.Data) > MaxRecordBytes || len(r.ID) > 128 || len(r.Path) > 2048 || len(r.IP) > 64 || len(r.Action) > 32 {
		s.dropped.Add(1)
		return false
	}
	// Ownership transfers by copy, bounded by MaxRecordBytes.
	r.Data = append([]byte(nil), r.Data...)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		s.dropped.Add(1)
		return false
	}
	s.pending.Add(1)
	select {
	case s.queue <- item{record: &r}:
		return true
	default:
		s.pending.Add(-1)
		s.dropped.Add(1)
		return false
	}
}
func (s *Store) setResult(err error) {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	if err != nil {
		s.lastError = err.Error()
		if len(s.lastError) > 300 {
			s.lastError = s.lastError[:300]
		}
	} else {
		s.lastError = ""
		s.lastCommit = s.now().UTC()
	}
}
func (s *Store) run() {
	// The worker owns final closure even when Close's caller times out and
	// never calls it again. done means the database handle is also closed.
	defer func() { s.exportCancel(); <-s.exportDone; _ = s.db.Close(); _ = s.lease.Close(); close(s.done) }()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case first, ok := <-s.queue:
			if !ok {
				return
			}
			batch := []Record{}
			checkpoints := []exportReceipt{}
			checkpointItems := 0
			barriers := []chan error{}
			acks := []chan error{}
			collect := func(it item) {
				if len(it.checkpoint) > 0 {
					checkpoints = append(checkpoints, it.checkpoint...)
					checkpointItems++
				}
				if it.record != nil {
					batch = append(batch, *it.record)
				}
				if it.barrier != nil {
					barriers = append(barriers, it.barrier)
				}
				if it.ack != nil {
					acks = append(acks, it.ack)
				}
			}
			collect(first)
			// A short group-commit window amortizes FULL sync across concurrent
			// producers; there is no unbounded queue or per-event disk flush.
			window := time.NewTimer(10 * time.Millisecond)
			for len(batch)+checkpointItems < 128 && len(barriers) == 0 {
				select {
				case next, open := <-s.queue:
					if !open {
						goto flush
					}
					collect(next)
				case <-window.C:
					goto flush
				}
			}
		flush:
			window.Stop()
			err := s.writeWithRetry(batch, checkpoints)
			s.pending.Add(-int64(len(batch)))
			s.setResult(err)
			if err != nil {
				s.failed.Add(uint64(len(batch)))
			}
			for _, barrier := range barriers {
				barrier <- err
				close(barrier)
			}
			for _, ack := range acks {
				ack <- err
				close(ack)
			}
		case <-ticker.C:
			err := s.writeWithRetry(nil, nil)
			s.setResult(err)
		}
	}
}

func (s *Store) writeBatch(batch []Record) error {
	return s.writeBatchContext(context.Background(), batch)
}
func (s *Store) writeWithRetry(batch []Record, checkpoints []exportReceipt) error {
	started := time.Now()
	defer func() {
		micros := time.Since(started).Microseconds()
		for old := s.maxCommitMicroseconds.Load(); micros > old; old = s.maxCommitMicroseconds.Load() {
			if s.maxCommitMicroseconds.CompareAndSwap(old, micros) {
				break
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), s.opts.CommitTimeout*4/5)
	defer cancel()
	for {
		err := s.writeBatchAndCheckpoints(ctx, batch, checkpoints, 2*time.Second)
		if err == nil || !retryableWrite(err) || ctx.Err() != nil {
			return err
		}
		s.writeRetries.Add(1)
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
func retryableWrite(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var code interface{ Code() int }
	if errors.As(err, &code) {
		switch code.Code() & 255 {
		case sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED, sqlite3.SQLITE_INTERRUPT:
			return true
		}
	}
	return false
}
func (s *Store) writeBatchContext(parent context.Context, batch []Record) error {
	return s.writeBatchWithTimeout(parent, batch, 2*time.Second)
}
func (s *Store) writeBatchWithTimeout(parent context.Context, batch []Record, timeout time.Duration) error {
	return s.writeBatchAndCheckpoints(parent, batch, nil, timeout)
}
func (s *Store) writeBatchAndCheckpoints(parent context.Context, batch []Record, checkpoints []exportReceipt, timeout time.Duration) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	quota := s.opts.MaxBytes / 2
	if s.exportBound {
		quota = s.opts.MaxBytes / 4
	}
	var outCount, outBytes int64
	var acknowledged, acknowledgedOccurrences uint64
	if s.exportBound {
		if err = tx.QueryRowContext(ctx, "SELECT count(*),coalesce(sum(size),0) FROM export_outbox").Scan(&outCount, &outBytes); err != nil {
			return err
		}
		// A checkpoint may be retried after an uncertain local acknowledgement.
		// Charge counters only for receipts still present in this transaction.
		for _, receipt := range checkpoints {
			var size int64
			var occurrences uint64
			err := tx.QueryRowContext(ctx, "SELECT size,occurrences FROM export_outbox WHERE seq=? AND id=?", receipt.sequence, receipt.id).Scan(&size, &occurrences)
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			if err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, "DELETE FROM export_outbox WHERE seq=? AND id=?", receipt.sequence, receipt.id); err != nil {
				return err
			}
			outCount--
			outBytes -= size
			acknowledged++
			acknowledgedOccurrences += occurrences
		}
	}
	var committed, occurrences uint64
	if _, err = tx.ExecContext(ctx, "DELETE FROM events WHERE time_ns < ?", s.now().Add(-s.opts.MaxAge).UnixNano()); err != nil {
		return err
	}
	var count, total int64
	if err = tx.QueryRowContext(ctx, "SELECT count(*),coalesce(sum(size),0) FROM events").Scan(&count, &total); err != nil {
		return err
	}
	// Enforce reduced row/logical budgets on reopen, even without new traffic.
	for count > int64(s.opts.MaxRows) || total > quota {
		var seq, size int64
		if err = tx.QueryRowContext(ctx, "SELECT seq,size FROM events ORDER BY seq LIMIT 1").Scan(&seq, &size); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "DELETE FROM events WHERE seq=?", seq); err != nil {
			return err
		}
		count--
		total -= size
	}
	for _, r := range batch {
		if s.exportBound && !json.Valid(r.Data) {
			return errors.New("event export requires valid JSON records")
		}
		var existing []byte
		err = tx.QueryRowContext(ctx, "SELECT data FROM events WHERE id=? UNION ALL SELECT data FROM export_outbox WHERE id=? LIMIT 1", r.ID, r.ID).Scan(&existing)
		if err == nil {
			if !bytes.Equal(existing, r.Data) {
				return errors.New("event ID already has different immutable content")
			}
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		charge := int64(len(r.Data) + len(r.ID) + len(r.Path) + len(r.IP) + len(r.Action) + 256)
		if r.Time.Before(s.now().Add(-s.opts.MaxAge)) {
			continue
		}
		// Logical payload quota leaves room for indexes and SQLite page overhead;
		// max_page_count independently caps the main database file.
		for count >= int64(s.opts.MaxRows) || total+charge > quota {
			var seq, size int64
			if err = tx.QueryRowContext(ctx, "SELECT seq,size FROM events ORDER BY seq LIMIT 1").Scan(&seq, &size); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, "DELETE FROM events WHERE seq=?", seq); err != nil {
				return err
			}
			count--
			total -= size
		}
		result, e := tx.ExecContext(ctx, "INSERT OR IGNORE INTO events(id,time_ns,action,ip,path,size,data) VALUES(?,?,?,?,?,?,?)", r.ID, r.Time.UnixNano(), r.Action, r.IP, r.Path, charge, r.Data)
		if e != nil {
			return e
		}
		added, _ := result.RowsAffected()
		count += added
		total += added * charge
		if added > 0 {
			n := r.Occurrences
			if n == 0 {
				n = 1
			}
			committed++
			occurrences += n
			if s.exportBound {
				if outCount >= int64(s.opts.Export.maxRows()) || outBytes+charge > quota {
					return errors.New("durable export outbox is full; restore collector delivery or increase storage budget")
				}
				seq, e := result.LastInsertId()
				if e != nil {
					return e
				}
				if _, err = tx.ExecContext(ctx, "INSERT INTO export_outbox(seq,id,occurrences,size,data) VALUES(?,?,?,?,?)", seq, r.ID, n, charge, r.Data); err != nil {
					return err
				}
				outCount++
				outBytes += charge
			}
		}
	}
	var enqueued, enqueuedOccurrences uint64
	if s.exportBound {
		enqueued = committed
		enqueuedOccurrences = occurrences
	}
	if _, err = tx.ExecContext(ctx, "UPDATE event_totals SET records=records+?,occurrences=occurrences+?,enqueued=enqueued+?,enqueued_occurrences=enqueued_occurrences+?,acked=acked+?,acked_occurrences=acked_occurrences+? WHERE singleton=1", committed, occurrences, enqueued, enqueuedOccurrences, acknowledged, acknowledgedOccurrences); err != nil {
		return err
	}
	if err = s.commit(tx); err != nil {
		return err
	}
	s.rows.Store(count)
	s.bytes.Store(total)
	s.committedRecords.Add(committed)
	s.committedOccurrences.Add(occurrences)
	s.exportRows.Store(outCount)
	s.exportBytes.Store(outBytes)
	s.exportEnqueued.Add(enqueued)
	s.exportEnqueuedOccurrences.Add(enqueuedOccurrences)
	s.exportAcked.Add(acknowledged)
	s.exportAckedOccurrences.Add(acknowledgedOccurrences)
	return nil
}

func (s *Store) Query(ctx context.Context, q Query) ([]Record, error) {
	if len(q.Application) > 64 {
		return nil, errors.New("application filter exceeds 64 bytes")
	}
	if q.Limit < 1 || q.Limit > 500 {
		q.Limit = 100
	}
	if len(q.Search) > 128 {
		return nil, errors.New("event search exceeds 128 bytes")
	}
	// Match search text literally, including LIKE metacharacters.
	search := strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(q.Search)
	sqlText := "SELECT seq,id,time_ns,action,ip,path,data FROM events WHERE time_ns>=?"
	args := []any{s.now().Add(-s.opts.MaxAge).UnixNano()}
	if q.Before > 0 {
		sqlText += " AND seq<?"
		args = append(args, q.Before)
	}
	if q.Action != "" {
		sqlText += " AND action=?"
		args = append(args, q.Action)
	}
	if q.Application != "" {
		sqlText += ` AND json_extract(CASE WHEN json_valid(CAST(data AS TEXT)) THEN CAST(data AS TEXT) ELSE '{}' END,'$.application_id')=?`
		args = append(args, q.Application)
	}
	if q.Search != "" {
		sqlText += ` AND (ip LIKE ? ESCAPE '\' OR path LIKE ? ESCAPE '\' OR CAST(data AS TEXT) LIKE ? ESCAPE '\')`
		term := "%" + search + "%"
		args = append(args, term, term, term)
	}
	sqlText += " ORDER BY seq DESC LIMIT ?"
	args = append(args, q.Limit)
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, sqlText, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := []Record{}
	for rows.Next() {
		var r Record
		var unix int64
		if err = rows.Scan(&r.Sequence, &r.ID, &unix, &r.Action, &r.IP, &r.Path, &r.Data); err != nil {
			return nil, err
		}
		r.Time = time.Unix(0, unix).UTC()
		records = append(records, r)
	}
	return records, rows.Err()
}

func (s *Store) Status() Status {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	exported := s.ExportStatus()
	return Status{StartupMilliseconds: s.startupMilliseconds, Enabled: true, Healthy: s.lastError == "" && s.dropped.Load() == 0 && s.failed.Load() == 0 && s.ingestTimeouts.Load() == 0 && exported.Healthy, Queued: len(s.queue), QueueCapacity: cap(s.queue), Pending: s.pending.Load(), Stored: s.rows.Load(), PayloadBytes: s.bytes.Load(), MaxBytes: s.opts.MaxBytes, MaxRows: s.opts.MaxRows, RetentionDays: s.opts.MaxAge.Hours() / 24, QueueDropped: s.dropped.Load(), WriteFailed: s.failed.Load(), LastError: s.lastError, LastCommit: s.lastCommit, CommittedRecords: s.committedRecords.Load(), CommittedOccurrences: s.committedOccurrences.Load(), IngestTimeouts: s.ingestTimeouts.Load(), Export: exported, WriteRetries: s.writeRetries.Load(), MaxCommitMilliseconds: float64(s.maxCommitMicroseconds.Load()) / 1000}
}
func (s *Store) Flush(ctx context.Context) error {
	barrier := make(chan error, 1)
	if err := s.send(ctx, item{barrier: barrier}); err != nil {
		return err
	}
	select {
	case err := <-barrier:
		if err == nil && s.failed.Load() > 0 {
			return errors.New("event writes failed during this process lifetime; inspect storage health")
		}
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *Store) Close(ctx context.Context) error {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.closing)
		go func() { s.senders.Wait(); close(s.queue) }()
		s.exportCancel()
	}
	s.mu.Unlock()
	select {
	case <-s.done:
		err := s.db.Close()
		if err == nil && s.failed.Load() > 0 {
			return errors.New("event writes failed during this process lifetime; inspect storage health")
		}
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
