package eventstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type ExportOptions struct {
	URL      string
	Token    string
	MaxRows  int
	Timeout  time.Duration
	RetryMin time.Duration
	RetryMax time.Duration
}

func (o ExportOptions) maxRows() int {
	if o.MaxRows == 0 {
		return 10000
	}
	return o.MaxRows
}

func (o ExportOptions) Validate() error { return o.validate() }
func (o ExportOptions) validate() error {
	if o.maxRows() < 1 || o.maxRows() > 100000 || len(o.Token) > 4096 || strings.ContainsAny(o.Token, "\r\n") {
		return errors.New("invalid event export settings")
	}
	if o.URL != "" {
		u, err := url.Parse(o.URL)
		if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(o.URL) > 2048 {
			return errors.New("event export requires an absolute URL without credentials, query or fragment")
		}
		if u.Scheme != "https" && (u.Scheme != "http" || !net.ParseIP(u.Hostname()).IsLoopback()) {
			return errors.New("event export requires HTTPS, or HTTP to an explicit loopback IP")
		}
	}
	if o.Timeout != 0 && (o.Timeout < time.Millisecond || o.Timeout > time.Minute) {
		return errors.New("invalid event export timeout")
	}
	if o.RetryMin < 0 || o.RetryMin > time.Minute || o.RetryMax < 0 || o.RetryMax > 5*time.Minute || (o.RetryMax != 0 && o.RetryMin > o.RetryMax) {
		return errors.New("invalid event export retry bounds")
	}
	return nil
}

type ExportStatus struct {
	Enabled             bool      `json:"enabled"`
	Paused              bool      `json:"paused"`
	Healthy             bool      `json:"healthy"`
	Endpoint            string    `json:"endpoint,omitempty"`
	SourceID            string    `json:"source_id,omitempty"`
	Pending             int64     `json:"pending_records"`
	PendingBytes        int64     `json:"pending_bytes"`
	MaxRows             int       `json:"max_rows"`
	Enqueued            uint64    `json:"enqueued_records"`
	EnqueuedOccurrences uint64    `json:"enqueued_occurrences"`
	Acked               uint64    `json:"acked_records"`
	AckedOccurrences    uint64    `json:"acked_occurrences"`
	Attempts            uint64    `json:"attempts"`
	Failures            uint64    `json:"failures"`
	LastError           string    `json:"last_error,omitempty"`
	LastSuccess         time.Time `json:"last_success,omitempty"`
}

// ExportBatch is the collector protocol. Collectors durably deduplicate by
// (source_id,event.id), commit all records, then acknowledge the entire batch.
type ExportBatch struct {
	SchemaVersion int           `json:"schema_version"`
	SourceID      string        `json:"source_id"`
	BatchID       string        `json:"batch_id"`
	Events        []ExportEvent `json:"events"`
}
type ExportEvent struct {
	Sequence    int64           `json:"sequence"`
	ID          string          `json:"id"`
	Occurrences uint64          `json:"occurrences"`
	Event       json.RawMessage `json:"event"`
}
type ExportAck struct {
	BatchID string   `json:"batch_id"`
	IDs     []string `json:"acked_ids"`
}

func (s *Store) initializeExport(ctx context.Context) error {
	var destination, source string
	err := s.db.QueryRowContext(ctx, "SELECT destination,source_id FROM export_settings WHERE singleton=1").Scan(&destination, &source)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if s.opts.Export.URL != "" && destination != s.opts.Export.URL {
		var pending int
		if err = s.db.QueryRowContext(ctx, "SELECT count(*) FROM export_outbox").Scan(&pending); err != nil {
			return err
		}
		if pending > 0 {
			return errors.New("event export destination cannot change while durable deliveries are pending")
		}
		destination = s.opts.Export.URL
		if source == "" {
			var b [16]byte
			if _, err = rand.Read(b[:]); err != nil {
				return err
			}
			source = hex.EncodeToString(b[:])
		}
		if _, err = s.db.ExecContext(ctx, "INSERT INTO export_settings(singleton,destination,source_id) VALUES(1,?,?) ON CONFLICT(singleton) DO UPDATE SET destination=excluded.destination", destination, source); err != nil {
			return err
		}
	}
	s.exportBound = destination != ""
	s.exportDestination = destination
	s.exportSource = source
	var records, occurrences, enqueued, enqueuedOccurrences, acked, ackedOccurrences uint64
	if err = s.db.QueryRowContext(ctx, "SELECT records,occurrences,enqueued,enqueued_occurrences,acked,acked_occurrences FROM event_totals WHERE singleton=1").Scan(&records, &occurrences, &enqueued, &enqueuedOccurrences, &acked, &ackedOccurrences); err != nil {
		return err
	}
	s.committedRecords.Store(records)
	s.committedOccurrences.Store(occurrences)
	s.exportEnqueued.Store(enqueued)
	s.exportEnqueuedOccurrences.Store(enqueuedOccurrences)
	s.exportAcked.Store(acked)
	s.exportAckedOccurrences.Store(ackedOccurrences)
	var count, total int64
	if err = s.db.QueryRowContext(ctx, "SELECT count(*),coalesce(sum(size),0) FROM export_outbox").Scan(&count, &total); err != nil {
		return err
	}
	if count > int64(s.opts.Export.maxRows()) || total > s.opts.MaxBytes/4 {
		return errors.New("existing durable export backlog exceeds configured limits")
	}
	s.exportRows.Store(count)
	s.exportBytes.Store(total)
	return nil
}
func (s *Store) ExportStatus() ExportStatus {
	s.exportMu.Lock()
	defer s.exportMu.Unlock()
	paused := s.exportBound && s.opts.Export.URL == ""
	return ExportStatus{Enabled: s.exportBound, Paused: paused, Healthy: s.exportError == "" && (!paused || s.exportRows.Load() == 0), Endpoint: s.exportDestination, SourceID: s.exportSource, Pending: s.exportRows.Load(), PendingBytes: s.exportBytes.Load(), MaxRows: s.opts.Export.maxRows(), Enqueued: s.exportEnqueued.Load(), EnqueuedOccurrences: s.exportEnqueuedOccurrences.Load(), Acked: s.exportAcked.Load(), AckedOccurrences: s.exportAckedOccurrences.Load(), Attempts: s.exportAttempts.Load(), Failures: s.exportFailures.Load(), LastError: s.exportError, LastSuccess: s.exportSuccess}
}
func (s *Store) WaitExport(ctx context.Context) error {
	if s.exportBound && s.opts.Export.URL == "" {
		return errors.New("event export is paused")
	}
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		if s.exportRows.Load() == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.done:
			return errors.New("event store closed with pending exports")
		case <-tick.C:
		}
	}
}
func (s *Store) loadExport(ctx context.Context) (ExportBatch, error) {
	batch := ExportBatch{SchemaVersion: 1, SourceID: s.exportSource, Events: []ExportEvent{}}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, "SELECT seq,id,occurrences,data FROM export_outbox ORDER BY seq LIMIT 32")
	if err != nil {
		return batch, err
	}
	defer rows.Close()
	h := sha256.New()
	h.Write([]byte(s.exportSource))
	for rows.Next() {
		var e ExportEvent
		if err = rows.Scan(&e.Sequence, &e.ID, &e.Occurrences, &e.Event); err != nil {
			return batch, err
		}
		batch.Events = append(batch.Events, e)
		h.Write([]byte{0})
		h.Write([]byte(e.ID))
	}
	batch.BatchID = hex.EncodeToString(h.Sum(nil))
	return batch, rows.Err()
}
func (s *Store) ackExport(ctx context.Context, batch ExportBatch) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	receipts := make([]exportReceipt, 0, len(batch.Events))
	for _, event := range batch.Events {
		receipts = append(receipts, exportReceipt{sequence: event.Sequence, id: event.ID})
	}
	ack := make(chan error, 1)
	if err := s.send(ctx, item{checkpoint: receipts, ack: ack}); err != nil {
		return err
	}
	err, _ := awaitCommit(ctx, ack)
	return err
}
func (s *Store) sendExport(ctx context.Context, client *http.Client, batch ExportBatch) (time.Duration, time.Time, error) {
	s.exportAttempts.Add(1)
	delay, err := SendExportBatch(ctx, client, s.opts.Export, batch)
	if err != nil {
		return delay, time.Time{}, err
	}
	verifiedAt := time.Now().UTC()
	return 0, verifiedAt, s.ackExport(ctx, batch)
}

// SendExportBatch verifies an acknowledgement for every immutable record before
// its caller advances local delivery state. The caller owns transport lifetime.
func SendExportBatch(ctx context.Context, client *http.Client, options ExportOptions, batch ExportBatch) (time.Duration, error) {
	data, err := json.Marshal(batch)
	if err != nil {
		return 0, errors.New("invalid event JSON in export outbox")
	}
	req, err := http.NewRequestWithContext(ctx, "POST", options.URL, bytes.NewReader(data))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", batch.BatchID)
	if options.Token != "" {
		req.Header.Set("Authorization", "Bearer "+options.Token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, errors.New("collector request failed (network, TLS or timeout)")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		delay := time.Duration(0)
		if seconds, e := strconv.Atoi(resp.Header.Get("Retry-After")); e == nil && seconds > 0 {
			delay = min(time.Duration(min(seconds, 30))*time.Second, 30*time.Second)
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8192))
		return delay, fmt.Errorf("collector returned HTTP %d", resp.StatusCode)
	}
	data, err = io.ReadAll(io.LimitReader(resp.Body, 8193))
	if err != nil || len(data) > 8192 {
		return 0, errors.New("collector acknowledgement is unreadable or oversized")
	}
	var ack ExportAck
	if err = json.Unmarshal(data, &ack); err != nil || ack.BatchID != batch.BatchID || len(ack.IDs) != len(batch.Events) {
		return 0, errors.New("collector did not acknowledge this complete batch")
	}
	ids := map[string]bool{}
	for _, id := range ack.IDs {
		if ids[id] {
			return 0, errors.New("collector acknowledgement contains duplicate IDs")
		}
		ids[id] = true
	}
	for _, e := range batch.Events {
		if !ids[e.ID] {
			return 0, errors.New("collector acknowledgement contains incorrect IDs")
		}
	}
	return 0, nil
}
func (s *Store) runExport(ctx context.Context) {
	defer close(s.exportDone)
	timeout := s.opts.Export.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.MaxConnsPerHost = 1
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	minimum := s.opts.Export.RetryMin
	if minimum == 0 {
		minimum = 200 * time.Millisecond
	}
	maximum := s.opts.Export.RetryMax
	if maximum == 0 {
		maximum = 10 * time.Second
	}
	backoff := minimum
	var uncertainCheckpoint time.Time
	loadFailed := false
	wait := func(delay time.Duration) bool {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return true
		}
	}
	for ctx.Err() == nil {
		batch, err := s.loadExport(ctx)
		delay := time.Duration(0)
		if err == nil && len(batch.Events) == 0 {
			// The local checkpoint may commit after its caller timed out.
			// A verified receiver ACK plus a freshly empty durable outbox and
			// published writer counters resolves that uncertainty without
			// another event, replay, or invented receiver-contact timestamp.
			// A recovered empty-outbox read also clears its own transient
			// failure, without claiming a receiver acknowledgement.
			if (loadFailed || !uncertainCheckpoint.IsZero()) && s.exportRows.Load() == 0 {
				s.exportMu.Lock()
				s.exportError = ""
				if !uncertainCheckpoint.IsZero() {
					s.exportSuccess = uncertainCheckpoint
				}
				s.exportMu.Unlock()
				uncertainCheckpoint = time.Time{}
				loadFailed = false
				backoff = minimum
			}
			if !wait(100 * time.Millisecond) {
				return
			}
			continue
		}
		loadFailed = err != nil
		if err == nil {
			var verifiedAt time.Time
			delay, verifiedAt, err = s.sendExport(ctx, client, batch)
			if err == nil {
				uncertainCheckpoint = time.Time{}
			} else if !verifiedAt.IsZero() {
				uncertainCheckpoint = verifiedAt
			}
		}
		if ctx.Err() != nil {
			return
		}
		s.exportMu.Lock()
		if err != nil {
			s.exportError = clipError(err.Error())
			s.exportFailures.Add(1)
		} else {
			s.exportError = ""
			s.exportSuccess = time.Now().UTC()
		}
		s.exportMu.Unlock()
		if err != nil {
			delay = max(delay, time.Duration(float64(backoff)*(0.8+mathrand.Float64()*0.4)))
			backoff = min(maximum, backoff*2)
			if !wait(delay) {
				return
			}
		} else {
			backoff = minimum
		}
	}
}
func clipError(message string) string {
	if len(message) > 300 {
		return message[:300]
	}
	return message
}
