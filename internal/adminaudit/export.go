package adminaudit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/eventstore"
)

type ExportStatus struct {
	Enabled      bool      `json:"enabled"`
	Paused       bool      `json:"paused"`
	Healthy      bool      `json:"healthy"`
	SourceID     string    `json:"source_id,omitempty"`
	Acknowledged uint64    `json:"acknowledged_records"`
	Pending      uint64    `json:"pending_records"`
	Attempts     uint64    `json:"attempts"`
	Failures     uint64    `json:"failures"`
	LastError    string    `json:"last_error,omitempty"`
	LastSuccess  time.Time `json:"last_success,omitempty"`
}

type Exporter struct {
	journal *Journal
	options eventstore.ExportOptions
	mu      sync.Mutex
	status  ExportStatus
	cancel  context.CancelFunc
	done    chan struct{}
}

func NewExporter(journal *Journal, options eventstore.ExportOptions) (*Exporter, error) {
	return newExporter(journal, options, true)
}

// NewReplayExporter preserves the source journal while replaying an offline copy.
// The caller holds its exclusive journal lease through OpenReadOnly.
func NewReplayExporter(journal *Journal, options eventstore.ExportOptions) (*Exporter, error) {
	return newExporter(journal, options, false)
}

func newExporter(journal *Journal, options eventstore.ExportOptions, bind bool) (*Exporter, error) {
	if err := options.Validate(); err != nil {
		return nil, err
	}
	if options.URL != "" && len(options.Token) < 32 {
		return nil, errors.New("audit export requires a separate credential of at least 32 characters")
	}
	bound := journal.Status().ExportDestinationSHA256
	if options.URL != "" {
		digest := sha256.Sum256([]byte(options.URL))
		destination := hex.EncodeToString(digest[:])
		if bound != "" && bound != destination {
			return nil, errors.New("audit export destination differs from the journal binding; preserve and archive the stopped journal before changing receivers")
		}
		if bound == "" {
			if bind {
				if _, err := journal.Append(Record{Operation: "audit.export.bound", Actor: "service", Outcome: "success", Resource: destination}); err != nil {
					return nil, err
				}
			}
			bound = destination
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &Exporter{journal: journal, options: options, cancel: cancel, done: make(chan struct{})}
	e.status.Enabled = bound != ""
	e.status.Paused = bound != "" && options.URL == ""
	if e.status.Enabled {
		first, err := journal.After(0, 1)
		if err != nil || len(first) != 1 {
			cancel()
			return nil, errors.New("audit export cannot read the bound journal genesis")
		}
		e.status.SourceID = first[0].Hash[:32]
	}
	if !e.status.Enabled || e.status.Paused {
		close(e.done)
	} else {
		go e.run(ctx)
	}
	return e, nil
}

func (e *Exporter) Status() ExportStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	status := e.status
	total := e.journal.Status().Records
	if status.Enabled && total > status.Acknowledged {
		status.Pending = total - status.Acknowledged
	}
	status.Healthy = !status.Enabled || (status.LastError == "" && (!status.Paused || status.Pending == 0))
	return status
}

func (e *Exporter) Wait(ctx context.Context) error {
	if !e.status.Enabled {
		return nil
	}
	if e.status.Paused {
		return errors.New("audit export is paused")
	}
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		if e.Status().Pending == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-e.done:
			return errors.New("audit exporter stopped with pending records")
		case <-tick.C:
		}
	}
}

func (e *Exporter) Close() { e.cancel(); <-e.done }

func (e *Exporter) run(ctx context.Context) {
	defer close(e.done)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.MaxConnsPerHost = 1
	defer transport.CloseIdleConnections()
	timeout := e.options.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	minimum := e.options.RetryMin
	if minimum == 0 {
		minimum = 200 * time.Millisecond
	}
	maximum := e.options.RetryMax
	if maximum == 0 {
		maximum = 10 * time.Second
	}
	backoff := minimum
	cursor := uint64(0)
	previous := ""
	for ctx.Err() == nil {
		records, err := e.journal.After(cursor, 32)
		batch := eventstore.ExportBatch{SchemaVersion: 1, SourceID: e.status.SourceID, Events: []eventstore.ExportEvent{}}
		hash := sha256.New()
		hash.Write([]byte(batch.SourceID))
		last := previous
		for _, record := range records {
			if record.Previous != last {
				err = errors.New("audit export hash chain discontinuity")
				break
			}
			last = record.Hash
			data, encodeErr := json.Marshal(record)
			if encodeErr != nil {
				err = encodeErr
				break
			}
			batch.Events = append(batch.Events, eventstore.ExportEvent{Sequence: int64(record.Sequence), ID: record.ID, Occurrences: 1, Event: data})
			hash.Write([]byte{0})
			hash.Write([]byte(record.ID))
		}
		batch.BatchID = hex.EncodeToString(hash.Sum(nil))
		delay := 100 * time.Millisecond
		if err == nil && len(batch.Events) > 0 {
			e.mu.Lock()
			e.status.Attempts++
			e.mu.Unlock()
			delay, err = eventstore.SendExportBatch(ctx, client, e.options, batch)
		}
		if ctx.Err() != nil {
			return
		}
		e.mu.Lock()
		if err != nil {
			e.status.LastError = err.Error()
			e.status.Failures++
		} else if len(batch.Events) > 0 {
			cursor = records[len(records)-1].Sequence
			previous = last
			e.status.Acknowledged = cursor
			e.status.LastError = ""
			e.status.LastSuccess = time.Now().UTC()
		}
		e.mu.Unlock()
		if err != nil {
			delay = max(delay, backoff)
			backoff = min(maximum, backoff*2)
		} else {
			backoff = minimum
			if len(batch.Events) > 0 {
				continue
			}
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
