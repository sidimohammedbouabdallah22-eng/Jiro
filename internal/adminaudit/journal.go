// Package adminaudit stores a bounded, append-only administration journal.
package adminaudit

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofrs/flock"
)

const MaxBytes int64 = 32 << 20
const MaxRecordBytes = 2048

type Record struct {
	Sequence    uint64    `json:"sequence"`
	ID          string    `json:"id"`
	Correlation string    `json:"correlation"`
	Time        time.Time `json:"time"`
	Operation   string    `json:"operation"`
	Actor       string    `json:"actor"`
	Outcome     string    `json:"outcome"`
	Status      int       `json:"status,omitempty"`
	Revision    uint64    `json:"revision,omitempty"`
	Resource    string    `json:"resource,omitempty"`
	Previous    string    `json:"previous,omitempty"`
	Hash        string    `json:"hash"`
}

type Metadata struct {
	ExportDestinationSHA256 string `json:"export_destination_sha256,omitempty"`
	Records                 uint64 `json:"records"`
	Bytes                   int64  `json:"bytes"`
	LastHash                string `json:"last_hash"`
}

type Status struct {
	Metadata
	Healthy  bool  `json:"healthy"`
	MaxBytes int64 `json:"max_bytes"`
}

type Journal struct {
	status   atomic.Pointer[Status]
	mu       sync.Mutex
	file     *os.File
	lease    *flock.Flock
	metadata Metadata
	offsets  []int64
	failed   bool
	closed   bool
	readOnly bool
}

func digest(record Record) string {
	record.Hash = ""
	data, _ := json.Marshal(record)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func scan(reader io.Reader) (Metadata, []int64, error) {
	var meta Metadata
	var offsets []int64
	scanner := bufio.NewScanner(io.LimitReader(reader, MaxBytes+1))
	scanner.Buffer(make([]byte, MaxRecordBytes+1), MaxRecordBytes+1)
	// Retain newline evidence so an interrupted final append cannot look committed.
	scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		for i, b := range data {
			if b == '\n' {
				return i + 1, data[:i+1], nil
			}
		}
		if atEOF && len(data) > 0 {
			return 0, nil, errors.New("incomplete audit record")
		}
		return 0, nil, nil
	})
	for scanner.Scan() {
		line := scanner.Bytes()
		var record Record
		if len(line) > MaxRecordBytes || json.Unmarshal(line, &record) != nil || record.Sequence != meta.Records+1 || record.Previous != meta.LastHash || record.Hash != digest(record) || record.ID == "" || record.Correlation == "" || record.Time.IsZero() {
			return meta, nil, errors.New("administration journal integrity verification failed")
		}
		canonical, err := json.Marshal(record)
		if err != nil || !bytes.Equal(line, append(canonical, '\n')) {
			return meta, nil, errors.New("administration journal contains a noncanonical record")
		}
		offsets = append(offsets, meta.Bytes)
		meta.Records++
		meta.Bytes += int64(len(line))
		meta.LastHash = record.Hash
		if record.Operation == "audit.export.bound" {
			if err := recordBinding(&meta, record); err != nil {
				return meta, nil, err
			}
		}
		if meta.Bytes > MaxBytes {
			return meta, nil, errors.New("administration journal size limit exceeded")
		}
	}
	return meta, offsets, scanner.Err()
}

func Inspect(path string) (Metadata, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Metadata{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > MaxBytes {
		return Metadata{}, errors.New("audit journal must be a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return Metadata{}, err
	}
	defer file.Close()
	meta, _, err := scan(file)
	return meta, err
}

func Open(path string) (*Journal, error) {
	return openJournal(path, false)
}

func OpenReadOnly(path string) (*Journal, error) { return openJournal(path, true) }

func openJournal(path string, readOnly bool) (*Journal, error) {
	if !readOnly {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, err
		}
	}
	lease := flock.New(path + ".lock")
	locked, err := lease.TryLock()
	if err != nil || !locked {
		lease.Close()
		return nil, errors.New("administration journal is unavailable or owned by another process")
	}
	good := false
	defer func() {
		if !good {
			lease.Close()
		}
	}()
	info, err := os.Lstat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if info != nil && (!info.Mode().IsRegular() || info.Size() > MaxBytes) {
		return nil, errors.New("unsafe administration journal")
	}
	flags := os.O_CREATE | os.O_RDWR | os.O_APPEND
	if readOnly {
		flags = os.O_RDONLY
	}
	file, err := os.OpenFile(path, flags, 0600)
	if err != nil {
		return nil, err
	}
	meta, offsets, err := scan(file)
	if err != nil {
		file.Close()
		return nil, err
	}
	good = true
	journal := &Journal{file: file, lease: lease, metadata: meta, offsets: offsets, readOnly: readOnly}
	journal.publishStatus()
	return journal, nil
}

func (j *Journal) Append(record Record) (Record, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	defer j.publishStatus()
	if j.readOnly {
		return record, errors.New("administration journal is open read-only")
	}
	if j.closed || j.failed {
		return record, errors.New("administration audit is unavailable")
	}
	if len(record.Operation) > 64 || len(record.Actor) > 100 || len(record.Outcome) > 32 || len(record.Resource) > 128 || len(record.Correlation) > 64 {
		return record, errors.New("audit metadata exceeds limits")
	}
	nextMeta := j.metadata
	if record.Operation == "audit.export.bound" {
		if err := recordBinding(&nextMeta, record); err != nil {
			return record, err
		}
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return record, err
	}
	record.ID = hex.EncodeToString(nonce[:])
	if record.Correlation == "" {
		record.Correlation = record.ID
	}
	record.Sequence = j.metadata.Records + 1
	record.Time = time.Now().UTC()
	record.Previous = j.metadata.LastHash
	record.Hash = digest(record)
	data, err := json.Marshal(record)
	if err != nil {
		return record, err
	}
	data = append(data, '\n')
	if len(data) > MaxRecordBytes || int64(len(data)) > MaxBytes-j.metadata.Bytes {
		j.failed = true
		return record, errors.New("administration journal is full; archive it while stopped before further changes")
	}
	n, err := j.file.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = j.file.Sync()
	}
	if err != nil {
		j.failed = true
		return record, errors.New("administration audit commit failed")
	}
	j.offsets = append(j.offsets, j.metadata.Bytes)
	nextMeta.Records = record.Sequence
	nextMeta.Bytes = j.metadata.Bytes + int64(n)
	nextMeta.LastHash = record.Hash
	j.metadata = nextMeta
	return record, nil
}

func recordBinding(meta *Metadata, record Record) error {
	digest, err := hex.DecodeString(record.Resource)
	if err != nil || len(digest) != 32 || len(record.Resource) != 64 || record.Outcome != "success" || meta.ExportDestinationSHA256 != "" {
		return errors.New("invalid or duplicate audit export binding")
	}
	meta.ExportDestinationSHA256 = record.Resource
	return nil
}

// After reads only the sync-acknowledged prefix under the journal writer lock.
func (j *Journal) After(sequence uint64, limit int) ([]Record, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || limit < 1 || limit > 32 || sequence > j.metadata.Records {
		return nil, errors.New("invalid audit export cursor or closed journal")
	}
	items := make([]Record, 0, limit)
	for index := sequence; index < j.metadata.Records && len(items) < limit; index++ {
		start := j.offsets[index]
		end := j.metadata.Bytes
		if index+1 < j.metadata.Records {
			end = j.offsets[index+1]
		}
		data := make([]byte, end-start)
		if _, err := j.file.ReadAt(data, start); err != nil {
			return nil, err
		}
		var record Record
		if err := json.Unmarshal(data, &record); err != nil || record.Sequence != index+1 || record.Hash != digest(record) || (index+1 == j.metadata.Records && record.Hash != j.metadata.LastHash) {
			return nil, errors.New("audit export record integrity failed")
		}
		items = append(items, record)
	}
	return items, nil
}

func (j *Journal) Query(before uint64, limit int) ([]Record, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil, errors.New("administration journal closed")
	}
	if limit < 1 || limit > 100 {
		return nil, errors.New("audit limit must be 1..100")
	}
	end := j.metadata.Records
	if before > 0 && before <= end {
		end = before - 1
	}
	items := []Record{}
	for n := end; n > 0 && len(items) < limit; n-- {
		start := j.offsets[n-1]
		finish := j.metadata.Bytes
		if n < uint64(len(j.offsets)) {
			finish = j.offsets[n]
		}
		data := make([]byte, finish-start)
		if _, err := j.file.ReadAt(data, start); err != nil {
			return nil, err
		}
		var record Record
		if err := json.Unmarshal(data, &record); err != nil {
			return nil, fmt.Errorf("decode audit record: %w", err)
		}
		items = append(items, record)
	}
	return items, nil
}

func (j *Journal) Status() Status {
	if status := j.status.Load(); status != nil {
		return *status
	}
	return Status{MaxBytes: MaxBytes}
}

// Call while holding mu, or before publishing the newly opened Journal.
func (j *Journal) publishStatus() {
	status := Status{Metadata: j.metadata, Healthy: !j.failed && !j.closed, MaxBytes: MaxBytes}
	j.status.Store(&status)
}

func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	defer j.publishStatus()
	if j.closed {
		return nil
	}
	j.closed = true
	err := j.file.Close()
	leaseErr := j.lease.Close()
	return errors.Join(err, leaseErr)
}
