// Package operations implements offline, non-overwriting recovery operations.
package operations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/gofrs/flock"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/accounts"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/adminaudit"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/gateway"
)

const FormatVersion = 1
const maxBundleBytes int64 = 3 << 30
const maxMembers = 1008

type Paths struct {
	Accounts  string `json:"accounts,omitempty"`
	Audit     string `json:"audit,omitempty"`
	Policy    string `json:"policy"`
	Events    string `json:"events,omitempty"`
	Collector string `json:"collector,omitempty"`
}
type Member struct {
	Path   string `json:"path"`
	Role   string `json:"role"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type Manifest struct {
	Format     int       `json:"format"`
	Created    time.Time `json:"created"`
	Sensitive  bool      `json:"sensitive"`
	Scope      string    `json:"scope"`
	Paths      Paths     `json:"paths"`
	Binary     string    `json:"binary,omitempty"`
	Credential string    `json:"credential,omitempty"`
	State      State     `json:"state"`
	Files      []Member  `json:"files"`
}
type State struct {
	Accounts      *accounts.Metadata   `json:"accounts,omitempty"`
	Audit         *adminaudit.Metadata `json:"audit,omitempty"`
	Policy        gateway.PolicyState  `json:"policy"`
	PolicyDigest  string               `json:"policy_digest"`
	HistoryDigest string               `json:"history_digest"`
	Events        *Database            `json:"events,omitempty"`
	Collector     *Database            `json:"collector,omitempty"`
}
type Database struct {
	Schema              int    `json:"schema"`
	Rows                int64  `json:"rows"`
	Digest              string `json:"record_digest"`
	OutboxRows          int64  `json:"outbox_rows,omitempty"`
	OutboxDigest        string `json:"outbox_digest,omitempty"`
	Source              string `json:"source_id,omitempty"`
	Destination         string `json:"destination,omitempty"`
	Records             uint64 `json:"committed_records,omitempty"`
	Occurrences         uint64 `json:"committed_occurrences,omitempty"`
	Enqueued            uint64 `json:"enqueued,omitempty"`
	EnqueuedOccurrences uint64 `json:"enqueued_occurrences,omitempty"`
	Acked               uint64 `json:"acked,omitempty"`
	AckedOccurrences    uint64 `json:"acked_occurrences,omitempty"`
}

func regular(path string, max int64) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > max {
		return fmt.Errorf("%s must be a regular file no larger than %d bytes", path, max)
	}
	return nil
}
func absolute(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	p, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(p), nil
}
func normalized(p Paths) (Paths, error) {
	var err error
	p.Policy, err = absolute(p.Policy)
	if err != nil || p.Policy == "" {
		return p, errors.New("a policy path is required")
	}
	p.Events, err = absolute(p.Events)
	if err != nil {
		return p, err
	}
	p.Collector, err = absolute(p.Collector)
	if err != nil {
		return p, err
	}
	if p.Accounts == "" {
		if _, e := os.Lstat(p.Policy + ".accounts.json"); e == nil {
			p.Accounts = p.Policy + ".accounts.json"
		} else if !errors.Is(e, os.ErrNotExist) {
			return p, e
		}
	}
	p.Accounts, err = absolute(p.Accounts)
	if err != nil {
		return p, err
	}
	if p.Accounts != "" && p.Accounts != p.Policy+".accounts.json" {
		return p, errors.New("accounts must be adjacent to the policy")
	}
	if p.Audit == "" {
		if _, e := os.Lstat(p.Policy + ".audit.jsonl"); e == nil {
			p.Audit = p.Policy + ".audit.jsonl"
		} else if !errors.Is(e, os.ErrNotExist) {
			return p, e
		}
	}
	p.Audit, err = absolute(p.Audit)
	if err != nil {
		return p, err
	}
	seen := map[string]bool{}
	for _, pointer := range []*string{&p.Policy, &p.Events, &p.Collector, &p.Audit, &p.Accounts} {
		path := *pointer
		if path == "" {
			continue
		}
		resolved, e := filepath.EvalSymlinks(path)
		if e != nil {
			return p, e
		}
		info, e := os.Lstat(path)
		if e != nil {
			return p, e
		}
		if !info.Mode().IsRegular() {
			return p, errors.New("state paths must be regular files, not links")
		}
		*pointer = resolved
		key := resolved
		if runtime.GOOS == "windows" {
			key = strings.ToLower(key)
		}
		if seen[key] {
			return p, errors.New("policy, sender and collector must be distinct files")
		}
		seen[key] = true
	}
	return p, nil
}

// Leases are never deleted: all service and maintenance participants use the
// same stable lock inode. Acquisition is nonblocking, avoiding lock-order waits.
func acquire(paths Paths) (func(), error) {
	names := []string{paths.Policy}
	if paths.Audit != "" {
		names = append(names, paths.Audit)
	}
	if paths.Events != "" {
		names = append(names, paths.Events)
	}
	if paths.Collector != "" {
		names = append(names, paths.Collector)
	}
	sort.Strings(names)
	held := []*flock.Flock{}
	release := func() {
		for i := len(held) - 1; i >= 0; i-- {
			_ = held[i].Close()
		}
	}
	for _, name := range names {
		lease := flock.New(name + ".lock")
		ok, err := lease.TryLock()
		if err != nil || !ok {
			lease.Close()
			release()
			if err != nil {
				return nil, fmt.Errorf("acquire maintenance lease for %s: %w", name, err)
			}
			return nil, fmt.Errorf("state is in use: stop its services before maintenance (%s)", name)
		}
		held = append(held, lease)
	}
	return release, nil
}
func hashFile(ctx context.Context, path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := copyContext(ctx, h, f, maxBundleBytes)
	return hex.EncodeToString(h.Sum(nil)), n, err
}
func copyContext(ctx context.Context, dst io.Writer, src io.Reader, limit int64) (int64, error) {
	buffer := make([]byte, 64<<10)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, err := src.Read(buffer)
		if n > 0 {
			total += int64(n)
			if total > limit {
				return total, errors.New("file exceeds operation size budget")
			}
			written, e := dst.Write(buffer[:n])
			if e != nil {
				return total, e
			}
			if written != n {
				return total, io.ErrShortWrite
			}
		}
		if errors.Is(err, io.EOF) {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}
func pathsUnder(root string, p Paths) Paths {
	return Paths{Policy: filepath.Join(root, filepath.FromSlash(p.Policy)), Events: joinOptional(root, p.Events), Collector: joinOptional(root, p.Collector), Audit: joinOptional(root, p.Audit), Accounts: joinOptional(root, p.Accounts)}
}
func joinOptional(root, path string) string {
	if path == "" {
		return ""
	}
	return filepath.Join(root, filepath.FromSlash(path))
}
