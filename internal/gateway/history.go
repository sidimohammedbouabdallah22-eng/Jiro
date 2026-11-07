package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// The active JSON file is the commit point. Immutable snapshots are prepared
// before that atomic rename. Only its parent chain is committed history; orphan
// snapshots left by failed writes or crashes are never displayed or restored.
// A process-held file lock enforces one writer per policy path.
const maxPolicySnapshots = 1000

type Revision struct {
	Revision     uint64    `json:"revision"`
	Parent       uint64    `json:"parent_revision"`
	RestoredFrom uint64    `json:"restored_from,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	Actor        string    `json:"actor"`
	Reason       string    `json:"reason"`
	SHA256       string    `json:"sha256"`
}
type PolicySnapshot struct {
	Revision
	Config Config `json:"config"`
}

func policyDigest(c Config) string {
	b, _ := json.Marshal(c.clone())
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func (g *Gateway) snapshotPath(revision uint64) string {
	return filepath.Join(g.historyDir, fmt.Sprintf("%020d.json", revision))
}

func (g *Gateway) readSnapshot(revision uint64) (PolicySnapshot, error) {
	var s PolicySnapshot
	b, err := os.ReadFile(g.snapshotPath(revision))
	if err != nil {
		return s, err
	}
	if len(b) > 256<<10 {
		return s, errors.New("policy snapshot exceeds size limit")
	}
	if err = json.Unmarshal(b, &s); err != nil {
		return s, err
	}
	if s.Revision.Revision != revision || s.Config.Revision != revision || s.Parent >= revision || s.SHA256 != policyDigest(s.Config) {
		return s, errors.New("policy snapshot integrity check failed")
	}
	if err = s.Config.Validate(); err != nil {
		return s, err
	}
	return s, nil
}

func (g *Gateway) nextRevision() (uint64, error) {
	entries, err := os.ReadDir(g.historyDir)
	if err != nil {
		return 0, err
	}
	count := 0
	var largest uint64
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSuffix(entry.Name(), ".json"), 10, 64)
		if err != nil {
			continue
		}
		count++
		if n > largest {
			largest = n
		}
	}
	if count >= maxPolicySnapshots {
		return 0, errors.New("policy snapshot limit reached (1000); a supported history migration is required before further updates")
	}
	if largest == ^uint64(0) {
		return 0, errors.New("policy revision exhausted")
	}
	return largest + 1, nil
}

func (g *Gateway) prepareSnapshot(c Config, parent, restoredFrom uint64, actor, reason string) error {
	s := PolicySnapshot{Revision: Revision{Revision: c.Revision, Parent: parent, RestoredFrom: restoredFrom, CreatedAt: time.Now().UTC(), Actor: actor, Reason: reason, SHA256: policyDigest(c)}, Config: c.clone()}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if len(b) > 256<<10 {
		return errors.New("policy snapshot exceeds 256 KiB")
	}
	// O_EXCL prevents overwriting historical revisions. Partial files from a
	// crash remain unreachable and their numbers are not reused.
	f, err := os.OpenFile(g.snapshotPath(c.Revision), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func (g *Gateway) initializeHistory(c Config, missing bool) error {
	if err := os.MkdirAll(g.historyDir, 0700); err != nil {
		return err
	}
	entries, err := os.ReadDir(g.historyDir)
	if err != nil {
		return err
	}
	if missing && len(entries) > 0 {
		return errors.New("active policy file is missing but history exists; restore the active policy instead of booting defaults")
	}
	s, err := g.readSnapshot(c.Revision)
	if errors.Is(err, os.ErrNotExist) && len(entries) == 0 {
		return g.prepareSnapshot(c, 0, 0, "bootstrap", "Imported initial policy")
	}
	if err != nil {
		return fmt.Errorf("read active policy history: %w", err)
	}
	if s.SHA256 != policyDigest(c) {
		return errors.New("active policy differs from its recorded revision; restore the recorded file or use the management API for changes")
	}
	for depth := 1; s.Parent != 0; depth++ {
		if depth >= maxPolicySnapshots {
			return errors.New("policy history exceeds supported depth")
		}
		s, err = g.readSnapshot(s.Parent)
		if err != nil {
			return fmt.Errorf("read policy ancestor: %w", err)
		}
	}
	return nil
}

func (g *Gateway) committedSnapshots() ([]PolicySnapshot, error) {
	revision := g.active.Load().config.Revision
	snapshots := []PolicySnapshot{}
	for revision != 0 {
		if len(snapshots) >= maxPolicySnapshots {
			return nil, errors.New("policy history exceeds supported depth")
		}
		s, err := g.readSnapshot(revision)
		if err != nil {
			return nil, err
		}
		snapshots = append(snapshots, s)
		revision = s.Parent
	}
	return snapshots, nil
}

func (g *Gateway) History() ([]Revision, error) {
	g.update.Lock()
	defer g.update.Unlock()
	snapshots, err := g.committedSnapshots()
	if err != nil {
		return nil, err
	}
	history := make([]Revision, 0, len(snapshots))
	for _, s := range snapshots {
		history = append(history, s.Revision)
	}
	return history, nil
}

func (g *Gateway) Snapshot(revision uint64) (PolicySnapshot, error) {
	g.update.Lock()
	defer g.update.Unlock()
	return g.committedSnapshot(revision)
}
func (g *Gateway) committedSnapshot(revision uint64) (PolicySnapshot, error) {
	snapshots, err := g.committedSnapshots()
	if err != nil {
		return PolicySnapshot{}, err
	}
	for _, s := range snapshots {
		if s.Revision.Revision == revision {
			return s, nil
		}
	}
	return PolicySnapshot{}, errors.New("revision is not in committed policy history")
}

func (g *Gateway) Rollback(expected, target uint64, actor, reason string) (Config, error) {
	if !g.update.TryLock() {
		return Config{}, errors.New("another policy operation is in progress; retry")
	}
	defer g.update.Unlock()
	if expected != g.active.Load().config.Revision {
		return Config{}, errors.New("configuration changed; reload before saving")
	}
	if strings.TrimSpace(reason) == "" {
		return Config{}, errors.New("a rollback reason is required")
	}
	snapshot, err := g.committedSnapshot(target)
	if err != nil {
		return Config{}, err
	}
	c := snapshot.Config.clone()
	c.Revision = expected
	return g.applyLocked(c, false, actor, reason, target)
}
