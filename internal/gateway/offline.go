package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
)

type PolicyState struct {
	UpstreamPools   bool     `json:"upstream_pools,omitempty"`
	TrafficControls bool     `json:"traffic_controls,omitempty"`
	PolicySchemas   []int    `json:"policy_schemas,omitempty"`
	ApplicationIDs  []string `json:"application_ids,omitempty"`
	Schema          int      `json:"schema"`
	Config          Config   `json:"-"`
	Revision        uint64   `json:"revision"`
	ApplicationID   string   `json:"application_id"`
	HistoryDepth    int      `json:"history_depth"`
	SnapshotFiles   int      `json:"snapshot_files"`
	Orphans         int      `json:"orphan_snapshots"`
}

var snapshotName = regexp.MustCompile(`^[0-9]{20}\.json$`)

// CheckState reads/compiles without importing or repairing state. The caller
// owns the offline lease; this function never acquires it or creates files.
func CheckState(path string, compileHistory bool) (PolicyState, error) {
	return CheckStateContext(context.Background(), path, compileHistory)
}
func CheckStateContext(ctx context.Context, path string, compileHistory bool) (PolicyState, error) {
	var result PolicyState
	if err := ctx.Err(); err != nil {
		return result, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return result, err
	}
	if !info.Mode().IsRegular() || info.Size() > 256<<10 {
		return result, errors.New("policy must be a regular file of at most 256 KiB")
	}
	c, err := CheckPolicy(path)
	if err != nil {
		return result, err
	}
	result.Config = c
	result.UpstreamPools = hasUpstreamPools(c)
	result.TrafficControls = hasTrafficControls(c)
	result.Schema = c.SchemaVersion
	result.Revision = c.Revision
	result.ApplicationID = c.ApplicationID
	if c.SchemaVersion == 2 {
		result.PolicySchemas = []int{2}
		for _, app := range c.Applications {
			result.ApplicationIDs = append(result.ApplicationIDs, app.ApplicationID)
		}
	}
	directory := path + ".history"
	info, err = os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return result, errors.New("history must be a real directory")
	}
	file, err := os.Open(directory)
	if err != nil {
		return result, err
	}
	defer file.Close()
	entries, err := file.ReadDir(maxPolicySnapshots + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return result, err
	}
	if len(entries) > maxPolicySnapshots {
		return result, errors.New("history exceeds 1000 snapshot files")
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if !snapshotName.MatchString(entry.Name()) {
			return result, fmt.Errorf("unsupported history entry %q", entry.Name())
		}
		if _, err = strconv.ParseUint(entry.Name()[:20], 10, 64); err != nil {
			return result, err
		}
		snapshotInfo, e := os.Lstat(filepath.Join(directory, entry.Name()))
		if e != nil {
			return result, e
		}
		if !snapshotInfo.Mode().IsRegular() || snapshotInfo.Size() > 256<<10 {
			return result, errors.New("snapshot must be a regular file of at most 256 KiB")
		}
		result.SnapshotFiles++
	}
	if len(entries) == 0 {
		return result, nil
	}
	g := &Gateway{historyDir: directory}
	revision := c.Revision
	for revision != 0 {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if result.HistoryDepth >= maxPolicySnapshots {
			return result, errors.New("history exceeds supported depth")
		}
		s, e := g.readSnapshot(revision)
		if e != nil {
			return result, e
		}
		result.UpstreamPools = result.UpstreamPools || hasUpstreamPools(s.Config)
		result.TrafficControls = result.TrafficControls || hasTrafficControls(s.Config)
		if s.Config.SchemaVersion == 2 && len(result.PolicySchemas) == 0 {
			result.PolicySchemas = []int{1, 2}
		}
		if s.Config.SchemaVersion == 1 && len(result.PolicySchemas) == 1 && result.PolicySchemas[0] == 2 {
			result.PolicySchemas = []int{1, 2}
		}
		if result.HistoryDepth == 0 && s.SHA256 != policyDigest(c) {
			return result, errors.New("active policy differs from its recorded revision")
		}
		if compileHistory && revision != c.Revision {
			deployment, e := buildRuntime(s.Config, compile)
			if e != nil {
				return result, fmt.Errorf("compile historical revision %d: %w", revision, e)
			}
			closeRuntime(deployment)
		}
		result.HistoryDepth++
		revision = s.Parent
	}
	result.Orphans = result.SnapshotFiles - result.HistoryDepth
	return result, nil
}
