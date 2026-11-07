package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	crs "github.com/corazawaf/coraza-coreruleset/crs/v4"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/engineinfo"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/eventcollector"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/eventstore"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/gateway"
)

type Capabilities struct {
	UpstreamPools   int    `json:"upstream_pools,omitempty"`
	AuditExport     int    `json:"audit_export,omitempty"`
	TrafficControls int    `json:"traffic_controls,omitempty"`
	AccountsFormat  int    `json:"accounts_format,omitempty"`
	AccountSchemas  []int  `json:"account_schemas,omitempty"`
	AuditFormat     int    `json:"audit_format,omitempty"`
	Protocol        int    `json:"protocol"`
	Product         string `json:"product"`
	OS              string `json:"os"`
	Arch            string `json:"arch"`
	Go              string `json:"go"`
	PolicySchemas   []int  `json:"policy_schemas"`
	SenderMin       int    `json:"sender_min"`
	SenderMax       int    `json:"sender_max"`
	CollectorMin    int    `json:"collector_min"`
	CollectorMax    int    `json:"collector_max"`
	HistoryFormat   int    `json:"history_format"`
	Engine          string `json:"engine"`
	CRS             string `json:"crs"`
}

func CurrentCapabilities() Capabilities {
	c := Capabilities{Protocol: 1, Product: "OpenWAF", OS: runtime.GOOS, Arch: runtime.GOARCH, Go: runtime.Version(), PolicySchemas: []int{1, 2}, SenderMin: 1, SenderMax: 2, CollectorMin: 1, CollectorMax: 1, HistoryFormat: 1, CRS: crs.Version}
	c.AuditFormat = 1
	c.AuditExport = 1
	c.TrafficControls = 1
	c.UpstreamPools = 1
	c.AccountsFormat = 1
	c.AccountSchemas = []int{1, 2, 3, 4}
	c.Engine = engineinfo.Version()
	return c
}

type CheckReport struct {
	Compatible      bool         `json:"compatible"`
	CandidateSHA256 string       `json:"candidate_sha256"`
	Capabilities    Capabilities `json:"capabilities"`
	Before          State        `json:"before"`
	After           State        `json:"after"`
	Changes         []string     `json:"changes"`
}

func supports(s State, c Capabilities) error {
	if s.Policy.UpstreamPools && c.UpstreamPools != 1 {
		return errors.New("candidate does not support upstream pools in committed history")
	}
	if s.Audit != nil && s.Audit.ExportDestinationSHA256 != "" && c.AuditExport != 1 {
		return errors.New("candidate does not support the bound administration audit export")
	}
	if s.Accounts != nil && c.AccountsFormat != 1 {
		return errors.New("candidate does not support local administration accounts")
	}
	if s.Accounts != nil && s.Accounts.Schema != 1 {
		found := false
		for _, schema := range c.AccountSchemas {
			if schema == s.Accounts.Schema {
				found = true
			}
		}
		if !found {
			return errors.New("candidate does not support this administration credential schema; restore a compatible pre-feature checkpoint")
		}
	}
	if s.Policy.TrafficControls && c.TrafficControls != 1 {
		return errors.New("candidate does not support traffic controls in committed policy history")
	}
	for _, required := range s.Policy.PolicySchemas {
		found := false
		for _, supported := range c.PolicySchemas {
			if required == supported {
				found = true
				break
			}
		}
		if !found {
			return errors.New("candidate cannot read a policy schema in committed history")
		}
	}
	if s.Audit != nil && c.AuditFormat != 1 {
		return errors.New("candidate does not support the administration audit format")
	}
	if c.Protocol != 1 || c.Product != "OpenWAF" || c.HistoryFormat != 1 {
		return errors.New("candidate lacks the supported offline capability/probe protocol")
	}
	policy := false
	for _, v := range c.PolicySchemas {
		if v == s.Policy.Schema {
			policy = true
		}
	}
	if !policy {
		return errors.New("candidate does not support this policy schema")
	}
	if s.Events != nil && (s.Events.Schema < c.SenderMin || s.Events.Schema > c.SenderMax) {
		return fmt.Errorf("candidate sender schema range %d..%d cannot read schema %d; restore a compatible pre-upgrade backup", c.SenderMin, c.SenderMax, s.Events.Schema)
	}
	if s.Collector != nil && (s.Collector.Schema < c.CollectorMin || s.Collector.Schema > c.CollectorMax) {
		return errors.New("candidate does not support this collector schema")
	}
	return nil
}
func preserved(before, after State) error {
	if before.Accounts != nil && (after.Accounts == nil || *before.Accounts != *after.Accounts) {
		return errors.New("candidate changed administration accounts")
	}
	if before.Audit != nil && (after.Audit == nil || *before.Audit != *after.Audit) {
		return errors.New("candidate changed administration audit records")
	}
	if before.PolicyDigest != after.PolicyDigest {
		return errors.New("candidate changed the active policy")
	}
	if before.HistoryDigest != after.HistoryDigest && !(before.Policy.HistoryDepth == 0 && before.Policy.SnapshotFiles == 0 && after.Policy.HistoryDepth == 1 && after.Policy.SnapshotFiles == 1) {
		return errors.New("candidate changed existing policy history")
	}
	if before.Events != nil {
		a, b := before.Events, after.Events
		if b == nil || a.Rows != b.Rows || a.Digest != b.Digest || a.OutboxRows != b.OutboxRows || a.Source != b.Source || a.Destination != b.Destination || a.Records != b.Records || a.Occurrences != b.Occurrences || a.Enqueued != b.Enqueued || a.EnqueuedOccurrences != b.EnqueuedOccurrences || a.Acked != b.Acked || a.AckedOccurrences != b.AckedOccurrences {
			return errors.New("candidate changed event records or delivery accounting")
		}
		if a.OutboxRows > 0 && a.OutboxDigest != b.OutboxDigest {
			return errors.New("candidate changed pending deliveries")
		}
	}
	if before.Collector != nil {
		a, b := before.Collector, after.Collector
		if b == nil || a.Digest != b.Digest || a.Rows != b.Rows || a.Records != b.Records || a.Occurrences != b.Occurrences {
			return errors.New("candidate changed collector receipts")
		}
	}
	return nil
}

// Probe is invoked only by an explicitly requested offline candidate process on
// disposable copies. No listeners are opened and persisted export is paused.
func Probe(ctx context.Context, p Paths) (CheckReport, error) {
	report := CheckReport{Capabilities: CurrentCapabilities(), Changes: []string{}}
	var err error
	if err = checkProbeMarker(p); err != nil {
		return report, err
	}
	report.Before, err = Inspect(ctx, p, true)
	if err != nil {
		return report, err
	}
	if err = supports(report.Before, report.Capabilities); err != nil {
		return report, err
	}
	options := gateway.Options{DisableEventStore: p.Events == "", EventStore: eventstore.Options{Path: p.Events, MaxBytes: 1 << 30, MaxRows: 100000, MaxAge: 365 * 24 * time.Hour, Export: eventstore.ExportOptions{MaxRows: 100000}}}
	options.AuditPath = p.Audit
	options.DisableAudit = p.Audit == ""
	g, err := gateway.NewWithOptions(p.Policy, options)
	if err != nil {
		return report, err
	}
	g.Close(ctx)
	if err = ctx.Err(); err != nil {
		return report, err
	}
	if p.Collector != "" {
		receiver, e := eventcollector.Open(eventcollector.Options{Path: p.Collector, Token: "offline-probe-credential-never-used-on-a-listener", MaxBytes: 1 << 30})
		if e != nil {
			return report, e
		}
		if e = receiver.Close(); e != nil {
			return report, e
		}
	}
	report.After, err = Inspect(ctx, p, true)
	if err != nil {
		return report, err
	}
	if err = preserved(report.Before, report.After); err != nil {
		return report, err
	}
	report.Compatible = true
	if report.Before.Events != nil && report.Before.Events.Schema != report.After.Events.Schema {
		report.Changes = append(report.Changes, fmt.Sprintf("sender schema %d -> %d", report.Before.Events.Schema, report.After.Events.Schema))
	}
	if report.Before.Policy.HistoryDepth == 0 && report.After.Policy.HistoryDepth == 1 {
		report.Changes = append(report.Changes, "bootstrap initial policy history")
	}
	return report, nil
}

type candidateRunner interface {
	capabilities(context.Context) (Capabilities, error)
	probe(context.Context, Paths) error
}
type executable struct{ path string }
type limitedOutput struct {
	mu     sync.Mutex
	buffer bytes.Buffer
	cancel context.CancelFunc
}

func (b *limitedOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.buffer.Len()+len(p) > 128<<10 {
		b.cancel()
		return 0, errors.New("candidate output exceeds 128 KiB")
	}
	return b.buffer.Write(p)
}
func (e executable) run(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	workingDirectory, err := os.MkdirTemp("", "openwaf-candidate-process-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(workingDirectory)
	command := exec.CommandContext(ctx, e.path, args...)
	command.Dir = workingDirectory
	output := &limitedOutput{cancel: cancel}
	stderr := &limitedOutput{cancel: cancel}
	command.Stdout = output
	command.Stderr = stderr
	// Do not expose administrator/export/cloud credentials to the probe.
	for _, key := range []string{"SystemRoot", "WINDIR", "TEMP", "TMP", "TMPDIR", "PATH"} {
		if value, ok := os.LookupEnv(key); ok {
			command.Env = append(command.Env, key+"="+value)
		}
	}
	if command.Env == nil {
		command.Env = []string{}
	}
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("candidate failed: %w; %s", err, stderr.buffer.String())
	}
	return output.buffer.Bytes(), nil
}
func (e executable) capabilities(ctx context.Context) (Capabilities, error) {
	var c Capabilities
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	data, err := e.run(ctx, "-capabilities-json")
	if err != nil {
		return c, fmt.Errorf("capability handshake failed (older binaries require separate qualification): %w", err)
	}
	if err = json.Unmarshal(data, &c); err != nil {
		return c, err
	}
	return c, nil
}
func (e executable) probe(ctx context.Context, p Paths) error {
	args := []string{"-upgrade-probe", "-config", p.Policy}
	if p.Events != "" {
		args = append(args, "-event-db", p.Events)
	} else {
		args = append(args, "-probe-policy-only")
	}
	if p.Audit != "" {
		args = append(args, "-audit-file", p.Audit)
	}
	if p.Collector != "" {
		args = append(args, "-probe-collector", p.Collector)
	}
	data, err := e.run(ctx, args...)
	if err != nil {
		return err
	}
	var result CheckReport
	if err = json.Unmarshal(data, &result); err != nil {
		return err
	}
	if !result.Compatible {
		return errors.New("candidate probe did not report successful validation")
	}
	return nil
}

func UpgradeCheck(ctx context.Context, backup, candidate string) (CheckReport, error) {
	path, err := absolute(candidate)
	if err != nil {
		return CheckReport{}, err
	}
	if err = regular(path, 256<<20); err != nil {
		return CheckReport{}, err
	}
	sum, _, err := hashFile(ctx, path)
	if err != nil {
		return CheckReport{}, err
	}
	report, err := checkWith(ctx, backup, executable{path: path})
	report.CandidateSHA256 = sum
	if err == nil {
		after, _, e := hashFile(ctx, path)
		if e != nil || after != sum {
			return report, errors.New("candidate executable changed during qualification")
		}
	}
	return report, err
}
func checkWith(ctx context.Context, backup string, runner candidateRunner) (CheckReport, error) {
	var report CheckReport
	manifest, err := Verify(ctx, backup)
	if err != nil {
		return report, err
	}
	report.Before = manifest.State
	report.Capabilities, err = runner.capabilities(ctx)
	if err != nil {
		return report, err
	}
	if err = supports(report.Before, report.Capabilities); err != nil {
		return report, err
	}
	root, err := os.MkdirTemp("", "openwaf-upgrade-probe-")
	if err != nil {
		return report, err
	}
	defer os.RemoveAll(root)
	stage := filepath.Join(root, "state-copy")
	if _, err = Restore(ctx, backup, stage); err != nil {
		return report, err
	}
	paths := pathsUnder(stage, manifest.Paths)
	if err = prepareProbe(stage, paths); err != nil {
		return report, err
	}
	if err = runner.probe(ctx, paths); err != nil {
		return report, err
	}
	report.After, err = Inspect(ctx, paths, true)
	if err != nil {
		return report, err
	}
	if err = supports(report.After, report.Capabilities); err != nil {
		return report, err
	}
	if err = preserved(report.Before, report.After); err != nil {
		return report, err
	}
	report.Compatible = true
	report.Changes = []string{}
	if report.Before.Events != nil && report.Before.Events.Schema != report.After.Events.Schema {
		report.Changes = append(report.Changes, fmt.Sprintf("sender schema %d -> %d", report.Before.Events.Schema, report.After.Events.Schema))
	}
	if report.Before.Policy.HistoryDepth == 0 && report.After.Policy.HistoryDepth == 1 {
		report.Changes = append(report.Changes, "bootstrap initial policy history")
	}
	return report, nil
}

type RollbackReport struct {
	Prepared    bool        `json:"prepared"`
	Destination string      `json:"destination"`
	Paths       Paths       `json:"paths"`
	Check       CheckReport `json:"check"`
}

func Rollback(ctx context.Context, backup, destination, candidate string) (RollbackReport, error) {
	var report RollbackReport
	if destination == "" {
		return report, errors.New("rollback destination is required")
	}
	target, e := absolute(destination)
	if e != nil {
		return report, e
	}
	if _, e = os.Lstat(target); !errors.Is(e, os.ErrNotExist) {
		return report, errors.New("rollback requires a new destination")
	}
	manifest, err := Verify(ctx, backup)
	if err != nil {
		return report, err
	}
	if candidate == "" {
		if manifest.Binary == "" {
			return report, errors.New("rollback requires a bundled or explicitly supplied trusted binary")
		}
		candidate = filepath.Join(backup, filepath.FromSlash(manifest.Binary))
	}
	report.Check, err = UpgradeCheck(ctx, backup, candidate)
	if err != nil {
		return report, err
	}
	if _, err = Restore(ctx, backup, destination); err != nil {
		return report, err
	}
	report.Destination, _ = absolute(destination)
	report.Paths = pathsUnder(report.Destination, manifest.Paths)
	report.Prepared = true
	return report, nil
}

func prepareProbe(root string, p Paths) error {
	root, err := absolute(root)
	if err != nil {
		return err
	}
	p, err = normalized(p)
	if err != nil {
		return err
	}
	for _, path := range []string{p.Policy, p.Events, p.Collector, p.Audit, p.Accounts} {
		if path != "" && !inside(root, path) {
			return errors.New("probe paths must remain within the disposable copy")
		}
	}
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(root, ".openwaf-probe.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	e := f.Close()
	if err != nil {
		return err
	}
	return e
}
func checkProbeMarker(p Paths) error {
	p, err := normalized(p)
	if err != nil {
		return err
	}
	if filepath.Base(p.Policy) != "policy.json" || filepath.Base(filepath.Dir(p.Policy)) != "state" {
		return errors.New("upgrade probe requires a disposable recovery copy created by waf-admin")
	}
	root := filepath.Dir(filepath.Dir(p.Policy))
	path := filepath.Join(root, ".openwaf-probe.json")
	if err = regular(path, 4096); err != nil {
		return errors.New("upgrade probe marker is missing; use waf-admin upgrade-check")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	expected, _ := json.Marshal(p)
	if !bytes.Equal(data, expected) {
		return errors.New("upgrade probe marker does not match the supplied state")
	}
	return nil
}

var _ io.Writer = (*limitedOutput)(nil)
