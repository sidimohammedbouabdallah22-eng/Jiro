package operations

import (
	"context"
	"debug/buildinfo"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type BackupOptions struct {
	Paths                           Paths
	Destination, Binary, Credential string
	ExternalCollector               bool
	copyCheckpoint                  func(int) // private fault-injection seam; never set by CLI
}

var historicalMember = regexp.MustCompile(`^state/policy\.json\.history/[0-9]{20}\.json$`)

func memberLimit(m Member) (int64, error) {
	switch {
	case m.Path == "state/policy.json" && m.Role == "policy":
		return 256 << 10, nil
	case historicalMember.MatchString(m.Path) && m.Role == "history":
		return 256 << 10, nil
	case m.Path == "state/policy.json.audit.jsonl" && m.Role == "audit":
		return 32 << 20, nil
	case m.Path == "state/policy.json.accounts.json" && m.Role == "accounts":
		return 256 << 10, nil
	case m.Path == "state/events.db" && m.Role == "events", m.Path == "state/collector.db" && m.Role == "collector":
		return 1 << 30, nil
	case (m.Path == "bin/waf-server" || m.Path == "bin/waf-server.exe") && m.Role == "binary":
		return 256 << 20, nil
	case m.Path == "private/admin-token.txt" && m.Role == "credential":
		return 4096, nil
	}
	return 0, fmt.Errorf("unsupported backup member %q", m.Path)
}
func inside(parent, path string) bool {
	rel, err := filepath.Rel(parent, path)
	return err == nil && (rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".." && !filepath.IsAbs(rel)))
}
func newStage(destination string) (string, string, error) {
	target, err := absolute(destination)
	if err != nil || target == "" {
		return "", "", errors.New("destination is required")
	}
	if _, err = os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		return "", "", errors.New("destination already exists or cannot be inspected; overwrite is never allowed")
	}
	parent := filepath.Dir(target)
	if err = os.MkdirAll(parent, 0700); err != nil {
		return "", "", err
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", "", err
	}
	target = filepath.Join(resolved, filepath.Base(target))
	if _, err = os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		return "", "", errors.New("resolved destination already exists")
	}
	stage, err := os.MkdirTemp(resolved, ".openwaf-recovery-")
	if err == nil {
		if e := secureDirectory(stage); e != nil {
			os.RemoveAll(stage)
			return "", "", e
		}
	}
	return stage, target, err
}
func copyMember(ctx context.Context, source, root string, m Member) (Member, error) {
	limit, err := memberLimit(m)
	if err != nil {
		return m, err
	}
	if err = regular(source, limit); err != nil {
		return m, err
	}
	target := filepath.Join(root, filepath.FromSlash(m.Path))
	if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		return m, err
	}
	input, err := os.Open(source)
	if err != nil {
		return m, err
	}
	defer input.Close()
	mode := os.FileMode(0600)
	if m.Role == "binary" {
		mode = 0700
	}
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return m, err
	}
	_, err = copyContext(ctx, output, input, limit)
	if err == nil {
		err = output.Sync()
	}
	closeErr := output.Close()
	if err != nil {
		return m, err
	}
	if closeErr != nil {
		return m, closeErr
	}
	sum, size, err := hashFile(ctx, target)
	if err != nil {
		return m, err
	}
	original, originalSize, err := hashFile(ctx, source)
	if err != nil {
		return m, err
	}
	if sum != original || size != originalSize {
		return m, errors.New("source changed while copying")
	}
	if m.SHA256 != "" && (m.SHA256 != sum || m.Size != size) {
		return m, errors.New("backup member changed since verification")
	}
	m.SHA256 = sum
	m.Size = size
	return m, nil
}
func writeManifest(root string, m Manifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if len(data) > 1<<20 {
		return errors.New("manifest exceeds 1 MiB")
	}
	f, err := os.OpenFile(filepath.Join(root, "manifest.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(append(data, '\n'))
	if err == nil {
		err = f.Sync()
	}
	e := f.Close()
	if err != nil {
		return err
	}
	return e
}
func stateEqual(a, b State) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func Backup(ctx context.Context, o BackupOptions) (Manifest, error) {
	var manifest Manifest
	p, err := normalized(o.Paths)
	if err != nil {
		return manifest, err
	}
	target, err := absolute(o.Destination)
	if err != nil {
		return manifest, err
	}
	if inside(p.Policy+".history", target) {
		return manifest, errors.New("backup destination cannot be inside source history")
	}
	release, err := acquire(p)
	if err != nil {
		return manifest, err
	}
	defer release()
	state, readers, err := inspectHeld(ctx, p, false)
	if err != nil {
		return manifest, err
	}
	defer func() {
		for _, r := range readers {
			r.close()
		}
	}()
	scope := "local"
	if p.Events == "" {
		scope = "policy-only"
	}
	if state.Events != nil && state.Events.Destination != "" {
		if p.Collector != "" {
			scope = "coordinated"
		} else if o.ExternalCollector {
			scope = "external-current-collector"
		} else {
			return manifest, errors.New("export-bound state requires -collector-db or explicit -external-collector scope")
		}
	}
	manifest = Manifest{Format: FormatVersion, Created: time.Now().UTC(), Sensitive: true, Scope: scope, Paths: Paths{Policy: "state/policy.json"}, State: state, Files: []Member{}}
	type planned struct {
		source string
		member Member
	}
	plan := []planned{{p.Policy, Member{Path: manifest.Paths.Policy, Role: "policy"}}}
	history, err := historyFiles(p.Policy)
	if err != nil {
		return manifest, err
	}
	for _, path := range history {
		plan = append(plan, planned{path, Member{Path: "state/policy.json.history/" + filepath.Base(path), Role: "history"}})
	}
	if p.Audit != "" {
		manifest.Paths.Audit = "state/policy.json.audit.jsonl"
		plan = append(plan, planned{p.Audit, Member{Path: manifest.Paths.Audit, Role: "audit"}})
	}
	if p.Accounts != "" {
		manifest.Paths.Accounts = "state/policy.json.accounts.json"
		plan = append(plan, planned{p.Accounts, Member{Path: manifest.Paths.Accounts, Role: "accounts"}})
	}
	if p.Events != "" {
		manifest.Paths.Events = "state/events.db"
		plan = append(plan, planned{p.Events, Member{Path: manifest.Paths.Events, Role: "events"}})
	}
	if p.Collector != "" {
		manifest.Paths.Collector = "state/collector.db"
		plan = append(plan, planned{p.Collector, Member{Path: manifest.Paths.Collector, Role: "collector"}})
	}
	if o.Binary != "" {
		if err = regular(o.Binary, 256<<20); err != nil {
			return manifest, err
		}
		if _, err = buildinfo.ReadFile(o.Binary); err != nil {
			return manifest, fmt.Errorf("backup binary must be a Go executable: %w", err)
		}
		manifest.Binary = "bin/waf-server"
		if strings.EqualFold(filepath.Ext(o.Binary), ".exe") {
			manifest.Binary += ".exe"
		}
		plan = append(plan, planned{o.Binary, Member{Path: manifest.Binary, Role: "binary"}})
	}
	if o.Credential != "" {
		manifest.Credential = "private/admin-token.txt"
		plan = append(plan, planned{o.Credential, Member{Path: manifest.Credential, Role: "credential"}})
	}
	stage, destination, err := newStage(o.Destination)
	if err != nil {
		return manifest, err
	}
	defer os.RemoveAll(stage)
	if inside(p.Policy+".history", destination) {
		return manifest, errors.New("resolved backup destination is inside source history")
	}
	var total int64
	for _, file := range plan {
		member, e := copyMember(ctx, file.source, stage, file.member)
		if e != nil {
			return manifest, e
		}
		total += member.Size
		if total > maxBundleBytes {
			return manifest, errors.New("backup exceeds 3 GiB")
		}
		manifest.Files = append(manifest.Files, member)
		if o.copyCheckpoint != nil {
			o.copyCheckpoint(len(manifest.Files))
		}
	}
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
	if err = writeManifest(stage, manifest); err != nil {
		return manifest, err
	}
	if _, err = Verify(ctx, stage); err != nil {
		return manifest, fmt.Errorf("verify staged backup: %w", err)
	}
	if err = ctx.Err(); err != nil {
		return manifest, err
	}
	if _, err = os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		return manifest, errors.New("destination appeared during backup")
	}
	if err = publishDirectory(stage, destination); err != nil {
		return manifest, err
	}
	return manifest, nil
}

func Verify(ctx context.Context, root string) (Manifest, error) {
	var manifest Manifest
	root, err := absolute(root)
	if err != nil {
		return manifest, err
	}
	info, err := os.Lstat(root)
	if err != nil {
		return manifest, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return manifest, errors.New("backup must be a real directory")
	}
	path := filepath.Join(root, "manifest.json")
	if err = regular(path, 1<<20); err != nil {
		return manifest, err
	}
	f, err := os.Open(path)
	if err != nil {
		return manifest, err
	}
	data, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	f.Close()
	if err != nil {
		return manifest, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&manifest); err != nil {
		return manifest, err
	}
	if err = decoder.Decode(new(any)); err != io.EOF {
		return manifest, errors.New("trailing manifest data")
	}
	if manifest.Format != FormatVersion || !manifest.Sensitive || len(manifest.Files) < 1 || len(manifest.Files) > maxMembers || manifest.Paths.Policy != "state/policy.json" || (manifest.Paths.Events != "" && manifest.Paths.Events != "state/events.db") || (manifest.Paths.Collector != "" && manifest.Paths.Collector != "state/collector.db") || (manifest.Paths.Audit != "" && manifest.Paths.Audit != "state/policy.json.audit.jsonl") || (manifest.Paths.Accounts != "" && manifest.Paths.Accounts != "state/policy.json.accounts.json") {
		return manifest, errors.New("unsupported or invalid backup manifest")
	}
	switch manifest.Scope {
	case "local":
		if manifest.Paths.Events == "" || manifest.Paths.Collector != "" {
			return manifest, errors.New("invalid local scope")
		}
	case "policy-only":
		if manifest.Paths.Events != "" || manifest.Paths.Collector != "" {
			return manifest, errors.New("invalid policy scope")
		}
	case "coordinated":
		if manifest.Paths.Events == "" || manifest.Paths.Collector == "" {
			return manifest, errors.New("invalid coordinated scope")
		}
	case "external-current-collector":
		if manifest.Paths.Events == "" || manifest.Paths.Collector != "" {
			return manifest, errors.New("invalid external-collector scope")
		}
	default:
		return manifest, errors.New("unknown backup scope")
	}
	files := map[string]Member{}
	directories := map[string]bool{".": true}
	var total int64
	for _, member := range manifest.Files {
		limit, e := memberLimit(member)
		if e != nil {
			return manifest, e
		}
		if (member.Role == "accounts" && member.Path != manifest.Paths.Accounts) || (member.Role == "audit" && member.Path != manifest.Paths.Audit) || (member.Role == "events" && member.Path != manifest.Paths.Events) || (member.Role == "collector" && member.Path != manifest.Paths.Collector) || (member.Role == "binary" && member.Path != manifest.Binary) || (member.Role == "credential" && member.Path != manifest.Credential) {
			return manifest, errors.New("backup member is not declared in its recovery coverage")
		}
		if _, ok := files[member.Path]; ok || member.Size < 0 || member.Size > limit {
			return manifest, errors.New("duplicate or oversized backup member")
		}
		total += member.Size
		if total > maxBundleBytes {
			return manifest, errors.New("backup exceeds size budget")
		}
		files[member.Path] = member
		for parent := filepath.ToSlash(filepath.Dir(filepath.FromSlash(member.Path))); parent != "."; parent = filepath.ToSlash(filepath.Dir(filepath.FromSlash(parent))) {
			directories[parent] = true
		}
	}
	for _, required := range []string{manifest.Paths.Policy, manifest.Paths.Events, manifest.Paths.Collector, manifest.Paths.Audit, manifest.Paths.Accounts, manifest.Binary, manifest.Credential} {
		if required != "" {
			if _, ok := files[required]; !ok {
				return manifest, errors.New("manifest is missing a declared member")
			}
		}
	}
	if manifest.Binary != "" && manifest.Binary != "bin/waf-server" && manifest.Binary != "bin/waf-server.exe" {
		return manifest, errors.New("invalid binary path")
	}
	if manifest.Credential != "" && manifest.Credential != "private/admin-token.txt" {
		return manifest, errors.New("invalid credential path")
	}
	stack := []string{"."}
	seen := map[string]bool{}
	nodes := 0
	for len(stack) > 0 {
		relative := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		dir := filepath.Join(root, filepath.FromSlash(relative))
		handle, e := os.Open(dir)
		if e != nil {
			return manifest, e
		}
		entries, e := handle.ReadDir(maxMembers + 10)
		handle.Close()
		if e != nil && e != io.EOF {
			return manifest, e
		}
		nodes += len(entries)
		if nodes > maxMembers+10 {
			return manifest, errors.New("backup contains too many entries")
		}
		for _, entry := range entries {
			name := entry.Name()
			if relative != "." {
				name = relative + "/" + name
			}
			full := filepath.Join(root, filepath.FromSlash(name))
			stat, e := os.Lstat(full)
			if e != nil {
				return manifest, e
			}
			if stat.Mode()&os.ModeSymlink != 0 {
				return manifest, errors.New("symlink backup entries are forbidden")
			}
			if stat.IsDir() {
				if !directories[name] {
					return manifest, errors.New("unlisted backup directory")
				}
				stack = append(stack, name)
				continue
			}
			if name == "manifest.json" {
				continue
			}
			member, ok := files[name]
			if !ok {
				return manifest, fmt.Errorf("unlisted backup member %q", name)
			}
			limit, _ := memberLimit(member)
			if e = regular(full, limit); e != nil {
				return manifest, e
			}
			sum, size, e := hashFile(ctx, full)
			if e != nil {
				return manifest, e
			}
			if sum != member.SHA256 || size != member.Size {
				return manifest, fmt.Errorf("checksum/size mismatch for %s", name)
			}
			seen[name] = true
		}
	}
	if len(seen) != len(files) {
		return manifest, errors.New("backup is incomplete")
	}
	state, readers, err := inspectHeld(ctx, pathsUnder(root, manifest.Paths), false)
	for _, r := range readers {
		r.close()
	}
	if err != nil {
		return manifest, err
	}
	if !stateEqual(state, manifest.State) {
		return manifest, errors.New("backup logical state differs from its manifest")
	}
	if state.Events != nil && state.Events.Destination != "" && manifest.Scope != "coordinated" && manifest.Scope != "external-current-collector" {
		return manifest, errors.New("export-bound backup has unsafe recovery scope")
	}
	return manifest, nil
}

func Restore(ctx context.Context, backup, destination string) (Manifest, error) {
	manifest, err := Verify(ctx, backup)
	if err != nil {
		return manifest, err
	}
	source, err := absolute(backup)
	if err != nil {
		return manifest, err
	}
	source, err = filepath.EvalSymlinks(source)
	if err != nil {
		return manifest, err
	}
	target, err := absolute(destination)
	if err != nil {
		return manifest, err
	}
	if inside(source, target) {
		return manifest, errors.New("restore destination cannot be inside its backup")
	}
	stage, target, err := newStage(destination)
	if err != nil {
		return manifest, err
	}
	defer os.RemoveAll(stage)
	if inside(source, target) {
		return manifest, errors.New("resolved restore destination is inside its backup")
	}
	for _, member := range manifest.Files {
		if _, err = copyMember(ctx, filepath.Join(source, filepath.FromSlash(member.Path)), stage, member); err != nil {
			return manifest, err
		}
	}
	if err = writeManifest(stage, manifest); err != nil {
		return manifest, err
	}
	if _, err = Verify(ctx, stage); err != nil {
		return manifest, err
	}
	if err = ctx.Err(); err != nil {
		return manifest, err
	}
	if _, err = os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		return manifest, errors.New("restore destination appeared during staging")
	}
	if err = publishDirectory(stage, target); err != nil {
		return manifest, err
	}
	return manifest, nil
}
