// waf-package builds a portable Linux systemd package from the source tree.
package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	arch := flag.String("arch", "amd64", "Linux architecture, amd64 or arm64")
	version := flag.String("version", "development", "Package label")
	out := flag.String("out", "artifacts", "Output directory")
	flag.Parse()
	if (*arch != "amd64" && *arch != "arm64") || !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`).MatchString(*version) {
		return fmt.Errorf("invalid architecture or package label")
	}
	stage, err := os.MkdirTemp("", "openwaf-package-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	files := map[string]string{
		"usr/lib/systemd/system/openwaf.service": "deploy/linux/openwaf.service",
		"usr/lib/sysusers.d/openwaf.conf":        "deploy/linux/openwaf.sysusers",
		"etc/openwaf/openwaf.env":                "deploy/linux/openwaf.env",
		"install.sh":                             "deploy/linux/install.sh",
		"LICENSE":                                "LICENSE", "NOTICE": "NOTICE",
		"docs/LINUX-OPERATIONS.md":                "docs/LINUX-OPERATIONS.md",
		"docs/VALIDATION-APPLIANCE-OPERATIONS.md": "docs/VALIDATION-APPLIANCE-OPERATIONS.md",
		"docs/BACKUP-RESTORE-UPGRADES.md":         "docs/BACKUP-RESTORE-UPGRADES.md",
		"docs/audit-export.conf.example":          "deploy/linux/audit-export.conf.example",
	}
	files["THIRD_PARTY_LICENSES/Go-LICENSE"] = filepath.Join(runtime.GOROOT(), "LICENSE")
	files["THIRD_PARTY_LICENSES/Coraza-OpenWAF/LICENSE"] = "third_party/coraza/LICENSE"
	files["THIRD_PARTY_LICENSES/Coraza-OpenWAF/OPENWAF-UPSTREAM.json"] = "third_party/coraza/OPENWAF-UPSTREAM.json"
	files["docs/CORAZA-DOWNSTREAM.md"] = "third_party/coraza/OPENWAF-PATCHES.md"
	files["docs/TRUSTED-PROXIES.md"] = "docs/TRUSTED-PROXIES.md"
	files["docs/APPLICATIONS.md"] = "docs/APPLICATIONS.md"
	files["docs/VALIDATION-APPLICATIONS.md"] = "docs/VALIDATION-APPLICATIONS.md"
	files["docs/PROGRESS.md"] = "docs/PROGRESS.md"
	files["docs/AUDIT-EXPORT.md"] = "docs/AUDIT-EXPORT.md"
	files["docs/M2-QUALIFICATION.md"] = "docs/M2-QUALIFICATION.md"
	files["docs/ARM64-QUALIFICATION.md"] = "docs/ARM64-QUALIFICATION.md"
	files["docs/M2-OPERATIONAL-RUNBOOK.md"] = "docs/M2-OPERATIONAL-RUNBOOK.md"
	files["docs/VIRTUALBOX-QUALIFICATION.md"] = "docs/VIRTUALBOX-QUALIFICATION.md"
	files["docs/TRAFFIC-AND-ACCESS.md"] = "docs/TRAFFIC-AND-ACCESS.md"
	files["docs/M3-AUTHENTICATION.md"] = "docs/M3-AUTHENTICATION.md"
	files["docs/M3-AUTHORIZATION.md"] = "docs/M3-AUTHORIZATION.md"
	files["docs/M3-COMPLETION.md"] = "docs/M3-COMPLETION.md"
	files["docs/SSO-AND-PASSKEYS.md"] = "docs/SSO-AND-PASSKEYS.md"
	files["docs/RULE-UPDATES.md"] = "docs/RULE-UPDATES.md"
	files["docs/authentication.conf.example"] = "deploy/linux/authentication.conf.example"
	files["docs/VALIDATION-TRAFFIC-ACCESS.md"] = "docs/VALIDATION-TRAFFIC-ACCESS.md"
	if err = filepath.WalkDir("THIRD_PARTY_LICENSES", func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() {
			files[filepath.ToSlash(path)] = path
		}
		return nil
	}); err != nil {
		return err
	}
	for target, source := range files {
		data, e := os.ReadFile(source)
		if e != nil {
			return e
		}
		path := filepath.Join(stage, filepath.FromSlash(target))
		if e = os.MkdirAll(filepath.Dir(path), 0755); e != nil {
			return e
		}
		if e = os.WriteFile(path, data, 0644); e != nil {
			return e
		}
	}
	for _, name := range []string{"waf-server", "waf-admin", "event-collector"} {
		path := filepath.Join(stage, "usr", "lib", "openwaf", name)
		if err = os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}
		cmd := exec.Command("go", "build", "-trimpath", "-o", path, "./cmd/"+name)
		for _, value := range os.Environ() {
			if !strings.HasPrefix(value, "GOOS=") && !strings.HasPrefix(value, "GOARCH=") && !strings.HasPrefix(value, "CGO_ENABLED=") {
				cmd.Env = append(cmd.Env, value)
			}
		}
		cmd.Env = append(cmd.Env, "GOOS=linux", "GOARCH="+*arch, "CGO_ENABLED=0")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err = cmd.Run(); err != nil {
			return err
		}
	}
	if err = os.MkdirAll(*out, 0755); err != nil {
		return err
	}
	name := fmt.Sprintf("openwaf-%s-linux-%s.tar.gz", *version, *arch)
	path := filepath.Join(*out, name)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	hash := sha256.New()
	zip := gzip.NewWriter(io.MultiWriter(file, hash))
	archive := tar.NewWriter(zip)
	err = filepath.WalkDir(stage, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		info, e := entry.Info()
		if e != nil {
			return e
		}
		rel, e := filepath.Rel(stage, path)
		if e != nil {
			return e
		}
		member := filepath.ToSlash(rel)
		mode := int64(0644)
		if member == "install.sh" || strings.HasPrefix(member, "usr/lib/openwaf/") {
			mode = 0755
		}
		if e = archive.WriteHeader(&tar.Header{Name: member, Mode: mode, Size: info.Size()}); e != nil {
			return e
		}
		input, e := os.Open(path)
		if e != nil {
			return e
		}
		_, e = io.Copy(archive, input)
		return errors.Join(e, input.Close())
	})
	err = errors.Join(err, archive.Close(), zip.Close(), file.Sync(), file.Close())
	if err != nil {
		return err
	}
	checksum := fmt.Sprintf("%x  %s\n", hash.Sum(nil), name)
	if err = os.WriteFile(path+".sha256", []byte(checksum), 0644); err != nil {
		return err
	}
	fmt.Println(path)
	return nil
}
