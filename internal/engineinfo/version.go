// Package engineinfo identifies the exact upstream engine and downstream patch.
package engineinfo

import (
	"runtime/debug"
	"strings"
)

func Version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dependency := range info.Deps {
		if dependency.Path != "github.com/corazawaf/coraza/v3" {
			continue
		}
		version := dependency.Version
		if dependency.Replace != nil && strings.HasSuffix(strings.ReplaceAll(dependency.Replace.Path, `\`, "/"), "third_party/coraza") {
			patch := "+openwaf-ascii-presence-v1"
			for _, setting := range info.Settings {
				if setting.Key == "-tags" && strings.Contains(setting.Value, "openwaf.no_ascii_guard") {
					patch = "+openwaf-ascii-presence-disabled"
				}
			}
			version += patch
		}
		return version
	}
	return "unknown"
}
