//go:build !linux

package accounts

import "os"

// Non-Linux qualification covers synced file publication and process crashes.
func publishDurable(temporary, target string) error {
	return os.Rename(temporary, target)
}
