//go:build !windows && !linux

package operations

import "errors"

func publishDirectory(from, to string) error {
	return errors.New("atomic no-replace recovery publication is currently supported on Windows and Linux only")
}
