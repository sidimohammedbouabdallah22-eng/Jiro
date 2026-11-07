//go:build !windows

package operations

import "os"

func secureDirectory(path string) error { return os.Chmod(path, 0700) }
