package credentials

import (
	"errors"
	"io"
	"os"
	"strings"
)

// Value reads one bounded credential source without including its value in errors.
func Value(environment, path string) (string, error) {
	value := strings.TrimSpace(os.Getenv(environment))
	if path == "" {
		return value, nil
	}
	if value != "" {
		return "", errors.New("choose a credential file or environment value, not both")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", errors.New("credential file unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 {
		return "", errors.New("credential file must be a regular file of at most 4096 bytes")
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(data) > 4096 {
		return "", errors.New("credential file read failed")
	}
	return strings.TrimSpace(string(data)), nil
}
