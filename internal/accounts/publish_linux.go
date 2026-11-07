package accounts

import (
	"fmt"
	"os"
	"path/filepath"
)

func publishDurable(temporary, target string) error {
	if err := os.Rename(temporary, target); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(target))
	if err != nil {
		return fmt.Errorf("%w: %v", errPublicationUncertain, err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("%w: %v", errPublicationUncertain, err)
	}
	return nil
}
