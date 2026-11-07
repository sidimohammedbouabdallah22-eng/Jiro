package operations

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestPrepareProbeWithWindowsShortDirectory(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recovery directory with long name")
	state := filepath.Join(root, "state")
	if err := os.MkdirAll(state, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "policy.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	longPath, err := syscall.UTF16PtrFromString(root)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]uint16, 32768)
	n, err := syscall.GetShortPathName(longPath, &buffer[0], uint32(len(buffer)))
	if err != nil || n >= uint32(len(buffer)) {
		t.Fatalf("get Windows short path: length %d, error %v", n, err)
	}
	shortRoot := syscall.UTF16ToString(buffer[:n])
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	if strings.EqualFold(shortRoot, resolved) {
		t.Skip("this volume does not provide a distinct short path")
	}
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := prepareProbe(shortRoot, Paths{Policy: outside}); err == nil {
		t.Fatal("probe accepted state outside the disposable directory")
	}
	paths := Paths{Policy: filepath.Join(shortRoot, "state", "policy.json")}
	if err := prepareProbe(shortRoot, paths); err != nil {
		t.Fatal(err)
	}
	if err := checkProbeMarker(paths); err != nil {
		t.Fatal(err)
	}
}
