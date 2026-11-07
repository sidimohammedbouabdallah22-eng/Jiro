package accounts

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestAccountPublicationCrashHelper(t *testing.T) {
	path, phase := os.Getenv("OPENWAF_ACCOUNT_CRASH_PATH"), os.Getenv("OPENWAF_ACCOUNT_CRASH_PHASE")
	if path == "" {
		t.Skip("subprocess helper")
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.write = func(path string, data []byte) error {
		return writeAtomicWithPublish(path, data, func(temporary, target string) error {
			stop := func() {
				if err := os.WriteFile(path+".ready", []byte(phase), 0600); err != nil {
					t.Fatal(err)
				}
				for {
					time.Sleep(time.Hour)
				}
			}
			if phase == "before" {
				stop()
			}
			if err := os.Rename(temporary, target); err != nil {
				return err
			}
			stop()
			return nil
		})
	}
	if _, err := s.Save(2, "admin", "administrator", false, "new password after publication", "test", "Crash qualification"); err != nil {
		t.Fatal(err)
	}
	t.Fatal("crash helper unexpectedly returned")
}

func TestAccountCrashBeforeAndAfterPublication(t *testing.T) {
	for _, phase := range []string{"before", "after"} {
		t.Run(phase, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "accounts.json")
			s, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Save(1, "admin", "administrator", false, "old acknowledged password", "test", "Acknowledged baseline"); err != nil {
				t.Fatal(err)
			}
			command := exec.Command(os.Args[0], "-test.run=^TestAccountPublicationCrashHelper$")
			command.Env = append(os.Environ(), "OPENWAF_ACCOUNT_CRASH_PATH="+path, "OPENWAF_ACCOUNT_CRASH_PHASE="+phase)
			var output bytes.Buffer
			command.Stdout = &output
			command.Stderr = &output
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(10 * time.Second)
			ready := false
			for time.Now().Before(deadline) {
				if _, err := os.Stat(path + ".ready"); err == nil {
					ready = true
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			_ = command.Process.Kill()
			_ = command.Wait()
			if !ready {
				t.Fatalf("publication boundary was not reached: %s", output.String())
			}
			recovered, err := Open(path)
			if err != nil {
				t.Fatal("process crash damaged account state", err)
			}
			expectedVersion, password := uint64(2), "old acknowledged password"
			if phase == "after" {
				expectedVersion, password = 3, "new password after publication"
			}
			if recovered.List().Revision != expectedVersion {
				t.Fatal("unexpected publication state", recovered.List().Revision)
			}
			if _, ok := recovered.Verify("admin", password); !ok {
				t.Fatal("recovered account verifier is inconsistent")
			}
		})
	}
}
