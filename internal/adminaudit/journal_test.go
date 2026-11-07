package adminaudit

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestJournalDurabilityIntegrityAndLease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	j, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := Open(path); err == nil {
		other.Close()
		t.Fatal("second writer acquired journal")
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := j.Append(Record{Operation: "policy.activate", Actor: "test", Outcome: "intent"}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	meta := j.Status().Metadata
	if meta.Records != 20 {
		t.Fatal(meta)
	}
	j.Close()
	j, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	items, err := j.Query(20, 3)
	if err != nil || len(items) != 3 || items[0].Sequence != 19 || j.Status().Metadata != meta {
		t.Fatalf("reopen/pagination: %v %+v", err, items)
	}
	j.Close()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := bytes.Replace(data, []byte("policy.activate"), []byte("policy.tampered"), 1)
	if err = os.WriteFile(path, corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Inspect(path); err == nil {
		t.Fatal("tampered journal accepted")
	}
	if err = os.WriteFile(path, data[:len(data)-1], 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(path); err == nil {
		t.Fatal("incomplete final append accepted")
	}
}

func TestJournalCrashHelper(t *testing.T) {
	path := os.Getenv("OPENWAF_AUDIT_CRASH_PATH")
	if path == "" {
		t.Skip("subprocess helper")
	}
	j, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = j.Append(Record{Operation: "policy.activate", Actor: "test", Outcome: "intent"}); err != nil {
		t.Fatal(err)
	}
	fmt.Println("AUDIT_COMMITTED")
	time.Sleep(time.Minute)
}

func TestKilledProcessRetainsDurableIntent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestJournalCrashHelper$")
	command.Env = append(os.Environ(), "OPENWAF_AUDIT_CRASH_PATH="+path)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	defer command.Process.Kill()
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if scanner.Text() == "AUDIT_COMMITTED" {
				ready <- true
				return
			}
		}
		ready <- false
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("child failed before commit")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("child commit timed out")
	}
	if err = command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	j, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	items, err := j.Query(0, 1)
	if err != nil || len(items) != 1 || items[0].Outcome != "intent" {
		t.Fatalf("durable intent lost after process kill %v", err)
	}
}

func TestCommitFailureAndCapacityAreSticky(t *testing.T) {
	for _, failure := range []string{"closed-file", "capacity"} {
		t.Run(failure, func(t *testing.T) {
			j, err := Open(filepath.Join(t.TempDir(), "audit.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			if failure == "closed-file" {
				j.file.Close()
			} else {
				j.metadata.Bytes = MaxBytes
			}
			if _, err = j.Append(Record{Operation: "test", Outcome: "intent"}); err == nil || j.Status().Healthy {
				t.Fatal("failure not exposed")
			}
			if _, err = j.Append(Record{Operation: "test", Outcome: "intent"}); err == nil {
				t.Fatal("journal accepted mutation after failure")
			}
		})
	}
}

func TestStatusDoesNotWaitForJournalIO(t *testing.T) {
	j, err := Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	j.mu.Lock()
	done := make(chan Status, 1)
	go func() { done <- j.Status() }()
	select {
	case status := <-done:
		j.mu.Unlock()
		if !status.Healthy {
			t.Fatal("incorrect cached status")
		}
	case <-time.After(time.Second):
		j.mu.Unlock()
		t.Fatal("health waited for the journal IO lock")
	}
}
