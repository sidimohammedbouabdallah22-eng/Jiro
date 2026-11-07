package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCredentialFileAndEnvironmentSelection(t *testing.T) {
	const environment = "OPENWAF_CREDENTIAL_TEST"
	t.Setenv(environment, "")
	path := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(path, []byte("  private-test-value\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if value, err := secretValue(environment, path); err != nil || value != "private-test-value" {
		t.Fatal("credential file read failed")
	}
	t.Setenv(environment, "environment-test-value")
	if _, err := secretValue(environment, path); err == nil {
		t.Fatal("ambiguous credential sources accepted")
	}
	if value, err := secretValue(environment, ""); err != nil || value != "environment-test-value" {
		t.Fatal("existing environment behavior changed")
	}
	t.Setenv(environment, "")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 4097)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := secretValue(environment, path); err == nil {
		t.Fatal("oversized credential accepted")
	}
	if _, err := secretValue(environment, filepath.Dir(path)); err == nil {
		t.Fatal("credential directory accepted")
	}
}
