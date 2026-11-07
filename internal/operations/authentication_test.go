package operations

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/accounts"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/gateway"
)

func TestAuthenticationAndPoolStateRecoveryAndCandidateRejection(t *testing.T) {
	ctx := context.Background()
	p := simpleState(t, false)
	g, err := gateway.New(p.Policy)
	if err != nil {
		t.Fatal(err)
	}
	c := g.Config()
	app := gateway.ApplicationFromConfig(c, []string{"application.test"})
	app.Pool = &gateway.UpstreamPool{Backends: []gateway.Backend{{ID: "primary", URL: app.Upstream}}, FailureThreshold: 2, CooldownSeconds: 5, HeaderTimeoutSeconds: 2}
	_, err = g.Apply(gateway.Config{SchemaVersion: 2, Revision: c.Revision, Applications: []gateway.Application{app}}, false)
	if err != nil {
		t.Fatal(err)
	}
	// History must keep the compatibility requirement after pools are removed.
	c = g.Config()
	c.Applications[0].Pool = nil
	if _, err := g.Apply(c, false); err != nil {
		t.Fatal(err)
	}
	g.Close(ctx)
	s, err := accounts.Open(p.Policy + ".accounts.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Save(1, "admin", "administrator", false, "a long authentication recovery password", "test", "Fixture"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BindOIDC(s.List().Revision, "admin", "https://issuer.test", "immutable-subject", "test", "Explicit binding", false); err != nil {
		t.Fatal(err)
	}
	u, err := s.PreparePasskeyUser("admin", s.List().Accounts[0].Version, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	key := webauthn.Credential{ID: []byte("recovery-key"), PublicKey: []byte("recovery-public-key")}
	key.Flags.UserVerified = true
	if _, err := s.AddPasskey("admin", u.Version, "Recovery fixture", key, "test", "localhost"); err != nil {
		t.Fatal(err)
	}
	checkpoint := filepath.Join(t.TempDir(), "checkpoint")
	manifest, err := Backup(ctx, BackupOptions{Paths: p, Destination: checkpoint})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.State.Accounts.Schema != 4 || !manifest.State.Policy.UpstreamPools {
		t.Fatal("new state omitted", manifest.State)
	}
	old := CurrentCapabilities()
	old.AccountSchemas = []int{1, 2, 3}
	if err := supports(manifest.State, old); err == nil {
		t.Fatal("accepted old credential reader")
	}
	old = CurrentCapabilities()
	old.UpstreamPools = 0
	if err := supports(manifest.State, old); err == nil {
		t.Fatal("accepted old routing reader for history")
	}
	if previous := os.Getenv("OPENWAF_AUTHENTICATION_PREVIOUS"); previous != "" {
		if _, err := UpgradeCheck(ctx, checkpoint, previous); err == nil {
			t.Fatal("actual old executable accepted schema 4")
		}
	}
	if candidate := os.Getenv("OPENWAF_RECOVERY_CANDIDATE"); candidate != "" {
		if _, err := UpgradeCheck(ctx, checkpoint, candidate); err != nil {
			t.Fatal(err)
		}
	}
	destination := filepath.Join(t.TempDir(), "restored")
	if _, err := Restore(ctx, checkpoint, destination); err != nil {
		t.Fatal(err)
	}
	restored, err := accounts.Open(pathsUnder(destination, manifest.Paths).Accounts)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := restored.OIDCAccount("https://issuer.test", "immutable-subject"); !ok {
		t.Fatal("binding lost")
	}
	u, ok := restored.PasskeyUser("admin", "localhost")
	if !ok || len(u.Credentials) != 1 || !bytes.Equal(u.Credentials[0].PublicKey, key.PublicKey) {
		t.Fatal("passkey changed")
	}
}
