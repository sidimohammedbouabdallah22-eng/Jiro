package certificates

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func pairFixture(t *testing.T, path string, serial int64, notBefore, notAfter time.Time, name string, additionalNames ...string) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: notBefore, NotAfter: notAfter, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	template.DNSNames = append(template.DNSNames, additionalNames...)
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err = os.WriteFile(filepath.Join(path, "cert.pem"), certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(path, "key.pem"), keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	return certPEM, keyPEM
}

func TestApplicationNamesGatePolicyAndCertificateActivation(t *testing.T) {
	path := t.TempDir()
	now := time.Now()
	pairFixture(t, path, 1, now.Add(-time.Hour), now.Add(90*24*time.Hour), "shop.test", "portal.test")
	m, err := New(filepath.Join(path, "cert.pem"), filepath.Join(path, "key.pem"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	activated := false
	if err := m.WithApplicationNames([]string{"missing.test"}, func() error { activated = true; return nil }); err == nil || activated {
		t.Fatal("uncovered policy activated")
	}
	if err := m.WithApplicationNames([]string{"shop.test", "portal.test"}, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	fingerprint := m.Status().Fingerprint
	pairFixture(t, path, 2, now.Add(-time.Hour), now.Add(90*24*time.Hour), "shop.test")
	if err := m.Reload(); err == nil || m.Status().Fingerprint != fingerprint {
		t.Fatal("certificate lost a configured application")
	}
	if err := m.WithApplicationNames([]string{"shop.test"}, func() error { return errors.New("disk unavailable") }); err == nil {
		t.Fatal("failed commit accepted")
	}
	if err := m.Reload(); err == nil {
		t.Fatal("failed policy commit narrowed certificate requirements")
	}
	if err := m.WithApplicationNames([]string{"shop.test"}, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := m.Reload(); err != nil {
		t.Fatal("removed application still required by reload", err)
	}
}

func TestCertificateReloadCannotRaceApplicationCommit(t *testing.T) {
	path := t.TempDir()
	now := time.Now()
	pairFixture(t, path, 1, now.Add(-time.Hour), now.Add(90*24*time.Hour), "shop.test", "portal.test")
	m, err := New(filepath.Join(path, "cert.pem"), filepath.Join(path, "key.pem"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	committed := make(chan error, 1)
	go func() {
		committed <- m.WithApplicationNames([]string{"shop.test", "portal.test"}, func() error { close(entered); <-release; return nil })
	}()
	<-entered
	pairFixture(t, path, 2, now.Add(-time.Hour), now.Add(90*24*time.Hour), "shop.test")
	reloaded := make(chan error, 1)
	go func() { reloaded <- m.Reload() }()
	select {
	case <-reloaded:
		close(release)
		t.Fatal("reload bypassed policy commit lock")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	if err := <-committed; err != nil {
		t.Fatal(err)
	}
	if err := <-reloaded; err == nil {
		t.Fatal("racing reload dropped newly committed hostname")
	}
}

func TestLiveRotationRejectsInvalidAndRetainsCertificate(t *testing.T) {
	path := t.TempDir()
	now := time.Now()
	pairFixture(t, path, 1, now.Add(-time.Hour), now.Add(90*24*time.Hour), "application.test")
	var denyAudit atomic.Bool
	m, err := New(filepath.Join(path, "cert.pem"), filepath.Join(path, "key.pem"), []string{"application.test"}, func(outcome, fingerprint, correlation string) (string, error) {
		if denyAudit.Load() {
			return "", errors.New("audit unavailable")
		}
		return "test-correlation", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	server.TLS = m.TLSConfig()
	server.StartTLS()
	defer server.Close()
	readSerial := func() int64 {
		conn, err := tls.Dial("tcp", server.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, ServerName: "application.test"})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64()
	}
	if readSerial() != 1 || !m.Status().Healthy {
		t.Fatal("initial certificate missing")
	}
	pairFixture(t, path, 2, now.Add(-time.Hour), now.Add(90*24*time.Hour), "application.test")
	denyAudit.Store(true)
	if m.Reload() == nil || readSerial() != 1 {
		t.Fatal("unaudited certificate activated")
	}
	denyAudit.Store(false)
	if err = m.Reload(); err != nil || readSerial() != 2 {
		t.Fatalf("rotation %v", err)
	}
	for _, test := range []struct {
		name       string
		start, end time.Time
		host       string
	}{
		{"expired", now.Add(-48 * time.Hour), now.Add(-24 * time.Hour), "application.test"},
		{"future", now.Add(time.Hour), now.Add(90 * 24 * time.Hour), "application.test"},
		{"wrong-host", now.Add(-time.Hour), now.Add(90 * 24 * time.Hour), "other.test"},
	} {
		t.Run(test.name, func(t *testing.T) {
			pairFixture(t, path, 3, test.start, test.end, test.host)
			if m.Reload() == nil || readSerial() != 2 || m.Status().Healthy {
				t.Fatal("invalid replacement activated or health stayed healthy")
			}
		})
	}
	if err = os.WriteFile(filepath.Join(path, "key.pem"), []byte("incomplete write"), 0600); err != nil {
		t.Fatal(err)
	}
	if m.Reload() == nil || readSerial() != 2 {
		t.Fatal("malformed replacement displaced working pair")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); m.Run(ctx, 10*time.Millisecond) }()
	pairFixture(t, path, 4, now.Add(-time.Hour), now.Add(10*24*time.Hour), "application.test")
	deadline := time.Now().Add(3 * time.Second)
	for m.active.Load().Leaf.SerialNumber.Int64() != 4 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if readSerial() != 4 || !m.Status().Expiring || m.Status().Healthy {
		t.Fatal("poll reload or expiry warning missing")
	}
}

func TestInitialInvalidCertificateRefused(t *testing.T) {
	path := t.TempDir()
	now := time.Now()
	certPEM, keyPEM := pairFixture(t, path, 1, now.Add(-time.Hour), now.Add(time.Hour), "application.test")
	pairFixture(t, path, 2, now.Add(-time.Hour), now.Add(time.Hour), "application.test")
	otherKey, err := os.ReadFile(filepath.Join(path, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = validate(certPEM, otherKey, []string{"application.test"}, now); err == nil {
		t.Fatal("mismatched key accepted")
	}
	if _, err = validate(certPEM, keyPEM, []string{"other.test"}, now); err == nil {
		t.Fatal("wrong hostname accepted")
	}
	if err = os.WriteFile(filepath.Join(path, "cert.pem"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = New(filepath.Join(path, "cert.pem"), filepath.Join(path, "key.pem"), nil, nil); err == nil {
		t.Fatal("invalid initial pair accepted")
	}
}

func TestChainExpiryWarningPrecedesLeafExpiry(t *testing.T) {
	path := t.TempDir()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(11), DNSNames: []string{"application.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	if err = os.WriteFile(filepath.Join(path, "cert.pem"), chain, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(path, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := New(filepath.Join(path, "cert.pem"), filepath.Join(path, "key.pem"), []string{"application.test"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	status := m.Status()
	if !status.Expiring || status.Healthy || status.NotAfter.Sub(status.ChainNotAfter) < 79*24*time.Hour {
		t.Fatalf("chain expiry warning missing %+v", status)
	}
}

func TestStatusDoesNotWaitForReloadIO(t *testing.T) {
	path := t.TempDir()
	now := time.Now()
	pairFixture(t, path, 1, now.Add(-time.Hour), now.Add(90*24*time.Hour), "application.test")
	m, err := New(filepath.Join(path, "cert.pem"), filepath.Join(path, "key.pem"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	done := make(chan Status, 1)
	go func() { done <- m.Status() }()
	select {
	case status := <-done:
		m.mu.Unlock()
		if !status.Healthy {
			t.Fatal("incorrect cached status")
		}
	case <-time.After(time.Second):
		m.mu.Unlock()
		t.Fatal("health waited for the certificate reload lock")
	}
}
