// Package certificates validates externally renewed PEM pairs and replaces the
// certificate used for new TLS handshakes without restarting active traffic.
package certificates

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Status struct {
	Enabled       bool      `json:"enabled"`
	Healthy       bool      `json:"healthy"`
	Fingerprint   string    `json:"sha256,omitempty"`
	NotBefore     time.Time `json:"not_before,omitempty"`
	NotAfter      time.Time `json:"not_after,omitempty"`
	ChainNotAfter time.Time `json:"chain_not_after,omitempty"`
	LastAttempt   time.Time `json:"last_attempt,omitempty"`
	LastSuccess   time.Time `json:"last_success,omitempty"`
	LastError     string    `json:"last_error,omitempty"`
	Expiring      bool      `json:"expiring"`
}

// Audit persists an intent before activation and its outcome afterward. An
// intent failure prevents activation. An outcome failure remains observable.
type Audit func(outcome, fingerprint, correlation string) (string, error)

type Manager struct {
	cachedStatus      atomic.Pointer[Status]
	mu                sync.Mutex
	certPath, keyPath string
	names             []string
	applicationNames  []string
	audit             Audit
	active            atomic.Pointer[tls.Certificate]
	inputDigest       [32]byte
	status            Status
}

func New(certPath, keyPath string, names []string, audit Audit) (*Manager, error) {
	m := &Manager{certPath: certPath, keyPath: keyPath, names: append([]string(nil), names...), audit: audit}
	if err := m.Reload(); err != nil {
		return nil, err
	}
	return m, nil
}

func readBounded(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("certificate_file_unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("certificate_file_unsafe_or_oversized")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("certificate_file_read_failed")
	}
	return data, nil
}

func validate(certPEM, keyPEM []byte, names []string, now time.Time) (tls.Certificate, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil || len(pair.Certificate) == 0 || len(pair.Certificate) > 16 {
		return pair, errors.New("certificate_pair_invalid")
	}
	for i, der := range pair.Certificate {
		cert, err := x509.ParseCertificate(der)
		if err != nil || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			return pair, errors.New("certificate_chain_outside_validity")
		}
		if i == 0 {
			pair.Leaf = cert
			continue
		}
		child, err := x509.ParseCertificate(pair.Certificate[i-1])
		if err != nil || child.CheckSignatureFrom(cert) != nil {
			return pair, errors.New("certificate_chain_signature_invalid")
		}
	}
	leaf := pair.Leaf
	if leaf.IsCA || len(leaf.DNSNames)+len(leaf.IPAddresses) == 0 {
		return pair, errors.New("certificate_server_identity_missing")
	}
	serverAuth := len(leaf.ExtKeyUsage) == 0
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
			serverAuth = true
		}
	}
	if !serverAuth {
		return pair, errors.New("certificate_server_auth_missing")
	}
	for _, name := range names {
		if name == "" || leaf.VerifyHostname(name) != nil {
			return pair, errors.New("certificate_hostname_mismatch")
		}
	}
	return pair, nil
}

func (m *Manager) Reload() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	defer func() { status := m.status; m.cachedStatus.Store(&status) }()
	now := time.Now().UTC()
	m.status.LastAttempt = now
	certPEM, err := readBounded(m.certPath, 1<<20)
	var keyPEM []byte
	if err == nil {
		keyPEM, err = readBounded(m.keyPath, 64<<10)
	}
	var pair tls.Certificate
	if err == nil {
		pair, err = validate(certPEM, keyPEM, m.names, now)
	}
	if err == nil {
		err = validateNames(pair.Leaf, m.applicationNames)
	}
	if err != nil {
		code := err.Error()
		if m.status.LastError != code && m.audit != nil {
			if _, auditErr := m.audit("rejected", m.status.Fingerprint, ""); auditErr != nil {
				code = "certificate_rejection_audit_failed"
			}
		}
		m.status.LastError = code
		return errors.New(code)
	}
	input := sha256.New()
	input.Write(certPEM)
	input.Write([]byte{0})
	input.Write(keyPEM)
	var inputDigest [32]byte
	copy(inputDigest[:], input.Sum(nil))
	if m.active.Load() != nil && inputDigest == m.inputDigest {
		// A prior activation whose outcome could not be audited requires explicit
		// operator reconciliation, even when the current certificate still works.
		if strings.Contains(m.status.LastError, "audit_failed") {
			return errors.New(m.status.LastError)
		}
		m.status.LastError = ""
		return nil
	}
	sum := sha256.Sum256(pair.Certificate[0])
	fingerprint := hex.EncodeToString(sum[:])
	correlation := ""
	if m.audit != nil {
		correlation, err = m.audit("intent", fingerprint, "")
		if err != nil {
			m.status.LastError = "certificate_intent_audit_failed"
			return errors.New(m.status.LastError)
		}
	}
	m.active.Store(&pair)
	m.inputDigest = inputDigest
	chainExpiry := pair.Leaf.NotAfter
	for _, der := range pair.Certificate[1:] {
		cert, _ := x509.ParseCertificate(der)
		if cert.NotAfter.Before(chainExpiry) {
			chainExpiry = cert.NotAfter
		}
	}
	m.status = Status{Enabled: true, Fingerprint: fingerprint, NotBefore: pair.Leaf.NotBefore, NotAfter: pair.Leaf.NotAfter, ChainNotAfter: chainExpiry, LastAttempt: now, LastSuccess: now}
	if m.audit != nil {
		if _, err = m.audit("success", fingerprint, correlation); err != nil {
			m.status.LastError = "certificate_outcome_audit_failed"
			return errors.New(m.status.LastError)
		}
	}
	return nil
}

func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return m.active.Load(), nil }}
}

func validateNames(leaf *x509.Certificate, names []string) error {
	for _, name := range names {
		if leaf.VerifyHostname(name) != nil {
			return errors.New("certificate_application_hostname_mismatch")
		}
	}
	return nil
}

func (m *Manager) ValidateApplicationNames(names []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return validateNames(m.active.Load().Leaf, names)
}

// The callback commits policy while certificate reload is excluded. It must not
// call Manager methods. TLS handshakes and cached health remain lock-free.
func (m *Manager) WithApplicationNames(names []string, activate func() error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := validateNames(m.active.Load().Leaf, names); err != nil {
		return err
	}
	if err := activate(); err != nil {
		return err
	}
	m.applicationNames = append([]string{}, names...)
	return nil
}

func (m *Manager) Status() Status {
	var status Status
	if cached := m.cachedStatus.Load(); cached != nil {
		status = *cached
	}
	now := time.Now()
	status.Expiring = status.Enabled && status.ChainNotAfter.Sub(now) < 30*24*time.Hour
	status.Healthy = status.Enabled && status.LastError == "" && !status.Expiring && !now.Before(status.NotBefore)
	return status
}

func (m *Manager) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = m.Reload()
		}
	}
}
