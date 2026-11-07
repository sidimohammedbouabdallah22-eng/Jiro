package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestActualManagementTLSAuthenticationOrigin(t *testing.T) {
	binary := os.Getenv("OPENWAF_RECOVERY_CANDIDATE")
	if binary == "" {
		t.Skip("set OPENWAF_RECOVERY_CANDIDATE to the actual server")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_, port, _ := net.SplitHostPort(address)
	listener.Close()
	origin := "https://localhost:" + port
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := x509.MarshalPKCS8PrivateKey(key)
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0600)
	auth, _ := json.Marshal(map[string]string{"origin": origin, "passkey_rp_id": "localhost"})
	authPath := filepath.Join(dir, "authentication.json")
	os.WriteFile(authPath, auth, 0600)
	const token = "management-tls-test-token-012345678901234567890123456789"
	command := exec.Command(binary, "-config="+filepath.Join(dir, "policy.json"), "-admin="+address, "-listen=127.0.0.1:0", "-auth-config="+authPath, "-admin-tls-cert="+certPath, "-admin-tls-key="+keyPath)
	command.Env = append(os.Environ(), "OPENWAF_ADMIN_TOKEN="+token)
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { command.Process.Kill(); command.Wait() }()
	certificate, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	deadline := time.Now().Add(15 * time.Second)
	for {
		request, _ := http.NewRequest("GET", origin+"/api/v1/auth/options", nil)
		response, err := client.Do(request)
		if err == nil {
			var options map[string]any
			json.NewDecoder(response.Body).Decode(&options)
			response.Body.Close()
			if response.StatusCode != 200 || options["origin"] != origin || options["passkeys"] != true {
				t.Fatal("incorrect TLS auth options", response.StatusCode, options)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("TLS console unavailable", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	response, err := client.Post(origin+"/api/v1/login", "application/json", strings.NewReader(`{"token":"`+token+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("TLS login failed", response.StatusCode)
	}
	for _, cookie := range response.Cookies() {
		if cookie.Name == "openwaf_session" {
			if !cookie.Secure || !cookie.HttpOnly {
				t.Fatal("unsafe TLS session cookie")
			}
			return
		}
	}
	t.Fatal("TLS login omitted session cookie")
}
