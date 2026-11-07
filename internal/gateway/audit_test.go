package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestAdministrationAuditPersistsAndBlocksUnauditedChanges(t *testing.T) {
	g, path := fixture(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("backend")) })
	const token = "audit-test-secret-token-12345678901234567890"
	admin := NewAdmin(g, token)
	r := httptest.NewRequest("POST", "/api/v1/login", strings.NewReader(`{"token":"wrong-sensitive-secret"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	admin.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
	c := g.Config()
	c.Name = "Updated fixture"
	if _, err := g.ApplyWithMetadata(c, false, "trusted local operator", "sensitive reason not copied into journal"); err != nil {
		t.Fatal(err)
	}
	items, err := g.audit.Query(0, 100)
	if err != nil || len(items) != 4 {
		t.Fatalf("audit records %d %v", len(items), err)
	}
	if items[0].Outcome != "success" || items[0].Operation != "policy.activate" || items[2].Status != 401 {
		t.Fatal(items)
	}
	data, err := os.ReadFile(path + ".audit.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{token, "wrong-sensitive-secret", "sensitive reason"} {
		if strings.Contains(string(data), secret) {
			t.Fatal("audit contains secret")
		}
	}
	g.Close(context.Background())
	g2, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer g2.Close(context.Background())
	if g2.AuditStatus().Records != 4 {
		t.Fatal("audit lost across restart")
	}
	admin = NewAdmin(g2, token)
	if w = monitoringRequest(admin, "/api/v1/audit", ""); w.Code != 401 {
		t.Fatal("audit endpoint is public")
	}
	if w = monitoringRequest(admin, "/api/v1/audit?limit=1", token); w.Code != 200 {
		t.Fatal(w.Code)
	}
	var response struct {
		Items []json.RawMessage `json:"items"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &response); err != nil || len(response.Items) != 1 {
		t.Fatal("audit pagination failed")
	}
	before := g2.Config()
	g2.audit.Close()
	c = g2.Config()
	c.Name = "Must not activate"
	if _, err = g2.Apply(c, false); err == nil || g2.Config().Revision != before.Revision {
		t.Fatal("policy activated without audit")
	}
	r = httptest.NewRequest("POST", "/api/v1/logout", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	admin.ServeHTTP(w, r)
	if w.Code != 503 || g2.Health().Healthy || !g2.Health().Ready {
		t.Fatal("audit failure not enforced or exposed")
	}
	if w = request(g2, "GET", "/", "", ""); w.Code != 200 {
		t.Fatal("audit failure disabled traffic")
	}
}
