package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func comparisonException() ScopedException {
	return ScopedException{ID: "price-search", Method: "GET", Path: "/search", Collection: "ARGS_GET", Parameter: "q", RuleIDs: []int{942131}, Owner: "test operator", Reason: "Allow a price comparison in this one field"}
}

func TestScopedExceptionBoundaries(t *testing.T) {
	g, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	c := g.Config()
	c.Paranoia = 2
	c.ScopedExceptions = []ScopedException{comparisonException()}
	c, err := g.Apply(c, false)
	if err != nil {
		t.Fatal(err)
	}
	value := url.QueryEscape("price < 100")
	tests := []struct {
		name, method, path, ct, body string
		status                       int
	}{
		{"selected field", "GET", "/search?q=" + value, "", "", 200},
		{"decoded path", "GET", "/se%61rch?q=" + value, "", "", 200},
		{"other path", "GET", "/other?q=" + value, "", "", 403},
		{"path prefix is not wildcard", "GET", "/search/more?q=" + value, "", "", 403},
		{"other field", "GET", "/search?other=" + value, "", "", 403},
		{"other method", "POST", "/search?q=" + value, "application/json", `{}`, 403},
		{"other collection", "GET", "/search", "application/x-www-form-urlencoded", "q=" + value, 403},
		{"other attack rule remains", "GET", "/search?q=" + url.QueryEscape("<script>alert(1)</script>"), "", "", 403},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := request(g, tt.method, tt.path, tt.ct, tt.body)
			if w.Code != tt.status {
				t.Fatalf("got %d want %d: %s", w.Code, tt.status, w.Body)
			}
		})
	}
	c.ScopedExceptions[0].ExpiresAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	c, err = g.Apply(c, false)
	if err != nil {
		t.Fatal(err)
	}
	if w := request(g, "GET", "/search?q="+value, "", ""); w.Code != 403 {
		t.Fatal("expired exception still active")
	}
	c.ScopedExceptions[0].ExpiresAt = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if _, err = g.Apply(c, false); err != nil {
		t.Fatal(err)
	}
	if w := request(g, "GET", "/search?q="+value, "", ""); w.Code != 200 {
		t.Fatal("future expiry did not allow scoped input")
	}
}

func TestJSONTargetAndConfigIsolation(t *testing.T) {
	g, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	c := g.Config()
	c.Paranoia = 2
	e := comparisonException()
	e.Method = "POST"
	e.Collection = "ARGS_POST"
	e.Parameter = "json.price"
	c.ScopedExceptions = []ScopedException{e}
	returned, err := g.Apply(c, false)
	if err != nil {
		t.Fatal(err)
	}
	c.ScopedExceptions[0].RuleIDs[0] = 941100
	returned.ScopedExceptions[0].RuleIDs[0] = 941100
	if got := g.Config().ScopedExceptions[0].RuleIDs[0]; got != 942131 {
		t.Fatal("caller mutated active policy")
	}
	if w := request(g, "POST", "/search", "application/json", `{"price":"price < 100"}`); w.Code != 200 {
		t.Fatalf("JSON scoped input blocked: %d", w.Code)
	}
	if w := request(g, "POST", "/search", "application/json", `{"other":"price < 100"}`); w.Code != 403 {
		t.Fatal("JSON exception leaked into another field")
	}
}

func TestExceptionValidationRejectsDirectiveInjection(t *testing.T) {
	for _, bad := range []func(*ScopedException){
		func(e *ScopedException) { e.Path = `/search" phase:1` }, func(e *ScopedException) { e.Parameter = "q,ctl:ruleEngine=Off" },
		func(e *ScopedException) { e.RuleIDs = []int{949110} }, func(e *ScopedException) { e.Owner = "" },
		func(e *ScopedException) { e.Reason = "" }, func(e *ScopedException) { e.ExpiresAt = "tomorrow" },
		func(e *ScopedException) { e.Collection = "ARGS" }, func(e *ScopedException) { e.Method = "" },
	} {
		c := Defaults()
		e := comparisonException()
		bad(&e)
		c.ScopedExceptions = []ScopedException{e}
		if _, err := Directives(c); err == nil {
			t.Fatal("accepted invalid exception", e)
		}
	}
}

func TestHistoryRollbackAndRestart(t *testing.T) {
	g, path := fixture(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	original := g.Config()
	c := original
	c.Paranoia = 2
	c.ScopedExceptions = []ScopedException{comparisonException()}
	c, err := g.ApplyWithMetadata(c, false, "test operator", "Enable scoped price input")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = g.Apply(c, true); err != nil {
		t.Fatal(err)
	}
	h, err := g.History()
	if err != nil || len(h) != 2 || h[0].Reason != "Enable scoped price input" {
		t.Fatal("history missing", h, err)
	}
	restored, err := g.Rollback(c.Revision, original.Revision, "test operator", "Return to baseline")
	if err != nil {
		t.Fatal(err)
	}
	if restored.Revision <= c.Revision || restored.Paranoia != original.Paranoia || len(restored.ScopedExceptions) != 0 {
		t.Fatal("rollback did not create a new baseline revision")
	}
	h, err = g.History()
	if err != nil || len(h) != 3 || h[0].RestoredFrom != original.Revision {
		t.Fatal("rollback audit missing", h, err)
	}
	if _, err = g.Rollback(c.Revision, original.Revision, "operator", "stale"); err == nil {
		t.Fatal("stale rollback accepted")
	}
	g.Close(context.Background())
	restarted, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close(context.Background())
	if restarted.Config().Revision != restored.Revision {
		t.Fatal("rollback did not survive restart")
	}
}

func TestOrphanSnapshotsAreNeverCommitted(t *testing.T) {
	g, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	original := g.Config()
	orphan := original
	orphan.Revision = 2
	orphan.Mode = "disabled"
	if err := g.prepareSnapshot(orphan, original.Revision, 0, "test", "Simulated crash before active-file rename"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Snapshot(2); err == nil {
		t.Fatal("orphan snapshot exposed")
	}
	c := original
	c.Name = "Committed update"
	c, err := g.Apply(c, false)
	if err != nil {
		t.Fatal(err)
	}
	if c.Revision != 3 {
		t.Fatal("uncommitted revision number reused")
	}
	h, err := g.History()
	if err != nil || len(h) != 2 || h[0].Parent != original.Revision {
		t.Fatal("orphan entered committed history", h, err)
	}
	if _, err = g.Rollback(c.Revision, 2, "operator", "Bad target"); err == nil {
		t.Fatal("orphan rollback allowed")
	}
}

func TestPolicyLeaseAndTamperedStartup(t *testing.T) {
	g, path := fixture(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	if second, err := New(path); err == nil {
		second.Close(context.Background())
		t.Fatal("second writer allowed")
	}
	g.Close(context.Background())
	c := g.Config()
	c.Mode = "disabled"
	if err := persist(path, c); err != nil {
		t.Fatal(err)
	}
	if bad, err := New(path); err == nil {
		bad.Close(context.Background())
		t.Fatal("unrecorded policy edit silently accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if bad, err := New(path); err == nil {
		bad.Close(context.Background())
		t.Fatal("missing active policy fell back to defaults despite history")
	}
}

func TestHistoryWriteFailurePreservesPolicy(t *testing.T) {
	g, path := fixture(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	original := g.Config()
	broken := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(broken, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	dir := g.historyDir
	g.historyDir = broken
	c := original
	c.Mode = "disabled"
	_, err := g.Apply(c, false)
	g.historyDir = dir
	if err == nil || g.Config().Mode != original.Mode {
		t.Fatal("failed history write changed active policy")
	}
	disk, err := load(path)
	if err != nil || disk.Mode != original.Mode {
		t.Fatal("failed history write changed durable policy")
	}
}

func TestHistoryAPIRequiresAuthenticationAndAuditsActor(t *testing.T) {
	g, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	token := strings.Repeat("h", 40)
	admin := httptest.NewServer(NewAdmin(g, token))
	defer admin.Close()
	resp, err := http.Get(admin.URL + "/api/v1/config/history")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatal("history exposed")
	}
	c := g.Config()
	c.Name = "Reviewed policy"
	payload, _ := json.Marshal(map[string]any{"config": c, "reason": "Change fixture"})
	req, _ := http.NewRequest("POST", admin.URL+"/api/v1/config/apply", strings.NewReader(string(payload)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal("apply endpoint failed", resp.StatusCode)
	}
	history, err := g.History()
	if err != nil || history[0].Actor != "administrator API token" || history[0].Reason != "Change fixture" {
		t.Fatal("actor not recorded", history, err)
	}
}

func TestFailedActiveCommitLeavesPreparedSnapshotUnreachable(t *testing.T) {
	g, path := fixture(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	original := g.Config()
	g.writePolicy = func(string, Config) error { return errors.New("simulated rename failure") }
	c := original
	c.Mode = "disabled"
	if _, err := g.Apply(c, false); err == nil {
		t.Fatal("commit failure ignored")
	}
	if g.Config().Revision != original.Revision {
		t.Fatal("failed commit activated a revision")
	}
	if _, err := g.Snapshot(2); err == nil {
		t.Fatal("prepared snapshot exposed as committed")
	}
	h, err := g.History()
	if err != nil || len(h) != 1 {
		t.Fatal("failed commit changed history", h, err)
	}
	disk, err := load(path)
	if err != nil || disk.Revision != original.Revision || disk.Mode != original.Mode {
		t.Fatal("failed commit changed policy file")
	}
	g.Close(context.Background())
	restarted, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close(context.Background())
	c = restarted.Config()
	c.Name = "After failed commit"
	c, err = restarted.Apply(c, false)
	if err != nil {
		t.Fatal(err)
	}
	if c.Revision != 3 {
		t.Fatal("failed revision reused after restart")
	}
}

func TestOfflinePolicyCheckDoesNotWriteOrLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	c := Defaults()
	if err := persist(path, c); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	if _, err := CheckPolicy(path); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("offline check changed policy")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatal("offline check created files")
	}
}

func TestRuleEvidenceSupportsScopedTuning(t *testing.T) {
	g, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	w := request(g, "GET", "/?q="+url.QueryEscape("1' UNION SELECT password FROM users--"), "", "")
	if w.Code != 403 {
		t.Fatal("fixture not blocked")
	}
	found := false
	for _, evt := range g.Events() {
		for _, m := range evt.Matches {
			if m.ID == 942100 {
				found = true
				if m.Phase != 2 {
					t.Fatal("incorrect phase evidence", m)
				}
				hasTarget := false
				for _, target := range m.Targets {
					if target == "ARGS:q" {
						hasTarget = true
					}
					if strings.Contains(target, "UNION") {
						t.Fatal("target metadata contains matched values")
					}
				}
				if !hasTarget {
					t.Fatal("missing parameter target evidence", m)
				}
			}
		}
	}
	if !found {
		t.Fatal("SQLi rule evidence missing")
	}
}
