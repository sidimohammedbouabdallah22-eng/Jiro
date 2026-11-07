package accounts

import (
	"slices"
	"testing"
	"time"
)

func TestMFAPolicyPreservesEnrollmentAndRecoveryBoundaries(t *testing.T) {
	s, path := securityFixture(t)
	if _, err := s.SetMFAPolicy(s.List().Revision, true); err == nil {
		t.Fatal("required MFA without a ready administrator")
	}
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	if _, err := s.SetMFA("admin", s.List().Accounts[0].Version, secret, "287082", time.Unix(59, 0), "test", "Enroll administrator"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetMFAPolicy(s.List().Revision, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Save(s.List().Revision, "second", "administrator", false, "a second administrator password", "test", "Enrollment pending"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Save(s.List().Revision, "admin", "administrator", true, "", "test", "Disable last ready administrator"); err == nil {
		t.Fatal("last ready administrator was disabled")
	}
	if _, err := s.SetMFA("admin", s.List().Accounts[0].Version, "", "", time.Now(), "test", "Disable"); err == nil {
		t.Fatal("ordinary disable bypassed required MFA")
	}
	if _, err := s.RecoverMFA("admin", s.List().Accounts[0].Version, time.Now(), "bootstrap", "Lost authenticator"); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil || !s.RequiresAdminMFA() || s.List().Schema != 3 {
		t.Fatal("recovery weakened persisted MFA policy", err)
	}
}

func TestApplicationTokenAndAccountViewsDoNotAliasLiveGrants(t *testing.T) {
	s, _ := securityFixture(t)
	access := &ApplicationAccess{IDs: []string{"shop"}}
	if _, err := s.SaveAccess(s.List().Revision, "scoped", "operator", false, "a scoped operator test password", "test", "Assign shop", access); err != nil {
		t.Fatal(err)
	}
	access.IDs[0] = "portal"
	now := time.Now()
	token, secret, err := s.CreateToken(s.List().Revision, "scoped", "reader", []string{"policy:read"}, now.Add(time.Hour), now, "test", "Assigned automation")
	if err != nil {
		t.Fatal(err)
	}
	token.Access.IDs[0] = "portal"
	token.Scopes[0] = "policy:write"
	verified, ok := s.VerifyToken(secret, now)
	if !ok || verified.Access.IDs[0] != "shop" || verified.Scopes[0] != "policy:read" {
		t.Fatal("returned token mutated active grants")
	}
	d := s.List()
	d.Accounts[1].Access.IDs[0] = "portal"
	d.Tokens[0].Access.IDs[0] = "portal"
	if !slices.Equal(s.List().Accounts[1].Access.IDs, []string{"shop"}) {
		t.Fatal("account view mutated grants")
	}
	if _, _, err := s.CreateScopedToken(s.List().Revision, "scoped", "escape", []string{"policy:read"}, now.Add(time.Hour), now, "test", "Escape attempt", &ApplicationAccess{IDs: []string{"portal"}}); err == nil {
		t.Fatal("token exceeded owner assignment")
	}
	if err := s.CheckApplications(2, []string{"portal"}); err == nil {
		t.Fatal("missing application grant accepted")
	}
	if _, _, err := s.CreateToken(s.List().Revision, "scoped", "monitor", []string{"monitoring:read"}, now.Add(time.Hour), now, "test", "Global scope attempt"); err == nil {
		t.Fatal("scoped token received appliance telemetry")
	}
}
