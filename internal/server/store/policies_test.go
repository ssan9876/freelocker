package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"

	"github.com/google/uuid"
)

func TestPolicyCrudRulesAndVersions(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")

	pid, err := s.CreatePolicy(ctx, tenant, "Baseline", "")
	if err != nil {
		t.Fatal(err)
	}
	p, _ := s.GetPolicy(ctx, tenant, pid)
	if p.Mode != "audit" {
		t.Errorf("default mode = %q, want audit", p.Mode)
	}
	if err := s.SetPolicyMode(ctx, tenant, pid, "enforce"); err != nil {
		t.Fatal(err)
	}

	rid, err := s.AddRule(ctx, tenant, pid, store.PolicyRule{Kind: "hash", Value: "ABC", Description: "notepad"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rules, _ := s.ListRules(ctx, tenant, pid)
	if len(rules) != 1 || rules[0].ID != rid {
		t.Fatalf("rules = %+v", rules)
	}
	if err := s.DeleteRule(ctx, tenant, pid, rid); err != nil {
		t.Fatal(err)
	}
	if rules, _ := s.ListRules(ctx, tenant, pid); len(rules) != 0 {
		t.Error("rule not deleted")
	}

	v := store.PolicyVersion{PolicyID: pid, Version: "v1", Mode: "enforce", XML: []byte("<x/>"), Signature: []byte("sig")}
	if err := s.PutPolicyVersion(ctx, tenant, v); err != nil {
		t.Fatal(err)
	}
	got, err := s.LatestPolicyVersion(ctx, tenant, pid)
	if err != nil || got.Version != "v1" || string(got.XML) != "<x/>" {
		t.Fatalf("latest = %+v, %v", got, err)
	}

	other, _ := s.CreateTenant(ctx, "Other")
	if _, err := s.GetPolicy(ctx, other, pid); !errors.Is(err, store.ErrNotFound) {
		t.Error("policy must be tenant-scoped")
	}
}

func TestEffectivePolicyResolution(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	gid, _ := s.CreateDeviceGroup(ctx, tenant, "Workstations")
	s.CreateInstallToken(ctx, tenant, store.InstallToken{Name: "t", GroupID: &gid}, []byte("h"))
	dev := uuid.New()
	s.EnrollDevice(ctx, []byte("h"), time.Now(), func(uuid.UUID) (store.NewDevice, error) {
		return store.NewDevice{ID: dev, Hostname: "pc", CertSerial: "s", CertExpiresAt: time.Now().Add(time.Hour)}, nil
	})

	if _, err := s.EffectivePolicyForDevice(ctx, tenant, dev); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unassigned device err = %v, want ErrNotFound", err)
	}
	pid, _ := s.CreatePolicy(ctx, tenant, "Baseline", "audit")
	s.PutPolicyVersion(ctx, tenant, store.PolicyVersion{PolicyID: pid, Version: "v1", Mode: "audit", XML: []byte("<x/>"), Signature: []byte("s")})
	if err := s.AssignPolicy(ctx, tenant, gid, pid); err != nil {
		t.Fatal(err)
	}
	eff, err := s.EffectivePolicyForDevice(ctx, tenant, dev)
	if err != nil || eff.Version != "v1" {
		t.Fatalf("effective = %+v, %v", eff, err)
	}
	if err := s.SetDevicePolicyVersion(ctx, tenant, dev, "v1"); err != nil {
		t.Fatal(err)
	}
}

// A policy assignment must never cross a tenant boundary. policy_assignments
// has group_id as its SOLE primary key, so an unguarded
// `ON CONFLICT (group_id) DO UPDATE` silently repoints another tenant's
// assignment: tenant B names tenant A's group and A's devices quietly start
// enforcing B's policy. Asserting only the returned error is not enough —
// the error can be right while the row was still overwritten — so this also
// reads A's assignment back afterwards.
func TestAssignPolicyCannotCrossTenants(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)

	// Tenant A: a group with a device, assigned to A's own policy.
	tenantA, _ := s.CreateTenant(ctx, "Acme")
	groupA, _ := s.CreateDeviceGroup(ctx, tenantA, "A-Workstations")
	s.CreateInstallToken(ctx, tenantA, store.InstallToken{Name: "ta", GroupID: &groupA}, []byte("ha"))
	devA := uuid.New()
	s.EnrollDevice(ctx, []byte("ha"), time.Now(), func(uuid.UUID) (store.NewDevice, error) {
		return store.NewDevice{ID: devA, Hostname: "a-pc", CertSerial: "sa", CertExpiresAt: time.Now().Add(time.Hour)}, nil
	})
	policyA, _ := s.CreatePolicy(ctx, tenantA, "A-Baseline", "audit")
	s.PutPolicyVersion(ctx, tenantA, store.PolicyVersion{PolicyID: policyA, Version: "a-v1", Mode: "audit", XML: []byte("<a/>"), Signature: []byte("s")})
	if err := s.AssignPolicy(ctx, tenantA, groupA, policyA); err != nil {
		t.Fatal(err)
	}

	// Tenant B, with its own group and policy.
	tenantB, _ := s.CreateTenant(ctx, "Beta")
	groupB, _ := s.CreateDeviceGroup(ctx, tenantB, "B-Workstations")
	policyB, _ := s.CreatePolicy(ctx, tenantB, "B-Baseline", "enforce")
	s.PutPolicyVersion(ctx, tenantB, store.PolicyVersion{PolicyID: policyB, Version: "b-v1", Mode: "enforce", XML: []byte("<b/>"), Signature: []byte("s")})

	// B points its own policy at A's group: rejected.
	if err := s.AssignPolicy(ctx, tenantB, groupA, policyB); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("B assigning to A's group = %v, want ErrNotFound", err)
	}
	// B points A's policy at its own group: also rejected.
	if err := s.AssignPolicy(ctx, tenantB, groupB, policyA); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("B assigning A's policy = %v, want ErrNotFound", err)
	}

	// The assertion that actually proves the ON CONFLICT was blocked: A's
	// device still resolves to A's policy, not B's.
	eff, err := s.EffectivePolicyForDevice(ctx, tenantA, devA)
	if err != nil {
		t.Fatal(err)
	}
	if eff.PolicyID != policyA || eff.Version != "a-v1" {
		t.Fatalf("A's device resolves to %+v — tenant B overwrote A's assignment", eff)
	}

	// A same-tenant reassignment still works, so the guard is not too tight.
	policyA2, _ := s.CreatePolicy(ctx, tenantA, "A-Strict", "enforce")
	s.PutPolicyVersion(ctx, tenantA, store.PolicyVersion{PolicyID: policyA2, Version: "a-v2", Mode: "enforce", XML: []byte("<a2/>"), Signature: []byte("s")})
	if err := s.AssignPolicy(ctx, tenantA, groupA, policyA2); err != nil {
		t.Fatalf("same-tenant reassign = %v, want success", err)
	}
	if eff, _ := s.EffectivePolicyForDevice(ctx, tenantA, devA); eff.PolicyID != policyA2 {
		t.Errorf("reassign did not take effect: %+v", eff)
	}
}
