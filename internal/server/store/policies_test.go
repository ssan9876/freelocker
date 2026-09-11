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
