package policysvc_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"freelocker/internal/server/bootstrap"
	"freelocker/internal/server/policysvc"
	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"

	"github.com/google/uuid"
)

func setup(t *testing.T) (*store.Store, *bootstrap.Keys) {
	t.Helper()
	ctx := context.Background()
	s := storetest.New(t)
	master := bytes.Repeat([]byte{8}, 32)
	if _, err := bootstrap.Init(ctx, s, master, "Acme", time.Now()); err != nil {
		t.Fatal(err)
	}
	k, err := bootstrap.Load(ctx, s, master)
	if err != nil {
		t.Fatal(err)
	}
	return s, k
}

func TestRecompileSignsAndVersions(t *testing.T) {
	ctx := context.Background()
	s, k := setup(t)
	svc := &policysvc.Service{Store: s, Keys: k}

	pid, _ := s.CreatePolicy(ctx, k.TenantID, "Baseline", "audit")
	v1, err := svc.Recompile(ctx, k.TenantID, pid)
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := s.LatestPolicyVersion(ctx, k.TenantID, pid)
	if stored.Version != v1 {
		t.Fatalf("version mismatch %q vs %q", stored.Version, v1)
	}
	if !policysvc.Verify(k.UpdateKey.Public().(ed25519.PublicKey), v1, stored.Signature) {
		t.Error("signature must verify")
	}

	// Adding a rule changes the version.
	s.AddRule(ctx, k.TenantID, pid, store.PolicyRule{Kind: "hash", Value: "ABC"}, nil)
	v2, _ := svc.Recompile(ctx, k.TenantID, pid)
	if v2 == v1 {
		t.Error("version should change when rules change")
	}
}

func TestEffectiveFallsBackToDenyAll(t *testing.T) {
	ctx := context.Background()
	s, k := setup(t)
	svc := &policysvc.Service{Store: s, Keys: k}

	// Unassigned device → audit deny-all default.
	h := []byte("h1")
	s.CreateInstallToken(ctx, k.TenantID, store.InstallToken{Name: "t"}, h)
	dev := uuid.New()
	s.EnrollDevice(ctx, h, time.Now(), func(uuid.UUID) (store.NewDevice, error) {
		return store.NewDevice{ID: dev, Hostname: "pc", CertSerial: "s", CertExpiresAt: time.Now().Add(time.Hour)}, nil
	})
	eff, err := svc.Effective(ctx, k.TenantID, dev)
	if err != nil || eff.Mode != "audit" || len(eff.XML) == 0 {
		t.Fatalf("deny-all default = %+v, %v", eff, err)
	}
	if !policysvc.Verify(k.UpdateKey.Public().(ed25519.PublicKey), eff.Version, eff.Signature) {
		t.Error("deny-all signature must verify")
	}
}
