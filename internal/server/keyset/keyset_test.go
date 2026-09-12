package keyset_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"freelocker/internal/server/bootstrap"
	"freelocker/internal/server/keyset"
	"freelocker/internal/server/policysvc"
	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"

	"github.com/google/uuid"
)

// TestPerTenantKeyIsolation proves the provider resolves each tenant's own
// CA and signing keys, and that policy signing/verification is scoped per
// tenant (one tenant's key does not verify another's policy).
func TestPerTenantKeyIsolation(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	master := bytes.Repeat([]byte{5}, 32)

	tenantA, err := bootstrap.Init(ctx, s, master, "Acme", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tenantB, err := bootstrap.ProvisionTenant(ctx, s, master, "Beta", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	kp := keyset.New(s, master)
	ka, err := kp.For(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := kp.For(ctx, tenantB)
	if err != nil {
		t.Fatal(err)
	}

	// Distinct CAs and distinct signing keys.
	if ka.CA.Pin() == kb.CA.Pin() {
		t.Fatal("tenants must have distinct CAs")
	}
	if ka.UpdateKey.Public().(ed25519.PublicKey).Equal(kb.UpdateKey.Public().(ed25519.PublicKey)) {
		t.Fatal("tenants must have distinct update keys")
	}
	// Cache returns the same instance.
	if again, _ := kp.For(ctx, tenantA); again != ka {
		t.Error("provider should cache per tenant")
	}

	// Policy compiled for tenant A is signed by A's key and verifies with
	// A's key, not B's.
	svc := &policysvc.Service{Store: s, KeyFor: kp.For}
	pidA, _ := s.CreatePolicy(ctx, tenantA, "Baseline", "audit")
	verA, err := svc.Recompile(ctx, tenantA, pidA)
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := s.LatestPolicyVersion(ctx, tenantA, pidA)
	if !policysvc.Verify(ka.UpdateKey.Public().(ed25519.PublicKey), verA, stored.Signature) {
		t.Error("tenant A policy must verify with A's key")
	}
	if policysvc.Verify(kb.UpdateKey.Public().(ed25519.PublicKey), verA, stored.Signature) {
		t.Error("tenant A policy must NOT verify with tenant B's key")
	}

	// Effective (deny-all) for a device is signed by that device's tenant key.
	devB := seedDevice(t, s, tenantB)
	effB, err := svc.Effective(ctx, tenantB, devB)
	if err != nil {
		t.Fatal(err)
	}
	if !policysvc.Verify(kb.UpdateKey.Public().(ed25519.PublicKey), effB.Version, effB.Signature) {
		t.Error("tenant B effective policy must verify with B's key")
	}
	if policysvc.Verify(ka.UpdateKey.Public().(ed25519.PublicKey), effB.Version, effB.Signature) {
		t.Error("tenant B effective policy must NOT verify with A's key")
	}
}

func seedDevice(t *testing.T, s *store.Store, tenant uuid.UUID) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	h := []byte("h-" + uuid.NewString())
	s.CreateInstallToken(ctx, tenant, store.InstallToken{Name: "t"}, h)
	id := uuid.New()
	if _, err := s.EnrollDevice(ctx, h, time.Now(), func(uuid.UUID) (store.NewDevice, error) {
		return store.NewDevice{ID: id, Hostname: "pc", CertSerial: "s", CertExpiresAt: time.Now().Add(time.Hour)}, nil
	}); err != nil {
		t.Fatal(err)
	}
	return id
}
