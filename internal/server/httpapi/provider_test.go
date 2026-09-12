package httpapi_test

import (
	"context"
	"testing"

	"freelocker/internal/server/auth"
	"freelocker/internal/server/bootstrap"
	"freelocker/internal/server/store"

	"github.com/google/uuid"
)

// TestProviderCreatesTenant is the Phase 3 acceptance test: the provider (the
// setup owner) creates a second tenant through the API; that tenant's owner
// then logs in with no tenant hint; and the new tenant has its own CA, so a
// device enrolling into it trusts B's CA, not the default tenant's.
func TestProviderCreatesTenant(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	prov := e.initialized(t) // the setup owner is the provider

	const betaOwner, betaPass = "owner@beta.example.com", "beta-password-1234"

	// A non-provider owner in the default tenant cannot reach the provider API.
	hash, _ := auth.HashPassword(betaPass)
	defTenant, _ := e.store.FirstTenant(ctx)
	if _, err := e.store.CreateAdmin(ctx, defTenant, store.Admin{Email: "plain@example.com", PasswordHash: hash, Role: "owner"}); err != nil {
		t.Fatal(err)
	}
	nonProv := e.client(t)
	nonProv.loginFull("plain@example.com", betaPass, "")
	if code := nonProv.do("POST", "/api/provider/tenants", map[string]string{"org_name": "X", "owner_email": "x@y.z", "owner_password": betaPass}, nil); code != 403 {
		t.Fatalf("non-provider create tenant = %d, want 403", code)
	}

	// The provider creates tenant Beta with its owner.
	var cr struct {
		TenantID string `json:"tenant_id"`
	}
	if code := prov.do("POST", "/api/provider/tenants", map[string]string{"org_name": "Beta", "owner_email": betaOwner, "owner_password": betaPass}, &cr); code != 201 {
		t.Fatalf("create tenant = %d", code)
	}
	if cr.TenantID == "" {
		t.Fatal("no tenant_id returned")
	}

	// Beta appears in the tenant list alongside the default tenant.
	var list []map[string]any
	if code := prov.do("GET", "/api/provider/tenants", nil, &list); code != 200 || len(list) != 2 {
		t.Fatalf("list tenants = %d, %v", code, list)
	}

	// Beta's owner logs in with no tenant hint and reaches /api/me; they are a
	// tenant owner but NOT a provider.
	cb := e.client(t)
	cb.loginFull(betaOwner, betaPass, "")
	var me struct {
		Email    string
		Provider bool
	}
	if code := cb.do("GET", "/api/me", nil, &me); code != 200 || me.Email != betaOwner || me.Provider {
		t.Fatalf("beta /api/me = %d %+v (should not be provider)", code, me)
	}

	// Beta has its own CA, distinct from the default tenant's — so a device
	// enrolling into Beta trusts Beta's CA.
	kA, err := bootstrap.LoadForTenant(ctx, e.store, e.master, defTenant)
	if err != nil {
		t.Fatal(err)
	}
	betaTenant, err := uuid.Parse(cr.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	kB, err := bootstrap.LoadForTenant(ctx, e.store, e.master, betaTenant)
	if err != nil {
		t.Fatal(err)
	}
	if kA.CA.Pin() == kB.CA.Pin() {
		t.Fatalf("Beta must have its own CA; both pins = %s", kA.CA.Pin())
	}

	// A cross-tenant duplicate owner email is rejected (global uniqueness).
	if code := prov.do("POST", "/api/provider/tenants", map[string]string{"org_name": "Gamma", "owner_email": betaOwner, "owner_password": betaPass}, nil); code != 409 {
		t.Errorf("duplicate owner email = %d, want 409", code)
	}
}
