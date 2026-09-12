package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"
)

func TestAdminsAndSessions(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")

	id, err := s.CreateAdmin(ctx, tenant, store.Admin{Email: "Owner@Example.com", PasswordHash: "h", Role: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAdmin(ctx, tenant, store.Admin{Email: "owner@example.com", PasswordHash: "h", Role: "admin"}); !errors.Is(err, store.ErrConflict) {
		t.Errorf("duplicate email err = %v", err)
	}
	a, err := s.GetAdminByEmail(ctx, tenant, "OWNER@example.com")
	if err != nil || a.ID != id || a.Email != "owner@example.com" || a.TOTPConfirmed {
		t.Fatalf("GetAdminByEmail = %+v, %v", a, err)
	}
	if err := s.SetAdminTOTP(ctx, tenant, id, []byte("enc"), true); err != nil {
		t.Fatal(err)
	}
	a, _ = s.GetAdmin(ctx, tenant, id)
	if string(a.TOTPSecretEnc) != "enc" || !a.TOTPConfirmed {
		t.Errorf("totp not stored: %+v", a)
	}

	now := time.Now()
	sess := store.Session{ID: "sid", TenantID: tenant, AdminID: id, CSRFToken: "csrf", ExpiresAt: now.Add(time.Hour), IP: "1.2.3.4", UserAgent: "ua"}
	if err := s.CreateSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetSession(ctx, "sid", now)
	if err != nil || got.AdminID != id || got.MFAPassed || got.CSRFToken != "csrf" {
		t.Fatalf("GetSession = %+v, %v", got, err)
	}
	s.MarkSessionMFA(ctx, "sid")
	got, _ = s.GetSession(ctx, "sid", now)
	if !got.MFAPassed {
		t.Error("MFA flag not set")
	}
	if _, err := s.GetSession(ctx, "sid", now.Add(2*time.Hour)); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expired session err = %v", err)
	}

	s.CreateSession(ctx, store.Session{ID: "sid2", TenantID: tenant, AdminID: id, CSRFToken: "c", ExpiresAt: now.Add(time.Hour)})
	if err := s.SetAdminDisabled(ctx, tenant, id, true); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAdminSessions(ctx, tenant, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(ctx, "sid2", now); !errors.Is(err, store.ErrNotFound) {
		t.Error("admin sessions should be deleted")
	}
	list, _ := s.ListAdmins(ctx, tenant)
	if len(list) != 1 || !list[0].Disabled {
		t.Errorf("admins = %+v", list)
	}
}

// TestGlobalEmail proves email is globally unique across tenants and that an
// admin (with its tenant) can be resolved by email alone — the basis for
// tenant-from-email login.
func TestGlobalEmail(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenantA, _ := s.CreateTenant(ctx, "Acme")
	tenantB, _ := s.CreateTenant(ctx, "Beta")

	idA, err := s.CreateAdmin(ctx, tenantA, store.Admin{Email: "Amy@Example.com", PasswordHash: "h", Role: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAdmin(ctx, tenantB, store.Admin{Email: "bob@example.com", PasswordHash: "h", Role: "owner"}); err != nil {
		t.Fatal(err)
	}
	// Same email in a different tenant is now rejected globally.
	if _, err := s.CreateAdmin(ctx, tenantB, store.Admin{Email: "amy@example.com", PasswordHash: "h", Role: "admin"}); !errors.Is(err, store.ErrConflict) {
		t.Errorf("cross-tenant duplicate email err = %v, want ErrConflict", err)
	}

	// Resolve by email alone → correct admin and tenant (case-insensitive).
	a, tid, err := s.GetAdminByEmailGlobal(ctx, "AMY@example.com")
	if err != nil || a.ID != idA || tid != tenantA {
		t.Fatalf("GetAdminByEmailGlobal = %+v, tid=%v, err=%v; want id=%v tenant=%v", a, tid, err, idA, tenantA)
	}
	if _, _, err := s.GetAdminByEmailGlobal(ctx, "nobody@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown email err = %v, want ErrNotFound", err)
	}
}
