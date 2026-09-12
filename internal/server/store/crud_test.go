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

func TestRenameAndDeleteDeviceGroup(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	other, _ := s.CreateTenant(ctx, "Other")
	gid, _ := s.CreateDeviceGroup(ctx, tenant, "Laptops")
	s.CreateDeviceGroup(ctx, tenant, "Servers")

	if err := s.RenameDeviceGroup(ctx, tenant, gid, "Servers"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("rename to existing name err = %v, want ErrConflict", err)
	}
	if err := s.RenameDeviceGroup(ctx, other, gid, "X"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant rename err = %v, want ErrNotFound", err)
	}
	if err := s.RenameDeviceGroup(ctx, tenant, gid, "Notebooks"); err != nil {
		t.Fatal(err)
	}

	// A device and a token in the group are ungrouped when it is deleted.
	s.CreateInstallToken(ctx, tenant, store.InstallToken{Name: "t", GroupID: &gid}, []byte("h"))
	dev := uuid.New()
	if _, err := s.EnrollDevice(ctx, []byte("h"), time.Now(), func(uuid.UUID) (store.NewDevice, error) { return newDev(dev), nil }); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteDeviceGroup(ctx, other, gid); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant delete err = %v, want ErrNotFound", err)
	}
	if err := s.DeleteDeviceGroup(ctx, tenant, gid); err != nil {
		t.Fatal(err)
	}
	d, _ := s.GetDevice(ctx, tenant, dev)
	if d.GroupID != nil {
		t.Errorf("device still grouped: %v", d.GroupID)
	}
	toks, _ := s.ListInstallTokens(ctx, tenant)
	if toks[0].GroupID != nil {
		t.Errorf("token still grouped: %v", toks[0].GroupID)
	}
	groups, _ := s.ListDeviceGroups(ctx, tenant)
	if len(groups) != 1 || groups[0].Name != "Servers" {
		t.Errorf("groups = %+v", groups)
	}
}

func TestSetDeviceGroup(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	other, _ := s.CreateTenant(ctx, "Other")
	gid, _ := s.CreateDeviceGroup(ctx, tenant, "Laptops")
	foreign, _ := s.CreateDeviceGroup(ctx, other, "Theirs")
	s.CreateInstallToken(ctx, tenant, store.InstallToken{Name: "t"}, []byte("h"))
	dev := uuid.New()
	s.EnrollDevice(ctx, []byte("h"), time.Now(), func(uuid.UUID) (store.NewDevice, error) { return newDev(dev), nil })

	if err := s.SetDeviceGroup(ctx, tenant, dev, &gid); err != nil {
		t.Fatal(err)
	}
	if d, _ := s.GetDevice(ctx, tenant, dev); d.GroupID == nil || *d.GroupID != gid {
		t.Fatalf("group = %v", d.GroupID)
	}
	if err := s.SetDeviceGroup(ctx, tenant, dev, &foreign); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("foreign group err = %v, want ErrNotFound", err)
	}
	if err := s.SetDeviceGroup(ctx, tenant, dev, nil); err != nil {
		t.Fatal(err)
	}
	if d, _ := s.GetDevice(ctx, tenant, dev); d.GroupID != nil {
		t.Fatalf("group = %v, want nil", d.GroupID)
	}
}

func TestUpdateAlertRuleClearsBreaches(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	s.CreateInstallToken(ctx, tenant, store.InstallToken{Name: "t"}, []byte("h"))
	dev := uuid.New()
	s.EnrollDevice(ctx, []byte("h"), time.Now(), func(uuid.UUID) (store.NewDevice, error) { return newDev(dev), nil })
	id, _ := s.CreateAlertRule(ctx, tenant, store.AlertRule{Name: "cpu", Metric: "cpu", Op: "gt", Threshold: 90, Enabled: true})
	t0 := time.Now().Add(-time.Hour).Truncate(time.Second)
	s.MarkBreach(ctx, tenant, dev, id, t0)

	upd := store.AlertRule{ID: id, Name: "cpu high", Metric: "cpu", Op: "gt", Threshold: 80, DurationSeconds: 60, Enabled: false}
	if err := s.UpdateAlertRule(ctx, tenant, upd); err != nil {
		t.Fatal(err)
	}
	rules, _ := s.ListAlertRules(ctx, tenant)
	r := rules[0]
	if r.Name != "cpu high" || r.Threshold != 80 || r.DurationSeconds != 60 || r.Enabled {
		t.Errorf("rule = %+v", r)
	}
	// The old breach onset is gone: a fresh breach starts now, not at t0.
	now := time.Now().Truncate(time.Second)
	if since, _ := s.MarkBreach(ctx, tenant, dev, id, now); !since.Equal(now) {
		t.Errorf("breach since = %v, want %v (stale onset kept)", since, now)
	}
	upd.ID = uuid.New()
	if err := s.UpdateAlertRule(ctx, tenant, upd); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("missing rule err = %v", err)
	}
}

func TestSetAdminRole(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	o1, _ := s.CreateAdmin(ctx, tenant, store.Admin{Email: "o1@x.io", PasswordHash: "h", Role: "owner"})

	if err := s.SetAdminRole(ctx, tenant, o1, "readonly"); err != nil {
		t.Fatal(err)
	}
	if a, _ := s.GetAdmin(ctx, tenant, o1); a.Role != "readonly" {
		t.Errorf("role = %s", a.Role)
	}
	if err := s.SetAdminRole(ctx, tenant, uuid.New(), "admin"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("missing admin err = %v", err)
	}
}

func TestTenantRenameAndSuspend(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	admin, _ := s.CreateAdmin(ctx, tenant, store.Admin{Email: "a@x.io", PasswordHash: "h", Role: "owner"})
	s.CreateSession(ctx, store.Session{ID: "sess", TenantID: tenant, AdminID: admin, CSRFToken: "c",
		ExpiresAt: time.Now().Add(time.Hour), IP: "1.2.3.4", UserAgent: "ua"})
	s.CreateInstallToken(ctx, tenant, store.InstallToken{Name: "t"}, []byte("h"))

	if err := s.RenameTenant(ctx, tenant, "Acme Corp"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetTenantSuspended(ctx, tenant, true); err != nil {
		t.Fatal(err)
	}
	if sus, err := s.TenantSuspended(ctx, tenant); err != nil || !sus {
		t.Fatalf("suspended = %v, %v", sus, err)
	}
	list, _ := s.ListTenantDetails(ctx)
	if list[0].Name != "Acme Corp" || !list[0].Suspended {
		t.Errorf("tenant = %+v", list[0])
	}
	// Suspending drops the tenant's sessions.
	if _, err := s.GetSession(ctx, "sess", time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("session survived suspend: %v", err)
	}
	// A suspended tenant's install tokens no longer enroll devices.
	_, err := s.EnrollDevice(ctx, []byte("h"), time.Now(), func(uuid.UUID) (store.NewDevice, error) { return newDev(uuid.New()), nil })
	if !errors.Is(err, store.ErrTokenInvalid) {
		t.Errorf("enroll into suspended tenant err = %v, want ErrTokenInvalid", err)
	}

	s.SetTenantSuspended(ctx, tenant, false)
	if sus, _ := s.TenantSuspended(ctx, tenant); sus {
		t.Error("still suspended")
	}
	if err := s.SetTenantSuspended(ctx, uuid.New(), true); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("missing tenant err = %v", err)
	}
}
