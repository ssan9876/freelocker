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

func newDev(id uuid.UUID) store.NewDevice {
	return store.NewDevice{ID: id, Hostname: "pc-01", MachineGUID: "guid", OSBuild: "26100",
		CertSerial: "abc", CertExpiresAt: time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)}
}

func TestEnrollDeviceConsumesTokenAndInheritsGroup(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	gid, _ := s.CreateDeviceGroup(ctx, tenant, "Laptops")
	max := 1
	s.CreateInstallToken(ctx, tenant, store.InstallToken{Name: "t", GroupID: &gid, MaxUses: &max}, []byte("h"))

	id := uuid.New()
	got, err := s.EnrollDevice(ctx, []byte("h"), time.Now(), func(tid uuid.UUID) (store.NewDevice, error) {
		if tid != tenant {
			t.Errorf("build got tenant %v", tid)
		}
		return newDev(id), nil
	})
	if err != nil || got != tenant {
		t.Fatalf("EnrollDevice = %v, %v", got, err)
	}
	d, err := s.GetDevice(ctx, tenant, id)
	if err != nil || d.Hostname != "pc-01" || d.GroupID == nil || *d.GroupID != gid || d.Status(time.Now()) != "never_seen" {
		t.Fatalf("device = %+v, %v", d, err)
	}
	toks, _ := s.ListInstallTokens(ctx, tenant)
	if toks[0].Uses != 1 {
		t.Errorf("uses = %d", toks[0].Uses)
	}
	// max_uses = 1 is now exhausted
	_, err = s.EnrollDevice(ctx, []byte("h"), time.Now(), func(uuid.UUID) (store.NewDevice, error) { return newDev(uuid.New()), nil })
	if !errors.Is(err, store.ErrTokenInvalid) {
		t.Errorf("exhausted token err = %v", err)
	}
}

func TestEnrollDeviceRejectsBadTokensAndRollsBack(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	past := time.Now().Add(-time.Hour)
	s.CreateInstallToken(ctx, tenant, store.InstallToken{Name: "expired", ExpiresAt: &past}, []byte("expired"))
	rid, _ := s.CreateInstallToken(ctx, tenant, store.InstallToken{Name: "revoked"}, []byte("revoked"))
	s.RevokeInstallToken(ctx, tenant, rid)
	s.CreateInstallToken(ctx, tenant, store.InstallToken{Name: "ok"}, []byte("ok"))

	build := func(uuid.UUID) (store.NewDevice, error) { return newDev(uuid.New()), nil }
	for _, h := range []string{"expired", "revoked", "unknown"} {
		if _, err := s.EnrollDevice(ctx, []byte(h), time.Now(), build); !errors.Is(err, store.ErrTokenInvalid) {
			t.Errorf("%s: err = %v", h, err)
		}
	}

	boom := errors.New("bad csr")
	_, err := s.EnrollDevice(ctx, []byte("ok"), time.Now(), func(uuid.UUID) (store.NewDevice, error) { return store.NewDevice{}, boom })
	if !errors.Is(err, boom) {
		t.Fatalf("build error not propagated: %v", err)
	}
	for _, tok := range mustTokens(t, s, tenant) {
		if tok.Name == "ok" && tok.Uses != 0 {
			t.Error("failed build must not consume the token")
		}
	}
	if devs, _ := s.ListDevices(ctx, tenant); len(devs) != 0 {
		t.Errorf("devices = %d, want 0", len(devs))
	}
}

func mustTokens(t *testing.T, s *store.Store, tenant uuid.UUID) []store.InstallToken {
	t.Helper()
	toks, err := s.ListInstallTokens(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	return toks
}

// TestSetDeviceASRAvailable checks the nullable round trip: a device that
// has never reported ASR availability reads back nil (distinct from a
// reported false), and SetDeviceASRAvailable persists true/false per tenant.
func TestSetDeviceASRAvailable(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	s.CreateInstallToken(ctx, tenant, store.InstallToken{Name: "t"}, []byte("h"))
	id := uuid.New()
	s.EnrollDevice(ctx, []byte("h"), time.Now(), func(uuid.UUID) (store.NewDevice, error) { return newDev(id), nil })

	d, err := s.GetDevice(ctx, tenant, id)
	if err != nil {
		t.Fatal(err)
	}
	if d.ASRAvailable != nil {
		t.Fatalf("ASRAvailable before any report = %v, want nil", d.ASRAvailable)
	}

	if err := s.SetDeviceASRAvailable(ctx, tenant, id, false); err != nil {
		t.Fatal(err)
	}
	d, err = s.GetDevice(ctx, tenant, id)
	if err != nil || d.ASRAvailable == nil || *d.ASRAvailable != false {
		t.Fatalf("ASRAvailable after reporting false = %+v, %v", d.ASRAvailable, err)
	}

	if err := s.SetDeviceASRAvailable(ctx, tenant, id, true); err != nil {
		t.Fatal(err)
	}
	d, err = s.GetDevice(ctx, tenant, id)
	if err != nil || d.ASRAvailable == nil || *d.ASRAvailable != true {
		t.Fatalf("ASRAvailable after reporting true = %+v, %v", d.ASRAvailable, err)
	}

	// Wrong tenant must not be able to set or see it.
	otherTenant, _ := s.CreateTenant(ctx, "Other")
	if err := s.SetDeviceASRAvailable(ctx, otherTenant, id, true); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("SetDeviceASRAvailable across tenants = %v, want ErrNotFound", err)
	}
}

func TestHeartbeatStatusRevokeAndCert(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	s.CreateInstallToken(ctx, tenant, store.InstallToken{Name: "t"}, []byte("h"))
	id := uuid.New()
	s.EnrollDevice(ctx, []byte("h"), time.Now(), func(uuid.UUID) (store.NewDevice, error) { return newDev(id), nil })

	now := time.Now()
	inv := store.Inventory{Hostname: "pc-renamed", OSBuild: "26200", IPs: []string{"10.0.0.9"}, LoggedOnUser: "ACME\\bob", AgentVersion: "0.1.0", UptimeSeconds: 42}
	if err := s.RecordHeartbeat(ctx, tenant, id, inv, now); err != nil {
		t.Fatal(err)
	}
	d, _ := s.GetDevice(ctx, tenant, id)
	if d.Hostname != "pc-renamed" || d.IPs[0] != "10.0.0.9" || d.LoggedOnUser != `ACME\bob` || d.UptimeSeconds != 42 {
		t.Fatalf("inventory not stored: %+v", d)
	}
	if st := d.Status(now); st != "online" {
		t.Errorf("status now = %s", st)
	}
	if st := d.Status(now.Add(2 * time.Minute)); st != "unexpected_offline" {
		t.Errorf("status later = %s", st)
	}
	s.MarkCleanShutdown(ctx, tenant, id)
	d, _ = s.GetDevice(ctx, tenant, id)
	if st := d.Status(now.Add(2 * time.Minute)); st != "offline" {
		t.Errorf("status after goodbye = %s", st)
	}

	exp := time.Now().Add(200 * time.Hour).Truncate(time.Second)
	if err := s.UpdateDeviceCert(ctx, tenant, id, "new-serial", exp); err != nil {
		t.Fatal(err)
	}
	tid, serial, revoked, err := s.DeviceAuthState(ctx, id)
	if err != nil || tid != tenant || serial != "new-serial" || revoked {
		t.Fatalf("auth state = %v %q %v %v", tid, serial, revoked, err)
	}

	if err := s.RevokeDevice(ctx, tenant, id); err != nil {
		t.Fatal(err)
	}
	_, _, revoked, _ = s.DeviceAuthState(ctx, id)
	d, _ = s.GetDevice(ctx, tenant, id)
	if !revoked || d.Status(now) != "revoked" {
		t.Error("device should be revoked")
	}

	other, _ := s.CreateTenant(ctx, "Other")
	if _, err := s.GetDevice(ctx, other, id); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("cross-tenant GetDevice err = %v", err)
	}
	if err := s.RevokeDevice(ctx, other, id); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("cross-tenant RevokeDevice err = %v", err)
	}
	if _, _, _, err := s.DeviceAuthState(ctx, uuid.New()); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown device auth state err = %v", err)
	}
}
