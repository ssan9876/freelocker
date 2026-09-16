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

func TestDeviceControls(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	gid, _ := s.CreateDeviceGroup(ctx, tenant, "WS")

	if _, err := s.GetControls(ctx, tenant, gid); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unset controls err = %v", err)
	}
	if err := s.SetControls(ctx, tenant, gid, store.DeviceControls{USBStorageBlocked: true}); err != nil {
		t.Fatal(err)
	}
	c, err := s.GetControls(ctx, tenant, gid)
	if err != nil || !c.USBStorageBlocked {
		t.Fatalf("controls = %+v, %v", c, err)
	}
	// upsert
	s.SetControls(ctx, tenant, gid, store.DeviceControls{USBStorageBlocked: false})
	c, _ = s.GetControls(ctx, tenant, gid)
	if c.USBStorageBlocked {
		t.Error("upsert should clear the block")
	}
}

func TestEffectiveControlsDefaultAllow(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	gid, _ := s.CreateDeviceGroup(ctx, tenant, "WS")
	s.CreateInstallToken(ctx, tenant, store.InstallToken{Name: "t", GroupID: &gid}, []byte("h"))
	dev := uuid.New()
	s.EnrollDevice(ctx, []byte("h"), time.Now(), func(uuid.UUID) (store.NewDevice, error) {
		return store.NewDevice{ID: dev, Hostname: "pc", CertSerial: "s", CertExpiresAt: time.Now().Add(time.Hour)}, nil
	})

	// No controls row → default allow.
	c, err := s.EffectiveControlsForDevice(ctx, tenant, dev)
	if err != nil || c.USBStorageBlocked {
		t.Fatalf("default = %+v, %v (want allow)", c, err)
	}
	s.SetControls(ctx, tenant, gid, store.DeviceControls{USBStorageBlocked: true})
	c, _ = s.EffectiveControlsForDevice(ctx, tenant, dev)
	if !c.USBStorageBlocked {
		t.Error("effective controls should reflect the group setting")
	}
	// Unknown device → ErrNotFound.
	if _, err := s.EffectiveControlsForDevice(ctx, tenant, uuid.New()); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown device err = %v", err)
	}
}

// Device controls must never cross a tenant boundary. device_controls has
// group_id as its SOLE primary key, and group_id does not determine the
// tenant — the caller names the group — so an unguarded
// `ON CONFLICT (group_id) DO UPDATE` lets tenant B rewrite tenant A's
// controls: B can cut A's fleet off the network, or silently clear a block
// A believes is enforced. Asserting only the returned error is not enough,
// because the error can be right while the row was still overwritten, so
// this reads A's effective controls back afterwards.
func TestSetControlsCannotCrossTenants(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)

	// Tenant A: a group with a device, with USB storage blocked.
	tenantA, _ := s.CreateTenant(ctx, "Acme")
	groupA, _ := s.CreateDeviceGroup(ctx, tenantA, "A-Workstations")
	s.CreateInstallToken(ctx, tenantA, store.InstallToken{Name: "ta", GroupID: &groupA}, []byte("ha"))
	devA := uuid.New()
	s.EnrollDevice(ctx, []byte("ha"), time.Now(), func(uuid.UUID) (store.NewDevice, error) {
		return store.NewDevice{ID: devA, Hostname: "a-pc", CertSerial: "sa", CertExpiresAt: time.Now().Add(time.Hour)}, nil
	})
	if err := s.SetControls(ctx, tenantA, groupA, store.DeviceControls{USBStorageBlocked: true}); err != nil {
		t.Fatal(err)
	}

	tenantB, _ := s.CreateTenant(ctx, "Beta")

	// B rewrites the controls on A's group: rejected. Clearing the USB
	// block and cutting the network is exactly the damage this prevents.
	err := s.SetControls(ctx, tenantB, groupA, store.DeviceControls{USBStorageBlocked: false, NetworkBlocked: true})
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("B setting controls on A's group = %v, want ErrNotFound", err)
	}

	// The assertion that proves the ON CONFLICT was blocked rather than
	// merely reported: A's device still sees A's controls.
	eff, err := s.EffectiveControlsForDevice(ctx, tenantA, devA)
	if err != nil {
		t.Fatal(err)
	}
	if !eff.USBStorageBlocked || eff.NetworkBlocked {
		t.Fatalf("A's device controls = %+v — tenant B overwrote them", eff)
	}

	// A same-tenant update still works, so the guard is not too tight.
	if err := s.SetControls(ctx, tenantA, groupA, store.DeviceControls{NetworkBlocked: true}); err != nil {
		t.Fatalf("same-tenant set = %v, want success", err)
	}
	if eff, _ := s.EffectiveControlsForDevice(ctx, tenantA, devA); !eff.NetworkBlocked {
		t.Errorf("same-tenant update did not take effect: %+v", eff)
	}
}
