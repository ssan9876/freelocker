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
