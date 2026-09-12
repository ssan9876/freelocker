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

func ptr(b bool) *bool { return &b }

// overrideEnv returns a store, tenant, the device's group, and a device in it.
func overrideEnv(t *testing.T) (*store.Store, uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	gid, _ := s.CreateDeviceGroup(ctx, tenant, "Laptops")
	s.CreateInstallToken(ctx, tenant, store.InstallToken{Name: "t", GroupID: &gid}, []byte("h"))
	dev := uuid.New()
	if _, err := s.EnrollDevice(ctx, []byte("h"), time.Now(), func(uuid.UUID) (store.NewDevice, error) {
		return store.NewDevice{ID: dev, Hostname: "pc", CertSerial: "s", CertExpiresAt: time.Now().Add(time.Hour)}, nil
	}); err != nil {
		t.Fatal(err)
	}
	return s, tenant, gid, dev
}

func TestEffectiveControlsResolution(t *testing.T) {
	ctx := context.Background()
	s, tenant, gid, dev := overrideEnv(t)
	// Group: USB blocked, network allowed, elevation has no explicit value (false).
	s.SetControls(ctx, tenant, gid, store.DeviceControls{USBStorageBlocked: true})

	cases := []struct {
		name string
		o    store.DeviceControlOverrides
		want store.DeviceControls
	}{
		{"all inherit", store.DeviceControlOverrides{}, store.DeviceControls{USBStorageBlocked: true}},
		{"allow loosens group block", store.DeviceControlOverrides{USBStorageBlocked: ptr(false)}, store.DeviceControls{}},
		{"block tightens group allow", store.DeviceControlOverrides{NetworkBlocked: ptr(true)},
			store.DeviceControls{USBStorageBlocked: true, NetworkBlocked: true}},
		{"mixed", store.DeviceControlOverrides{USBStorageBlocked: ptr(false), ElevationBlocked: ptr(true)},
			store.DeviceControls{ElevationBlocked: true}},
	}
	for _, tc := range cases {
		if err := s.SetDeviceOverrides(ctx, tenant, dev, tc.o); err != nil {
			t.Fatalf("%s: set: %v", tc.name, err)
		}
		got, err := s.EffectiveControlsForDevice(ctx, tenant, dev)
		if err != nil || got != tc.want {
			t.Errorf("%s: effective = %+v, %v; want %+v", tc.name, got, err, tc.want)
		}
	}
}

func TestEffectiveControlsOverrideWithoutGroup(t *testing.T) {
	ctx := context.Background()
	s, tenant, _, dev := overrideEnv(t)
	s.SetDeviceGroup(ctx, tenant, dev, nil)
	s.SetDeviceOverrides(ctx, tenant, dev, store.DeviceControlOverrides{NetworkBlocked: ptr(true)})
	got, _ := s.EffectiveControlsForDevice(ctx, tenant, dev)
	if got != (store.DeviceControls{NetworkBlocked: true}) {
		t.Errorf("ungrouped effective = %+v", got)
	}
}

func TestDeviceOverridesGetSet(t *testing.T) {
	ctx := context.Background()
	s, tenant, _, dev := overrideEnv(t)
	other, _ := s.CreateTenant(ctx, "Other")

	o, err := s.GetDeviceOverrides(ctx, tenant, dev)
	if err != nil || o.USBStorageBlocked != nil || o.NetworkBlocked != nil || o.ElevationBlocked != nil {
		t.Fatalf("fresh overrides = %+v, %v; want all nil", o, err)
	}
	s.SetDeviceOverrides(ctx, tenant, dev, store.DeviceControlOverrides{USBStorageBlocked: ptr(false), ElevationBlocked: ptr(true)})
	o, _ = s.GetDeviceOverrides(ctx, tenant, dev)
	if o.USBStorageBlocked == nil || *o.USBStorageBlocked || o.NetworkBlocked != nil || o.ElevationBlocked == nil || !*o.ElevationBlocked {
		t.Fatalf("overrides = %+v", o)
	}
	// All-nil removes the row: reads back as all nil again.
	if err := s.SetDeviceOverrides(ctx, tenant, dev, store.DeviceControlOverrides{}); err != nil {
		t.Fatal(err)
	}
	o, _ = s.GetDeviceOverrides(ctx, tenant, dev)
	if o.USBStorageBlocked != nil || o.ElevationBlocked != nil {
		t.Errorf("after clear = %+v", o)
	}
	// Cross-tenant and unknown devices are not found.
	if _, err := s.GetDeviceOverrides(ctx, other, dev); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("cross-tenant get err = %v", err)
	}
	if err := s.SetDeviceOverrides(ctx, other, dev, store.DeviceControlOverrides{NetworkBlocked: ptr(true)}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("cross-tenant set err = %v", err)
	}
	if err := s.SetDeviceOverrides(ctx, tenant, uuid.New(), store.DeviceControlOverrides{}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown device clear err = %v", err)
	}
}
