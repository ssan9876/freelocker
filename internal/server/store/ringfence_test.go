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

func TestRingfenceCRUD(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")

	rf := store.Ringfence{ID: uuid.New(), Name: "Office", Mode: "audit"}
	if err := s.CreateRingfence(ctx, tenant, rf); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetRingfence(ctx, tenant, rf.ID)
	if err != nil || got.Name != "Office" || got.Mode != "audit" {
		t.Fatalf("get = %+v, %v", got, err)
	}

	// A duplicate name in the same tenant is a conflict.
	if err := s.CreateRingfence(ctx, tenant, store.Ringfence{ID: uuid.New(), Name: "Office", Mode: "audit"}); !errors.Is(err, store.ErrConflict) {
		t.Errorf("duplicate name err = %v, want ErrConflict", err)
	}

	if err := s.RenameRingfence(ctx, tenant, rf.ID, "Office apps"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRingfenceMode(ctx, tenant, rf.ID, "enforce"); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetRingfence(ctx, tenant, rf.ID)
	if got.Name != "Office apps" || got.Mode != "enforce" {
		t.Errorf("after update = %+v", got)
	}

	list, err := s.ListRingfences(ctx, tenant)
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %+v, %v", list, err)
	}

	// Another tenant cannot see or touch it.
	other, _ := s.CreateTenant(ctx, "Beta")
	if _, err := s.GetRingfence(ctx, other, rf.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("cross-tenant get err = %v", err)
	}
	if err := s.DeleteRingfence(ctx, other, rf.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("cross-tenant delete err = %v", err)
	}

	if err := s.DeleteRingfence(ctx, tenant, rf.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetRingfence(ctx, tenant, rf.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("after delete err = %v", err)
	}
}

func TestRingfenceForDevice(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	group, _ := s.CreateDeviceGroup(ctx, tenant, "WS")
	dev := enrollTestDevice(t, s, tenant, &group, "pc1", "1.0.0")

	// No ringfence assigned → ErrNotFound, which the agent API treats as
	// "nothing to enforce".
	if _, err := s.RingfenceForDevice(ctx, tenant, dev); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unassigned err = %v, want ErrNotFound", err)
	}

	rf := store.Ringfence{ID: uuid.New(), Name: "Office", Mode: "enforce"}
	if err := s.CreateRingfence(ctx, tenant, rf); err != nil {
		t.Fatal(err)
	}
	prog := store.RingfenceProgram{ID: uuid.New(), Path: `C:\Program Files\App\app.exe`, NetworkBlocked: true, Note: "no internet"}
	if err := s.AddRingfenceProgram(ctx, tenant, rf.ID, prog); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRingfenceProtection(ctx, tenant, rf.ID, "D4F940AB-401B-4EFC-AADC-AD5F3C50688A", "block"); err != nil {
		t.Fatal(err)
	}
	if err := s.AssignRingfence(ctx, tenant, group, rf.ID); err != nil {
		t.Fatal(err)
	}

	got, err := s.RingfenceForDevice(ctx, tenant, dev)
	if err != nil {
		t.Fatal(err)
	}
	if got.Mode != "enforce" || len(got.Programs) != 1 || got.Programs[0].Path != prog.Path || len(got.Protections) != 1 {
		t.Fatalf("resolved = %+v", got)
	}
	if got.Version == "" {
		t.Error("resolved ringfence must carry a content version")
	}

	// The version is a content hash: unchanged content, unchanged version.
	again, _ := s.RingfenceForDevice(ctx, tenant, dev)
	if again.Version != got.Version {
		t.Errorf("version changed without a content change: %q then %q", got.Version, again.Version)
	}
	// Changing content changes the version.
	if err := s.SetRingfenceProtection(ctx, tenant, rf.ID, "D4F940AB-401B-4EFC-AADC-AD5F3C50688A", "audit"); err != nil {
		t.Fatal(err)
	}
	changed, _ := s.RingfenceForDevice(ctx, tenant, dev)
	if changed.Version == got.Version {
		t.Error("version must change when a protection action changes")
	}
	// "off" removes the protection entirely.
	if err := s.SetRingfenceProtection(ctx, tenant, rf.ID, "D4F940AB-401B-4EFC-AADC-AD5F3C50688A", "off"); err != nil {
		t.Fatal(err)
	}
	off, _ := s.RingfenceForDevice(ctx, tenant, dev)
	if len(off.Protections) != 0 {
		t.Errorf("protections after off = %+v, want none", off.Protections)
	}

	// Unassigning returns the device to "nothing to enforce".
	if err := s.UnassignRingfence(ctx, tenant, group); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RingfenceForDevice(ctx, tenant, dev); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("after unassign err = %v, want ErrNotFound", err)
	}

	// Cross-tenant security: Tenant B cannot hijack Tenant A's group with its own ringfence.
	tenantB, _ := s.CreateTenant(ctx, "Beta")
	groupB, _ := s.CreateDeviceGroup(ctx, tenantB, "BG")
	rfB := store.Ringfence{ID: uuid.New(), Name: "Beta RF", Mode: "enforce"}
	if err := s.CreateRingfence(ctx, tenantB, rfB); err != nil {
		t.Fatal(err)
	}

	// Re-assign A's group to A's ringfence for the cross-tenant test.
	if err := s.AssignRingfence(ctx, tenant, group, rf.ID); err != nil {
		t.Fatal(err)
	}

	// B tries to assign its ringfence to A's group — must be rejected.
	if err := s.AssignRingfence(ctx, tenantB, group, rfB.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("B.AssignRingfence(B, GA, RB) err = %v, want ErrNotFound", err)
	}

	// Verify A's assignment is still pointing at RA (not overwritten by B's attempt).
	checkA, err := s.RingfenceForDevice(ctx, tenant, dev)
	if err != nil {
		t.Fatal(err)
	}
	if checkA.Mode != "enforce" {
		t.Errorf("after B's attempt, A's ringfence corrupted; Mode = %q, want enforce", checkA.Mode)
	}

	// B tries to assign A's ringfence to B's group — must also be rejected.
	if err := s.AssignRingfence(ctx, tenantB, groupB, rf.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("B.AssignRingfence(B, GB, RA) err = %v, want ErrNotFound", err)
	}
}

func TestRingfenceEvents(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	dev := enrollTestDevice(t, s, tenant, nil, "pc1", "1.0.0")

	evs := []store.RingfenceEvent{
		{Kind: "network", Program: `C:\app.exe`, Detail: "203.0.113.5:443", Enforced: false, At: time.Now()},
		{Kind: "child_process", Program: `C:\Program Files\Office\winword.exe`, Detail: "ASR D4F940AB…: powershell.exe", Enforced: true, At: time.Now()},
	}
	if err := s.AppendRingfenceEvents(ctx, tenant, dev, evs); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListRingfenceEvents(ctx, tenant, 10, nil)
	if err != nil || len(got) != 2 {
		t.Fatalf("list = %+v, %v", got, err)
	}
	if got[0].Hostname != "pc1" {
		t.Errorf("events must carry the hostname for the console: %+v", got[0])
	}

	// An empty batch is a no-op, not an error: the agent reports on a timer.
	if err := s.AppendRingfenceEvents(ctx, tenant, dev, nil); err != nil {
		t.Errorf("empty batch = %v", err)
	}

	// Another tenant sees none of it.
	other, _ := s.CreateTenant(ctx, "Beta")
	if got, _ := s.ListRingfenceEvents(ctx, other, 10, nil); len(got) != 0 {
		t.Errorf("cross-tenant list = %+v", got)
	}
}

// TestRingfenceEventsFilterByDevice covers FINDING 4: on a tenant with
// several devices, the console needs a server-side device_id filter — the
// tenant-wide feed is capped, and client-side filtering after the fact can
// silently show "no activity" for a device that actually has violations
// buried past the cap.
func TestRingfenceEventsFilterByDevice(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	devA := enrollTestDevice(t, s, tenant, nil, "pc-a", "1.0.0")
	devB := enrollTestDevice(t, s, tenant, nil, "pc-b", "1.0.0")

	if err := s.AppendRingfenceEvents(ctx, tenant, devA, []store.RingfenceEvent{
		{Kind: "network", Program: `C:\a.exe`, Detail: "203.0.113.5:443", At: time.Now()},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendRingfenceEvents(ctx, tenant, devB, []store.RingfenceEvent{
		{Kind: "network", Program: `C:\b.exe`, Detail: "203.0.113.6:443", At: time.Now()},
	}); err != nil {
		t.Fatal(err)
	}

	got, err := s.ListRingfenceEvents(ctx, tenant, 10, &devA)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].DeviceID != devA {
		t.Fatalf("ListRingfenceEvents(deviceID=A) = %+v, want exactly devA's event", got)
	}

	if got, _ := s.ListRingfenceEvents(ctx, tenant, 10, nil); len(got) != 2 {
		t.Errorf("ListRingfenceEvents(nil) = %+v, want both events (unfiltered)", got)
	}
}
