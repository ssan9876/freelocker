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

func TestRolloutCreateGetListConflict(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	s.PutRelease(ctx, tenant, store.Release{Version: "1.0.1", SHA256: make([]byte, 32), Signature: []byte("sig")})

	// Unknown version → ErrNotFound.
	err := s.CreateRollout(ctx, tenant, store.Rollout{ID: uuid.New(), Version: "9.9.9", BatchSize: 5, MaxFailures: 1, State: "active", CreatedBy: "admin:a@x"})
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown version err = %v", err)
	}

	gid, _ := s.CreateDeviceGroup(ctx, tenant, "WS")
	r := store.Rollout{ID: uuid.New(), Version: "1.0.1", GroupIDs: []uuid.UUID{gid}, BatchSize: 5, MaxFailures: 1, State: "active", CreatedBy: "admin:a@x"}
	if err := s.CreateRollout(ctx, tenant, r); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetRollout(ctx, tenant, r.ID)
	if err != nil || got.Version != "1.0.1" || len(got.GroupIDs) != 1 || got.GroupIDs[0] != gid || got.BatchSize != 5 || got.State != "active" || got.CreatedBy != "admin:a@x" {
		t.Fatalf("get = %+v, %v", got, err)
	}

	// A second open rollout in the tenant → ErrConflict.
	err = s.CreateRollout(ctx, tenant, store.Rollout{ID: uuid.New(), Version: "1.0.1", BatchSize: 1, MaxFailures: 0, State: "active", CreatedBy: "x"})
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("second open err = %v", err)
	}

	// Other tenant cannot see it.
	other, _ := s.CreateTenant(ctx, "Beta")
	if _, err := s.GetRollout(ctx, other, r.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("cross-tenant get err = %v", err)
	}

	list, err := s.ListRollouts(ctx, tenant, 10)
	if err != nil || len(list) != 1 || list[0].ID != r.ID {
		t.Fatalf("list = %+v, %v", list, err)
	}
}

func TestRolloutStateTransitions(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	s.PutRelease(ctx, tenant, store.Release{Version: "1.0.1", SHA256: make([]byte, 32), Signature: []byte("sig")})
	r := store.Rollout{ID: uuid.New(), Version: "1.0.1", BatchSize: 5, MaxFailures: 1, State: "active", CreatedBy: "x"}
	s.CreateRollout(ctx, tenant, r)
	now := time.Now()

	if err := s.SetRolloutState(ctx, tenant, r.ID, []string{"paused"}, "active", now); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("resume an active rollout err = %v, want ErrConflict", err)
	}
	if err := s.SetRolloutState(ctx, tenant, r.ID, []string{"active"}, "paused", now); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetRollout(ctx, tenant, r.ID)
	if got.State != "paused" || got.FinishedAt != nil {
		t.Fatalf("after pause = %+v", got)
	}
	if err := s.SetRolloutState(ctx, tenant, r.ID, []string{"active", "paused"}, "cancelled", now); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetRollout(ctx, tenant, r.ID)
	if got.State != "cancelled" || got.FinishedAt == nil {
		t.Fatalf("after cancel = %+v", got)
	}
	// Terminal: a new open rollout is now allowed.
	if err := s.CreateRollout(ctx, tenant, store.Rollout{ID: uuid.New(), Version: "1.0.1", BatchSize: 1, MaxFailures: 0, State: "active", CreatedBy: "x"}); err != nil {
		t.Fatalf("create after cancel: %v", err)
	}
	// Unknown id → ErrNotFound.
	if err := s.SetRolloutState(ctx, tenant, uuid.New(), []string{"active"}, "paused", now); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown id err = %v", err)
	}
}

func TestReplaceRollout(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	s.PutRelease(ctx, tenant, store.Release{Version: "1.0.0", SHA256: make([]byte, 32), Signature: []byte("sig")})
	s.PutRelease(ctx, tenant, store.Release{Version: "1.0.1", SHA256: make([]byte, 32), Signature: []byte("sig")})
	now := time.Now()

	// Open old rollout → replaced: new created, old cancelled.
	old := store.Rollout{ID: uuid.New(), Version: "1.0.1", BatchSize: 5, MaxFailures: 1, State: "active", CreatedBy: "x"}
	if err := s.CreateRollout(ctx, tenant, old); err != nil {
		t.Fatal(err)
	}
	next := store.Rollout{ID: uuid.New(), Version: "1.0.0", BatchSize: 5, MaxFailures: 1, State: "active", CreatedBy: "x"}
	if err := s.ReplaceRollout(ctx, tenant, old.ID, next, now); err != nil {
		t.Fatalf("replace open: %v", err)
	}
	gotOld, err := s.GetRollout(ctx, tenant, old.ID)
	if err != nil || gotOld.State != "cancelled" || gotOld.FinishedAt == nil {
		t.Fatalf("old after replace = %+v, %v", gotOld, err)
	}
	gotNext, err := s.GetRollout(ctx, tenant, next.ID)
	if err != nil || gotNext.Version != "1.0.0" || gotNext.State != "active" {
		t.Fatalf("next after replace = %+v, %v", gotNext, err)
	}
	// Free the open slot so later creates in this test don't conflict.
	if err := s.SetRolloutState(ctx, tenant, next.ID, []string{"active"}, "cancelled", now); err != nil {
		t.Fatal(err)
	}

	// Already-terminal old rollout → new created, old left untouched.
	term := store.Rollout{ID: uuid.New(), Version: "1.0.1", BatchSize: 1, MaxFailures: 0, State: "active", CreatedBy: "x"}
	if err := s.CreateRollout(ctx, tenant, term); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRolloutState(ctx, tenant, term.ID, []string{"active"}, "completed", now); err != nil {
		t.Fatal(err)
	}
	next2 := store.Rollout{ID: uuid.New(), Version: "1.0.1", BatchSize: 1, MaxFailures: 0, State: "active", CreatedBy: "x"}
	if err := s.ReplaceRollout(ctx, tenant, term.ID, next2, now); err != nil {
		t.Fatalf("replace terminal: %v", err)
	}
	gotTerm, err := s.GetRollout(ctx, tenant, term.ID)
	if err != nil || gotTerm.State != "completed" {
		t.Fatalf("terminal old after replace = %+v, %v", gotTerm, err)
	}
	gotNext2, err := s.GetRollout(ctx, tenant, next2.ID)
	if err != nil || gotNext2.State != "active" {
		t.Fatalf("next2 after replace = %+v, %v", gotNext2, err)
	}
	// Cancel next2 so it doesn't block later opens.
	if err := s.SetRolloutState(ctx, tenant, next2.ID, []string{"active"}, "cancelled", now); err != nil {
		t.Fatal(err)
	}

	// Unknown version → ErrNotFound, and the old rollout must NOT be
	// cancelled (atomicity guarantee).
	bad := store.Rollout{ID: uuid.New(), Version: "9.9.9", BatchSize: 1, MaxFailures: 0, State: "active", CreatedBy: "x"}
	if err := s.ReplaceRollout(ctx, tenant, term.ID, bad, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("bad version err = %v, want ErrNotFound", err)
	}
	gotTermAfter, err := s.GetRollout(ctx, tenant, term.ID)
	if err != nil || gotTermAfter.State != "completed" {
		t.Fatalf("term state changed on failed replace = %+v, %v", gotTermAfter, err)
	}

	// Unknown oldID → ErrNotFound.
	if err := s.ReplaceRollout(ctx, tenant, uuid.New(), store.Rollout{ID: uuid.New(), Version: "1.0.0", BatchSize: 1, MaxFailures: 0, State: "active", CreatedBy: "x"}, now); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown oldID err = %v, want ErrNotFound", err)
	}
}

func TestOpenRolloutsSkipsSuspendedTenants(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	a, _ := s.CreateTenant(ctx, "A")
	b, _ := s.CreateTenant(ctx, "B")
	for _, tid := range []uuid.UUID{a, b} {
		s.PutRelease(ctx, tid, store.Release{Version: "1", SHA256: make([]byte, 32), Signature: []byte("s")})
		s.CreateRollout(ctx, tid, store.Rollout{ID: uuid.New(), Version: "1", BatchSize: 1, MaxFailures: 0, State: "active", CreatedBy: "x"})
	}
	s.SetTenantSuspended(ctx, b, true)
	open, err := s.OpenRollouts(ctx)
	if err != nil || len(open) != 1 || open[0].TenantID != a {
		t.Fatalf("open = %+v, %v", open, err)
	}
}

// enrollTestDevice creates a device in the tenant (optionally in a group)
// reporting the given agent version.
func enrollTestDevice(t *testing.T, s *store.Store, tenant uuid.UUID, group *uuid.UUID, hostname, version string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	id := uuid.New()
	hash := []byte("h-" + id.String())
	if _, err := s.CreateInstallToken(ctx, tenant, store.InstallToken{Name: hostname, GroupID: group}, hash); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnrollDevice(ctx, hash, time.Now(), func(uuid.UUID) (store.NewDevice, error) {
		return store.NewDevice{ID: id, Hostname: hostname, CertSerial: "s-" + hostname, CertExpiresAt: time.Now().Add(time.Hour)}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordHeartbeat(ctx, tenant, id, store.Inventory{Hostname: hostname, AgentVersion: version}, time.Now()); err != nil {
		t.Fatal(err)
	}
	return id
}

func newTestRollout(t *testing.T, s *store.Store, tenant uuid.UUID, groups []uuid.UUID) store.Rollout {
	t.Helper()
	ctx := context.Background()
	s.PutRelease(ctx, tenant, store.Release{Version: "2.0.0", SHA256: make([]byte, 32), Signature: []byte("sig")})
	r := store.Rollout{ID: uuid.New(), Version: "2.0.0", GroupIDs: groups, BatchSize: 10, MaxFailures: 3, State: "active", CreatedBy: "x"}
	if err := s.CreateRollout(ctx, tenant, r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRolloutCandidates(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	ws, _ := s.CreateDeviceGroup(ctx, tenant, "WS")
	srv, _ := s.CreateDeviceGroup(ctx, tenant, "SRV")
	old := enrollTestDevice(t, s, tenant, &ws, "b-old", "1.0.0")
	enrollTestDevice(t, s, tenant, &ws, "a-current", "2.0.0")
	enrollTestDevice(t, s, tenant, &srv, "c-other-group", "1.0.0")
	revoked := enrollTestDevice(t, s, tenant, &ws, "d-revoked", "1.0.0")
	s.RevokeDevice(ctx, tenant, revoked)
	rowed := enrollTestDevice(t, s, tenant, &ws, "e-rowed", "1.0.0")

	r := newTestRollout(t, s, tenant, []uuid.UUID{ws})
	s.AddRolloutDevice(ctx, r.ID, rowed, uuid.New(), time.Now())

	c, err := s.RolloutCandidates(ctx, tenant, r.ID)
	if err != nil || len(c) != 1 || c[0].DeviceID != old || c[0].Hostname != "b-old" {
		t.Fatalf("group candidates = %+v, %v (want only b-old)", c, err)
	}

	// Empty group set = every device in the tenant.
	s.SetRolloutState(ctx, tenant, r.ID, []string{"active"}, "cancelled", time.Now())
	all := newTestRollout(t, s, tenant, nil)
	c, _ = s.RolloutCandidates(ctx, tenant, all.ID)
	if len(c) != 3 || c[0].Hostname != "b-old" || c[1].Hostname != "c-other-group" || c[2].Hostname != "e-rowed" {
		t.Fatalf("all candidates = %+v (want b-old, c-other-group, e-rowed by hostname)", c)
	}
}

func TestResolveRolloutDevices(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	r := newTestRollout(t, s, tenant, nil)
	now := time.Now()
	timeout := 10 * time.Minute

	mk := func(name string) (uuid.UUID, uuid.UUID) {
		dev := enrollTestDevice(t, s, tenant, nil, name, "1.0.0")
		cmd := uuid.New()
		if err := s.CreateCommand(ctx, tenant, store.Command{ID: cmd, DeviceID: dev, Type: "update_agent", IssuedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		if err := s.AddRolloutDevice(ctx, r.ID, dev, cmd, now); err != nil {
			t.Fatal(err)
		}
		return dev, cmd
	}
	updatedDev, updatedCmd := mk("updated")
	failedDev, failedCmd := mk("failed")
	timedOutDev, timedOutCmd := mk("timedout")
	freshDev, freshCmd := mk("fresh")
	_, _ = mk("pending")

	// updated: command succeeded AND version reported.
	s.CompleteCommand(ctx, tenant, updatedDev, updatedCmd, true, "ok", now)
	s.RecordHeartbeat(ctx, tenant, updatedDev, store.Inventory{Hostname: "updated", AgentVersion: "2.0.0"}, now)
	// failed: command result failure.
	s.CompleteCommand(ctx, tenant, failedDev, failedCmd, false, "hash mismatch", now)
	// timed out: succeeded long ago, still old version.
	s.CompleteCommand(ctx, tenant, timedOutDev, timedOutCmd, true, "ok", now.Add(-timeout-time.Minute))
	// fresh: succeeded just now, old version → still issued.
	s.CompleteCommand(ctx, tenant, freshDev, freshCmd, true, "ok", now)

	up, fail, err := s.ResolveRolloutDevices(ctx, tenant, r.ID, now, timeout)
	if err != nil || up != 1 || fail != 2 {
		t.Fatalf("resolve = %d updated, %d failed, %v (want 1, 2)", up, fail, err)
	}
	devs, _ := s.ListRolloutDevices(ctx, tenant, r.ID)
	states := map[string]string{}
	details := map[string]string{}
	for _, d := range devs {
		states[d.Hostname] = d.State
		details[d.Hostname] = d.Detail
	}
	want := map[string]string{"updated": "updated", "failed": "failed", "timedout": "failed", "fresh": "issued", "pending": "issued"}
	for h, st := range want {
		if states[h] != st {
			t.Errorf("%s state = %q, want %q", h, states[h], st)
		}
	}
	if details["failed"] != "failed: hash mismatch" {
		t.Errorf("failed detail = %q", details["failed"])
	}
	if details["timedout"] == "" {
		t.Error("timed-out device should carry a detail")
	}
	// Idempotent: nothing new resolves on a second call.
	up, fail, _ = s.ResolveRolloutDevices(ctx, tenant, r.ID, now, timeout)
	if up != 0 || fail != 0 {
		t.Errorf("second resolve = %d, %d", up, fail)
	}

	sum, err := s.RolloutSummary(ctx, tenant, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Targeted != 5 || sum.AlreadyCurrent != 0 || sum.Issued != 2 || sum.Updated != 1 || sum.Failed != 2 || sum.Remaining != 0 {
		t.Errorf("summary = %+v", sum)
	}
}

func TestRolloutSummaryCountsCurrentAndRemaining(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	enrollTestDevice(t, s, tenant, nil, "cur", "2.0.0")
	enrollTestDevice(t, s, tenant, nil, "old1", "1.0.0")
	enrollTestDevice(t, s, tenant, nil, "old2", "1.0.0")
	r := newTestRollout(t, s, tenant, nil)
	sum, _ := s.RolloutSummary(ctx, tenant, r.ID)
	if sum.Targeted != 3 || sum.AlreadyCurrent != 1 || sum.Remaining != 2 || sum.Issued != 0 {
		t.Errorf("summary = %+v", sum)
	}
	// Expired command → failed.
	dev := enrollTestDevice(t, s, tenant, nil, "old3", "1.0.0")
	cmd := uuid.New()
	past := time.Now().Add(-2 * time.Hour)
	s.CreateCommand(ctx, tenant, store.Command{ID: cmd, DeviceID: dev, Type: "update_agent", IssuedAt: past, ExpiresAt: past.Add(time.Hour)})
	s.AddRolloutDevice(ctx, r.ID, dev, cmd, past)
	s.ExpireCommands(ctx, time.Now())
	_, fail, _ := s.ResolveRolloutDevices(ctx, tenant, r.ID, time.Now(), 10*time.Minute)
	if fail != 1 {
		t.Errorf("expired command should fail the device; failed = %d", fail)
	}
}

// Remaining must be a real count of untouched targeted devices, not a
// subtraction: progress rows survive a device being revoked or moved out of
// the targeted set, so subtracting them can reach 0 while a device that was
// never issued to is still on the old version.
func TestRolloutSummaryRemainingIsACount(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	a := enrollTestDevice(t, s, tenant, nil, "a", "1.0.0")
	enrollTestDevice(t, s, tenant, nil, "b", "1.0.0") // never issued to
	r := newTestRollout(t, s, tenant, nil)

	// a is issued to, updates, then is revoked mid-rollout.
	now := time.Now()
	cmd := uuid.New()
	if err := s.CreateCommand(ctx, tenant, store.Command{ID: cmd, DeviceID: a, Type: "update_agent", IssuedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddRolloutDevice(ctx, r.ID, a, cmd, now); err != nil {
		t.Fatal(err)
	}
	s.CompleteCommand(ctx, tenant, a, cmd, true, "ok", now)
	s.RecordHeartbeat(ctx, tenant, a, store.Inventory{Hostname: "a", AgentVersion: "2.0.0"}, now)
	if up, _, err := s.ResolveRolloutDevices(ctx, tenant, r.ID, now, 10*time.Minute); err != nil || up != 1 {
		t.Fatalf("resolve = %d, %v", up, err)
	}
	if err := s.RevokeDevice(ctx, tenant, a); err != nil {
		t.Fatal(err)
	}

	sum, err := s.RolloutSummary(ctx, tenant, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Targeted drops to 1 (b) while Updated still counts revoked a.
	if sum.Targeted != 1 || sum.Updated != 1 || sum.Remaining != 1 {
		t.Fatalf("summary = %+v, want Remaining 1 (b is untouched and still on 1.0.0)", sum)
	}
}
