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
