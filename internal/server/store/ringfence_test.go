package store_test

import (
	"context"
	"errors"
	"testing"

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
