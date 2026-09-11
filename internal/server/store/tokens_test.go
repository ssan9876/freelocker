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

func TestInstallTokensAndGroups(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")

	gid, err := s.CreateDeviceGroup(ctx, tenant, "Workstations")
	if err != nil {
		t.Fatal(err)
	}
	groups, err := s.ListDeviceGroups(ctx, tenant)
	if err != nil || len(groups) != 1 || groups[0].Name != "Workstations" {
		t.Fatalf("groups = %+v, %v", groups, err)
	}

	exp := time.Now().Add(24 * time.Hour).Truncate(time.Microsecond)
	max := 5
	id, err := s.CreateInstallToken(ctx, tenant, store.InstallToken{
		Name: "HQ rollout", GroupID: &gid, ExpiresAt: &exp, MaxUses: &max,
	}, []byte("hash-1"))
	if err != nil {
		t.Fatal(err)
	}
	list, err := s.ListInstallTokens(ctx, tenant)
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	got := list[0]
	if got.ID != id || got.Name != "HQ rollout" || *got.GroupID != gid || !got.ExpiresAt.Equal(exp) || *got.MaxUses != 5 || got.Revoked {
		t.Fatalf("token = %+v", got)
	}

	if err := s.RevokeInstallToken(ctx, tenant, id); err != nil {
		t.Fatal(err)
	}
	list, _ = s.ListInstallTokens(ctx, tenant)
	if !list[0].Revoked {
		t.Error("token should be revoked")
	}
	if err := s.RevokeInstallToken(ctx, tenant, uuid.New()); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("revoke missing err = %v", err)
	}
	other, _ := s.CreateTenant(ctx, "Other")
	if list, _ := s.ListInstallTokens(ctx, other); len(list) != 0 {
		t.Error("tokens must be tenant-scoped")
	}
}
