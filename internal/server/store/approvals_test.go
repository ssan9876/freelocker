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

func TestApprovalRequestsAggregate(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	pol, _ := s.CreatePolicy(ctx, tenant, "Baseline", "audit")
	dev1 := seedDevice(t, s, tenant)
	dev2 := seedDevice(t, s, tenant)
	t0 := time.Now().Add(-time.Hour).Truncate(time.Second)

	// One batch: two events for AA (first with no signer), one event with no hash.
	err := s.UpsertApprovalRequests(ctx, tenant, pol, dev1, []store.BlockEvent{
		{SHA256: "AA", Path: `C:\a.exe`, At: t0},
		{SHA256: "AA", Path: `C:\a.exe`, Signer: "Acme", At: t0.Add(time.Minute)},
		{SHA256: "", Path: `C:\nohash.exe`, At: t0},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Same device again, then a second device.
	s.UpsertApprovalRequests(ctx, tenant, pol, dev1, []store.BlockEvent{{SHA256: "AA", At: t0.Add(2 * time.Minute)}})
	s.UpsertApprovalRequests(ctx, tenant, pol, dev2, []store.BlockEvent{{SHA256: "AA", At: t0.Add(3 * time.Minute)}})

	list, err := s.ListApprovalRequests(ctx, tenant, "pending", 10)
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %+v, %v (empty-hash events must be skipped)", list, err)
	}
	r := list[0]
	if r.EventCount != 4 || r.DeviceCount != 2 {
		t.Errorf("counts = events %d devices %d, want 4 and 2", r.EventCount, r.DeviceCount)
	}
	if r.Path != `C:\a.exe` || r.Signer != "Acme" || r.PolicyName != "Baseline" || r.Status != "pending" {
		t.Errorf("fields = %+v", r)
	}
	if !r.FirstSeen.Equal(t0) || !r.LastSeen.Equal(t0.Add(3*time.Minute)) {
		t.Errorf("first/last = %v / %v", r.FirstSeen, r.LastSeen)
	}
	if n, _ := s.CountPendingApprovals(ctx, tenant); n != 1 {
		t.Errorf("pending count = %d", n)
	}
	if err := s.UpsertApprovalRequests(ctx, tenant, pol, dev1, nil); err != nil {
		t.Errorf("empty batch should be a no-op: %v", err)
	}
}

func TestApprovalRequestDecide(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	pol, _ := s.CreatePolicy(ctx, tenant, "Baseline", "audit")
	dev := seedDevice(t, s, tenant)
	admin, err := s.CreateAdmin(ctx, tenant, store.Admin{Email: "a@example.com", PasswordHash: "h", Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	s.UpsertApprovalRequests(ctx, tenant, pol, dev, []store.BlockEvent{{SHA256: "AA", At: time.Now()}})
	list, _ := s.ListApprovalRequests(ctx, tenant, "", 10)
	id := list[0].ID

	if err := s.DecideApprovalRequest(ctx, tenant, id, "approved", admin, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.DecideApprovalRequest(ctx, tenant, id, "denied", admin, time.Now()); !errors.Is(err, store.ErrConflict) {
		t.Errorf("second decide = %v, want ErrConflict", err)
	}
	if err := s.DecideApprovalRequest(ctx, tenant, uuid.New(), "denied", admin, time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown id = %v, want ErrNotFound", err)
	}

	// New events for a decided hash do not reopen it.
	s.UpsertApprovalRequests(ctx, tenant, pol, dev, []store.BlockEvent{{SHA256: "AA", At: time.Now()}})
	got, err := s.GetApprovalRequest(ctx, tenant, id)
	if err != nil || got.Status != "approved" || got.DecidedBy == nil || *got.DecidedBy != admin || got.DecidedAt == nil {
		t.Fatalf("after re-report = %+v, %v", got, err)
	}
	if pending, _ := s.ListApprovalRequests(ctx, tenant, "pending", 10); len(pending) != 0 {
		t.Errorf("pending = %+v, want none", pending)
	}

	// Tenant isolation.
	other, _ := s.CreateTenant(ctx, "Other")
	if l, _ := s.ListApprovalRequests(ctx, other, "", 10); len(l) != 0 {
		t.Errorf("other tenant sees %+v", l)
	}
	if _, err := s.GetApprovalRequest(ctx, other, id); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("other tenant get = %v, want ErrNotFound", err)
	}
}

func TestExpireApprovalRequests(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	pol, _ := s.CreatePolicy(ctx, tenant, "Baseline", "audit")
	dev := seedDevice(t, s, tenant)

	old := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
	recent := time.Now().Add(-1 * time.Hour).Truncate(time.Second)
	s.UpsertApprovalRequests(ctx, tenant, pol, dev, []store.BlockEvent{{SHA256: "OLD", Path: `C:\o.exe`, At: old}})
	s.UpsertApprovalRequests(ctx, tenant, pol, dev, []store.BlockEvent{{SHA256: "NEW", Path: `C:\n.exe`, At: recent}})

	n, err := s.ExpireApprovalRequests(ctx, time.Now().Add(-24*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("expired %d, %v; want 1", n, err)
	}
	pending, _ := s.ListApprovalRequests(ctx, tenant, "pending", 10)
	if len(pending) != 1 || pending[0].SHA256 != "NEW" {
		t.Errorf("pending after expiry = %+v", pending)
	}
	expired, _ := s.ListApprovalRequests(ctx, tenant, "expired", 10)
	if len(expired) != 1 || expired[0].SHA256 != "OLD" {
		t.Errorf("expired list = %+v", expired)
	}
}
