package store_test

import (
	"context"
	"testing"
	"time"

	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"

	"github.com/google/uuid"
)

func TestLoginFailures(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	now := time.Now()

	for i := 0; i < 3; i++ {
		if err := s.RecordLoginFailure(ctx, tenant, "1.2.3.4|a@x.com", now.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	// Old failure outside the window shouldn't count.
	s.RecordLoginFailure(ctx, tenant, "1.2.3.4|a@x.com", now.Add(-time.Hour))

	n, err := s.CountLoginFailures(ctx, tenant, "1.2.3.4|a@x.com", now.Add(-time.Minute))
	if err != nil || n != 3 {
		t.Fatalf("count = %d, %v; want 3", n, err)
	}
	if n, _ := s.CountLoginFailures(ctx, tenant, "other", now.Add(-time.Minute)); n != 0 {
		t.Errorf("other key count = %d", n)
	}
	if err := s.ClearLoginFailures(ctx, tenant, "1.2.3.4|a@x.com"); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.CountLoginFailures(ctx, tenant, "1.2.3.4|a@x.com", now.Add(-time.Hour*2)); n != 0 {
		t.Errorf("after clear count = %d", n)
	}
	if pruned, err := s.PruneLoginFailures(ctx, now); err != nil || pruned < 0 {
		t.Errorf("prune = %d, %v", pruned, err)
	}
}

func TestAlertBreaches(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	dev := seedDevice(t, s, tenant)
	rid, _ := s.CreateAlertRule(ctx, tenant, store.AlertRule{Name: "r", Metric: "cpu", Op: "gt", Threshold: 90, Enabled: true})

	t0 := time.Now().Truncate(time.Microsecond) // Postgres timestamptz precision
	since, err := s.MarkBreach(ctx, tenant, dev, rid, t0)
	if err != nil || !since.Equal(t0) {
		t.Fatalf("first MarkBreach since = %v (want %v), err %v", since, t0, err)
	}
	// A later mark keeps the original onset.
	since2, _ := s.MarkBreach(ctx, tenant, dev, rid, t0.Add(5*time.Minute))
	if !since2.Equal(t0) {
		t.Errorf("onset should be stable: %v vs %v", since2, t0)
	}
	// Clear, then a new mark starts fresh.
	if err := s.ClearBreach(ctx, tenant, dev, rid); err != nil {
		t.Fatal(err)
	}
	since3, _ := s.MarkBreach(ctx, tenant, dev, rid, t0.Add(10*time.Minute))
	if !since3.Equal(t0.Add(10 * time.Minute)) {
		t.Errorf("after clear onset = %v, want fresh", since3)
	}
	_ = uuid.Nil
}
