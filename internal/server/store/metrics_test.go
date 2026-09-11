package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"
)

func TestMetricsRecordAndList(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	dev := seedDevice(t, s, tenant)

	now := time.Now()
	for i := 0; i < 3; i++ {
		if err := s.RecordMetrics(ctx, tenant, dev, store.MetricSample{CPUPct: float64(10 * i), MemPct: 50, DiskPct: 60}, now.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	list, err := s.ListMetrics(ctx, tenant, dev, now.Add(-time.Hour), 10)
	if err != nil || len(list) != 3 || list[0].CPUPct != 20 {
		t.Fatalf("metrics = %+v, %v (newest first)", list, err)
	}
}

func TestAlertRulesAndRaiseResolve(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	dev := seedDevice(t, s, tenant)

	rid, err := s.CreateAlertRule(ctx, tenant, store.AlertRule{Name: "High CPU", Metric: "cpu", Op: "gt", Threshold: 90, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	rules, _ := s.ListEnabledAlertRules(ctx, tenant)
	if len(rules) != 1 || rules[0].ID != rid {
		t.Fatalf("enabled rules = %+v", rules)
	}

	now := time.Now()
	created, err := s.RaiseAlert(ctx, tenant, dev, rid, "cpu", "CPU 95% > 90%", now)
	if err != nil || !created {
		t.Fatalf("first raise created=%v err=%v", created, err)
	}
	// Second raise must not create a duplicate open alert.
	created, _ = s.RaiseAlert(ctx, tenant, dev, rid, "cpu", "again", now)
	if created {
		t.Error("duplicate open alert created")
	}
	if _, err := s.OpenAlertFor(ctx, tenant, dev, rid); err != nil {
		t.Fatalf("open alert missing: %v", err)
	}

	if err := s.ResolveAlert(ctx, tenant, dev, rid, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.OpenAlertFor(ctx, tenant, dev, rid); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("alert should be resolved: %v", err)
	}
	// After resolve, a new breach can raise again.
	created, _ = s.RaiseAlert(ctx, tenant, dev, rid, "cpu", "again", now.Add(2*time.Minute))
	if !created {
		t.Error("should raise a fresh alert after resolve")
	}
	list, _ := s.ListAlerts(ctx, tenant, 10)
	if len(list) != 2 {
		t.Fatalf("alerts history = %d, want 2", len(list))
	}
}
