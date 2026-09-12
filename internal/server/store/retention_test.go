package store_test

import (
	"context"
	"testing"
	"time"

	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"
)

func TestRetention(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	dev := seedDevice(t, s, tenant)
	old := time.Now().Add(-48 * time.Hour)
	recent := time.Now().Add(-1 * time.Hour)

	// Two metric samples: one old, one recent.
	s.RecordMetrics(ctx, tenant, dev, store.MetricSample{CPUPct: 1}, old)
	s.RecordMetrics(ctx, tenant, dev, store.MetricSample{CPUPct: 2}, recent)
	// Two block events.
	s.RecordBlockEvents(ctx, tenant, dev, []store.BlockEvent{
		{SHA256: "OLD", Path: `C:\o.exe`, At: old},
		{SHA256: "NEW", Path: `C:\n.exe`, At: recent},
	})
	// A resolved alert (old) and an open alert.
	rid, _ := s.CreateAlertRule(ctx, tenant, store.AlertRule{Name: "r", Metric: "cpu", Op: "gt", Threshold: 90, Enabled: true})
	s.RaiseAlert(ctx, tenant, dev, rid, "cpu", "old", old)
	s.ResolveAlert(ctx, tenant, dev, rid, old.Add(time.Minute))
	rid2, _ := s.CreateAlertRule(ctx, tenant, store.AlertRule{Name: "r2", Metric: "mem", Op: "gt", Threshold: 90, Enabled: true})
	s.RaiseAlert(ctx, tenant, dev, rid2, "mem", "open", recent)

	cutoff := time.Now().Add(-24 * time.Hour)
	n, err := s.Retention(ctx, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 { // 1 metric + 1 block + 1 resolved alert
		t.Fatalf("pruned %d rows, want 3", n)
	}

	if m, _ := s.ListMetrics(ctx, tenant, dev, time.Now().Add(-72*time.Hour), 10); len(m) != 1 || m[0].CPUPct != 2 {
		t.Errorf("metrics after prune = %+v", m)
	}
	if be, _ := s.ListBlockEvents(ctx, tenant, 10); len(be) != 1 || be[0].SHA256 != "NEW" {
		t.Errorf("block events after prune = %+v", be)
	}
	// The open alert survives; the resolved one is gone.
	if al, _ := s.ListAlerts(ctx, tenant, 10); len(al) != 1 || al[0].ResolvedAt != nil {
		t.Errorf("alerts after prune = %+v", al)
	}
}
