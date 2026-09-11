package alerting_test

import (
	"context"
	"testing"
	"time"

	"freelocker/internal/server/alerting"
	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"

	"github.com/google/uuid"
)

func seedDevice(t *testing.T, s *store.Store, tenant uuid.UUID) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	h := []byte("h-" + uuid.NewString())
	s.CreateInstallToken(ctx, tenant, store.InstallToken{Name: "t"}, h)
	dev := uuid.New()
	s.EnrollDevice(ctx, h, time.Now(), func(uuid.UUID) (store.NewDevice, error) {
		return store.NewDevice{ID: dev, Hostname: "pc", CertSerial: "s", CertExpiresAt: time.Now().Add(time.Hour)}, nil
	})
	return dev
}

func TestImmediateRaiseAndResolve(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	dev := seedDevice(t, s, tenant)
	rid, _ := s.CreateAlertRule(ctx, tenant, store.AlertRule{Name: "High CPU", Metric: "cpu", Op: "gt", Threshold: 90, Enabled: true})
	svc := alerting.New(s)
	now := time.Now()

	// Breach → alert raised.
	if err := svc.Evaluate(ctx, tenant, dev, store.MetricSample{CPUPct: 95}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.OpenAlertFor(ctx, tenant, dev, rid); err != nil {
		t.Fatalf("expected open alert: %v", err)
	}
	// Clear → alert resolved.
	if err := svc.Evaluate(ctx, tenant, dev, store.MetricSample{CPUPct: 10}, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.OpenAlertFor(ctx, tenant, dev, rid); err == nil {
		t.Error("alert should have resolved when the breach cleared")
	}
}

func TestSustainedDurationRequiresTime(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	dev := seedDevice(t, s, tenant)
	rid, _ := s.CreateAlertRule(ctx, tenant, store.AlertRule{Name: "Sustained disk", Metric: "disk", Op: "gt", Threshold: 80, DurationSeconds: 300, Enabled: true})
	svc := alerting.New(s)
	t0 := time.Now()

	// First breach: onset recorded, no alert yet.
	svc.Evaluate(ctx, tenant, dev, store.MetricSample{DiskPct: 90}, t0)
	if _, err := s.OpenAlertFor(ctx, tenant, dev, rid); err == nil {
		t.Fatal("alert raised before duration elapsed")
	}
	// Still breaching but not long enough.
	svc.Evaluate(ctx, tenant, dev, store.MetricSample{DiskPct: 91}, t0.Add(2*time.Minute))
	if _, err := s.OpenAlertFor(ctx, tenant, dev, rid); err == nil {
		t.Fatal("alert raised too early")
	}
	// Now sustained past 5 minutes → raise.
	svc.Evaluate(ctx, tenant, dev, store.MetricSample{DiskPct: 92}, t0.Add(6*time.Minute))
	if _, err := s.OpenAlertFor(ctx, tenant, dev, rid); err != nil {
		t.Fatalf("expected alert after sustained breach: %v", err)
	}
	// lt rule that is not breaching does nothing.
	other, _ := s.CreateAlertRule(ctx, tenant, store.AlertRule{Name: "Low disk?", Metric: "disk", Op: "lt", Threshold: 5, Enabled: true})
	svc.Evaluate(ctx, tenant, dev, store.MetricSample{DiskPct: 92}, t0.Add(7*time.Minute))
	if _, err := s.OpenAlertFor(ctx, tenant, dev, other); err == nil {
		t.Error("lt rule should not fire when value is above threshold")
	}
}
