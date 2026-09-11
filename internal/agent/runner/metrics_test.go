package runner_test

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"

	"freelocker/internal/agent/agentpaths"
	"freelocker/internal/agent/executor"
	"freelocker/internal/agent/identity"
	"freelocker/internal/agent/inventory"
	"freelocker/internal/agent/metrics"
	"freelocker/internal/agent/runner"
	"freelocker/internal/agent/secret"
	"freelocker/internal/server/app"
	"freelocker/internal/server/config"
	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"
	"freelocker/internal/server/tokens"

	"github.com/google/uuid"
)

func TestMetricsReportedAndAlertRaised(t *testing.T) {
	ctx := context.Background()
	cfg := config.Config{AgentListen: "127.0.0.1:0", PublicHostnames: []string{"127.0.0.1"}, InsecureCookies: true}
	a, err := app.NewWithStore(cfg, storetest.New(t), bytes.Repeat([]byte{11}, 32), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	if _, err := a.Initialize(ctx, "Acme", "o@example.com", "owner-password-123"); err != nil {
		t.Fatal(err)
	}
	if err := a.ActivateForTests(ctx); err != nil {
		t.Fatal(err)
	}
	keys := a.KeysForTest()
	tenant := keys.TenantID

	// A rule that fires immediately when CPU > 80%.
	rid, _ := a.Store().CreateAlertRule(ctx, tenant, store.AlertRule{Name: "High CPU", Metric: "cpu", Op: "gt", Threshold: 80, Enabled: true})

	full, hash, _ := tokens.Generate(keys.CA.Pin())
	a.Store().CreateInstallToken(ctx, tenant, store.InstallToken{Name: "t"}, hash)

	dir := t.TempDir()
	st := &identity.Store{Paths: agentpaths.Paths{InstallDir: dir, DataDir: dir}, Protector: secret.Default()}
	inv := inventory.New()
	r := &runner.Runner{
		ServerURL: a.AgentAddr(), Identity: st, Inventory: inv,
		Executor:          &executor.Executor{Actions: noopActions{}},
		HeartbeatInterval: 150 * time.Millisecond,
		MetricsInterval:   120 * time.Millisecond,
		Metrics:           func() (metrics.Sample, error) { return metrics.Sample{CPUPct: 95, MemPct: 40, DiskPct: 50}, nil },
	}
	if err := r.EnsureEnrolled(ctx, full, runner.HardwareInfo(inv)); err != nil {
		t.Fatal(err)
	}
	enr, _ := st.Load()
	devID := uuid.MustParse(enr.DeviceID)

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go r.Run(runCtx)

	eventually(t, "metrics stored", func() bool {
		m, _ := a.Store().ListMetrics(ctx, tenant, devID, time.Now().Add(-time.Hour), 10)
		return len(m) >= 1 && m[0].CPUPct == 95
	})
	eventually(t, "alert raised", func() bool {
		_, err := a.Store().OpenAlertFor(ctx, tenant, devID, rid)
		return err == nil
	})
}
