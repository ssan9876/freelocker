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
	"freelocker/internal/agent/runner"
	"freelocker/internal/agent/secret"
	"freelocker/internal/server/app"
	"freelocker/internal/server/config"
	"freelocker/internal/server/store/storetest"

	"github.com/google/uuid"
)

// TestRequestHeartbeatSendsImmediately proves an on-demand heartbeat reaches
// the server without waiting for the (here, hour-long) heartbeat interval.
func TestRequestHeartbeatSendsImmediately(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cfg := config.Config{AgentListen: "127.0.0.1:0", PublicHostnames: []string{"127.0.0.1"}, InsecureCookies: true}
	a, err := app.NewWithStore(cfg, storetest.New(t), bytes.Repeat([]byte{7}, 32), slog.Default())
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
	token, err := a.TokenForTests(ctx)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	st := &identity.Store{Paths: agentpaths.Paths{InstallDir: dir, DataDir: dir}, Protector: secret.Default()}
	inv := inventory.New()
	r := &runner.Runner{
		ServerURL: a.AgentAddr(), Identity: st, Inventory: inv,
		Executor:          &executor.Executor{Actions: noopActions{}},
		HeartbeatInterval: time.Hour,
	}
	if err := r.EnsureEnrolled(ctx, token, runner.HardwareInfo(inv)); err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go r.Run(runCtx)

	enr, _ := st.Load()
	devID := uuid.MustParse(enr.DeviceID)
	tenant := mustTenant(t, a)
	var first time.Time
	eventually(t, "initial heartbeat", func() bool {
		d, _ := a.Store().GetDevice(ctx, tenant, devID)
		if d.LastSeenAt == nil {
			return false
		}
		first = *d.LastSeenAt
		return true
	})

	time.Sleep(20 * time.Millisecond)
	r.RequestHeartbeat()
	r.RequestHeartbeat() // coalesced; must not block
	eventually(t, "on-demand heartbeat", func() bool {
		d, _ := a.Store().GetDevice(ctx, tenant, devID)
		return d.LastSeenAt != nil && d.LastSeenAt.After(first)
	})
}
