package runner_test

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/agent/agentpaths"
	"freelocker/internal/agent/executor"
	"freelocker/internal/agent/identity"
	"freelocker/internal/agent/inventory"
	"freelocker/internal/agent/runner"
	"freelocker/internal/agent/secret"
	"freelocker/internal/server/agentapi"
	"freelocker/internal/server/app"
	"freelocker/internal/server/config"
	"freelocker/internal/server/store/storetest"

	"github.com/google/uuid"
)

type noopActions struct{}

func (noopActions) RefreshInventory(context.Context) error           { return nil }
func (noopActions) RotateCertificate(context.Context) error          { return nil }
func (noopActions) Uninstall(context.Context) error                  { return nil }
func (noopActions) UpdateAgent(context.Context, *flv1.Command) error { return nil }

func mustTenant(t *testing.T, a *app.App) uuid.UUID {
	t.Helper()
	id, ok := a.Tenant()
	if !ok {
		t.Fatal("not initialized")
	}
	return id
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(30 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestRunnerEnrollsOnlineCommandAndRevoke(t *testing.T) {
	ctx := context.Background()
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
		HeartbeatInterval: 150 * time.Millisecond,
	}
	if err := r.EnsureEnrolled(ctx, token, runner.HardwareInfo(inv)); err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- r.Run(runCtx) }()

	enr, _ := st.Load()
	devID := uuid.MustParse(enr.DeviceID)
	tenant := mustTenant(t, a)
	eventually(t, "online", func() bool {
		d, _ := a.Store().GetDevice(ctx, tenant, devID)
		return d.Status(time.Now()) == "online"
	})

	a.Store().RevokeDevice(ctx, tenant, devID)
	a.Hub().Disconnect(devID, agentapi.RevokedError())
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("runner should stop with an error after revoke")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runner did not stop after revoke")
	}
	cancel()
}
