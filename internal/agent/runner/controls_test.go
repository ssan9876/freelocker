package runner_test

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"

	"freelocker/internal/agent/agentpaths"
	"freelocker/internal/agent/controls"
	"freelocker/internal/agent/executor"
	"freelocker/internal/agent/identity"
	"freelocker/internal/agent/inventory"
	"freelocker/internal/agent/runner"
	"freelocker/internal/agent/secret"
	"freelocker/internal/server/app"
	"freelocker/internal/server/config"
	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"
	"freelocker/internal/server/tokens"
)

func TestControlsSyncedToAgent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cfg := config.Config{AgentListen: "127.0.0.1:0", PublicHostnames: []string{"127.0.0.1"}, InsecureCookies: true}
	a, err := app.NewWithStore(cfg, storetest.New(t), bytes.Repeat([]byte{12}, 32), slog.Default())
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

	gid, _ := a.Store().CreateDeviceGroup(ctx, tenant, "WS")
	a.Store().SetControls(ctx, tenant, gid, store.DeviceControls{USBStorageBlocked: true})
	full, hash, _ := tokens.Generate(keys.CA.Pin())
	a.Store().CreateInstallToken(ctx, tenant, store.InstallToken{Name: "t", GroupID: &gid}, hash)

	dir := t.TempDir()
	st := &identity.Store{Paths: agentpaths.Paths{InstallDir: dir, DataDir: dir}, Protector: secret.Default()}
	inv := inventory.New()
	enf := &controls.NoopEnforcer{}
	r := &runner.Runner{
		ServerURL: a.AgentAddr(), Identity: st, Inventory: inv,
		Executor:           &executor.Executor{Actions: noopActions{}},
		HeartbeatInterval:  150 * time.Millisecond,
		AppControlInterval: 150 * time.Millisecond,
		Controls:           enf,
	}
	if err := r.EnsureEnrolled(ctx, full, runner.HardwareInfo(inv)); err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go r.Run(runCtx)

	eventually(t, "USB block applied", func() bool { return enf.Last().USBStorageBlocked })
}
