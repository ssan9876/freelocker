package runner_test

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"

	"freelocker/internal/agent/agentpaths"
	"freelocker/internal/agent/blocks"
	"freelocker/internal/agent/enforcer"
	"freelocker/internal/agent/executor"
	"freelocker/internal/agent/identity"
	"freelocker/internal/agent/inventory"
	"freelocker/internal/agent/runner"
	"freelocker/internal/agent/scan"
	"freelocker/internal/agent/secret"
	"freelocker/internal/server/app"
	"freelocker/internal/server/config"
	"freelocker/internal/server/policysvc"
	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"
	"freelocker/internal/server/tokens"

	"github.com/google/uuid"
)

// recordingEnforcer captures applied policy and emits one block event once.
type recordingEnforcer struct {
	status  enforcer.Status
	emitted bool
}

func (e *recordingEnforcer) Apply(_ context.Context, version, mode string, _ []byte) error {
	e.status = enforcer.Status{AppliedVersion: version, AppliedMode: mode}
	return nil
}
func (e *recordingEnforcer) Events(context.Context) ([]blocks.BlockEvent, error) {
	if e.emitted {
		return nil, nil
	}
	e.emitted = true
	return []blocks.BlockEvent{{SHA256: "DEAD", Path: `C:\blocked.exe`, Blocked: false, At: time.Now()}}, nil
}
func (e *recordingEnforcer) Status() enforcer.Status { return e.status }

func TestAppControlSyncObserveAndBlocks(t *testing.T) {
	ctx := context.Background()
	cfg := config.Config{AgentListen: "127.0.0.1:0", PublicHostnames: []string{"127.0.0.1"}, InsecureCookies: true}
	a, err := app.NewWithStore(cfg, storetest.New(t), bytes.Repeat([]byte{9}, 32), slog.Default())
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
	pid, _ := a.Store().CreatePolicy(ctx, tenant, "Baseline", "audit")
	svc := &policysvc.Service{Store: a.Store(), Keys: keys}
	version, err := svc.Recompile(ctx, tenant, pid)
	if err != nil {
		t.Fatal(err)
	}
	a.Store().AssignPolicy(ctx, tenant, gid, pid)

	full, hash, _ := tokens.Generate(keys.CA.Pin())
	a.Store().CreateInstallToken(ctx, tenant, store.InstallToken{Name: "ws", GroupID: &gid}, hash)

	dir := t.TempDir()
	st := &identity.Store{Paths: agentpaths.Paths{InstallDir: dir, DataDir: dir}, Protector: secret.Default()}
	inv := inventory.New()
	enf := &recordingEnforcer{}
	r := &runner.Runner{
		ServerURL: a.AgentAddr(), Identity: st, Inventory: inv,
		Executor:           &executor.Executor{Actions: noopActions{}},
		HeartbeatInterval:  150 * time.Millisecond,
		Enforcer:           enf,
		AppControlInterval: 150 * time.Millisecond,
		Scan:               func() ([]scan.Observed, error) { return []scan.Observed{{SHA256: "FEED", Path: `C:\seen.exe`}}, nil },
	}
	if err := r.EnsureEnrolled(ctx, full, runner.HardwareInfo(inv)); err != nil {
		t.Fatal(err)
	}
	enr, _ := st.Load()
	devID := uuid.MustParse(enr.DeviceID)
	r.UpdatePub = enr.UpdatePub // the agent learned the update key at enrollment

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go r.Run(runCtx)

	eventually(t, "policy applied", func() bool { return enf.Status().AppliedVersion == version })
	eventually(t, "observation recorded", func() bool {
		obs, _ := a.Store().ListObservations(ctx, tenant, devID, 10)
		for _, o := range obs {
			if o.SHA256 == "FEED" {
				return true
			}
		}
		return false
	})
	eventually(t, "block event recorded", func() bool {
		be, _ := a.Store().ListBlockEvents(ctx, tenant, 10)
		return len(be) >= 1 && be[0].SHA256 == "DEAD"
	})
	eventually(t, "policy version on device", func() bool {
		d, _ := a.Store().GetDevice(ctx, tenant, devID)
		return d.Status(time.Now()) == "online"
	})
}
