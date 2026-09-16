package runner_test

import (
	"bytes"
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"freelocker/internal/agent/agentpaths"
	"freelocker/internal/agent/executor"
	"freelocker/internal/agent/identity"
	"freelocker/internal/agent/inventory"
	"freelocker/internal/agent/ringfence"
	"freelocker/internal/agent/runner"
	"freelocker/internal/agent/secret"
	"freelocker/internal/server/app"
	"freelocker/internal/server/config"
	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"
	"freelocker/internal/server/tokens"
)

// fakeRingfenceEnforcer records what Apply received and lets the test hand it
// canned violations to report back. It does not dedupe on its own: the
// runner is responsible for not calling Apply twice with the same version.
type fakeRingfenceEnforcer struct {
	mu           sync.Mutex
	applyCount   int
	applied      ringfence.Ringfence
	violations   []ringfence.Violation
	sent         bool
	asrAvailable bool
}

func (f *fakeRingfenceEnforcer) Apply(_ context.Context, r ringfence.Ringfence) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applyCount++
	f.applied = r
	return nil
}

func (f *fakeRingfenceEnforcer) Violations(context.Context) ([]ringfence.Violation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sent {
		return nil, nil
	}
	f.sent = true
	return f.violations, nil
}

func (f *fakeRingfenceEnforcer) Status() ringfence.Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return ringfence.Status{Applied: f.applied.Version, ASRAvailable: f.asrAvailable}
}

func (f *fakeRingfenceEnforcer) applyCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applyCount
}

func (f *fakeRingfenceEnforcer) lastApplied() ringfence.Ringfence {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applied
}

// TestRunnerAppliesRingfenceAndReportsViolations starts the runner against a
// real (in-process) server that has a ringfence assigned to the enrolled
// device's group, and asserts: the fake enforcer received what the server
// sent, violations it reports are stored server-side, and a second cycle
// with the same version does not re-apply.
func TestRunnerAppliesRingfenceAndReportsViolations(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cfg := config.Config{AgentListen: "127.0.0.1:0", PublicHostnames: []string{"127.0.0.1"}, InsecureCookies: true}
	a, err := app.NewWithStore(cfg, storetest.New(t), bytes.Repeat([]byte{13}, 32), slog.Default())
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

	gid, err := a.Store().CreateDeviceGroup(ctx, tenant, "WS")
	if err != nil {
		t.Fatal(err)
	}
	rfID := uuid.New()
	if err := a.Store().CreateRingfence(ctx, tenant, store.Ringfence{ID: rfID, Name: "rf1", Mode: "enforce"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Store().AddRingfenceProgram(ctx, tenant, rfID, store.RingfenceProgram{
		ID: uuid.New(), Path: `C:\a.exe`, NetworkBlocked: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.Store().AssignRingfence(ctx, tenant, gid, rfID); err != nil {
		t.Fatal(err)
	}

	full, hash, _ := tokens.Generate(keys.CA.Pin())
	a.Store().CreateInstallToken(ctx, tenant, store.InstallToken{Name: "t", GroupID: &gid}, hash)

	dir := t.TempDir()
	st := &identity.Store{Paths: agentpaths.Paths{InstallDir: dir, DataDir: dir}, Protector: secret.Default()}
	inv := inventory.New()
	enf := &fakeRingfenceEnforcer{
		violations: []ringfence.Violation{{Kind: "network", Program: `C:\a.exe`, Detail: "1.2.3.4:443", Enforced: true, At: time.Now()}},
	}
	r := &runner.Runner{
		ServerURL: a.AgentAddr(), Identity: st, Inventory: inv,
		Executor:           &executor.Executor{Actions: noopActions{}},
		HeartbeatInterval:  150 * time.Millisecond,
		AppControlInterval: 100 * time.Millisecond,
		Ringfence:          enf,
	}
	if err := r.EnsureEnrolled(ctx, full, runner.HardwareInfo(inv)); err != nil {
		t.Fatal(err)
	}
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	go r.Run(runCtx)

	eventually(t, "ringfence applied", func() bool {
		applied := enf.lastApplied()
		return applied.Version != "" && applied.Mode == "enforce" && len(applied.Programs) == 1 &&
			applied.Programs[0].Path == `C:\a.exe` && applied.Programs[0].NetworkBlocked
	})

	eventually(t, "violation reported to store", func() bool {
		evs, err := a.Store().ListRingfenceEvents(ctx, tenant, 10, nil)
		if err != nil {
			return false
		}
		for _, e := range evs {
			if e.Kind == "network" && e.Program == `C:\a.exe` && e.Detail == "1.2.3.4:443" && e.Enforced {
				return true
			}
		}
		return false
	})

	// Give a couple more ticks to happen, then confirm Apply was only called
	// once: the runner must not re-apply an unchanged version.
	time.Sleep(400 * time.Millisecond)
	if calls := enf.applyCalls(); calls != 1 {
		t.Fatalf("Apply called %d times; want 1 (idempotent on unchanged version)", calls)
	}
}

// TestRunnerReportsASRAvailabilityWithoutViolations asserts the defect this
// task closes: ASR (Defender) availability must reach the server even on
// ticks with zero violations, which is the common case. A control that
// silently does nothing must not look identical, server-side, to one the
// agent never reported on at all.
func TestRunnerReportsASRAvailabilityWithoutViolations(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cfg := config.Config{AgentListen: "127.0.0.1:0", PublicHostnames: []string{"127.0.0.1"}, InsecureCookies: true}
	a, err := app.NewWithStore(cfg, storetest.New(t), bytes.Repeat([]byte{14}, 32), slog.Default())
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

	full, hash, _ := tokens.Generate(keys.CA.Pin())
	a.Store().CreateInstallToken(ctx, tenant, store.InstallToken{Name: "t"}, hash)

	dir := t.TempDir()
	st := &identity.Store{Paths: agentpaths.Paths{InstallDir: dir, DataDir: dir}, Protector: secret.Default()}
	inv := inventory.New()
	// No violations at all, and Defender inactive: this is the case Task 13
	// exists for -- the console must be told "not enforced" rather than
	// hearing nothing.
	enf := &fakeRingfenceEnforcer{asrAvailable: false}
	r := &runner.Runner{
		ServerURL: a.AgentAddr(), Identity: st, Inventory: inv,
		Executor:           &executor.Executor{Actions: noopActions{}},
		HeartbeatInterval:  150 * time.Millisecond,
		AppControlInterval: 100 * time.Millisecond,
		Ringfence:          enf,
	}
	if err := r.EnsureEnrolled(ctx, full, runner.HardwareInfo(inv)); err != nil {
		t.Fatal(err)
	}
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	go r.Run(runCtx)

	eventually(t, "device ASRAvailable reported false with no violations", func() bool {
		devs, err := a.Store().ListDevices(ctx, tenant)
		if err != nil || len(devs) != 1 {
			return false
		}
		return devs[0].ASRAvailable != nil && *devs[0].ASRAvailable == false
	})
}
