package rollout_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"freelocker/internal/server/bootstrap"
	"freelocker/internal/server/commands"
	"freelocker/internal/server/hub"
	"freelocker/internal/server/rollout"
	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"

	"github.com/google/uuid"
)

type fixture struct {
	s      *store.Store
	tenant uuid.UUID
	svc    *rollout.Service
	now    time.Time
	online map[uuid.UUID]bool
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	s := storetest.New(t)
	master := bytes.Repeat([]byte{7}, 32)
	if _, err := bootstrap.Init(ctx, s, master, "Acme", time.Now()); err != nil {
		t.Fatal(err)
	}
	k, err := bootstrap.Load(ctx, s, master)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{s: s, tenant: k.TenantID, now: time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC), online: map[uuid.UUID]bool{}}
	cmds := &commands.Service{Store: s, Keys: k, Hub: hub.New(), Now: func() time.Time { return f.now }}
	f.svc = &rollout.Service{
		Store: s, Commands: cmds,
		Online:         func(id uuid.UUID) bool { return f.online[id] },
		ReleaseURL:     func(v string) string { return "http://test.local/agent/releases/" + v },
		Now:            func() time.Time { return f.now },
		ConfirmTimeout: 10 * time.Minute,
	}
	if err := s.PutRelease(ctx, f.tenant, store.Release{Version: "2.0.0", SHA256: make([]byte, 32), Signature: []byte("sig")}); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) device(t *testing.T, name, version string, online bool) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	id := uuid.New()
	hash := []byte("h-" + id.String())
	if _, err := f.s.CreateInstallToken(ctx, f.tenant, store.InstallToken{Name: name}, hash); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.EnrollDevice(ctx, hash, f.now, func(uuid.UUID) (store.NewDevice, error) {
		return store.NewDevice{ID: id, Hostname: name, CertSerial: "s-" + name, CertExpiresAt: f.now.Add(time.Hour)}, nil
	}); err != nil {
		t.Fatal(err)
	}
	f.s.RecordHeartbeat(ctx, f.tenant, id, store.Inventory{Hostname: name, AgentVersion: version}, f.now)
	f.online[id] = online
	return id
}

func (f *fixture) rollout(t *testing.T, batch, maxFail int) store.Rollout {
	t.Helper()
	r := store.Rollout{ID: uuid.New(), Version: "2.0.0", BatchSize: batch, MaxFailures: maxFail, State: "active", CreatedBy: "admin:t@x"}
	if err := f.s.CreateRollout(context.Background(), f.tenant, r); err != nil {
		t.Fatal(err)
	}
	return r
}

func (f *fixture) tick(t *testing.T) {
	t.Helper()
	if err := f.svc.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) summary(t *testing.T, id uuid.UUID) store.RolloutSummary {
	t.Helper()
	sum, err := f.s.RolloutSummary(context.Background(), f.tenant, id)
	if err != nil {
		t.Fatal(err)
	}
	return sum
}

// commandFor returns the update command issued to a device in a rollout.
func (f *fixture) commandFor(t *testing.T, rid, dev uuid.UUID) store.RolloutDevice {
	t.Helper()
	devs, _ := f.s.ListRolloutDevices(context.Background(), f.tenant, rid)
	for _, d := range devs {
		if d.DeviceID == dev {
			return d
		}
	}
	t.Fatalf("no rollout row for %s", dev)
	return store.RolloutDevice{}
}

func TestBatchCapAndOnlineFilter(t *testing.T) {
	f := newFixture(t)
	for i := 0; i < 5; i++ {
		f.device(t, "on-"+string(rune('a'+i)), "1.0.0", true)
	}
	off := f.device(t, "off", "1.0.0", false)
	r := f.rollout(t, 2, 0)

	f.tick(t)
	sum := f.summary(t, r.ID)
	if sum.Issued != 2 || sum.Remaining != 4 {
		t.Fatalf("after tick 1: %+v", sum)
	}
	// In-flight slots are full: another tick issues nothing.
	f.tick(t)
	if sum = f.summary(t, r.ID); sum.Issued != 2 {
		t.Fatalf("after tick 2: %+v", sum)
	}
	devs, _ := f.s.ListRolloutDevices(context.Background(), f.tenant, r.ID)
	for _, d := range devs {
		if d.DeviceID == off {
			t.Error("offline device must not be issued to")
		}
		// The payload must be a real update payload.
		cmds, _ := f.s.ListDeviceCommands(context.Background(), f.tenant, d.DeviceID, 5)
		if len(cmds) != 1 {
			t.Fatalf("device commands = %d", len(cmds))
		}
		p, err := commands.ParseUpdate(cmds[0].Payload)
		if err != nil || p.Version != "2.0.0" || p.URL != "http://test.local/agent/releases/2.0.0" {
			t.Errorf("payload = %+v, %v", p, err)
		}
	}
}

func TestResolvesAndCompletes(t *testing.T) {
	f := newFixture(t)
	a := f.device(t, "a", "1.0.0", true)
	b := f.device(t, "b", "1.0.0", true)
	f.device(t, "c-current", "2.0.0", true)
	r := f.rollout(t, 10, 0)
	ctx := context.Background()

	f.tick(t)
	// Both report the new version after succeeding.
	for _, d := range []uuid.UUID{a, b} {
		row := f.commandFor(t, r.ID, d)
		f.s.CompleteCommand(ctx, f.tenant, d, row.CommandID, true, "ok", f.now)
		f.s.RecordHeartbeat(ctx, f.tenant, d, store.Inventory{AgentVersion: "2.0.0"}, f.now)
	}
	f.now = f.now.Add(time.Minute)
	f.tick(t)
	got, _ := f.s.GetRollout(ctx, f.tenant, r.ID)
	sum := f.summary(t, r.ID)
	if got.State != "completed" || got.FinishedAt == nil || sum.Updated != 2 || sum.AlreadyCurrent != 1 {
		t.Fatalf("state = %s, summary = %+v", got.State, sum)
	}
}

func TestAutoPauseOnFailures(t *testing.T) {
	f := newFixture(t)
	a := f.device(t, "a", "1.0.0", true)
	b := f.device(t, "b", "1.0.0", true)
	f.device(t, "c", "1.0.0", true)
	r := f.rollout(t, 2, 2)
	ctx := context.Background()

	f.tick(t)
	for _, d := range []uuid.UUID{a, b} {
		row := f.commandFor(t, r.ID, d)
		f.s.CompleteCommand(ctx, f.tenant, d, row.CommandID, false, "hash mismatch", f.now)
	}
	f.tick(t)
	got, _ := f.s.GetRollout(ctx, f.tenant, r.ID)
	sum := f.summary(t, r.ID)
	if got.State != "paused" || sum.Failed != 2 || sum.Issued != 0 || sum.Remaining != 1 {
		t.Fatalf("state = %s, summary = %+v (want paused, 2 failed, c untouched)", got.State, sum)
	}
	// Paused: further ticks issue nothing.
	f.tick(t)
	if sum = f.summary(t, r.ID); sum.Issued != 0 {
		t.Errorf("paused rollout issued a command: %+v", sum)
	}
	// Audit row written by the system.
	entries, _ := f.s.ListAudit(ctx, f.tenant, 50, 0)
	found := false
	for _, e := range entries {
		if e.Action == "rollout.auto_pause" && e.Actor == "system" && e.TargetID == r.ID.String() {
			found = true
		}
	}
	if !found {
		t.Error("expected a rollout.auto_pause audit entry")
	}
}

func TestConfirmTimeoutFailsSilentRollback(t *testing.T) {
	f := newFixture(t)
	a := f.device(t, "a", "1.0.0", true)
	r := f.rollout(t, 10, 0)
	ctx := context.Background()

	f.tick(t)
	row := f.commandFor(t, r.ID, a)
	f.s.CompleteCommand(ctx, f.tenant, a, row.CommandID, true, "ok", f.now) // swap helper launched
	f.now = f.now.Add(5 * time.Minute)
	f.tick(t)
	if sum := f.summary(t, r.ID); sum.Issued != 1 {
		t.Fatalf("before timeout: %+v", sum)
	}
	f.now = f.now.Add(6 * time.Minute) // 11 min after completion, still 1.0.0
	f.tick(t)
	sum := f.summary(t, r.ID)
	got, _ := f.s.GetRollout(ctx, f.tenant, r.ID)
	if sum.Failed != 1 || got.State != "completed" {
		t.Fatalf("after timeout: summary %+v state %s", sum, got.State)
	}
}

func TestOfflineDevicesKeepRolloutActive(t *testing.T) {
	f := newFixture(t)
	f.device(t, "off", "1.0.0", false)
	r := f.rollout(t, 10, 0)
	f.tick(t)
	got, _ := f.s.GetRollout(context.Background(), f.tenant, r.ID)
	if got.State != "active" {
		t.Fatalf("state = %s, want active while an offline device remains", got.State)
	}
}

// A device revoked mid-rollout keeps its progress row, but must not make the
// reconciler believe every targeted device is done.
func TestRevokedDeviceDoesNotCompleteRollout(t *testing.T) {
	f := newFixture(t)
	a := f.device(t, "a", "1.0.0", true)
	f.device(t, "b-offline", "1.0.0", false)
	r := f.rollout(t, 10, 0)
	ctx := context.Background()

	f.tick(t)
	row := f.commandFor(t, r.ID, a)
	f.s.CompleteCommand(ctx, f.tenant, a, row.CommandID, true, "ok", f.now)
	f.s.RecordHeartbeat(ctx, f.tenant, a, store.Inventory{AgentVersion: "2.0.0"}, f.now)
	if err := f.s.RevokeDevice(ctx, f.tenant, a); err != nil {
		t.Fatal(err)
	}

	f.now = f.now.Add(time.Minute)
	f.tick(t)
	got, _ := f.s.GetRollout(ctx, f.tenant, r.ID)
	sum := f.summary(t, r.ID)
	if got.State != "active" || sum.Remaining != 1 {
		t.Fatalf("state = %s, summary = %+v (want active, b still remaining)", got.State, sum)
	}
}

// After an operator resumes an auto-paused rollout the next tick must carry
// on rather than immediately re-pause on the same cumulative failure count.
func TestResumeAfterAutoPauseContinues(t *testing.T) {
	f := newFixture(t)
	a := f.device(t, "a", "1.0.0", true)
	b := f.device(t, "b", "1.0.0", true)
	c := f.device(t, "c", "1.0.0", true)
	r := f.rollout(t, 2, 2)
	ctx := context.Background()

	f.tick(t)
	for _, d := range []uuid.UUID{a, b} {
		row := f.commandFor(t, r.ID, d)
		f.s.CompleteCommand(ctx, f.tenant, d, row.CommandID, false, "hash mismatch", f.now)
	}
	f.tick(t)
	if got, _ := f.s.GetRollout(ctx, f.tenant, r.ID); got.State != "paused" {
		t.Fatalf("state = %s, want paused", got.State)
	}

	// Operator resumes; the next tick must keep going and issue to c.
	f.now = f.now.Add(time.Minute)
	if err := f.s.SetRolloutState(ctx, f.tenant, r.ID, []string{"paused"}, "active", f.now); err != nil {
		t.Fatal(err)
	}
	f.tick(t)
	got, _ := f.s.GetRollout(ctx, f.tenant, r.ID)
	sum := f.summary(t, r.ID)
	if got.State != "active" || sum.Issued != 1 || sum.Remaining != 0 {
		t.Fatalf("after resume: state = %s, summary = %+v (want active with c issued)", got.State, sum)
	}
	if f.commandFor(t, r.ID, c).State != "issued" {
		t.Error("c should have been issued to after the resume")
	}
	// Resuming must not write a second auto-pause audit row.
	entries, _ := f.s.ListAudit(ctx, f.tenant, 50, 0)
	n := 0
	for _, e := range entries {
		if e.Action == "rollout.auto_pause" && e.TargetID == r.ID.String() {
			n++
		}
	}
	if n != 1 {
		t.Errorf("rollout.auto_pause audit rows = %d, want 1", n)
	}
}
