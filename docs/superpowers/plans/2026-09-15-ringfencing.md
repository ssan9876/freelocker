# Ringfencing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Constrain what an allowed application may do — per-application outbound network containment and Defender ASR child-process containment — assigned per device group, defaulting to audit.

**Architecture:** A ringfence is its own object assigned to a group (mirroring `policy_assignments`), holding per-program network entries and per-GUID ASR protections. It reaches the agent over a new `GetRingfence` RPC so ringfence mode stays independent of WDAC mode; violations return via `ReportRingfenceEvents` into their own table. The Windows enforcer uses `netsh` program-scoped firewall rules and ASR machine-policy registry values; everything off-Windows is a `NoopEnforcer`.

**Tech Stack:** Go, Postgres (goose migrations), gRPC/protobuf (buf), React+TS console, Playwright.

**Spec:** `docs/superpowers/specs/2026-09-15-ringfencing-design.md`

## Global Constraints

- **TDD throughout:** failing test → run it and watch it fail → minimal implementation → run it and watch it pass → commit. One feature per commit.
- **Conventional commits** (`feat(scope): …`), ending with the trailer:
  `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`
- **Every table has `tenant_id`; every store method takes `tenantID` first after `ctx`.**
- **Windows-only code** uses `//go:build windows` with a `!windows` sibling so `go build`, `go vet` and tests pass on any OS. Verify with `GOOS=linux go build ./...`.
- **Mode defaults to `audit`** at the schema level. Enforce is always an explicit opt-in.
- **Enforcement is never verified on the dev box** — only on a disposable VM.
- Dev Postgres: `docker compose -f deploy/docker-compose.dev.yml up -d` (port 55432). Store tests use `storetest.New`.
- Proto regeneration: `buf generate` (needs `$(go env GOPATH)/bin` on PATH).
- Console build: `npm --prefix web run build`. The console is embedded at compile time, so a UI change needs a rebuild **and** a server restart.
- `-race` is unavailable on the dev box (no cgo).
- **API verb style follows the repo, not the spec prose:** `POST /api/ringfences/{id}/mode` and `POST /api/ringfences/{id}/assign`, matching `policies`.

---

### Task 1: Schema and ringfence CRUD

**Files:**
- Create: `internal/server/store/migrations/0020_ringfencing.sql`
- Create: `internal/server/store/ringfence.go`
- Test: `internal/server/store/ringfence_test.go`

**Interfaces:**
- Consumes: `storetest.New`, `ErrNotFound`, `ErrConflict`, `conflict()`, `oneRow()` from the existing store package.
- Produces: `store.Ringfence{ID, Name, Mode, CreatedAt}`, `CreateRingfence(ctx, tenantID, Ringfence) error`, `GetRingfence(ctx, tenantID, id) (Ringfence, error)`, `ListRingfences(ctx, tenantID) ([]Ringfence, error)`, `SetRingfenceMode(ctx, tenantID, id, mode string) error`, `RenameRingfence(ctx, tenantID, id, name string) error`, `DeleteRingfence(ctx, tenantID, id) error`.

- [ ] **Step 1: Write the migration**

```sql
-- +goose Up
CREATE TABLE ringfence_policies (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    name text NOT NULL,
    mode text NOT NULL DEFAULT 'audit' CHECK (mode IN ('audit', 'enforce')),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE TABLE ringfence_programs (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    ringfence_id uuid NOT NULL REFERENCES ringfence_policies(id) ON DELETE CASCADE,
    path text NOT NULL,
    network_blocked boolean NOT NULL DEFAULT true,
    note text NOT NULL DEFAULT '',
    UNIQUE (ringfence_id, path)
);

CREATE TABLE ringfence_protections (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    ringfence_id uuid NOT NULL REFERENCES ringfence_policies(id) ON DELETE CASCADE,
    asr_rule text NOT NULL,
    action text NOT NULL CHECK (action IN ('audit', 'block')),
    PRIMARY KEY (ringfence_id, asr_rule)
);

CREATE TABLE ringfence_assignments (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    group_id uuid PRIMARY KEY REFERENCES device_groups(id) ON DELETE CASCADE,
    ringfence_id uuid NOT NULL REFERENCES ringfence_policies(id) ON DELETE CASCADE
);

CREATE TABLE ringfence_events (
    id bigserial PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('network', 'child_process')),
    program text NOT NULL DEFAULT '',
    detail text NOT NULL DEFAULT '',
    enforced boolean NOT NULL DEFAULT false,
    at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ringfence_events_tenant_at ON ringfence_events (tenant_id, at DESC);

-- +goose Down
DROP TABLE ringfence_events, ringfence_assignments, ringfence_protections, ringfence_programs, ringfence_policies;
```

Note `action` has no `'off'`: turning a protection off deletes the row, so an absent row is unambiguously "off" and there is only one representation of that state.

- [ ] **Step 2: Write the failing test**

```go
package store_test

import (
	"context"
	"errors"
	"testing"

	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"

	"github.com/google/uuid"
)

func TestRingfenceCRUD(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")

	rf := store.Ringfence{ID: uuid.New(), Name: "Office", Mode: "audit"}
	if err := s.CreateRingfence(ctx, tenant, rf); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetRingfence(ctx, tenant, rf.ID)
	if err != nil || got.Name != "Office" || got.Mode != "audit" {
		t.Fatalf("get = %+v, %v", got, err)
	}

	// A duplicate name in the same tenant is a conflict.
	if err := s.CreateRingfence(ctx, tenant, store.Ringfence{ID: uuid.New(), Name: "Office", Mode: "audit"}); !errors.Is(err, store.ErrConflict) {
		t.Errorf("duplicate name err = %v, want ErrConflict", err)
	}

	if err := s.RenameRingfence(ctx, tenant, rf.ID, "Office apps"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRingfenceMode(ctx, tenant, rf.ID, "enforce"); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetRingfence(ctx, tenant, rf.ID)
	if got.Name != "Office apps" || got.Mode != "enforce" {
		t.Errorf("after update = %+v", got)
	}

	list, err := s.ListRingfences(ctx, tenant)
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %+v, %v", list, err)
	}

	// Another tenant cannot see or touch it.
	other, _ := s.CreateTenant(ctx, "Beta")
	if _, err := s.GetRingfence(ctx, other, rf.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("cross-tenant get err = %v", err)
	}
	if err := s.DeleteRingfence(ctx, other, rf.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("cross-tenant delete err = %v", err)
	}

	if err := s.DeleteRingfence(ctx, tenant, rf.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetRingfence(ctx, tenant, rf.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("after delete err = %v", err)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/server/store/ -run TestRingfenceCRUD -v`
Expected: FAIL — build error, `s.CreateRingfence undefined`.

- [ ] **Step 4: Write the implementation**

```go
package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Ringfence constrains what an allowed application may do. It is assigned to
// a device group independently of that group's app-control policy.
type Ringfence struct {
	ID        uuid.UUID
	Name      string
	Mode      string // audit|enforce
	CreatedAt time.Time
}

const ringfenceCols = `id, name, mode, created_at`

func scanRingfence(r pgx.Row) (Ringfence, error) {
	var o Ringfence
	err := r.Scan(&o.ID, &o.Name, &o.Mode, &o.CreatedAt)
	return o, err
}

func (s *Store) CreateRingfence(ctx context.Context, tenantID uuid.UUID, r Ringfence) error {
	if r.Mode == "" {
		r.Mode = "audit"
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO ringfence_policies (id, tenant_id, name, mode) VALUES ($1,$2,$3,$4)`,
		r.ID, tenantID, r.Name, r.Mode)
	return conflict(err)
}

func (s *Store) GetRingfence(ctx context.Context, tenantID, id uuid.UUID) (Ringfence, error) {
	o, err := scanRingfence(s.pool.QueryRow(ctx,
		`SELECT `+ringfenceCols+` FROM ringfence_policies WHERE tenant_id=$1 AND id=$2`, tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return o, err
}

func (s *Store) ListRingfences(ctx context.Context, tenantID uuid.UUID) ([]Ringfence, error) {
	rows, _ := s.pool.Query(ctx,
		`SELECT `+ringfenceCols+` FROM ringfence_policies WHERE tenant_id=$1 ORDER BY name`, tenantID)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Ringfence, error) { return scanRingfence(r) })
}

func (s *Store) RenameRingfence(ctx context.Context, tenantID, id uuid.UUID, name string) error {
	return oneRow(s.pool.Exec(ctx,
		`UPDATE ringfence_policies SET name=$3 WHERE tenant_id=$1 AND id=$2`, tenantID, id, name))
}

// SetRingfenceMode expects an already-validated mode; the CHECK constraint is
// the backstop and the HTTP layer returns 400 for anything else (Task 10).
func (s *Store) SetRingfenceMode(ctx context.Context, tenantID, id uuid.UUID, mode string) error {
	return oneRow(s.pool.Exec(ctx,
		`UPDATE ringfence_policies SET mode=$3 WHERE tenant_id=$1 AND id=$2`, tenantID, id, mode))
}

func (s *Store) DeleteRingfence(ctx context.Context, tenantID, id uuid.UUID) error {
	return oneRow(s.pool.Exec(ctx,
		`DELETE FROM ringfence_policies WHERE tenant_id=$1 AND id=$2`, tenantID, id))
}
```

The store package has exactly two sentinels, `ErrNotFound` and `ErrConflict`
(`store.go:20-22`), plus the `conflict()` and `oneRow()` helpers — there is no
validation sentinel, which is why validation lives in the HTTP layer.

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/server/store/ -run TestRingfenceCRUD -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/server/store/migrations/0020_ringfencing.sql internal/server/store/ringfence.go internal/server/store/ringfence_test.go
git commit -m "feat(store): ringfence schema and CRUD"
```

---

### Task 2: Programs, protections, assignment and effective resolution

**Files:**
- Modify: `internal/server/store/ringfence.go`
- Test: `internal/server/store/ringfence_test.go`

**Interfaces:**
- Consumes: Task 1's `Ringfence` type and CRUD.
- Produces: `store.RingfenceProgram{ID, Path, NetworkBlocked, Note}`, `store.RingfenceProtection{ASRRule, Action}`, `store.ResolvedRingfence{Version, Mode, Programs, Protections}`, and:
  `AddRingfenceProgram(ctx, tenantID, ringfenceID uuid.UUID, p RingfenceProgram) error`,
  `DeleteRingfenceProgram(ctx, tenantID, ringfenceID, programID uuid.UUID) error`,
  `ListRingfencePrograms(ctx, tenantID, ringfenceID uuid.UUID) ([]RingfenceProgram, error)`,
  `SetRingfenceProtection(ctx, tenantID, ringfenceID uuid.UUID, asrRule, action string) error` (action `"off"` deletes),
  `ListRingfenceProtections(ctx, tenantID, ringfenceID uuid.UUID) ([]RingfenceProtection, error)`,
  `AssignRingfence(ctx, tenantID, groupID, ringfenceID uuid.UUID) error`,
  `UnassignRingfence(ctx, tenantID, groupID uuid.UUID) error`,
  `RingfenceForDevice(ctx, tenantID, deviceID uuid.UUID) (ResolvedRingfence, error)`.

- [ ] **Step 1: Write the failing test**

```go
func TestRingfenceForDevice(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	group, _ := s.CreateDeviceGroup(ctx, tenant, "WS")
	dev := enrollTestDevice(t, s, tenant, &group, "pc1", "1.0.0")

	// No ringfence assigned → ErrNotFound, which the agent API treats as
	// "nothing to enforce".
	if _, err := s.RingfenceForDevice(ctx, tenant, dev); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unassigned err = %v, want ErrNotFound", err)
	}

	rf := store.Ringfence{ID: uuid.New(), Name: "Office", Mode: "enforce"}
	if err := s.CreateRingfence(ctx, tenant, rf); err != nil {
		t.Fatal(err)
	}
	prog := store.RingfenceProgram{ID: uuid.New(), Path: `C:\Program Files\App\app.exe`, NetworkBlocked: true, Note: "no internet"}
	if err := s.AddRingfenceProgram(ctx, tenant, rf.ID, prog); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRingfenceProtection(ctx, tenant, rf.ID, "D4F940AB-401B-4EFC-AADC-AD5F3C50688A", "block"); err != nil {
		t.Fatal(err)
	}
	if err := s.AssignRingfence(ctx, tenant, group, rf.ID); err != nil {
		t.Fatal(err)
	}

	got, err := s.RingfenceForDevice(ctx, tenant, dev)
	if err != nil {
		t.Fatal(err)
	}
	if got.Mode != "enforce" || len(got.Programs) != 1 || got.Programs[0].Path != prog.Path || len(got.Protections) != 1 {
		t.Fatalf("resolved = %+v", got)
	}
	if got.Version == "" {
		t.Error("resolved ringfence must carry a content version")
	}

	// The version is a content hash: unchanged content, unchanged version.
	again, _ := s.RingfenceForDevice(ctx, tenant, dev)
	if again.Version != got.Version {
		t.Errorf("version changed without a content change: %q then %q", got.Version, again.Version)
	}
	// Changing content changes the version.
	if err := s.SetRingfenceProtection(ctx, tenant, rf.ID, "D4F940AB-401B-4EFC-AADC-AD5F3C50688A", "audit"); err != nil {
		t.Fatal(err)
	}
	changed, _ := s.RingfenceForDevice(ctx, tenant, dev)
	if changed.Version == got.Version {
		t.Error("version must change when a protection action changes")
	}
	// "off" removes the protection entirely.
	if err := s.SetRingfenceProtection(ctx, tenant, rf.ID, "D4F940AB-401B-4EFC-AADC-AD5F3C50688A", "off"); err != nil {
		t.Fatal(err)
	}
	off, _ := s.RingfenceForDevice(ctx, tenant, dev)
	if len(off.Protections) != 0 {
		t.Errorf("protections after off = %+v, want none", off.Protections)
	}

	// Unassigning returns the device to "nothing to enforce".
	if err := s.UnassignRingfence(ctx, tenant, group); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RingfenceForDevice(ctx, tenant, dev); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("after unassign err = %v, want ErrNotFound", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/server/store/ -run TestRingfenceForDevice -v`
Expected: FAIL — `s.RingfenceForDevice undefined`.

- [ ] **Step 3: Write the implementation**

```go
type RingfenceProgram struct {
	ID             uuid.UUID
	Path           string
	NetworkBlocked bool
	Note           string
}

type RingfenceProtection struct {
	ASRRule string
	Action  string // audit|block
}

// ResolvedRingfence is everything an agent needs, with a content hash so the
// agent can skip a reconcile when nothing changed.
type ResolvedRingfence struct {
	Version     string
	Mode        string
	Programs    []RingfenceProgram
	Protections []RingfenceProtection
}

func (s *Store) AddRingfenceProgram(ctx context.Context, tenantID, ringfenceID uuid.UUID, p RingfenceProgram) error {
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO ringfence_programs (id, tenant_id, ringfence_id, path, network_blocked, note)
		SELECT $1, $2, $3, $4, $5, $6
		WHERE EXISTS (SELECT 1 FROM ringfence_policies WHERE tenant_id=$2 AND id=$3)`,
		p.ID, tenantID, ringfenceID, p.Path, p.NetworkBlocked, p.Note)
	if err != nil {
		return conflict(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteRingfenceProgram(ctx context.Context, tenantID, ringfenceID, programID uuid.UUID) error {
	return oneRow(s.pool.Exec(ctx,
		`DELETE FROM ringfence_programs WHERE tenant_id=$1 AND ringfence_id=$2 AND id=$3`,
		tenantID, ringfenceID, programID))
}

func (s *Store) ListRingfencePrograms(ctx context.Context, tenantID, ringfenceID uuid.UUID) ([]RingfenceProgram, error) {
	rows, _ := s.pool.Query(ctx, `
		SELECT id, path, network_blocked, note FROM ringfence_programs
		WHERE tenant_id=$1 AND ringfence_id=$2 ORDER BY path`, tenantID, ringfenceID)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (RingfenceProgram, error) {
		var p RingfenceProgram
		return p, r.Scan(&p.ID, &p.Path, &p.NetworkBlocked, &p.Note)
	})
}

// SetRingfenceProtection upserts an ASR rule's action. action "off" deletes
// the row, so an absent row is the single representation of "not enabled".
func (s *Store) SetRingfenceProtection(ctx context.Context, tenantID, ringfenceID uuid.UUID, asrRule, action string) error {
	if action == "off" {
		_, err := s.pool.Exec(ctx,
			`DELETE FROM ringfence_protections WHERE tenant_id=$1 AND ringfence_id=$2 AND asr_rule=$3`,
			tenantID, ringfenceID, asrRule)
		return err
	}
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO ringfence_protections (tenant_id, ringfence_id, asr_rule, action)
		SELECT $1, $2, $3, $4
		WHERE EXISTS (SELECT 1 FROM ringfence_policies WHERE tenant_id=$1 AND id=$2)
		ON CONFLICT (ringfence_id, asr_rule) DO UPDATE SET action=EXCLUDED.action`,
		tenantID, ringfenceID, asrRule, action)
	if err != nil {
		return conflict(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ListRingfenceProtections(ctx context.Context, tenantID, ringfenceID uuid.UUID) ([]RingfenceProtection, error) {
	rows, _ := s.pool.Query(ctx, `
		SELECT asr_rule, action FROM ringfence_protections
		WHERE tenant_id=$1 AND ringfence_id=$2 ORDER BY asr_rule`, tenantID, ringfenceID)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (RingfenceProtection, error) {
		var p RingfenceProtection
		return p, r.Scan(&p.ASRRule, &p.Action)
	})
}

func (s *Store) AssignRingfence(ctx context.Context, tenantID, groupID, ringfenceID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO ringfence_assignments (tenant_id, group_id, ringfence_id) VALUES ($1,$2,$3)
		ON CONFLICT (group_id) DO UPDATE SET ringfence_id=EXCLUDED.ringfence_id`,
		tenantID, groupID, ringfenceID)
	return conflict(err)
}

func (s *Store) UnassignRingfence(ctx context.Context, tenantID, groupID uuid.UUID) error {
	return oneRow(s.pool.Exec(ctx,
		`DELETE FROM ringfence_assignments WHERE tenant_id=$1 AND group_id=$2`, tenantID, groupID))
}

// RingfenceForDevice resolves the ringfence assigned to the device's group.
// ErrNotFound when the device has no group or its group has no ringfence —
// the agent API turns that into "nothing to enforce".
func (s *Store) RingfenceForDevice(ctx context.Context, tenantID, deviceID uuid.UUID) (ResolvedRingfence, error) {
	var rfID uuid.UUID
	var out ResolvedRingfence
	err := s.pool.QueryRow(ctx, `
		SELECT rp.id, rp.mode FROM devices d
		JOIN ringfence_assignments ra ON ra.group_id = d.group_id AND ra.tenant_id = d.tenant_id
		JOIN ringfence_policies rp ON rp.id = ra.ringfence_id
		WHERE d.tenant_id=$1 AND d.id=$2`, tenantID, deviceID).Scan(&rfID, &out.Mode)
	if errors.Is(err, pgx.ErrNoRows) {
		return ResolvedRingfence{}, ErrNotFound
	}
	if err != nil {
		return ResolvedRingfence{}, err
	}
	if out.Programs, err = s.ListRingfencePrograms(ctx, tenantID, rfID); err != nil {
		return ResolvedRingfence{}, err
	}
	if out.Protections, err = s.ListRingfenceProtections(ctx, tenantID, rfID); err != nil {
		return ResolvedRingfence{}, err
	}
	out.Version = ringfenceVersion(out)
	return out, nil
}

// ringfenceVersion hashes the resolved content so an unchanged ringfence
// yields an unchanged version and the agent can skip the reconcile. Both
// lists are already ordered by the queries above, so the hash is stable.
func ringfenceVersion(r ResolvedRingfence) string {
	h := sha256.New()
	fmt.Fprintf(h, "mode=%s\n", r.Mode)
	for _, p := range r.Programs {
		fmt.Fprintf(h, "prog=%s|%t\n", p.Path, p.NetworkBlocked)
	}
	for _, p := range r.Protections {
		fmt.Fprintf(h, "prot=%s|%s\n", p.ASRRule, p.Action)
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}
```

Add `crypto/sha256`, `encoding/hex` and `fmt` to the file's imports.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/server/store/ -run 'TestRingfence' -v`
Expected: PASS (both tests).

- [ ] **Step 5: Commit**

```bash
git add internal/server/store/ringfence.go internal/server/store/ringfence_test.go
git commit -m "feat(store): ringfence programs, protections, assignment and resolution"
```

---

### Task 3: Ringfence events store

**Files:**
- Modify: `internal/server/store/ringfence.go`
- Test: `internal/server/store/ringfence_test.go`

**Interfaces:**
- Produces: `store.RingfenceEvent{ID, DeviceID, Hostname, Kind, Program, Detail, Enforced, At}`,
  `AppendRingfenceEvents(ctx, tenantID, deviceID uuid.UUID, evs []RingfenceEvent) error`,
  `ListRingfenceEvents(ctx, tenantID uuid.UUID, limit int) ([]RingfenceEvent, error)`.

- [ ] **Step 1: Write the failing test**

```go
func TestRingfenceEvents(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	dev := enrollTestDevice(t, s, tenant, nil, "pc1", "1.0.0")

	evs := []store.RingfenceEvent{
		{Kind: "network", Program: `C:\app.exe`, Detail: "203.0.113.5:443", Enforced: false, At: time.Now()},
		{Kind: "child_process", Program: `C:\Program Files\Office\winword.exe`, Detail: "ASR D4F940AB…: powershell.exe", Enforced: true, At: time.Now()},
	}
	if err := s.AppendRingfenceEvents(ctx, tenant, dev, evs); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListRingfenceEvents(ctx, tenant, 10)
	if err != nil || len(got) != 2 {
		t.Fatalf("list = %+v, %v", got, err)
	}
	if got[0].Hostname != "pc1" {
		t.Errorf("events must carry the hostname for the console: %+v", got[0])
	}

	// An empty batch is a no-op, not an error: the agent reports on a timer.
	if err := s.AppendRingfenceEvents(ctx, tenant, dev, nil); err != nil {
		t.Errorf("empty batch = %v", err)
	}

	// Another tenant sees none of it.
	other, _ := s.CreateTenant(ctx, "Beta")
	if got, _ := s.ListRingfenceEvents(ctx, other, 10); len(got) != 0 {
		t.Errorf("cross-tenant list = %+v", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/server/store/ -run TestRingfenceEvents -v`
Expected: FAIL — `s.AppendRingfenceEvents undefined`.

- [ ] **Step 3: Write the implementation**

```go
type RingfenceEvent struct {
	ID       int64
	DeviceID uuid.UUID
	Hostname string
	Kind     string // network|child_process
	Program  string
	Detail   string
	Enforced bool
	At       time.Time
}

func (s *Store) AppendRingfenceEvents(ctx context.Context, tenantID, deviceID uuid.UUID, evs []RingfenceEvent) error {
	if len(evs) == 0 {
		return nil
	}
	b := &pgx.Batch{}
	for _, e := range evs {
		b.Queue(`INSERT INTO ringfence_events (tenant_id, device_id, kind, program, detail, enforced, at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			tenantID, deviceID, e.Kind, e.Program, e.Detail, e.Enforced, e.At)
	}
	return s.pool.SendBatch(ctx, b).Close()
}

func (s *Store) ListRingfenceEvents(ctx context.Context, tenantID uuid.UUID, limit int) ([]RingfenceEvent, error) {
	rows, _ := s.pool.Query(ctx, `
		SELECT e.id, e.device_id, d.hostname, e.kind, e.program, e.detail, e.enforced, e.at
		FROM ringfence_events e JOIN devices d ON d.id = e.device_id
		WHERE e.tenant_id=$1 ORDER BY e.at DESC LIMIT $2`, tenantID, limit)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (RingfenceEvent, error) {
		var e RingfenceEvent
		return e, r.Scan(&e.ID, &e.DeviceID, &e.Hostname, &e.Kind, &e.Program, &e.Detail, &e.Enforced, &e.At)
	})
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/server/store/ -run TestRingfence -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/server/store/ringfence.go internal/server/store/ringfence_test.go
git commit -m "feat(store): ringfence violation events"
```

---

### Task 4: Protocol — GetRingfence and ReportRingfenceEvents

**Files:**
- Modify: `proto/freelocker/v1/agent.proto`
- Regenerate: `gen/freelocker/v1/*`

**Interfaces:**
- Produces: `flv1.GetRingfenceRequest`, `flv1.GetRingfenceResponse{Version, Mode, Programs, Protections}`, `flv1.RingfenceProgram{Path, NetworkBlocked}`, `flv1.RingfenceProtection{AsrRule, Action}`, `flv1.RingfenceEvent{Kind, Program, Detail, Enforced, AtUnix}`, `flv1.ReportRingfenceEventsRequest{Events}`, and the `Agent` service methods `GetRingfence` and `ReportRingfenceEvents`.

- [ ] **Step 1: Add the RPCs and messages**

In the `service Agent` block, after `ReportEvents`:

```proto
  rpc GetRingfence(GetRingfenceRequest) returns (GetRingfenceResponse);
  rpc ReportRingfenceEvents(ReportRingfenceEventsRequest) returns (Ack);
```

Then, next to the other control messages:

```proto
message GetRingfenceRequest {}

message RingfenceProgram {
  string path = 1;
  bool network_blocked = 2;
}

message RingfenceProtection {
  string asr_rule = 1; // ASR GUID
  string action = 2;   // audit | block
}

message GetRingfenceResponse {
  string version = 1; // content hash; empty means no ringfence assigned
  string mode = 2;    // audit | enforce
  repeated RingfenceProgram programs = 3;
  repeated RingfenceProtection protections = 4;
}

message RingfenceEvent {
  string kind = 1;    // network | child_process
  string program = 2;
  string detail = 3;
  bool enforced = 4;  // false = would have blocked (audit)
  int64 at_unix = 5;
}

message ReportRingfenceEventsRequest {
  repeated RingfenceEvent events = 1;
}
```

These are additive: new messages and new RPCs, no renumbering of existing fields.

- [ ] **Step 2: Regenerate and build**

Run: `export PATH="$PATH:$(go env GOPATH)/bin" && buf generate && go build ./...`
Expected: generated files update; build succeeds. The server will not yet implement the new methods — that is Task 5.

- [ ] **Step 3: Commit**

```bash
git add proto/freelocker/v1/agent.proto gen/
git commit -m "feat(proto): GetRingfence and ReportRingfenceEvents"
```

---

### Task 5: Agent API handlers

**Files:**
- Modify: `internal/server/agentapi/policy.go`
- Test: `internal/server/agentapi/ringfence_test.go`

**Interfaces:**
- Consumes: `store.RingfenceForDevice`, `store.AppendRingfenceEvents`, `deviceFrom(ctx)`.
- Produces: `agentService.GetRingfence`, `agentService.ReportRingfenceEvents`.

- [ ] **Step 1: Write the failing test**

Model it on the existing over-the-wire tests in this package (see how `TestMultiTenantEnrollmentOverTheWire` builds an app and a client).

```go
package agentapi_test

// TestRingfenceOverTheWire enrolls a device, assigns a ringfence to its
// group, and checks the agent receives it and can report a violation back.
func TestRingfenceOverTheWire(t *testing.T) {
	// Build the app + enrol a device exactly as the existing agentapi tests
	// do, then:
	//   1. group := create group, put the device in it
	//   2. rf := CreateRingfence(mode "enforce"); AddRingfenceProgram(path, true)
	//      SetRingfenceProtection(guid, "block"); AssignRingfence(group, rf)
	//   3. resp, err := client.GetRingfence(ctx, &flv1.GetRingfenceRequest{})
	//      assert resp.Mode == "enforce", len(resp.Programs) == 1,
	//      resp.Programs[0].Path == the path, len(resp.Protections) == 1,
	//      resp.Version != ""
	//   4. an unassigned device gets an empty Version and no error
	//   5. client.ReportRingfenceEvents with one network event, then
	//      store.ListRingfenceEvents returns it with the right device
}
```

Write this out fully against the package's existing helpers — do not leave it as comments. Read `internal/server/agentapi/*_test.go` first and copy the established setup.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/server/agentapi/ -run TestRingfenceOverTheWire -v`
Expected: FAIL — the method is unimplemented (`unknown method GetRingfence`).

- [ ] **Step 3: Write the implementation**

```go
func (s *agentService) GetRingfence(ctx context.Context, _ *flv1.GetRingfenceRequest) (*flv1.GetRingfenceResponse, error) {
	dev := deviceFrom(ctx)
	rf, err := s.d.Store.RingfenceForDevice(ctx, dev.TenantID, dev.ID)
	if err == store.ErrNotFound {
		return &flv1.GetRingfenceResponse{}, nil // nothing assigned; agent clears any rules it set
	}
	if err != nil {
		s.d.Log.Error("resolve ringfence", "device", dev.ID, "err", err)
		return nil, status.Error(codes.Internal, "could not resolve ringfence")
	}
	out := &flv1.GetRingfenceResponse{Version: rf.Version, Mode: rf.Mode}
	for _, p := range rf.Programs {
		out.Programs = append(out.Programs, &flv1.RingfenceProgram{Path: p.Path, NetworkBlocked: p.NetworkBlocked})
	}
	for _, p := range rf.Protections {
		out.Protections = append(out.Protections, &flv1.RingfenceProtection{AsrRule: p.ASRRule, Action: p.Action})
	}
	return out, nil
}

func (s *agentService) ReportRingfenceEvents(ctx context.Context, req *flv1.ReportRingfenceEventsRequest) (*flv1.Ack, error) {
	dev := deviceFrom(ctx)
	evs := make([]store.RingfenceEvent, 0, len(req.GetEvents()))
	for _, e := range req.GetEvents() {
		if e.GetKind() != "network" && e.GetKind() != "child_process" {
			continue // ignore unknown kinds rather than failing the batch
		}
		at := time.Unix(e.GetAtUnix(), 0)
		if e.GetAtUnix() == 0 {
			at = time.Now()
		}
		evs = append(evs, store.RingfenceEvent{
			Kind: e.GetKind(), Program: e.GetProgram(), Detail: e.GetDetail(),
			Enforced: e.GetEnforced(), At: at,
		})
	}
	if err := s.d.Store.AppendRingfenceEvents(ctx, dev.TenantID, dev.ID, evs); err != nil {
		s.d.Log.Error("append ringfence events", "device", dev.ID, "err", err)
		return nil, status.Error(codes.Internal, "could not record events")
	}
	return &flv1.Ack{}, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/server/agentapi/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/server/agentapi/policy.go internal/server/agentapi/ringfence_test.go
git commit -m "feat(agentapi): serve ringfences and record violations"
```

---

### Task 6: Agent ringfence package — types, reconcile diff, Noop

**Files:**
- Create: `internal/agent/ringfence/ringfence.go`
- Create: `internal/agent/ringfence/ringfence_other.go`
- Test: `internal/agent/ringfence/ringfence_test.go`

**Interfaces:**
- Produces: `ringfence.Ringfence{Version, Mode, Programs, Protections}`, `ringfence.Program{Path, NetworkBlocked}`, `ringfence.Protection{ASRRule, Action}`, `ringfence.Violation{Kind, Program, Detail, Enforced, At}`, `ringfence.Enforcer` interface, `ringfence.NoopEnforcer`, `ringfence.Status{Applied, ASRAvailable}`, `ringfence.RuleName(path string) string`, `ringfence.Diff(existing []string, desired map[string]Program) (add []Program, remove []string)`.

- [ ] **Step 1: Write the failing test**

```go
package ringfence

import "testing"

func TestRuleNameIsStableAndScoped(t *testing.T) {
	a := RuleName(`C:\Program Files\App\app.exe`)
	if a != RuleName(`C:\Program Files\App\app.exe`) {
		t.Error("rule name must be deterministic")
	}
	if a == RuleName(`C:\Other\app.exe`) {
		t.Error("different programs must get different rule names")
	}
	if len(a) < len(RulePrefix) || a[:len(RulePrefix)] != RulePrefix {
		t.Errorf("rule name %q must start with %q so reconcile can enumerate ours", a, RulePrefix)
	}
}

func TestDiffAddsMissingAndRemovesStale(t *testing.T) {
	keep := Program{Path: `C:\keep.exe`, NetworkBlocked: true}
	want := map[string]Program{RuleName(keep.Path): keep}
	existing := []string{RuleName(keep.Path), RulePrefix + "deadbeefdeadbeef"}

	add, remove := Diff(existing, want)
	if len(add) != 0 {
		t.Errorf("add = %+v, want none (the rule is already there)", add)
	}
	if len(remove) != 1 || remove[0] != RulePrefix+"deadbeefdeadbeef" {
		t.Errorf("remove = %+v, want the stale rule only", remove)
	}

	// A program with no rule yet must be added.
	add, remove = Diff(nil, want)
	if len(add) != 1 || add[0].Path != keep.Path || len(remove) != 0 {
		t.Errorf("add = %+v remove = %+v, want one add", add, remove)
	}

	// A listed program that is not network-blocked gets no rule at all.
	open := map[string]Program{RuleName(`C:\open.exe`): {Path: `C:\open.exe`, NetworkBlocked: false}}
	if add, _ := Diff(nil, open); len(add) != 0 {
		t.Errorf("add = %+v, want none for a program that is not network-blocked", add)
	}
}

func TestNoopEnforcerRecordsWithoutTouchingTheHost(t *testing.T) {
	var e NoopEnforcer
	rf := Ringfence{Version: "v1", Mode: "audit", Programs: []Program{{Path: `C:\a.exe`, NetworkBlocked: true}}}
	if err := e.Apply(context.Background(), rf); err != nil {
		t.Fatal(err)
	}
	if got := e.Status(); got.Applied != "v1" {
		t.Errorf("status = %+v, want the applied version", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/agent/ringfence/ -v`
Expected: FAIL — package does not exist.

- [ ] **Step 3: Write the implementation**

```go
// Package ringfence constrains what an allowed application may do: per-program
// outbound network containment and Defender ASR child-process protections.
// The Windows enforcer makes reversible firewall and registry changes; other
// platforms use a no-op.
//
// SAFETY: the enforcer refuses to ringfence the agent's own image or the
// updater, so a ringfence can never sever the management link.
package ringfence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// RulePrefix names every firewall rule this package owns, so reconcile can
// enumerate exactly ours and never touch a rule an admin added by hand.
const RulePrefix = "FreeLocker-RF-"

type Program struct {
	Path           string
	NetworkBlocked bool
}

type Protection struct {
	ASRRule string
	Action  string // audit|block
}

type Ringfence struct {
	Version     string // content hash; "" means nothing assigned
	Mode        string // audit|enforce
	Programs    []Program
	Protections []Protection
}

type Violation struct {
	Kind     string // network|child_process
	Program  string
	Detail   string
	Enforced bool
	At       time.Time
}

type Status struct {
	Applied      string // version last applied
	ASRAvailable bool   // Defender is active, so ASR values actually bite
}

type Enforcer interface {
	Apply(ctx context.Context, r Ringfence) error
	Violations(ctx context.Context) ([]Violation, error)
	Status() Status
}

// RuleName is the deterministic firewall rule name for a program path.
func RuleName(path string) string {
	sum := sha256.Sum256([]byte(path))
	return RulePrefix + hex.EncodeToString(sum[:])[:16]
}

// Diff compares the firewall rules already present (names starting with
// RulePrefix) against the programs that should have one, returning what to
// add and what to remove. Only network-blocked programs get a rule.
func Diff(existing []string, desired map[string]Program) (add []Program, remove []string) {
	have := make(map[string]bool, len(existing))
	for _, n := range existing {
		have[n] = true
	}
	for name, p := range desired {
		if p.NetworkBlocked && !have[name] {
			add = append(add, p)
		}
	}
	for _, n := range existing {
		p, ok := desired[n]
		if !ok || !p.NetworkBlocked {
			remove = append(remove, n)
		}
	}
	return add, remove
}

// NoopEnforcer records what would be applied without changing the host.
type NoopEnforcer struct{ status Status }

func (n *NoopEnforcer) Apply(_ context.Context, r Ringfence) error {
	n.status = Status{Applied: r.Version}
	return nil
}
func (n *NoopEnforcer) Violations(context.Context) ([]Violation, error) { return nil, nil }
func (n *NoopEnforcer) Status() Status                                  { return n.status }
```

`ringfence_other.go`:

```go
//go:build !windows

package ringfence

// Default returns the no-op enforcer off Windows.
func Default(agentImages []string) Enforcer { return &NoopEnforcer{} }
```

`Diff` returns `add` in map order, which is non-deterministic. That is fine for correctness (each rule is independent) but sort `add` by path and `remove` lexically before returning if a test ever needs stable ordering.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/agent/ringfence/ -v`
Expected: PASS. Add `"context"` to the test file's imports.

- [ ] **Step 5: Commit**

```bash
git add internal/agent/ringfence/
git commit -m "feat(agent): ringfence types and reconcile diff"
```

---

### Task 7: Event-log parsers

**Files:**
- Create: `internal/agent/ringfence/parse.go`
- Create: `internal/agent/ringfence/testdata/wfp_5156.xml`
- Create: `internal/agent/ringfence/testdata/defender_1121.xml`
- Test: `internal/agent/ringfence/parse_test.go`

**Interfaces:**
- Produces: `ParseWFP(xml []byte, ringfenced map[string]bool, enforced bool) ([]Violation, error)`, `ParseDefenderASR(xml []byte) ([]Violation, error)`, `Dedupe(v []Violation, cap int) []Violation`.

This is the highest-value task that runs anywhere: the parsers carry most of the real risk and cannot be tested on the VM cheaply.

- [ ] **Step 1: Capture fixtures**

On any Windows machine (the dev box is fine — reading the event log changes nothing):

```
wevtutil qe Security "/q:*[System[(EventID=5156)]]" /c:2 /f:xml > internal/agent/ringfence/testdata/wfp_5156.xml
```

If the Security log has no 5156 events (auditing not enabled), hand-write the fixture from the documented schema: an `<Event>` with `<EventID>5156</EventID>` and `<EventData>` containing `<Data Name="Application">\device\harddiskvolume3\program files\app\app.exe</Data>`, `<Data Name="DestAddress">203.0.113.5</Data>`, `<Data Name="DestPort">443</Data>`.

For Defender, `<EventID>1121</EventID>` with `<Data Name="Path">C:\…\winword.exe</Data>`, `<Data Name="ProcessName">powershell.exe</Data>`, `<Data Name="ID">D4F940AB-401B-4EFC-AADC-AD5F3C50688A</Data>`.

- [ ] **Step 2: Write the failing test**

```go
func TestParseWFPKeepsOnlyRingfencedPrograms(t *testing.T) {
	raw, err := os.ReadFile("testdata/wfp_5156.xml")
	if err != nil {
		t.Fatal(err)
	}
	// Only app.exe is ringfenced; everything else on the box must be dropped
	// before it ever reaches the server.
	ringfenced := map[string]bool{`c:\program files\app\app.exe`: true}
	got, err := ParseWFP(raw, ringfenced, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range got {
		if !ringfenced[strings.ToLower(v.Program)] {
			t.Errorf("parser leaked a non-ringfenced program: %+v", v)
		}
		if v.Kind != "network" || v.Enforced {
			t.Errorf("violation = %+v, want kind network and enforced false", v)
		}
		if v.Detail == "" {
			t.Error("a network violation must carry the remote endpoint")
		}
	}
}

func TestParseWFPNormalisesDevicePaths(t *testing.T) {
	// 5156 reports \device\harddiskvolumeN\... — the ringfence set holds
	// C:\... paths, so matching requires normalisation or every event is
	// silently dropped.
	raw := []byte(`<Events><Event><System><EventID>5156</EventID></System><EventData>` +
		`<Data Name="Application">\device\harddiskvolume3\program files\app\app.exe</Data>` +
		`<Data Name="DestAddress">203.0.113.5</Data><Data Name="DestPort">443</Data>` +
		`</EventData></Event></Events>`)
	got, err := ParseWFP(raw, map[string]bool{`c:\program files\app\app.exe`: true}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d violations, want 1 — device-path normalisation failed", len(got))
	}
	if got[0].Detail != "203.0.113.5:443" || !got[0].Enforced {
		t.Errorf("violation = %+v", got[0])
	}
}

func TestParseDefenderASR(t *testing.T) {
	raw, err := os.ReadFile("testdata/defender_1121.xml")
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseDefenderASR(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("no ASR violations parsed")
	}
	if got[0].Kind != "child_process" || !got[0].Enforced {
		t.Errorf("1121 is a block: %+v", got[0])
	}
}

func TestDedupeCollapsesRepeatsAndCaps(t *testing.T) {
	v := []Violation{
		{Kind: "network", Program: `C:\a.exe`, Detail: "1.2.3.4:443"},
		{Kind: "network", Program: `C:\a.exe`, Detail: "1.2.3.4:443"},
		{Kind: "network", Program: `C:\a.exe`, Detail: "5.6.7.8:443"},
	}
	if got := Dedupe(v, 10); len(got) != 2 {
		t.Errorf("dedupe = %d, want 2 distinct endpoints", len(got))
	}
	if got := Dedupe(v, 1); len(got) != 1 {
		t.Errorf("cap ignored: %d", len(got))
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/agent/ringfence/ -run 'Parse|Dedupe' -v`
Expected: FAIL — `ParseWFP undefined`.

- [ ] **Step 4: Write the implementation**

```go
package ringfence

import (
	"encoding/xml"
	"fmt"
	"regexp"
	"strings"
	"time"
)

type evtData struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

type evt struct {
	EventID int       `xml:"System>EventID"`
	Data    []evtData `xml:"EventData>Data"`
}

type evtList struct {
	Events []evt `xml:"Event"`
}

func (e evt) field(name string) string {
	for _, d := range e.Data {
		if d.Name == name {
			return strings.TrimSpace(d.Value)
		}
	}
	return ""
}

// parseEvents tolerates both a wrapped <Events> document and the bare
// concatenated <Event> elements wevtutil emits without /e.
func parseEvents(raw []byte) ([]evt, error) {
	var l evtList
	if err := xml.Unmarshal(raw, &l); err == nil && len(l.Events) > 0 {
		return l.Events, nil
	}
	wrapped := append(append([]byte("<Events>"), raw...), []byte("</Events>")...)
	if err := xml.Unmarshal(wrapped, &l); err != nil {
		return nil, fmt.Errorf("parse event xml: %w", err)
	}
	return l.Events, nil
}

var devicePath = regexp.MustCompile(`^\\device\\harddiskvolume\d+`)

// normalisePath turns the \device\harddiskvolumeN\... form that WFP events
// use into a comparable lower-case path. The volume number cannot be mapped
// to a drive letter without more work, so the leading segment is dropped and
// matching is done on the remainder.
func normalisePath(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	return devicePath.ReplaceAllString(p, "")
}

// ParseWFP extracts network violations for ringfenced programs only. Keys of
// `ringfenced` must be lower-case full paths; matching is on the path tail so
// a \device\harddiskvolume3\... event matches a C:\... ringfence entry.
func ParseWFP(raw []byte, ringfenced map[string]bool, enforced bool) ([]Violation, error) {
	evts, err := parseEvents(raw)
	if err != nil {
		return nil, err
	}
	var out []Violation
	for _, e := range evts {
		if e.EventID != 5156 && e.EventID != 5157 {
			continue
		}
		app := normalisePath(e.field("Application"))
		matched := ""
		for want := range ringfenced {
			tail := normalisePath(want)
			if i := strings.Index(tail, ":"); i == 1 { // strip "c:"
				tail = tail[2:]
			}
			if app == tail || strings.HasSuffix(app, tail) {
				matched = want
				break
			}
		}
		if matched == "" {
			continue // not ringfenced: drop before it reaches the server
		}
		out = append(out, Violation{
			Kind:     "network",
			Program:  matched,
			Detail:   e.field("DestAddress") + ":" + e.field("DestPort"),
			Enforced: enforced,
			At:       time.Now(),
		})
	}
	return out, nil
}

// ParseDefenderASR extracts child-process violations. 1121 is a block, 1122
// is an audit-mode detection.
func ParseDefenderASR(raw []byte) ([]Violation, error) {
	evts, err := parseEvents(raw)
	if err != nil {
		return nil, err
	}
	var out []Violation
	for _, e := range evts {
		if e.EventID != 1121 && e.EventID != 1122 {
			continue
		}
		out = append(out, Violation{
			Kind:     "child_process",
			Program:  e.field("Path"),
			Detail:   "ASR " + e.field("ID") + ": " + e.field("ProcessName"),
			Enforced: e.EventID == 1121,
			At:       time.Now(),
		})
	}
	return out, nil
}

// Dedupe collapses repeats of the same (kind, program, detail) and caps the
// batch. 5156 fires for every outbound connection on the machine, so without
// this an audit-mode ringfence floods the tenant's event table.
func Dedupe(v []Violation, cap int) []Violation {
	seen := make(map[string]bool, len(v))
	out := make([]Violation, 0, len(v))
	for _, x := range v {
		k := x.Kind + "|" + x.Program + "|" + x.Detail
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, x)
		if len(out) == cap {
			break
		}
	}
	return out
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/agent/ringfence/ -v`
Expected: PASS. Add `os` and `strings` to the test imports.

- [ ] **Step 6: Commit**

```bash
git add internal/agent/ringfence/parse.go internal/agent/ringfence/parse_test.go internal/agent/ringfence/testdata/
git commit -m "feat(agent): parse WFP and Defender ASR violation events"
```

---

### Task 8: Windows enforcer

**Files:**
- Create: `internal/agent/ringfence/ringfence_windows.go`

**Interfaces:**
- Consumes: `RuleName`, `Diff`, `ParseWFP`, `ParseDefenderASR`, `Dedupe` from Tasks 6-7.
- Produces: `ringfence.Default(agentImages []string) Enforcer` (Windows build).

There is no unit test here: every line touches the host. The logic worth testing was extracted into `Diff` and the parsers, which Tasks 6-7 cover. Verification is the VM checklist in Task 12.

- [ ] **Step 1: Write the enforcer**

```go
//go:build windows

package ringfence

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"golang.org/x/sys/windows/registry"
)

const asrKey = `SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules`

// WinEnforcer applies ringfences with netsh firewall rules and ASR machine
// policy. Both are reversible: rules are removed and values deleted.
type WinEnforcer struct {
	// agentImages are paths that must never be ringfenced, so a ringfence
	// can never sever the agent's own management link.
	agentImages []string

	mu      sync.Mutex
	applied string
}

func Default(agentImages []string) Enforcer {
	lower := make([]string, 0, len(agentImages))
	for _, p := range agentImages {
		lower = append(lower, strings.ToLower(p))
	}
	return &WinEnforcer{agentImages: lower}
}

func (e *WinEnforcer) Apply(_ context.Context, r Ringfence) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.applied == r.Version && r.Version != "" {
		return nil // idempotent
	}
	for _, p := range r.Programs {
		for _, self := range e.agentImages {
			if strings.EqualFold(p.Path, self) {
				return fmt.Errorf("refusing to ringfence the agent's own image %q: that would sever management", p.Path)
			}
		}
	}
	if err := e.applyNetwork(r); err != nil {
		return err
	}
	if err := e.applyASR(r); err != nil {
		return err
	}
	e.applied = r.Version
	return nil
}

// applyNetwork reconciles FreeLocker-RF-* rules. In audit mode no block rule
// is created: audit is observed through WFP connection logging instead.
func (e *WinEnforcer) applyNetwork(r Ringfence) error {
	desired := map[string]Program{}
	if r.Mode == "enforce" {
		for _, p := range r.Programs {
			desired[RuleName(p.Path)] = p
		}
	}
	add, remove := Diff(e.existingRules(), desired)
	for _, name := range remove {
		netsh("advfirewall", "firewall", "delete", "rule", "name="+name)
	}
	for _, p := range add {
		if err := netshErr("advfirewall", "firewall", "add", "rule",
			"name="+RuleName(p.Path), "dir=out", "action=block", "enable=yes",
			"program="+p.Path); err != nil {
			return err
		}
	}
	// Audit needs WFP connection auditing on; enforce needs it for 5157.
	exec.Command("auditpol", "/set", "/subcategory:Filtering Platform Connection", "/success:enable").Run()
	return nil
}

// existingRules lists the names of firewall rules this package owns.
func (e *WinEnforcer) existingRules() []string {
	out, err := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name=all").Output()
	if err != nil {
		return nil
	}
	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		if i := strings.Index(line, RulePrefix); i >= 0 {
			names = append(names, strings.TrimSpace(line[i:]))
		}
	}
	return names
}

func (e *WinEnforcer) applyASR(r Ringfence) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, asrKey, registry.ALL_ACCESS)
	if err != nil {
		return fmt.Errorf("open ASR policy key: %w", err)
	}
	defer k.Close()
	want := map[string]string{}
	for _, p := range r.Protections {
		want[strings.ToUpper(p.ASRRule)] = p.Action
	}
	// Remove values we previously set that are no longer wanted.
	if names, err := k.ReadValueNames(0); err == nil {
		for _, n := range names {
			if _, ok := want[strings.ToUpper(n)]; !ok {
				k.DeleteValue(n)
			}
		}
	}
	for guid, action := range want {
		v := uint32(1) // block
		if action == "audit" {
			v = 2
		}
		if err := k.SetDWordValue(guid, v); err != nil {
			return fmt.Errorf("set ASR %s: %w", guid, err)
		}
	}
	return nil
}

// Violations reads both sources. Which WFP event id matters depends on mode:
// enforce produces 5157 (blocked), audit produces 5156 (allowed, would have
// been blocked).
func (e *WinEnforcer) Violations(_ context.Context) ([]Violation, error) {
	// The caller sets the ringfenced set and mode through Apply; re-read
	// them from the last applied ringfence held by the runner (Task 9).
	return nil, nil
}

func (e *WinEnforcer) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	return Status{Applied: e.applied, ASRAvailable: defenderActive()}
}

// defenderActive reports whether Defender real-time protection is on, which
// is what makes ASR values actually bite. When it is off the values are
// inert and the console must say so rather than showing a green tick.
func defenderActive() bool {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"(Get-MpComputerStatus).RealTimeProtectionEnabled").Output()
	if err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(string(out)), "True")
}

func netsh(args ...string) { exec.Command("netsh", args...).Run() }

func netshErr(args ...string) error {
	out, err := exec.Command("netsh", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
```

`Violations` is deliberately left returning nothing here: the enforcer does not know the ringfenced path set on its own. Task 9 stores the last applied ringfence on the enforcer and fills this in — do that as part of Task 9's step 3, changing `WinEnforcer` to keep `last Ringfence` and having `Violations` call `ParseWFP(raw, set, r.Mode == "enforce")` plus `ParseDefenderASR`, then `Dedupe(v, 200)`.

- [ ] **Step 2: Verify it builds for both platforms**

Run: `GOOS=windows go build ./... && GOOS=linux go build ./... && go vet ./...`
Expected: both succeed.

- [ ] **Step 3: Commit**

```bash
git add internal/agent/ringfence/ringfence_windows.go
git commit -m "feat(agent): Windows ringfence enforcer (firewall + ASR policy)"
```

---

### Task 9: Agent runner wiring

**Files:**
- Modify: `internal/agent/runner/runner.go` (or the file holding the `GetControls` poll — find it with `grep -rn "GetControls" internal/agent/runner/`)
- Modify: `internal/agent/ringfence/ringfence_windows.go` (finish `Violations`, per Task 8's note)
- Modify: `cmd/agent/main.go` (construct the enforcer with the agent's own image paths)
- Test: `internal/agent/runner/ringfence_test.go`

**Interfaces:**
- Consumes: `ringfence.Enforcer`, `flv1.AgentClient.GetRingfence`, `flv1.AgentClient.ReportRingfenceEvents`.
- Produces: a ringfence poll in the runner's session loop, on the same cadence as the controls poll.

- [ ] **Step 1: Write the failing test**

Model it on `internal/agent/runner/controls_test.go`, which drives the runner against a fake server.

```go
// TestRunnerAppliesRingfenceAndReportsViolations starts the runner against a
// fake agent server that returns one ringfenced program, and asserts the
// enforcer received it and that violations the enforcer reports are sent back.
func TestRunnerAppliesRingfenceAndReportsViolations(t *testing.T) {
	// 1. fake server returns GetRingfenceResponse{Version:"v1", Mode:"enforce",
	//    Programs:[{Path:`C:\a.exe`, NetworkBlocked:true}]}
	// 2. enforcer := &fakeEnforcer{violations: []ringfence.Violation{{Kind:"network", Program:`C:\a.exe`, Detail:"1.2.3.4:443"}}}
	// 3. run the runner for one cycle
	// 4. assert enforcer.applied.Version == "v1" and len(applied.Programs) == 1
	// 5. assert the fake server received one ReportRingfenceEvents with that violation
	// 6. second cycle with the same version → Apply not called again (idempotent)
}
```

Write it out fully against `controls_test.go`'s helpers — do not leave comments.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/agent/runner/ -run TestRunnerAppliesRingfence -v`
Expected: FAIL — the runner has no ringfence poll.

- [ ] **Step 3: Implement**

In the runner's session loop, beside the existing controls poll:

```go
if rf, err := c.GetRingfence(ctx, &flv1.GetRingfenceRequest{}); err != nil {
	r.log.Error("get ringfence", "err", err)
} else {
	desired := ringfence.Ringfence{Version: rf.GetVersion(), Mode: rf.GetMode()}
	for _, p := range rf.GetPrograms() {
		desired.Programs = append(desired.Programs, ringfence.Program{Path: p.GetPath(), NetworkBlocked: p.GetNetworkBlocked()})
	}
	for _, p := range rf.GetProtections() {
		desired.Protections = append(desired.Protections, ringfence.Protection{ASRRule: p.GetAsrRule(), Action: p.GetAction()})
	}
	if err := r.ringfence.Apply(ctx, desired); err != nil {
		r.log.Error("apply ringfence", "err", err)
	}
	if vs, err := r.ringfence.Violations(ctx); err != nil {
		r.log.Error("read ringfence violations", "err", err)
	} else if len(vs) > 0 {
		req := &flv1.ReportRingfenceEventsRequest{}
		for _, v := range vs {
			req.Events = append(req.Events, &flv1.RingfenceEvent{
				Kind: v.Kind, Program: v.Program, Detail: v.Detail,
				Enforced: v.Enforced, AtUnix: v.At.Unix(),
			})
		}
		if _, err := c.ReportRingfenceEvents(ctx, req); err != nil {
			r.log.Error("report ringfence violations", "err", err)
		}
	}
}
```

Add a `ringfence ringfence.Enforcer` field to the runner, defaulting to `&ringfence.NoopEnforcer{}` when unset so existing tests keep working. In `cmd/agent/main.go`, construct it with the agent's own image paths:

```go
self, _ := os.Executable()
r.Ringfence = ringfence.Default([]string{self, agentpaths.UpdaterExe()})
```

Use whatever the real updater-path helper is — check `internal/agent/agentpaths`.

Then finish `WinEnforcer.Violations` as Task 8 noted: keep `last Ringfence` in `Apply`, build the lower-cased ringfenced path set from it, read the logs and parse:

```go
func (e *WinEnforcer) Violations(_ context.Context) ([]Violation, error) {
	e.mu.Lock()
	last := e.last
	e.mu.Unlock()
	if last.Version == "" {
		return nil, nil
	}
	set := make(map[string]bool, len(last.Programs))
	for _, p := range last.Programs {
		if p.NetworkBlocked {
			set[strings.ToLower(p.Path)] = true
		}
	}
	id := "5156"
	if last.Mode == "enforce" {
		id = "5157"
	}
	var out []Violation
	if raw, err := exec.Command("wevtutil", "qe", "Security",
		"/q:*[System[(EventID="+id+")]]", "/c:500", "/rd:true", "/f:xml").Output(); err == nil {
		if v, err := ParseWFP(raw, set, last.Mode == "enforce"); err == nil {
			out = append(out, v...)
		}
	}
	if raw, err := exec.Command("wevtutil", "qe", "Microsoft-Windows-Windows Defender/Operational",
		"/q:*[System[(EventID=1121 or EventID=1122)]]", "/c:200", "/rd:true", "/f:xml").Output(); err == nil {
		if v, err := ParseDefenderASR(raw); err == nil {
			out = append(out, v...)
		}
	}
	return Dedupe(out, 200), nil
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/agent/... && GOOS=windows go build ./...`
Expected: PASS and a clean Windows build.

- [ ] **Step 5: Commit**

```bash
git add internal/agent/runner/ internal/agent/ringfence/ cmd/agent/main.go
git commit -m "feat(agent): poll and apply ringfences, report violations"
```

---

### Task 10: HTTP API

**Files:**
- Create: `internal/server/httpapi/ringfences.go`
- Modify: `internal/server/httpapi/routes.go`
- Test: `internal/server/httpapi/ringfences_test.go`

**Interfaces:**
- Consumes: every store method from Tasks 1-3; `principalFrom`, `a.audit`, `a.storeErr`, `writeJSON`, `writeErr`, `pathID`.
- Produces: the routes listed below.

- [ ] **Step 1: Write the failing test**

```go
func TestRingfenceAPI(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)

	var created struct {
		ID string `json:"id"`
	}
	if code := c.do("POST", "/api/ringfences", map[string]string{"name": "Office"}, &created); code != 201 {
		t.Fatalf("create = %d", code)
	}
	// New ringfences must default to audit — never enforce.
	var list []map[string]any
	c.do("GET", "/api/ringfences", nil, &list)
	if len(list) != 1 || list[0]["mode"] != "audit" {
		t.Fatalf("list = %+v, want one audit-mode ringfence", list)
	}

	if code := c.do("POST", "/api/ringfences/"+created.ID+"/programs",
		map[string]any{"path": `C:\Program Files\App\app.exe`, "network_blocked": true}, nil); code != 201 {
		t.Errorf("add program = %d", code)
	}
	if code := c.do("PUT", "/api/ringfences/"+created.ID+"/protections",
		map[string]string{"asr_rule": "D4F940AB-401B-4EFC-AADC-AD5F3C50688A", "action": "block"}, nil); code != 204 {
		t.Errorf("set protection = %d", code)
	}
	// An ASR GUID outside the curated set is rejected.
	if code := c.do("PUT", "/api/ringfences/"+created.ID+"/protections",
		map[string]string{"asr_rule": "not-a-known-rule", "action": "block"}, nil); code != 400 {
		t.Errorf("unknown ASR rule = %d, want 400", code)
	}
	if code := c.do("POST", "/api/ringfences/"+created.ID+"/mode", map[string]string{"mode": "enforce"}, nil); code != 204 {
		t.Errorf("set mode = %d", code)
	}
	if code := c.do("POST", "/api/ringfences/"+created.ID+"/mode", map[string]string{"mode": "sideways"}, nil); code != 400 {
		t.Errorf("bad mode = %d, want 400", code)
	}

	// Readonly may read but not write.
	c.do("POST", "/api/admins", map[string]string{"email": "ro@example.com", "password": "readonly-password-1", "role": "readonly"}, nil)
	ro := e.client(t)
	ro.loginFull("ro@example.com", "readonly-password-1", "")
	if code := ro.do("GET", "/api/ringfences", nil, nil); code != 200 {
		t.Errorf("readonly list = %d, want 200", code)
	}
	if code := ro.do("POST", "/api/ringfences", map[string]string{"name": "Nope"}, nil); code != 403 {
		t.Errorf("readonly create = %d, want 403", code)
	}

	// Writes are audited.
	entries, _ := e.store.ListAudit(context.Background(), e.tenant(t), 50)
	seen := map[string]bool{}
	for _, en := range entries {
		seen[en.Action] = true
	}
	for _, want := range []string{"ringfence.create", "ringfence.program", "ringfence.protection", "ringfence.mode"} {
		if !seen[want] {
			t.Errorf("missing audit action %s", want)
		}
	}
}
```

Match the env helpers to whatever `helpers_test.go` actually exposes (`e.tenant(t)` may be `e.store.FirstTenant(ctx)`).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/server/httpapi/ -run TestRingfenceAPI -v`
Expected: FAIL — 404 on `/api/ringfences`.

- [ ] **Step 3: Implement the handlers and routes**

Add to `routes.go`, reads with the other unauthenticated-by-role reads:

```go
	r.Get("/api/ringfences", a.listRingfences)
	r.Get("/api/ringfences/{id}", a.getRingfence)
	r.Get("/api/ringfence-events", a.listRingfenceEvents)
```

and inside the admin-only group:

```go
	r.Post("/api/ringfences", a.createRingfence)
	r.Patch("/api/ringfences/{id}", a.renameRingfence)
	r.Delete("/api/ringfences/{id}", a.deleteRingfence)
	r.Post("/api/ringfences/{id}/mode", a.setRingfenceMode)
	r.Post("/api/ringfences/{id}/programs", a.addRingfenceProgram)
	r.Delete("/api/ringfences/{id}/programs/{programId}", a.deleteRingfenceProgram)
	r.Put("/api/ringfences/{id}/protections", a.setRingfenceProtection)
	r.Post("/api/ringfences/{id}/assign", a.assignRingfence)
	r.Delete("/api/groups/{id}/ringfence", a.unassignRingfence)
```

In `ringfences.go`, define the curated ASR set and validate against it — an admin must not be able to write an arbitrary GUID into machine policy:

```go
// asrRules is the curated set the console exposes. Writing an arbitrary GUID
// into Defender machine policy is not something an admin should be able to do
// through this API, so anything outside this set is a 400.
var asrRules = map[string]string{
	"D4F940AB-401B-4EFC-AADC-AD5F3C50688A": "Office applications creating child processes",
	"3B576869-A4EC-4529-8536-B80A7769E899": "Office applications creating executable content",
	"D3E037E1-3EB8-44C8-A917-57927947596D": "JS/VBScript launching downloaded executable content",
	"5BEB7EFE-FD9A-4556-801D-275E5FFC04CC": "Execution of potentially obfuscated scripts",
	"92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B": "Win32 API calls from Office macros",
	"D1E49AAC-8F56-4280-B9BA-993A6D77406C": "Process creation from PSExec and WMI",
}
```

Each handler follows the shape of the equivalent policy handler in `policies.go`: decode the body, validate, call the store, `a.storeErr` on failure, `a.audit(r, p, "ringfence.<verb>", "ringfence", id, detail, "success")`, then `writeJSON` or `w.WriteHeader(http.StatusNoContent)`. `setRingfenceProtection` validates `asr_rule` against `asrRules` and `action` against `audit|block|off`. `setRingfenceMode` validates `audit|enforce`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/server/httpapi/ -run TestRingfenceAPI -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/server/httpapi/ringfences.go internal/server/httpapi/routes.go internal/server/httpapi/ringfences_test.go
git commit -m "feat(api): ringfence CRUD, programs, protections and assignment"
```

---

### Task 11: Console

**Files:**
- Create: `web/src/pages/Ringfences.tsx`
- Create: `web/src/pages/RingfenceDetail.tsx`
- Modify: `web/src/App.tsx` (routes `/ringfences`, `/ringfences/:id`)
- Modify: `web/src/components/Layout.tsx` (nav item "Ringfences")
- Modify: `web/src/pages/DeviceDetail.tsx` (effective ringfence + ASR status)
- Modify: `web/src/api.ts` (types and calls)

**Interfaces:**
- Consumes: the Task 10 routes.
- Produces: the nav item and the two pages.

- [ ] **Step 1: Build the pages**

Follow `Policies.tsx` / `PolicyDetail.tsx` closely — same table density, same mutation-then-refetch pattern, same error handling through `ApiError` and `notify`.

`Ringfences.tsx`: a table of ringfences (name, mode, program count, assigned groups) with a create form and a row link to the detail page.

`RingfenceDetail.tsx`: rename, a mode control that makes the audit→enforce step explicit, a programs table (path, network blocked, note, delete) with an add form, the ASR protections list rendering all six curated rules each with an off/audit/block selector, and group assignment.

Every input needs an `aria-label` — the console has repeatedly shipped inputs with a visible `<label>` but no accessible name, which breaks Playwright's `getByLabel`. Note that `getByLabel` is substring-matching, so make labels unambiguous (`"Ringfence name"` vs `"Program path"`).

`DeviceDetail.tsx`: show the device's effective ringfence name and mode, and when the agent reports ASR unavailable, render "not enforced — Defender inactive" rather than a green tick.

- [ ] **Step 2: Type-check and build**

Run: `npm --prefix web run build`
Expected: succeeds. Remember the console is embedded at compile time — a server restart is needed before the UI change is visible.

- [ ] **Step 3: Commit**

```bash
git add web/src
git commit -m "feat(console): ringfence pages and device ringfence status"
```

---

### Task 12: E2E, docs and status

**Files:**
- Modify: `web/e2e/smoke.spec.ts`
- Create: `docs/ringfence-manual-test.md`
- Modify: `README.md`

- [ ] **Step 1: Extend the Playwright smoke test**

Append to the existing smoke flow, after the notifications block:

```ts
  // Ringfences: create, add a program, set a protection to audit, assign to
  // a group, switch to enforce, delete.
  await page.getByRole("link", { name: "Ringfences" }).click();
  await expect(page.getByRole("heading", { name: "Ringfences" })).toBeVisible();
  await page.getByLabel("Ringfence name").fill("Office apps");
  await page.getByRole("button", { name: "Create ringfence" }).click();
  await page.getByRole("link", { name: "Office apps" }).click();
  // A new ringfence must start in audit mode.
  await expect(page.getByLabel("Ringfence mode")).toHaveText("audit");

  await page.getByLabel("Program path").fill("C:\\Program Files\\App\\app.exe");
  await page.getByRole("button", { name: "Add program" }).click();
  await expect(page.getByRole("cell", { name: "C:\\Program Files\\App\\app.exe" })).toBeVisible();

  await page.getByLabel("Office applications creating child processes").selectOption("audit");
  await expect(page.getByLabel("Office applications creating child processes")).toHaveValue("audit");

  await page.getByRole("button", { name: "Switch to enforce" }).click();
  await expect(page.getByLabel("Ringfence mode")).toHaveText("enforce");

  await page.getByRole("button", { name: "Delete ringfence" }).click();
  await expect(page.getByText("No ringfences yet.")).toBeVisible();
```

- [ ] **Step 2: Run the E2E suite**

Follow `web/e2e/README.md`: drop and recreate `freelocker_e2e`, rebuild the console, restart the server, then
`cd web && E2E_BASE_URL=http://localhost:8080 npm run test:e2e`.
Expected: PASS.

- [ ] **Step 3: Write the VM checklist**

`docs/ringfence-manual-test.md`, in the style of the existing checklists:

```markdown
# Ringfencing — manual test (VM only)

Never run these against the dev box. Enforcement changes firewall rules and
Defender machine policy.

## Network containment
1. Create a ringfence, add `C:\Windows\System32\curl.exe`, leave it in audit.
   Assign it to the VM's group. On the VM, run `curl https://example.com` —
   it must SUCCEED, and within a minute a ringfence event appears with
   enforced = false (would have blocked).
2. Switch the ringfence to enforce. Re-run the curl — it must FAIL, and an
   event appears with enforced = true.
3. Confirm the agent still checks in: ringfencing curl must not affect the
   agent's own connection.
4. Try to ringfence the agent's own exe. The agent must refuse and log
   "refusing to ringfence the agent's own image".

## Child-process containment
5. Set "Office applications creating child processes" to audit. On the VM,
   have Word run a macro that launches PowerShell — it must SUCCEED and
   produce a child_process event with enforced = false.
6. Set it to block. Repeat — PowerShell must not launch, and the event has
   enforced = true.

## Reversibility
7. Unassign the ringfence. Confirm `netsh advfirewall firewall show rule
   name=all | findstr FreeLocker-RF` returns nothing, and that the ASR
   policy key has no values left.

## Defender inactive
8. Disable Defender real-time protection. The console must show
   "not enforced — Defender inactive" on the device, not a green tick.
```

- [ ] **Step 4: Update the README**

Add ringfencing to the capability paragraph, and state plainly that network and child-process containment are **built and tested, enforcement not yet verified on a VM** — do not imply otherwise. Note that file and registry containment remain part of sub-project 5.

- [ ] **Step 5: Full verification and commit**

Run: `go vet ./... && go test ./... && GOOS=linux go build ./... && npm --prefix web run build`
Expected: all clean.

```bash
git add web/e2e/smoke.spec.ts docs/ringfence-manual-test.md README.md
git commit -m "test(e2e): ringfence console flow; docs: VM checklist and status"
```

---

## Self-review notes

- **Spec coverage:** tables → Task 1; programs/protections/assignment/resolution → Task 2; events table → Task 3; protocol → Task 4; agent API → Task 5; agent package and diff → Task 6; parsers and noise mitigation → Task 7; Windows enforcer, firewall, ASR, Defender availability → Task 8; runner wiring and the self-exclusion safety rule → Tasks 8-9; HTTP API and audit → Task 10; console → Task 11; E2E, VM checklist, README honesty → Task 12.
- **Deviation from the spec, deliberate:** the spec wrote `PUT /api/ringfences/{id}/protections` and `PATCH` for mode; the plan uses `POST /…/mode` and `POST /…/assign` to match the existing `policies` routes. `PUT` is kept for protections because it is a true upsert of one keyed row.
- **Deviation from the spec, deliberate:** `ringfence_protections.action` has no `'off'` value — off is the absence of a row, so there is exactly one representation of that state. `SetRingfenceProtection(…, "off")` deletes.
- **Known soft spot:** `normalisePath` in Task 7 matches WFP `\device\harddiskvolumeN\…` paths against `C:\…` ringfence entries by path tail, not by resolving the volume. A program at the same tail path on a second volume would match. Resolving volume numbers to drive letters needs `QueryDosDevice`; if the VM run shows this matters, that is the fix.
