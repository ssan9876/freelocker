# Staged Agent Rollouts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let admins push an agent release to the fleet in batches with pause, resume, cancel, auto-pause on failures, and one-click rollback, and fix the per-device "Update agent" command that currently sends an empty payload.

**Architecture:** A new `agent_rollouts` table plus per-device progress rows; a reconciler (`internal/server/rollout`) driven from the server's existing minute ticker that issues signed `update_agent` commands through the existing `commands.Service`; admin HTTP routes; a Rollouts section on the console's Releases page. No proto or agent change.

**Tech Stack:** Go 1.2x, pgx v5, goose migrations, chi router, React + TypeScript (Vite), Playwright.

**Spec:** `docs/superpowers/specs/2026-09-14-agent-rollouts-design.md`

## Global Constraints

- Postgres test DB must be running: `docker compose -f deploy/docker-compose.dev.yml up -d` (port 55432). Store/API tests use `storetest.New(t)` which gives each test its own schema.
- Migrations live in `internal/server/store/migrations/`; next number is `0017`. Goose format (`-- +goose Up` / `-- +goose Down`).
- Versions are opaque strings; "current" means `devices.agent_version = rollout.version` (string equality).
- One non-terminal rollout (`active` or `paused`) per tenant, enforced by a partial unique index.
- Rollout states: `active | paused | completed | cancelled`. Device states: `issued | updated | failed`.
- Defaults: `batch_size` 10, `max_failures` 3 (0 disables auto-pause), `ConfirmTimeout` 10 min.
- Actor strings: admin actions `admin:<email>`; reconciler `rollout:<id>`; auto-pause audit actor `system`.
- Console build: `npm --prefix web run build` (runs `tsc -b`). Every new input needs an `aria-label`.
- `-race` is unavailable on the dev box (no cgo); run `go test ./...` without it.
- Commit after every task with the trailer `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- Work on branch `feat/agent-rollouts` off `master`.

---

## File map

| File | Responsibility |
|---|---|
| `internal/server/config/config.go` | new `ReleaseBaseURL` field + `ReleaseURL(version)` |
| `internal/server/httpapi/api.go` | new `API.ReleaseURL func(string) string`; `Runtime.Rollouts` |
| `internal/server/httpapi/devices.go` | `update_agent` issued via `IssueUpdate` |
| `internal/server/store/migrations/0017_agent_rollouts.sql` | tables + partial unique index |
| `internal/server/store/rollouts.go` | rollout types, CRUD, candidates, resolution, summary |
| `internal/server/rollout/rollout.go` | reconciler `Service` with `Tick`/`Reconcile` |
| `internal/server/app/app.go` | build reconciler, call `Tick` from the ticker |
| `internal/server/httpapi/rollouts.go` | HTTP handlers |
| `internal/server/httpapi/routes.go` | routes |
| `web/src/api.ts` | `Rollout`, `RolloutSummary`, `RolloutDevice` types |
| `web/src/pages/Releases.tsx` | Start rollout form, rollout card, device table, history |
| `web/e2e/smoke.spec.ts` | Releases page assertions |
| `README.md` | capability line |

---

### Task 1: Release download URL config and the per-device update fix

**Files:**
- Modify: `internal/server/config/config.go`
- Test: `internal/server/config/config_test.go` (create if absent)
- Modify: `internal/server/httpapi/api.go:38-50` (API struct)
- Modify: `internal/server/httpapi/devices.go:100-131` (`issueCommand`)
- Modify: `internal/server/httpapi/helpers_test.go:52-55` (set `ReleaseURL` on the test API)
- Modify: `internal/server/app/app.go:81-85` (pass `ReleaseURL` into the API)
- Test: `internal/server/httpapi/update_command_test.go`

**Interfaces:**
- Produces: `func (c Config) ReleaseURL(version string) string`; `API.ReleaseURL func(version string) string`.
- Later tasks call `API.ReleaseURL` from the reconciler wiring in `app.go`.

- [ ] **Step 1: Write the failing config test**

Create `internal/server/config/config_test.go` (if a file with that name exists, add the function to it):

```go
package config

import "testing"

func TestReleaseURLDefaultsAndOverride(t *testing.T) {
	c := Config{PublicHostnames: []string{"console.example.com"}, ConsoleListen: ":8080"}
	if got := c.ReleaseURL("1.2.3"); got != "http://console.example.com:8080/agent/releases/1.2.3" {
		t.Errorf("plain default = %q", got)
	}
	c.ConsoleTLSCert = "cert.pem"
	if got := c.ReleaseURL("1.2.3"); got != "https://console.example.com:8080/agent/releases/1.2.3" {
		t.Errorf("tls default = %q", got)
	}
	c.ReleaseBaseURL = "https://updates.example.com/"
	if got := c.ReleaseURL("1.2.3"); got != "https://updates.example.com/agent/releases/1.2.3" {
		t.Errorf("override = %q (trailing slash must be trimmed)", got)
	}
	c = Config{ConsoleListen: "0.0.0.0:443"}
	if got := c.ReleaseURL("v"); got != "http://localhost:443/agent/releases/v" {
		t.Errorf("no hostnames = %q", got)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/server/config/ -run TestReleaseURL -v`
Expected: FAIL, `c.ReleaseBaseURL undefined` / `c.ReleaseURL undefined`.

- [ ] **Step 3: Implement**

In `internal/server/config/config.go` add the field after `ReleaseDir`:

```go
	ReleaseBaseURL       string   `yaml:"release_base_url"`       // agents download releases from <this>/agent/releases/<version>; default derived from public_hostnames + console_listen
```

Add the env read next to `FREELOCKER_RELEASE_DIR`:

```go
	envStr(&c.ReleaseBaseURL, "FREELOCKER_RELEASE_BASE_URL")
```

Add the method (imports: `net`, `strings` — `strings` is already imported):

```go
// ReleaseURL is the URL an agent downloads a release from. ReleaseBaseURL
// wins when set; otherwise it is built from the first public hostname and
// the console listener's port, https unless the console has no TLS.
func (c Config) ReleaseURL(version string) string {
	base := strings.TrimRight(c.ReleaseBaseURL, "/")
	if base == "" {
		host := "localhost"
		if len(c.PublicHostnames) > 0 && c.PublicHostnames[0] != "" {
			host = c.PublicHostnames[0]
		}
		scheme := "https"
		if c.ConsoleTLSMode() == "plain" {
			scheme = "http"
		}
		_, port, err := net.SplitHostPort(c.ConsoleListen)
		if err != nil || port == "" {
			port = "8080"
		}
		base = scheme + "://" + host + ":" + port
	}
	return base + "/agent/releases/" + version
}
```

- [ ] **Step 4: Run config tests**

Run: `go test ./internal/server/config/ -v`
Expected: PASS.

- [ ] **Step 5: Write the failing HTTP test for the per-device update command**

Create `internal/server/httpapi/update_command_test.go`:

```go
package httpapi_test

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"testing"

	"freelocker/internal/server/commands"
)

// uploadRelease pushes a fake binary through the real upload endpoint so a
// release row + file exist for the tenant.
func (c *client) uploadRelease(t *testing.T, version string) {
	t.Helper()
	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	mw.WriteField("version", version)
	fw, _ := mw.CreateFormFile("file", "agent.exe")
	fw.Write([]byte("fake-agent-binary-" + version))
	mw.Close()
	req, _ := http.NewRequest("POST", c.base+"/api/releases", body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-CSRF-Token", c.csrf)
	resp, err := c.http.Do(req)
	if err != nil || resp.StatusCode != 201 {
		t.Fatalf("upload %s = %v %v", version, resp.StatusCode, err)
	}
	resp.Body.Close()
}

func TestUpdateAgentCommandCarriesReleasePayload(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)
	dev := e.fakeDevice(t)

	// No release yet → 409.
	if code := c.do("POST", "/api/devices/"+dev.String()+"/commands", map[string]string{"type": "update_agent"}, nil); code != 409 {
		t.Fatalf("no release: code = %d, want 409", code)
	}

	c.uploadRelease(t, "1.0.0")
	c.uploadRelease(t, "1.0.1") // latest
	var res idResp
	if code := c.do("POST", "/api/devices/"+dev.String()+"/commands", map[string]string{"type": "update_agent"}, &res); code != 201 {
		t.Fatalf("issue = %d", code)
	}

	k := e.rt().Keys
	cmds, err := e.store.ListDeviceCommands(context.Background(), k.TenantID, dev, 10)
	if err != nil || len(cmds) != 1 {
		t.Fatalf("commands = %v, %v", cmds, err)
	}
	p, err := commands.ParseUpdate(cmds[0].Payload)
	if err != nil {
		t.Fatalf("payload not parseable: %v", err)
	}
	if p.Version != "1.0.1" || p.URL != "http://test.local/agent/releases/1.0.1" || len(p.SHA256) != 32 || len(p.Signature) == 0 {
		t.Errorf("payload = %+v", p)
	}
}
```

- [ ] **Step 6: Run it to verify it fails**

Run: `go test ./internal/server/httpapi/ -run TestUpdateAgentCommandCarriesReleasePayload -v`
Expected: FAIL at the 409 assertion (currently returns 201 with an empty payload).

- [ ] **Step 7: Implement**

In `internal/server/httpapi/api.go`, add to the `API` struct after `ReleaseDir`:

```go
	// ReleaseURL builds the URL an agent downloads a release version from.
	ReleaseURL func(version string) string
```

In `internal/server/httpapi/devices.go` replace the `Issue` call in `issueCommand` (the block starting `cmdID, err := a.Runtime().Commands.Issue(...)`) with:

```go
	var cmdID uuid.UUID
	if typ == flv1.CommandType_COMMAND_TYPE_UPDATE_AGENT {
		rel, err := a.Store.LatestRelease(r.Context(), p.TenantID)
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusConflict, "no agent release uploaded")
			return
		}
		if err != nil {
			a.storeErr(w, err)
			return
		}
		cmdID, err = a.Runtime().Commands.IssueUpdate(r.Context(), p.TenantID, id, a.updatePayload(rel), "admin:"+p.Admin.Email)
		if err != nil {
			a.storeErr(w, err)
			return
		}
	} else {
		var err error
		cmdID, err = a.Runtime().Commands.Issue(r.Context(), p.TenantID, id, typ, nil, &p.Admin.ID, "admin:"+p.Admin.Email)
		if err != nil {
			a.storeErr(w, err)
			return
		}
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": cmdID.String()})
```

Add the helper at the bottom of `devices.go`:

```go
// updatePayload turns a stored release into the signed command payload the
// agent verifies before installing.
func (a *API) updatePayload(rel store.Release) commands.UpdatePayload {
	return commands.UpdatePayload{Version: rel.Version, URL: a.ReleaseURL(rel.Version), SHA256: rel.SHA256, Signature: rel.Signature}
}
```

Add imports `errors`, `flv1 "freelocker/gen/freelocker/v1"`, `freelocker/internal/server/store`, `github.com/google/uuid` to `devices.go` if not present.

In `internal/server/httpapi/helpers_test.go`, in the `api := &httpapi.API{...}` literal add:

```go
		ReleaseURL: func(v string) string { return "http://test.local/agent/releases/" + v },
```

In `internal/server/app/app.go` `NewWithStore`, in the `api := &httpapi.API{...}` literal add `ReleaseURL: cfg.ReleaseURL,`.

- [ ] **Step 8: Run the tests**

Run: `go test ./internal/server/httpapi/ ./internal/server/config/ ./internal/server/app/`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git checkout -b feat/agent-rollouts
git add internal/server/config internal/server/httpapi internal/server/app
git commit -m "server: per-device update_agent carries a real release payload; release_base_url config

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 2: Migration and rollout store CRUD

**Files:**
- Create: `internal/server/store/migrations/0017_agent_rollouts.sql`
- Create: `internal/server/store/rollouts.go`
- Test: `internal/server/store/rollouts_test.go`

**Interfaces:**
- Produces:
  ```go
  type Rollout struct { ID uuid.UUID; Version string; GroupIDs []uuid.UUID; BatchSize, MaxFailures int; State, CreatedBy string; CreatedAt, UpdatedAt time.Time; FinishedAt *time.Time }
  type OpenRollout struct { TenantID uuid.UUID; Rollout }
  func (s *Store) CreateRollout(ctx, tenantID uuid.UUID, r Rollout) error         // ErrNotFound if version unknown; ErrConflict if one is open
  func (s *Store) GetRollout(ctx, tenantID, id uuid.UUID) (Rollout, error)
  func (s *Store) ListRollouts(ctx, tenantID uuid.UUID, limit int) ([]Rollout, error)
  func (s *Store) SetRolloutState(ctx, tenantID, id uuid.UUID, from []string, to string, now time.Time) error // ErrConflict if state not in from
  func (s *Store) OpenRollouts(ctx) ([]OpenRollout, error)                         // active, non-suspended tenants
  ```

- [ ] **Step 1: Write the migration**

Create `internal/server/store/migrations/0017_agent_rollouts.sql`:

```sql
-- +goose Up
-- Staged agent update rollouts: one open (active|paused) rollout per tenant,
-- per-device progress rows resolved from command results + reported version.
CREATE TABLE agent_rollouts (
    id            uuid PRIMARY KEY,
    tenant_id     uuid NOT NULL REFERENCES tenants(id),
    version       text NOT NULL,
    group_ids     uuid[] NOT NULL DEFAULT '{}',
    batch_size    int  NOT NULL,
    max_failures  int  NOT NULL,
    state         text NOT NULL,
    created_by    text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    finished_at   timestamptz,
    CONSTRAINT agent_rollouts_state_chk CHECK (state IN ('active', 'paused', 'completed', 'cancelled'))
);
CREATE UNIQUE INDEX agent_rollouts_one_open ON agent_rollouts (tenant_id) WHERE state IN ('active', 'paused');
CREATE INDEX agent_rollouts_tenant_created ON agent_rollouts (tenant_id, created_at DESC);

CREATE TABLE agent_rollout_devices (
    rollout_id   uuid NOT NULL REFERENCES agent_rollouts(id) ON DELETE CASCADE,
    device_id    uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    command_id   uuid NOT NULL,
    state        text NOT NULL,
    detail       text NOT NULL DEFAULT '',
    issued_at    timestamptz NOT NULL,
    resolved_at  timestamptz,
    PRIMARY KEY (rollout_id, device_id),
    CONSTRAINT agent_rollout_devices_state_chk CHECK (state IN ('issued', 'updated', 'failed'))
);

-- +goose Down
DROP TABLE agent_rollout_devices;
DROP TABLE agent_rollouts;
```

- [ ] **Step 2: Write the failing store test**

Create `internal/server/store/rollouts_test.go`:

```go
package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"

	"github.com/google/uuid"
)

func TestRolloutCreateGetListConflict(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	s.PutRelease(ctx, tenant, store.Release{Version: "1.0.1", SHA256: make([]byte, 32), Signature: []byte("sig")})

	// Unknown version → ErrNotFound.
	err := s.CreateRollout(ctx, tenant, store.Rollout{ID: uuid.New(), Version: "9.9.9", BatchSize: 5, MaxFailures: 1, State: "active", CreatedBy: "admin:a@x"})
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown version err = %v", err)
	}

	gid, _ := s.CreateDeviceGroup(ctx, tenant, "WS")
	r := store.Rollout{ID: uuid.New(), Version: "1.0.1", GroupIDs: []uuid.UUID{gid}, BatchSize: 5, MaxFailures: 1, State: "active", CreatedBy: "admin:a@x"}
	if err := s.CreateRollout(ctx, tenant, r); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetRollout(ctx, tenant, r.ID)
	if err != nil || got.Version != "1.0.1" || len(got.GroupIDs) != 1 || got.GroupIDs[0] != gid || got.BatchSize != 5 || got.State != "active" || got.CreatedBy != "admin:a@x" {
		t.Fatalf("get = %+v, %v", got, err)
	}

	// A second open rollout in the tenant → ErrConflict.
	err = s.CreateRollout(ctx, tenant, store.Rollout{ID: uuid.New(), Version: "1.0.1", BatchSize: 1, MaxFailures: 0, State: "active", CreatedBy: "x"})
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("second open err = %v", err)
	}

	// Other tenant cannot see it.
	other, _ := s.CreateTenant(ctx, "Beta")
	if _, err := s.GetRollout(ctx, other, r.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("cross-tenant get err = %v", err)
	}

	list, err := s.ListRollouts(ctx, tenant, 10)
	if err != nil || len(list) != 1 || list[0].ID != r.ID {
		t.Fatalf("list = %+v, %v", list, err)
	}
}

func TestRolloutStateTransitions(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	s.PutRelease(ctx, tenant, store.Release{Version: "1.0.1", SHA256: make([]byte, 32), Signature: []byte("sig")})
	r := store.Rollout{ID: uuid.New(), Version: "1.0.1", BatchSize: 5, MaxFailures: 1, State: "active", CreatedBy: "x"}
	s.CreateRollout(ctx, tenant, r)
	now := time.Now()

	if err := s.SetRolloutState(ctx, tenant, r.ID, []string{"paused"}, "active", now); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("resume an active rollout err = %v, want ErrConflict", err)
	}
	if err := s.SetRolloutState(ctx, tenant, r.ID, []string{"active"}, "paused", now); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetRollout(ctx, tenant, r.ID)
	if got.State != "paused" || got.FinishedAt != nil {
		t.Fatalf("after pause = %+v", got)
	}
	if err := s.SetRolloutState(ctx, tenant, r.ID, []string{"active", "paused"}, "cancelled", now); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetRollout(ctx, tenant, r.ID)
	if got.State != "cancelled" || got.FinishedAt == nil {
		t.Fatalf("after cancel = %+v", got)
	}
	// Terminal: a new open rollout is now allowed.
	if err := s.CreateRollout(ctx, tenant, store.Rollout{ID: uuid.New(), Version: "1.0.1", BatchSize: 1, MaxFailures: 0, State: "active", CreatedBy: "x"}); err != nil {
		t.Fatalf("create after cancel: %v", err)
	}
	// Unknown id → ErrNotFound.
	if err := s.SetRolloutState(ctx, tenant, uuid.New(), []string{"active"}, "paused", now); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown id err = %v", err)
	}
}

func TestOpenRolloutsSkipsSuspendedTenants(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	a, _ := s.CreateTenant(ctx, "A")
	b, _ := s.CreateTenant(ctx, "B")
	for _, tid := range []uuid.UUID{a, b} {
		s.PutRelease(ctx, tid, store.Release{Version: "1", SHA256: make([]byte, 32), Signature: []byte("s")})
		s.CreateRollout(ctx, tid, store.Rollout{ID: uuid.New(), Version: "1", BatchSize: 1, MaxFailures: 0, State: "active", CreatedBy: "x"})
	}
	s.SetTenantSuspended(ctx, b, true)
	open, err := s.OpenRollouts(ctx)
	if err != nil || len(open) != 1 || open[0].TenantID != a {
		t.Fatalf("open = %+v, %v", open, err)
	}
}
```

Check the suspend helper name: `grep -n "Suspend" internal/server/store/tenants.go`. If it is not `SetTenantSuspended(ctx, id, bool)`, use the actual name.

- [ ] **Step 3: Run to verify failure**

Run: `go test ./internal/server/store/ -run 'TestRollout|TestOpenRollouts' -v`
Expected: FAIL, undefined `store.Rollout` etc.

- [ ] **Step 4: Implement the store**

Create `internal/server/store/rollouts.go`:

```go
package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Rollout is a staged agent update: one release version pushed to a set of
// groups (empty = every device) in batches.
type Rollout struct {
	ID          uuid.UUID
	Version     string
	GroupIDs    []uuid.UUID
	BatchSize   int
	MaxFailures int
	State       string // active|paused|completed|cancelled
	CreatedBy   string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	FinishedAt  *time.Time
}

// OpenRollout is an active rollout together with its tenant, for the ticker.
type OpenRollout struct {
	TenantID uuid.UUID
	Rollout
}

const rolloutCols = `id, version, group_ids, batch_size, max_failures, state, created_by, created_at, updated_at, finished_at`

func scanRollout(r pgx.Row) (Rollout, error) {
	var o Rollout
	err := r.Scan(&o.ID, &o.Version, &o.GroupIDs, &o.BatchSize, &o.MaxFailures, &o.State, &o.CreatedBy, &o.CreatedAt, &o.UpdatedAt, &o.FinishedAt)
	if o.GroupIDs == nil {
		o.GroupIDs = []uuid.UUID{}
	}
	return o, err
}

// CreateRollout inserts a rollout. ErrNotFound when the version is not an
// uploaded release of the tenant; ErrConflict when the tenant already has an
// open (active|paused) rollout — enforced by a partial unique index so two
// concurrent creates cannot both succeed.
func (s *Store) CreateRollout(ctx context.Context, tenantID uuid.UUID, r Rollout) error {
	if r.GroupIDs == nil {
		r.GroupIDs = []uuid.UUID{}
	}
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO agent_rollouts (id, tenant_id, version, group_ids, batch_size, max_failures, state, created_by)
		SELECT $1, $2, $3, $4, $5, $6, $7, $8
		WHERE EXISTS (SELECT 1 FROM agent_releases WHERE tenant_id = $2 AND version = $3)`,
		r.ID, tenantID, r.Version, r.GroupIDs, r.BatchSize, r.MaxFailures, r.State, r.CreatedBy)
	if err != nil {
		return conflict(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) GetRollout(ctx context.Context, tenantID, id uuid.UUID) (Rollout, error) {
	o, err := scanRollout(s.pool.QueryRow(ctx, `SELECT `+rolloutCols+` FROM agent_rollouts WHERE tenant_id = $1 AND id = $2`, tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return o, err
}

func (s *Store) ListRollouts(ctx context.Context, tenantID uuid.UUID, limit int) ([]Rollout, error) {
	rows, _ := s.pool.Query(ctx, `SELECT `+rolloutCols+` FROM agent_rollouts WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2`, tenantID, limit)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Rollout, error) { return scanRollout(r) })
}

// SetRolloutState moves a rollout from one of the `from` states to `to`.
// ErrNotFound when the rollout is not in the tenant; ErrConflict when its
// current state is not in `from`. Terminal states record finished_at.
func (s *Store) SetRolloutState(ctx context.Context, tenantID, id uuid.UUID, from []string, to string, now time.Time) error {
	terminal := to == "completed" || to == "cancelled"
	tag, err := s.pool.Exec(ctx, `
		UPDATE agent_rollouts SET state = $4, updated_at = $5,
			finished_at = CASE WHEN $6 THEN $5 ELSE finished_at END
		WHERE tenant_id = $1 AND id = $2 AND state = ANY($3)`,
		tenantID, id, from, to, now, terminal)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	if _, err := s.GetRollout(ctx, tenantID, id); err != nil {
		return err
	}
	return ErrConflict
}

// OpenRollouts lists every active rollout of every non-suspended tenant.
func (s *Store) OpenRollouts(ctx context.Context) ([]OpenRollout, error) {
	rows, _ := s.pool.Query(ctx, `
		SELECT r.tenant_id, `+prefixCols("r.", rolloutCols)+`
		FROM agent_rollouts r JOIN tenants t ON t.id = r.tenant_id
		WHERE r.state = 'active' AND NOT t.suspended ORDER BY r.created_at`)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (OpenRollout, error) {
		var o OpenRollout
		err := r.Scan(&o.TenantID, &o.ID, &o.Version, &o.GroupIDs, &o.BatchSize, &o.MaxFailures, &o.State, &o.CreatedBy, &o.CreatedAt, &o.UpdatedAt, &o.FinishedAt)
		if o.GroupIDs == nil {
			o.GroupIDs = []uuid.UUID{}
		}
		return o, err
	})
}
```

Add to the same file a tiny helper (unless one already exists — `grep -n "func prefixCols" internal/server/store/*.go`):

```go
// prefixCols prefixes every comma-separated column in cols with p.
func prefixCols(p, cols string) string {
	parts := strings.Split(cols, ", ")
	for i := range parts {
		parts[i] = p + parts[i]
	}
	return strings.Join(parts, ", ")
}
```

(add `"strings"` to imports.) Check the `tenants` table has a `suspended` column: `grep -n suspended internal/server/store/migrations/0014_tenant_suspend.sql`.

- [ ] **Step 5: Run tests**

Run: `go test ./internal/server/store/ -run 'TestRollout|TestOpenRollouts' -v`
Expected: PASS. If `uuid[]` scanning fails, scan `GroupIDs` as `[]uuid.UUID` is supported by pgx v5's uuid codec via `google/uuid`'s `Scan`; if it errors, scan into `[][16]byte` and convert.

- [ ] **Step 6: Commit**

```bash
git add internal/server/store
git commit -m "store: agent rollouts table, CRUD, guarded state transitions

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 3: Rollout device rows, candidates, resolution, summary

**Files:**
- Modify: `internal/server/store/rollouts.go`
- Test: `internal/server/store/rollouts_test.go`

**Interfaces:**
- Produces:
  ```go
  type RolloutDevice struct { DeviceID uuid.UUID; Hostname, State, Detail string; CommandID uuid.UUID; IssuedAt time.Time; ResolvedAt *time.Time }
  type RolloutCandidate struct { DeviceID uuid.UUID; Hostname string }
  type RolloutSummary struct { Targeted, AlreadyCurrent, Issued, Updated, Failed, Remaining int }
  func (s *Store) RolloutCandidates(ctx, tenantID, id uuid.UUID) ([]RolloutCandidate, error)
  func (s *Store) AddRolloutDevice(ctx, rolloutID, deviceID, commandID uuid.UUID, now time.Time) error
  func (s *Store) ListRolloutDevices(ctx, tenantID, id uuid.UUID) ([]RolloutDevice, error)
  func (s *Store) ResolveRolloutDevices(ctx, tenantID, id uuid.UUID, now time.Time, confirmTimeout time.Duration) (updated, failed int, err error)
  func (s *Store) RolloutSummary(ctx, tenantID, id uuid.UUID) (RolloutSummary, error)
  ```

- [ ] **Step 1: Write the failing tests**

Append to `internal/server/store/rollouts_test.go`:

```go
// enrollTestDevice creates a device in the tenant (optionally in a group)
// reporting the given agent version.
func enrollTestDevice(t *testing.T, s *store.Store, tenant uuid.UUID, group *uuid.UUID, hostname, version string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	id := uuid.New()
	hash := []byte("h-" + id.String())
	if _, err := s.CreateInstallToken(ctx, tenant, store.InstallToken{Name: hostname, GroupID: group}, hash); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnrollDevice(ctx, hash, time.Now(), func(uuid.UUID) (store.NewDevice, error) {
		return store.NewDevice{ID: id, Hostname: hostname, CertSerial: "s-" + hostname, CertExpiresAt: time.Now().Add(time.Hour)}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordHeartbeat(ctx, tenant, id, store.Inventory{Hostname: hostname, AgentVersion: version}, time.Now()); err != nil {
		t.Fatal(err)
	}
	return id
}

func newTestRollout(t *testing.T, s *store.Store, tenant uuid.UUID, groups []uuid.UUID) store.Rollout {
	t.Helper()
	ctx := context.Background()
	s.PutRelease(ctx, tenant, store.Release{Version: "2.0.0", SHA256: make([]byte, 32), Signature: []byte("sig")})
	r := store.Rollout{ID: uuid.New(), Version: "2.0.0", GroupIDs: groups, BatchSize: 10, MaxFailures: 3, State: "active", CreatedBy: "x"}
	if err := s.CreateRollout(ctx, tenant, r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRolloutCandidates(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	ws, _ := s.CreateDeviceGroup(ctx, tenant, "WS")
	srv, _ := s.CreateDeviceGroup(ctx, tenant, "SRV")
	old := enrollTestDevice(t, s, tenant, &ws, "b-old", "1.0.0")
	enrollTestDevice(t, s, tenant, &ws, "a-current", "2.0.0")
	enrollTestDevice(t, s, tenant, &srv, "c-other-group", "1.0.0")
	revoked := enrollTestDevice(t, s, tenant, &ws, "d-revoked", "1.0.0")
	s.RevokeDevice(ctx, tenant, revoked)
	rowed := enrollTestDevice(t, s, tenant, &ws, "e-rowed", "1.0.0")

	r := newTestRollout(t, s, tenant, []uuid.UUID{ws})
	s.AddRolloutDevice(ctx, r.ID, rowed, uuid.New(), time.Now())

	c, err := s.RolloutCandidates(ctx, tenant, r.ID)
	if err != nil || len(c) != 1 || c[0].DeviceID != old || c[0].Hostname != "b-old" {
		t.Fatalf("group candidates = %+v, %v (want only b-old)", c, err)
	}

	// Empty group set = every device in the tenant.
	s.SetRolloutState(ctx, tenant, r.ID, []string{"active"}, "cancelled", time.Now())
	all := newTestRollout(t, s, tenant, nil)
	c, _ = s.RolloutCandidates(ctx, tenant, all.ID)
	if len(c) != 3 || c[0].Hostname != "b-old" || c[1].Hostname != "c-other-group" || c[2].Hostname != "e-rowed" {
		t.Fatalf("all candidates = %+v (want b-old, c-other-group, e-rowed by hostname)", c)
	}
}

func TestResolveRolloutDevices(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	r := newTestRollout(t, s, tenant, nil)
	now := time.Now()
	timeout := 10 * time.Minute

	mk := func(name string) (uuid.UUID, uuid.UUID) {
		dev := enrollTestDevice(t, s, tenant, nil, name, "1.0.0")
		cmd := uuid.New()
		if err := s.CreateCommand(ctx, tenant, store.Command{ID: cmd, DeviceID: dev, Type: "update_agent", IssuedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		if err := s.AddRolloutDevice(ctx, r.ID, dev, cmd, now); err != nil {
			t.Fatal(err)
		}
		return dev, cmd
	}
	updatedDev, updatedCmd := mk("updated")
	failedDev, failedCmd := mk("failed")
	timedOutDev, timedOutCmd := mk("timedout")
	freshDev, freshCmd := mk("fresh")
	_, _ = mk("pending")

	// updated: command succeeded AND version reported.
	s.CompleteCommand(ctx, tenant, updatedDev, updatedCmd, true, "ok", now)
	s.RecordHeartbeat(ctx, tenant, updatedDev, store.Inventory{Hostname: "updated", AgentVersion: "2.0.0"}, now)
	// failed: command result failure.
	s.CompleteCommand(ctx, tenant, failedDev, failedCmd, false, "hash mismatch", now)
	// timed out: succeeded long ago, still old version.
	s.CompleteCommand(ctx, tenant, timedOutDev, timedOutCmd, true, "ok", now.Add(-timeout-time.Minute))
	// fresh: succeeded just now, old version → still issued.
	s.CompleteCommand(ctx, tenant, freshDev, freshCmd, true, "ok", now)

	up, fail, err := s.ResolveRolloutDevices(ctx, tenant, r.ID, now, timeout)
	if err != nil || up != 1 || fail != 2 {
		t.Fatalf("resolve = %d updated, %d failed, %v (want 1, 2)", up, fail, err)
	}
	devs, _ := s.ListRolloutDevices(ctx, tenant, r.ID)
	states := map[string]string{}
	details := map[string]string{}
	for _, d := range devs {
		states[d.Hostname] = d.State
		details[d.Hostname] = d.Detail
	}
	want := map[string]string{"updated": "updated", "failed": "failed", "timedout": "failed", "fresh": "issued", "pending": "issued"}
	for h, st := range want {
		if states[h] != st {
			t.Errorf("%s state = %q, want %q", h, states[h], st)
		}
	}
	if details["failed"] != "failed: hash mismatch" {
		t.Errorf("failed detail = %q", details["failed"])
	}
	if details["timedout"] == "" {
		t.Error("timed-out device should carry a detail")
	}
	// Idempotent: nothing new resolves on a second call.
	up, fail, _ = s.ResolveRolloutDevices(ctx, tenant, r.ID, now, timeout)
	if up != 0 || fail != 0 {
		t.Errorf("second resolve = %d, %d", up, fail)
	}

	sum, err := s.RolloutSummary(ctx, tenant, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Targeted != 5 || sum.AlreadyCurrent != 0 || sum.Issued != 2 || sum.Updated != 1 || sum.Failed != 2 || sum.Remaining != 0 {
		t.Errorf("summary = %+v", sum)
	}
}

func TestRolloutSummaryCountsCurrentAndRemaining(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	enrollTestDevice(t, s, tenant, nil, "cur", "2.0.0")
	enrollTestDevice(t, s, tenant, nil, "old1", "1.0.0")
	enrollTestDevice(t, s, tenant, nil, "old2", "1.0.0")
	r := newTestRollout(t, s, tenant, nil)
	sum, _ := s.RolloutSummary(ctx, tenant, r.ID)
	if sum.Targeted != 3 || sum.AlreadyCurrent != 1 || sum.Remaining != 2 || sum.Issued != 0 {
		t.Errorf("summary = %+v", sum)
	}
	// Expired command → failed.
	dev := enrollTestDevice(t, s, tenant, nil, "old3", "1.0.0")
	cmd := uuid.New()
	past := time.Now().Add(-2 * time.Hour)
	s.CreateCommand(ctx, tenant, store.Command{ID: cmd, DeviceID: dev, Type: "update_agent", IssuedAt: past, ExpiresAt: past.Add(time.Hour)})
	s.AddRolloutDevice(ctx, r.ID, dev, cmd, past)
	s.ExpireCommands(ctx, time.Now())
	_, fail, _ := s.ResolveRolloutDevices(ctx, tenant, r.ID, time.Now(), 10*time.Minute)
	if fail != 1 {
		t.Errorf("expired command should fail the device; failed = %d", fail)
	}
}
```

Verify helper names before running: `grep -n "func (s \*Store) RevokeDevice\|func (s \*Store) CreateInstallToken\|func (s \*Store) EnrollDevice" internal/server/store/*.go`. Adjust argument order to match.

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/server/store/ -run 'TestRolloutCandidates|TestResolveRolloutDevices|TestRolloutSummary' -v`
Expected: FAIL, undefined methods.

- [ ] **Step 3: Implement**

Append to `internal/server/store/rollouts.go`:

```go
type RolloutDevice struct {
	DeviceID   uuid.UUID
	Hostname   string
	CommandID  uuid.UUID
	State      string // issued|updated|failed
	Detail     string
	IssuedAt   time.Time
	ResolvedAt *time.Time
}

type RolloutCandidate struct {
	DeviceID uuid.UUID
	Hostname string
}

type RolloutSummary struct {
	Targeted       int // non-revoked devices matched by the group set
	AlreadyCurrent int // targeted, no row, already on the version
	Issued         int
	Updated        int
	Failed         int
	Remaining      int // targeted − already_current − issued − updated − failed
}

// RolloutCandidates lists targeted, non-revoked devices not yet on the
// rollout's version and without a progress row, ordered by hostname. The
// caller filters by online presence and applies the batch cap.
func (s *Store) RolloutCandidates(ctx context.Context, tenantID, id uuid.UUID) ([]RolloutCandidate, error) {
	rows, _ := s.pool.Query(ctx, `
		SELECT d.id, d.hostname FROM devices d
		JOIN agent_rollouts r ON r.tenant_id = d.tenant_id AND r.id = $2
		WHERE d.tenant_id = $1 AND NOT d.revoked AND d.agent_version <> r.version
		  AND (cardinality(r.group_ids) = 0 OR d.group_id = ANY(r.group_ids))
		  AND NOT EXISTS (SELECT 1 FROM agent_rollout_devices rd WHERE rd.rollout_id = r.id AND rd.device_id = d.id)
		ORDER BY d.hostname, d.id`, tenantID, id)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (RolloutCandidate, error) {
		var c RolloutCandidate
		return c, r.Scan(&c.DeviceID, &c.Hostname)
	})
}

func (s *Store) AddRolloutDevice(ctx context.Context, rolloutID, deviceID, commandID uuid.UUID, now time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO agent_rollout_devices (rollout_id, device_id, command_id, state, issued_at)
		VALUES ($1, $2, $3, 'issued', $4)`, rolloutID, deviceID, commandID, now)
	return conflict(err)
}

func (s *Store) ListRolloutDevices(ctx context.Context, tenantID, id uuid.UUID) ([]RolloutDevice, error) {
	rows, _ := s.pool.Query(ctx, `
		SELECT rd.device_id, d.hostname, rd.command_id, rd.state, rd.detail, rd.issued_at, rd.resolved_at
		FROM agent_rollout_devices rd
		JOIN agent_rollouts r ON r.id = rd.rollout_id
		JOIN devices d ON d.id = rd.device_id
		WHERE r.tenant_id = $1 AND rd.rollout_id = $2
		ORDER BY rd.issued_at, d.hostname`, tenantID, id)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (RolloutDevice, error) {
		var d RolloutDevice
		return d, r.Scan(&d.DeviceID, &d.Hostname, &d.CommandID, &d.State, &d.Detail, &d.IssuedAt, &d.ResolvedAt)
	})
}

// ResolveRolloutDevices moves issued rows to a terminal state:
//   - updated: the device now reports the rollout version;
//   - failed:  the command failed or expired, or it succeeded before
//     now−confirmTimeout and the device still reports another version.
// Returns how many rows became updated and failed.
func (s *Store) ResolveRolloutDevices(ctx context.Context, tenantID, id uuid.UUID, now time.Time, confirmTimeout time.Duration) (updated, failed int, err error) {
	cutoff := now.Add(-confirmTimeout)
	rows, err := s.pool.Query(ctx, `
		UPDATE agent_rollout_devices rd SET state = x.state, detail = x.detail, resolved_at = $3
		FROM (
			SELECT rd.device_id,
				CASE
					WHEN d.agent_version = r.version THEN 'updated'
					WHEN c.state IN ('failed', 'expired') THEN 'failed'
					WHEN c.state = 'succeeded' AND c.completed_at <= $4 THEN 'failed'
				END AS state,
				CASE
					WHEN d.agent_version = r.version THEN ''
					WHEN c.state IN ('failed', 'expired') THEN c.state || ': ' || c.result
					ELSE 'agent did not report ' || r.version || ' after the update command succeeded'
				END AS detail
			FROM agent_rollout_devices rd
			JOIN agent_rollouts r ON r.id = rd.rollout_id
			JOIN devices d ON d.id = rd.device_id
			JOIN commands c ON c.id = rd.command_id
			WHERE r.tenant_id = $1 AND rd.rollout_id = $2 AND rd.state = 'issued'
		) x
		WHERE rd.rollout_id = $2 AND rd.device_id = x.device_id AND x.state IS NOT NULL
		RETURNING rd.state`, tenantID, id, now, cutoff)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var st string
		if err := rows.Scan(&st); err != nil {
			return 0, 0, err
		}
		if st == "updated" {
			updated++
		} else {
			failed++
		}
	}
	return updated, failed, rows.Err()
}

func (s *Store) RolloutSummary(ctx context.Context, tenantID, id uuid.UUID) (RolloutSummary, error) {
	var sum RolloutSummary
	var exists int
	err := s.pool.QueryRow(ctx, `
		WITH r AS (SELECT id, version, group_ids FROM agent_rollouts WHERE tenant_id = $1 AND id = $2),
		targeted AS (
			SELECT d.id, d.agent_version FROM devices d, r
			WHERE d.tenant_id = $1 AND NOT d.revoked AND (cardinality(r.group_ids) = 0 OR d.group_id = ANY(r.group_ids))
		),
		rows AS (SELECT state FROM agent_rollout_devices rd, r WHERE rd.rollout_id = r.id)
		SELECT
			(SELECT count(*) FROM targeted),
			(SELECT count(*) FROM targeted t, r WHERE t.agent_version = r.version
				AND NOT EXISTS (SELECT 1 FROM agent_rollout_devices rd WHERE rd.rollout_id = r.id AND rd.device_id = t.id)),
			(SELECT count(*) FROM rows WHERE state = 'issued'),
			(SELECT count(*) FROM rows WHERE state = 'updated'),
			(SELECT count(*) FROM rows WHERE state = 'failed'),
			(SELECT count(*) FROM r)`, tenantID, id).
		Scan(&sum.Targeted, &sum.AlreadyCurrent, &sum.Issued, &sum.Updated, &sum.Failed, &exists)
	if err != nil {
		return sum, err
	}
	if exists == 0 { // the rollout is not in this tenant
		return sum, ErrNotFound
	}
	sum.Remaining = sum.Targeted - sum.AlreadyCurrent - sum.Issued - sum.Updated - sum.Failed
	if sum.Remaining < 0 {
		sum.Remaining = 0
	}
	return sum, nil
}
```

Note: `commands.state` uses the values `pending|sent|succeeded|failed|expired` (see `store/commands.go`). Confirm `commands.result` is a non-null text column: `grep -n "result" internal/server/store/migrations/0001_init.sql`. If it is nullable, wrap it as `coalesce(c.result, '')` in the detail CASE.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/server/store/ -run 'Rollout' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/server/store
git commit -m "store: rollout device rows, candidates, resolution rules, summary

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 4: Reconciler service and ticker wiring

**Files:**
- Create: `internal/server/rollout/rollout.go`
- Test: `internal/server/rollout/rollout_test.go`
- Modify: `internal/server/httpapi/api.go:32-36` (`Runtime`)
- Modify: `internal/server/app/app.go:257-282` (`activate`) and `:334-370` (ticker)

**Interfaces:**
- Consumes: Task 2/3 store methods; `commands.Service.IssueUpdate`; `hub.Hub.Connected`.
- Produces:
  ```go
  package rollout
  type Service struct { Store *store.Store; Commands *commands.Service; Online func(uuid.UUID) bool; ReleaseURL func(string) string; Now func() time.Time; ConfirmTimeout time.Duration; Log *slog.Logger }
  func (s *Service) Tick(ctx context.Context) error
  func (s *Service) Reconcile(ctx context.Context, tenantID uuid.UUID, r store.Rollout) error
  ```
  and `httpapi.Runtime.Rollouts *rollout.Service`.

- [ ] **Step 1: Write the failing tests**

Create `internal/server/rollout/rollout_test.go`:

```go
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
	entries, _ := f.s.ListAudit(ctx, f.tenant, 50)
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
```

Check the audit list helper: `grep -n "func (s \*Store) ListAudit" internal/server/store/audit.go` and match its signature (name, args). Check `bootstrap.Init` creates the tenant that `Load` returns (it does — `helpers_test.go` relies on it).

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/server/rollout/ -v`
Expected: FAIL to compile, package `rollout` missing.

- [ ] **Step 3: Implement the reconciler**

Create `internal/server/rollout/rollout.go`:

```go
// Package rollout drives staged agent updates: each tick issues signed
// update commands to a batch of targeted devices and resolves progress from
// command results and the version each device reports.
package rollout

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"freelocker/internal/server/commands"
	"freelocker/internal/server/store"

	"github.com/google/uuid"
)

const DefaultConfirmTimeout = 10 * time.Minute

type Service struct {
	Store    *store.Store
	Commands *commands.Service
	// Online reports whether a device currently holds a stream to the hub.
	Online func(deviceID uuid.UUID) bool
	// ReleaseURL builds the download URL for a version.
	ReleaseURL func(version string) string
	Now        func() time.Time
	// ConfirmTimeout is how long after a successful update command a device
	// may keep reporting the old version before it counts as failed.
	ConfirmTimeout time.Duration
	Log            *slog.Logger
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Service) timeout() time.Duration {
	if s.ConfirmTimeout > 0 {
		return s.ConfirmTimeout
	}
	return DefaultConfirmTimeout
}

// Tick reconciles every active rollout of every non-suspended tenant. An
// error in one rollout is logged and does not stop the others.
func (s *Service) Tick(ctx context.Context) error {
	open, err := s.Store.OpenRollouts(ctx)
	if err != nil {
		return err
	}
	for _, o := range open {
		if err := s.Reconcile(ctx, o.TenantID, o.Rollout); err != nil {
			s.log().Error("rollout reconcile", "rollout", o.ID, "err", err)
		}
	}
	return nil
}

// Reconcile runs one pass over an active rollout: resolve in-flight rows,
// auto-pause on failures, issue the next batch, and complete when nothing
// is left.
func (s *Service) Reconcile(ctx context.Context, tenantID uuid.UUID, r store.Rollout) error {
	if r.State != "active" {
		return nil
	}
	now := s.now()

	// 1. Resolve in-flight devices first so freed batch slots are reused.
	if _, _, err := s.Store.ResolveRolloutDevices(ctx, tenantID, r.ID, now, s.timeout()); err != nil {
		return fmt.Errorf("resolve: %w", err)
	}
	sum, err := s.Store.RolloutSummary(ctx, tenantID, r.ID)
	if err != nil {
		return err
	}

	// 2. Auto-pause when failures reach the threshold.
	if r.MaxFailures > 0 && sum.Failed >= r.MaxFailures {
		if err := s.Store.SetRolloutState(ctx, tenantID, r.ID, []string{"active"}, "paused", now); err != nil {
			return fmt.Errorf("auto-pause: %w", err)
		}
		s.Store.AppendAudit(ctx, tenantID, store.AuditEntry{
			Actor: "system", Action: "rollout.auto_pause", TargetType: "rollout", TargetID: r.ID.String(),
			Detail: map[string]any{"version": r.Version, "failed": sum.Failed, "max_failures": r.MaxFailures}, Result: "success",
		})
		s.log().Warn("rollout auto-paused", "rollout", r.ID, "failed", sum.Failed)
		return nil
	}

	// 3. Issue the next batch to online candidates.
	if slots := r.BatchSize - sum.Issued; slots > 0 {
		rel, err := s.Store.GetRelease(ctx, tenantID, r.Version)
		if err != nil {
			return fmt.Errorf("release %s: %w", r.Version, err)
		}
		payload := commands.UpdatePayload{Version: rel.Version, URL: s.ReleaseURL(rel.Version), SHA256: rel.SHA256, Signature: rel.Signature}
		cands, err := s.Store.RolloutCandidates(ctx, tenantID, r.ID)
		if err != nil {
			return fmt.Errorf("candidates: %w", err)
		}
		for _, c := range cands {
			if slots == 0 {
				break
			}
			if s.Online != nil && !s.Online(c.DeviceID) {
				continue
			}
			cmdID, err := s.Commands.IssueUpdate(ctx, tenantID, c.DeviceID, payload, "rollout:"+r.ID.String())
			if err != nil {
				s.log().Error("rollout issue update", "rollout", r.ID, "device", c.DeviceID, "err", err)
				continue
			}
			if err := s.Store.AddRolloutDevice(ctx, r.ID, c.DeviceID, cmdID, now); err != nil {
				s.log().Error("rollout record device", "rollout", r.ID, "device", c.DeviceID, "err", err)
				continue
			}
			sum.Issued++
			sum.Remaining--
			slots--
		}
	}

	// 4. Complete when nothing is in flight and nothing is left to issue.
	if sum.Issued == 0 && sum.Remaining == 0 {
		if err := s.Store.SetRolloutState(ctx, tenantID, r.ID, []string{"active"}, "completed", now); err != nil {
			return fmt.Errorf("complete: %w", err)
		}
		s.log().Info("rollout completed", "rollout", r.ID, "version", r.Version, "updated", sum.Updated, "failed", sum.Failed)
	}
	return nil
}
```

- [ ] **Step 4: Run the reconciler tests**

Run: `go test ./internal/server/rollout/ -v`
Expected: PASS. In `TestResolvesAndCompletes`, note the second tick resolves both devices then sees Issued 0 / Remaining 0 and completes.

- [ ] **Step 5: Wire into Runtime and the ticker**

In `internal/server/httpapi/api.go` add to `Runtime`:

```go
	Rollouts *rollout.Service
```

with import `"freelocker/internal/server/rollout"`.

In `internal/server/app/app.go` `activate`, after `policy := ...` add:

```go
	rollouts := &rollout.Service{
		Store: a.store, Commands: cmds, Online: a.hub.Connected, ReleaseURL: a.cfg.ReleaseURL,
		ConfirmTimeout: rollout.DefaultConfirmTimeout, Log: a.log,
	}
```

and change the runtime literal to `&httpapi.Runtime{Keys: k, Commands: cmds, Policy: policy, Rollouts: rollouts}`.

In the ticker loop, directly after the `ExpireStale` block inside `if rt := a.runtime(); rt != nil {`, add:

```go
				if err := rt.Rollouts.Tick(ctx); err != nil {
					a.log.Error("rollout tick", "err", err)
				}
```

Add the import `"freelocker/internal/server/rollout"` to `app.go`. In `helpers_test.go`, add `Rollouts: &rollout.Service{Store: s, Commands: ..., Online: h.Connected, ReleaseURL: func(v string) string { return "http://test.local/agent/releases/" + v }}` to the `Runtime` literal — reuse the `commands.Service` value by assigning it to a variable first:

```go
			cmds := &commands.Service{Store: s, Keys: k, Hub: h}
			rt = &httpapi.Runtime{
				Keys:     k,
				Commands: cmds,
				Policy:   &policysvc.Service{Store: s, Keys: k},
				Rollouts: &rollout.Service{Store: s, Commands: cmds, Online: h.Connected, ReleaseURL: func(v string) string { return "http://test.local/agent/releases/" + v }},
			}
```

- [ ] **Step 6: Build and run the server packages**

Run: `go build ./... && go test ./internal/server/...`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/server
git commit -m "server: rollout reconciler — batches, auto-pause, confirm timeout, completion; ticker wiring

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 5: HTTP API for rollouts

**Files:**
- Create: `internal/server/httpapi/rollouts.go`
- Modify: `internal/server/httpapi/routes.go` (read group + admin group)
- Test: `internal/server/httpapi/rollouts_test.go`

**Interfaces:**
- Consumes: store methods from Tasks 2–3; `Runtime.Rollouts` (only for `Reconcile` in the test).
- Produces the routes listed in the spec's API table. JSON shapes:
  ```json
  rollout: {"id","version","group_ids":[],"batch_size","max_failures","state","created_by","created_at","updated_at","finished_at",
            "summary":{"targeted","already_current","issued","updated","failed","remaining"}}
  detail:  rollout + "devices":[{"device_id","hostname","command_id","state","detail","issued_at","resolved_at"}]
  ```

- [ ] **Step 1: Write the failing HTTP test**

Create `internal/server/httpapi/rollouts_test.go`:

```go
package httpapi_test

import (
	"context"
	"testing"
)

type rolloutJSON struct {
	ID          string   `json:"id"`
	Version     string   `json:"version"`
	GroupIDs    []string `json:"group_ids"`
	BatchSize   int      `json:"batch_size"`
	MaxFailures int      `json:"max_failures"`
	State       string   `json:"state"`
	CreatedBy   string   `json:"created_by"`
	Summary     struct {
		Targeted, AlreadyCurrent, Issued, Updated, Failed, Remaining int
	} `json:"summary"`
	Devices []struct {
		DeviceID string `json:"device_id"`
		Hostname string `json:"hostname"`
		State    string `json:"state"`
	} `json:"devices"`
}

func TestRolloutLifecycleOverHTTP(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)
	c.uploadRelease(t, "1.0.0")
	c.uploadRelease(t, "1.0.1")
	var g idResp
	c.do("POST", "/api/groups", map[string]string{"name": "Pilot"}, &g)
	dev := e.fakeDevice(t)
	c.do("POST", "/api/devices/"+dev.String()+"/group", map[string]any{"group_id": g.ID}, nil)

	// Validation.
	if code := c.do("POST", "/api/rollouts", map[string]any{"version": "nope"}, nil); code != 404 {
		t.Errorf("unknown version = %d, want 404", code)
	}
	if code := c.do("POST", "/api/rollouts", map[string]any{"version": "1.0.1", "batch_size": 0}, nil); code != 400 {
		t.Errorf("batch_size 0 = %d, want 400", code)
	}
	if code := c.do("POST", "/api/rollouts", map[string]any{"version": "1.0.1", "max_failures": -1}, nil); code != 400 {
		t.Errorf("negative max_failures = %d, want 400", code)
	}

	var created idResp
	if code := c.do("POST", "/api/rollouts", map[string]any{"version": "1.0.1", "group_ids": []string{g.ID}, "batch_size": 5}, &created); code != 201 {
		t.Fatalf("create = %d", code)
	}
	if code := c.do("POST", "/api/rollouts", map[string]any{"version": "1.0.0"}, nil); code != 409 {
		t.Errorf("second open rollout = %d, want 409", code)
	}

	var got rolloutJSON
	if code := c.do("GET", "/api/rollouts/"+created.ID, nil, &got); code != 200 {
		t.Fatalf("get = %d", code)
	}
	if got.Version != "1.0.1" || got.State != "active" || got.BatchSize != 5 || got.MaxFailures != 3 || len(got.GroupIDs) != 1 || got.GroupIDs[0] != g.ID || got.CreatedBy != "admin:"+ownerEmail {
		t.Errorf("rollout = %+v", got)
	}
	if got.Summary.Targeted != 1 || got.Summary.Remaining != 1 {
		t.Errorf("summary = %+v", got.Summary)
	}

	// The device is offline in this test, so a reconcile pass issues nothing
	// and the rollout stays active with the device remaining.
	k := e.rt().Keys
	r, _ := e.store.GetRollout(context.Background(), k.TenantID, mustUUID(t, created.ID))
	if err := e.rt().Rollouts.Reconcile(context.Background(), k.TenantID, r); err != nil {
		t.Fatal(err)
	}
	c.do("GET", "/api/rollouts/"+created.ID, nil, &got)
	if got.State != "active" || got.Summary.Issued != 0 {
		t.Errorf("after reconcile (offline device) = %+v", got)
	}

	var list []rolloutJSON
	if code := c.do("GET", "/api/rollouts", nil, &list); code != 200 || len(list) != 1 || list[0].ID != created.ID {
		t.Fatalf("list = %d %+v", code, list)
	}

	// Transitions.
	if code := c.do("POST", "/api/rollouts/"+created.ID+"/resume", nil, nil); code != 409 {
		t.Errorf("resume active = %d, want 409", code)
	}
	if code := c.do("POST", "/api/rollouts/"+created.ID+"/pause", nil, nil); code != 204 {
		t.Errorf("pause = %d", code)
	}
	if code := c.do("POST", "/api/rollouts/"+created.ID+"/resume", nil, nil); code != 204 {
		t.Errorf("resume = %d", code)
	}
	if code := c.do("POST", "/api/rollouts/"+created.ID+"/cancel", nil, nil); code != 204 {
		t.Errorf("cancel = %d", code)
	}
	c.do("GET", "/api/rollouts/"+created.ID, nil, &got)
	if got.State != "cancelled" {
		t.Errorf("after cancel state = %s", got.State)
	}
	if code := c.do("POST", "/api/rollouts/"+created.ID+"/pause", nil, nil); code != 409 {
		t.Errorf("pause cancelled = %d, want 409", code)
	}

	// Rollback from a terminal rollout creates a new one with the same targets.
	var rb idResp
	if code := c.do("POST", "/api/rollouts/"+created.ID+"/rollback", map[string]string{"version": "1.0.0"}, &rb); code != 201 {
		t.Fatalf("rollback = %d", code)
	}
	c.do("GET", "/api/rollouts/"+rb.ID, nil, &got)
	if got.Version != "1.0.0" || got.State != "active" || len(got.GroupIDs) != 1 || got.BatchSize != 5 {
		t.Errorf("rollback rollout = %+v", got)
	}
	// Rollback from an open rollout cancels it first.
	var rb2 idResp
	if code := c.do("POST", "/api/rollouts/"+rb.ID+"/rollback", map[string]string{"version": "1.0.1"}, &rb2); code != 201 {
		t.Fatalf("rollback of open = %d", code)
	}
	c.do("GET", "/api/rollouts/"+rb.ID, nil, &got)
	if got.State != "cancelled" {
		t.Errorf("rolled-back rollout state = %s, want cancelled", got.State)
	}
	// Rolling back to the rollout's own version is rejected.
	if code := c.do("POST", "/api/rollouts/"+rb2.ID+"/rollback", map[string]string{"version": "1.0.1"}, nil); code != 400 {
		t.Errorf("rollback to same version = %d, want 400", code)
	}

	// Audit trail.
	entries, _ := e.store.ListAudit(context.Background(), k.TenantID, 100)
	seen := map[string]bool{}
	for _, en := range entries {
		seen[en.Action] = true
	}
	for _, a := range []string{"rollout.create", "rollout.pause", "rollout.resume", "rollout.cancel", "rollout.rollback"} {
		if !seen[a] {
			t.Errorf("missing audit action %s", a)
		}
	}
}

func TestRolloutRbac(t *testing.T) {
	e := newEnv(t)
	owner := e.initialized(t)
	owner.uploadRelease(t, "1.0.0")
	owner.do("POST", "/api/admins", map[string]string{"email": "ro@example.com", "password": "readonly-password-1", "role": "readonly"}, nil)
	ro := e.client(t)
	ro.loginFull("ro@example.com", "readonly-password-1", "")
	if code := ro.do("GET", "/api/rollouts", nil, nil); code != 200 {
		t.Errorf("readonly list = %d, want 200", code)
	}
	if code := ro.do("POST", "/api/rollouts", map[string]any{"version": "1.0.0"}, nil); code != 403 {
		t.Errorf("readonly create = %d, want 403", code)
	}
}
```

Add a helper if none exists (`grep -n "func mustUUID" internal/server/httpapi/*_test.go`):

```go
func mustUUID(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
```

(import `github.com/google/uuid`). Check `ListAudit`'s real signature as in Task 4.

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/server/httpapi/ -run TestRollout -v`
Expected: FAIL — 404s from unrouted paths.

- [ ] **Step 3: Implement handlers**

Create `internal/server/httpapi/rollouts.go`:

```go
package httpapi

import (
	"errors"
	"net/http"
	"time"

	"freelocker/internal/server/store"

	"github.com/google/uuid"
)

type rolloutSummaryJSON struct {
	Targeted       int `json:"targeted"`
	AlreadyCurrent int `json:"already_current"`
	Issued         int `json:"issued"`
	Updated        int `json:"updated"`
	Failed         int `json:"failed"`
	Remaining      int `json:"remaining"`
}

type rolloutJSON struct {
	ID          string             `json:"id"`
	Version     string             `json:"version"`
	GroupIDs    []string           `json:"group_ids"`
	BatchSize   int                `json:"batch_size"`
	MaxFailures int                `json:"max_failures"`
	State       string             `json:"state"`
	CreatedBy   string             `json:"created_by"`
	CreatedAt   time.Time          `json:"created_at"`
	UpdatedAt   time.Time          `json:"updated_at"`
	FinishedAt  *time.Time         `json:"finished_at"`
	Summary     rolloutSummaryJSON `json:"summary"`
}

type rolloutDeviceJSON struct {
	DeviceID   string     `json:"device_id"`
	Hostname   string     `json:"hostname"`
	CommandID  string     `json:"command_id"`
	State      string     `json:"state"`
	Detail     string     `json:"detail"`
	IssuedAt   time.Time  `json:"issued_at"`
	ResolvedAt *time.Time `json:"resolved_at"`
}

type rolloutDetailJSON struct {
	rolloutJSON
	Devices []rolloutDeviceJSON `json:"devices"`
}

func toRolloutJSON(r store.Rollout, s store.RolloutSummary) rolloutJSON {
	gids := make([]string, 0, len(r.GroupIDs))
	for _, g := range r.GroupIDs {
		gids = append(gids, g.String())
	}
	return rolloutJSON{
		ID: r.ID.String(), Version: r.Version, GroupIDs: gids, BatchSize: r.BatchSize, MaxFailures: r.MaxFailures,
		State: r.State, CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, FinishedAt: r.FinishedAt,
		Summary: rolloutSummaryJSON{s.Targeted, s.AlreadyCurrent, s.Issued, s.Updated, s.Failed, s.Remaining},
	}
}

const (
	defaultRolloutBatch       = 10
	defaultRolloutMaxFailures = 3
)

type rolloutCreateReq struct {
	Version     string   `json:"version"`
	GroupIDs    []string `json:"group_ids"`
	BatchSize   *int     `json:"batch_size"`
	MaxFailures *int     `json:"max_failures"`
}

// newRollout validates a create request into a store.Rollout.
func newRollout(req rolloutCreateReq, actor string) (store.Rollout, string) {
	r := store.Rollout{ID: uuid.New(), Version: req.Version, State: "active", CreatedBy: actor, BatchSize: defaultRolloutBatch, MaxFailures: defaultRolloutMaxFailures, GroupIDs: []uuid.UUID{}}
	if r.Version == "" {
		return r, "version is required"
	}
	if req.BatchSize != nil {
		r.BatchSize = *req.BatchSize
	}
	if req.MaxFailures != nil {
		r.MaxFailures = *req.MaxFailures
	}
	if r.BatchSize < 1 {
		return r, "batch_size must be at least 1"
	}
	if r.MaxFailures < 0 {
		return r, "max_failures must be 0 or more"
	}
	for _, g := range req.GroupIDs {
		id, err := uuid.Parse(g)
		if err != nil {
			return r, "bad group id"
		}
		r.GroupIDs = append(r.GroupIDs, id)
	}
	return r, ""
}

func (a *API) createRollout(w http.ResponseWriter, r *http.Request) {
	var req rolloutCreateReq
	if !readJSON(w, r, &req) {
		return
	}
	p := principalFrom(r)
	ro, msg := newRollout(req, "admin:"+p.Admin.Email)
	if msg != "" {
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	if err := a.Store.CreateRollout(r.Context(), p.TenantID, ro); err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "rollout.create", "rollout", ro.ID.String(), map[string]any{"version": ro.Version, "group_ids": req.GroupIDs, "batch_size": ro.BatchSize, "max_failures": ro.MaxFailures}, "success")
	writeJSON(w, http.StatusCreated, map[string]string{"id": ro.ID.String()})
}

func (a *API) listRollouts(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	list, err := a.Store.ListRollouts(r.Context(), p.TenantID, queryInt(r, "limit", 50, 200))
	if err != nil {
		a.storeErr(w, err)
		return
	}
	out := make([]rolloutJSON, 0, len(list))
	for _, ro := range list {
		sum, err := a.Store.RolloutSummary(r.Context(), p.TenantID, ro.ID)
		if err != nil {
			a.storeErr(w, err)
			return
		}
		out = append(out, toRolloutJSON(ro, sum))
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) getRollout(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	ro, err := a.Store.GetRollout(r.Context(), p.TenantID, id)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	sum, err := a.Store.RolloutSummary(r.Context(), p.TenantID, id)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	devs, err := a.Store.ListRolloutDevices(r.Context(), p.TenantID, id)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	out := rolloutDetailJSON{rolloutJSON: toRolloutJSON(ro, sum), Devices: make([]rolloutDeviceJSON, 0, len(devs))}
	for _, d := range devs {
		out.Devices = append(out.Devices, rolloutDeviceJSON{
			DeviceID: d.DeviceID.String(), Hostname: d.Hostname, CommandID: d.CommandID.String(),
			State: d.State, Detail: d.Detail, IssuedAt: d.IssuedAt, ResolvedAt: d.ResolvedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// transition handles pause/resume/cancel: a guarded state change + audit.
func (a *API) transitionRollout(action string, from []string, to string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathID(w, r)
		if !ok {
			return
		}
		p := principalFrom(r)
		if err := a.Store.SetRolloutState(r.Context(), p.TenantID, id, from, to, time.Now()); err != nil {
			if errors.Is(err, store.ErrConflict) {
				writeErr(w, http.StatusConflict, "rollout is not "+from[0]+" (or another allowed state)")
				return
			}
			a.storeErr(w, err)
			return
		}
		a.audit(r, p, "rollout."+action, "rollout", id.String(), map[string]any{"state": to}, "success")
		w.WriteHeader(http.StatusNoContent)
	}
}

// rollbackRollout cancels the given rollout if it is still open and starts
// a new one for another version with the same targets and limits.
func (a *API) rollbackRollout(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		Version string `json:"version"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	p := principalFrom(r)
	old, err := a.Store.GetRollout(r.Context(), p.TenantID, id)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	if req.Version == "" || req.Version == old.Version {
		writeErr(w, http.StatusBadRequest, "rollback needs a different version")
		return
	}
	if _, err := a.Store.GetRelease(r.Context(), p.TenantID, req.Version); err != nil {
		a.storeErr(w, err)
		return
	}
	now := time.Now()
	if old.State == "active" || old.State == "paused" {
		if err := a.Store.SetRolloutState(r.Context(), p.TenantID, id, []string{"active", "paused"}, "cancelled", now); err != nil {
			a.storeErr(w, err)
			return
		}
	}
	nr := store.Rollout{
		ID: uuid.New(), Version: req.Version, GroupIDs: old.GroupIDs, BatchSize: old.BatchSize, MaxFailures: old.MaxFailures,
		State: "active", CreatedBy: "admin:" + p.Admin.Email,
	}
	if err := a.Store.CreateRollout(r.Context(), p.TenantID, nr); err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "rollout.rollback", "rollout", id.String(), map[string]any{"from_version": old.Version, "to_version": nr.Version, "new_rollout_id": nr.ID.String()}, "success")
	writeJSON(w, http.StatusCreated, map[string]string{"id": nr.ID.String()})
}
```

In `internal/server/httpapi/routes.go` add to the read group (next to `r.Get("/api/devices/{id}/controls", ...)`):

```go
	r.Get("/api/rollouts", a.listRollouts)
	r.Get("/api/rollouts/{id}", a.getRollout)
```

and to the `requireRole("admin")` group:

```go
		r.Post("/api/rollouts", a.createRollout)
		r.Post("/api/rollouts/{id}/pause", a.transitionRollout("pause", []string{"active"}, "paused"))
		r.Post("/api/rollouts/{id}/resume", a.transitionRollout("resume", []string{"paused"}, "active"))
		r.Post("/api/rollouts/{id}/cancel", a.transitionRollout("cancel", []string{"active", "paused"}, "cancelled"))
		r.Post("/api/rollouts/{id}/rollback", a.rollbackRollout)
```

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/server/httpapi/ -run 'TestRollout|TestUpdateAgent' -v`
Expected: PASS.

- [ ] **Step 5: Run the full Go suite**

Run: `go test ./...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/server/httpapi
git commit -m "httpapi: rollout create/list/get/pause/resume/cancel/rollback with audit

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 6: Console — Rollouts on the Releases page

**Files:**
- Modify: `web/src/api.ts` (types after `Release`)
- Modify: `web/src/pages/Releases.tsx`
- Modify: `web/e2e/smoke.spec.ts` (append to the existing test)

**Interfaces:**
- Consumes: the JSON shapes from Task 5; `Group` type and `/api/groups`.

- [ ] **Step 1: Add API types**

In `web/src/api.ts` after the `Release` type add:

```ts
export type RolloutSummary = {
  targeted: number;
  already_current: number;
  issued: number;
  updated: number;
  failed: number;
  remaining: number;
};
export type Rollout = {
  id: string;
  version: string;
  group_ids: string[];
  batch_size: number;
  max_failures: number;
  state: "active" | "paused" | "completed" | "cancelled";
  created_by: string;
  created_at: string;
  updated_at: string;
  finished_at: string | null;
  summary: RolloutSummary;
};
export type RolloutDevice = {
  device_id: string;
  hostname: string;
  command_id: string;
  state: "issued" | "updated" | "failed";
  detail: string;
  issued_at: string;
  resolved_at: string | null;
};
export type RolloutDetail = Rollout & { devices: RolloutDevice[] };
```

- [ ] **Step 2: Rewrite `Releases.tsx`**

Replace the file with:

```tsx
import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError, Group, Release, Rollout, RolloutDetail } from "../api";
import { useToast } from "../components/Toast";
import { fmtDate } from "../components/util";

const OPEN = (r: Rollout) => r.state === "active" || r.state === "paused";

export function Releases() {
  const { notify } = useToast();
  const [releases, setReleases] = useState<Release[] | null>(null);
  const [rollouts, setRollouts] = useState<Rollout[] | null>(null);
  const [groups, setGroups] = useState<Group[]>([]);
  const [version, setVersion] = useState("");
  const [busy, setBusy] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const load = useCallback(() => {
    api.get<Release[]>("/api/releases").then(setReleases).catch(() => setReleases([]));
    api.get<Rollout[]>("/api/rollouts").then(setRollouts).catch(() => setRollouts([]));
    api.get<Group[]>("/api/groups").then(setGroups).catch(() => setGroups([]));
  }, []);
  useEffect(() => {
    load();
  }, [load]);

  const open = rollouts?.find(OPEN) ?? null;
  // Poll while a rollout is open so progress moves without a reload.
  useEffect(() => {
    if (!open) return;
    const t = setInterval(() => api.get<Rollout[]>("/api/rollouts").then(setRollouts).catch(() => {}), 10_000);
    return () => clearInterval(t);
  }, [open?.id]);

  const upload = async (e: FormEvent) => {
    e.preventDefault();
    const file = fileRef.current?.files?.[0];
    if (!file || !version) return;
    const form = new FormData();
    form.append("version", version);
    form.append("file", file);
    setBusy(true);
    try {
      await api.upload("/api/releases", form);
      notify(`Uploaded ${version}`);
      setVersion("");
      if (fileRef.current) fileRef.current.value = "";
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Upload failed", "error");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <div className="page-head">
        <h1>Agent releases</h1>
      </div>
      <div className="panel" style={{ marginBottom: 20 }}>
        <h2>Upload a build</h2>
        <p className="who" style={{ marginTop: -6, marginBottom: 10 }}>
          The server signs each build; agents verify the hash and signature before installing.
        </p>
        <form onSubmit={upload}>
          <div className="toolbar" style={{ alignItems: "flex-end" }}>
            <div>
              <label>Version</label>
              <input aria-label="Release version" value={version} onChange={(e) => setVersion(e.target.value)} placeholder="0.2.0" />
            </div>
            <div>
              <label>Agent binary</label>
              <input aria-label="Agent binary" type="file" ref={fileRef} />
            </div>
            <button className="primary" disabled={busy || !version}>
              {busy ? "Uploading…" : "Upload"}
            </button>
          </div>
        </form>
      </div>

      <h2>Rollouts</h2>
      {!rollouts ? (
        <div className="spin">Loading…</div>
      ) : open ? (
        <RolloutCard rollout={open} releases={releases ?? []} groups={groups} onChange={load} />
      ) : (
        <div className="empty">No rollout in progress.</div>
      )}
      {rollouts && rollouts.some((r) => !OPEN(r)) && (
        <div className="table-wrap" style={{ marginTop: 12, marginBottom: 20 }}>
          <table>
            <thead>
              <tr>
                <th>Version</th>
                <th>State</th>
                <th>Updated</th>
                <th>Failed</th>
                <th>Finished</th>
              </tr>
            </thead>
            <tbody>
              {rollouts.filter((r) => !OPEN(r)).map((r) => (
                <tr key={r.id}>
                  <td className="mono">{r.version}</td>
                  <td>{r.state}</td>
                  <td>{r.summary.updated}</td>
                  <td>{r.summary.failed}</td>
                  <td>{r.finished_at ? fmtDate(r.finished_at) : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <h2 style={{ marginTop: 20 }}>Uploaded builds</h2>
      {!releases ? (
        <div className="spin">Loading…</div>
      ) : releases.length === 0 ? (
        <div className="empty">No releases uploaded yet.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Version</th>
                <th>SHA-256</th>
                <th>Uploaded</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {releases.map((r) => (
                <ReleaseRow key={r.version} release={r} groups={groups} disabled={!!open} onStarted={load} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function ReleaseRow({ release, groups, disabled, onStarted }: { release: Release; groups: Group[]; disabled: boolean; onStarted: () => void }) {
  const { notify } = useToast();
  const [openForm, setOpenForm] = useState(false);
  const [selected, setSelected] = useState<string[]>([]);
  const [batch, setBatch] = useState(10);
  const [maxFail, setMaxFail] = useState(3);
  const [busy, setBusy] = useState(false);

  const start = async () => {
    setBusy(true);
    try {
      await api.post("/api/rollouts", { version: release.version, group_ids: selected, batch_size: batch, max_failures: maxFail });
      notify(`Rollout of ${release.version} started`);
      setOpenForm(false);
      onStarted();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not start rollout", "error");
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <tr>
        <td className="mono">{release.version}</td>
        <td className="mono">{release.sha256.slice(0, 24)}…</td>
        <td>{fmtDate(release.uploaded_at)}</td>
        <td style={{ textAlign: "right" }}>
          <button disabled={disabled} onClick={() => setOpenForm((v) => !v)} aria-label={`Start rollout of ${release.version}`}>
            Start rollout
          </button>
        </td>
      </tr>
      {openForm && (
        <tr>
          <td colSpan={4}>
            <div className="toolbar" style={{ alignItems: "flex-end" }}>
              <div>
                <label>Groups (none = all devices)</label>
                <select
                  aria-label="Rollout groups"
                  multiple
                  value={selected}
                  onChange={(e) => setSelected(Array.from(e.target.selectedOptions).map((o) => o.value))}
                >
                  {groups.map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.name}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label>Batch size</label>
                <input aria-label="Batch size" type="number" min={1} value={batch} onChange={(e) => setBatch(Number(e.target.value))} />
              </div>
              <div>
                <label>Pause after failures (0 = never)</label>
                <input aria-label="Max failures" type="number" min={0} value={maxFail} onChange={(e) => setMaxFail(Number(e.target.value))} />
              </div>
              <button className="primary" disabled={busy || batch < 1 || maxFail < 0} onClick={start}>
                {busy ? "Starting…" : "Start"}
              </button>
              <button onClick={() => setOpenForm(false)}>Cancel</button>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

function RolloutCard({ rollout, releases, groups, onChange }: { rollout: Rollout; releases: Release[]; groups: Group[]; onChange: () => void }) {
  const { notify } = useToast();
  const [detail, setDetail] = useState<RolloutDetail | null>(null);
  const [showDevices, setShowDevices] = useState(false);
  const [rollbackTo, setRollbackTo] = useState("");
  const [busy, setBusy] = useState(false);
  const s = rollout.summary;
  const inScope = s.targeted - s.already_current;
  const pct = inScope > 0 ? Math.round((s.updated / inScope) * 100) : 100;
  const others = releases.filter((r) => r.version !== rollout.version);
  const groupNames = rollout.group_ids.length === 0 ? "all devices" : rollout.group_ids.map((id) => groups.find((g) => g.id === id)?.name ?? "deleted group").join(", ");

  useEffect(() => {
    if (!showDevices) return;
    const fetch = () => api.get<RolloutDetail>(`/api/rollouts/${rollout.id}`).then(setDetail).catch(() => {});
    fetch();
    const t = setInterval(fetch, 10_000);
    return () => clearInterval(t);
  }, [showDevices, rollout.id, rollout.updated_at]);

  useEffect(() => {
    if (!rollbackTo && others.length > 0) setRollbackTo(others[0].version);
  }, [others.length]);

  const act = async (path: string, body?: unknown, ok?: string) => {
    setBusy(true);
    try {
      await api.post(`/api/rollouts/${rollout.id}/${path}`, body);
      if (ok) notify(ok);
      onChange();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Request failed", "error");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="panel" data-testid="rollout-card">
      <div className="toolbar" style={{ justifyContent: "space-between" }}>
        <div>
          <strong className="mono">{rollout.version}</strong> → {groupNames} · <span aria-label="Rollout state">{rollout.state}</span>
        </div>
        <div className="toolbar">
          {rollout.state === "active" && (
            <button disabled={busy} onClick={() => act("pause", undefined, "Rollout paused")}>
              Pause
            </button>
          )}
          {rollout.state === "paused" && (
            <button disabled={busy} onClick={() => act("resume", undefined, "Rollout resumed")}>
              Resume
            </button>
          )}
          <button disabled={busy} onClick={() => act("cancel", undefined, "Rollout cancelled")}>
            Cancel rollout
          </button>
        </div>
      </div>
      <div style={{ margin: "10px 0" }}>
        <div style={{ height: 8, background: "var(--border, #333)", borderRadius: 4, overflow: "hidden" }}>
          <div style={{ width: `${pct}%`, height: "100%", background: "var(--accent, #3a6)" }} role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100} />
        </div>
        <p className="who" style={{ marginTop: 6 }}>
          {s.updated} updated · {s.issued} in flight · {s.failed} failed · {s.remaining} remaining · {s.already_current} already current · {s.targeted} targeted ·
          batch {rollout.batch_size} · pause after {rollout.max_failures || "∞"} failures
        </p>
      </div>
      {others.length > 0 && (
        <div className="toolbar" style={{ alignItems: "flex-end" }}>
          <div>
            <label>Roll back to</label>
            <select aria-label="Rollback version" value={rollbackTo} onChange={(e) => setRollbackTo(e.target.value)}>
              {others.map((r) => (
                <option key={r.version} value={r.version}>
                  {r.version}
                </option>
              ))}
            </select>
          </div>
          <button disabled={busy || !rollbackTo} onClick={() => act("rollback", { version: rollbackTo }, `Rolling back to ${rollbackTo}`)}>
            Roll back
          </button>
        </div>
      )}
      <button style={{ marginTop: 10 }} onClick={() => setShowDevices((v) => !v)}>
        {showDevices ? "Hide devices" : "Show devices"}
      </button>
      {showDevices && detail && (
        <div className="table-wrap" style={{ marginTop: 10 }}>
          <table>
            <thead>
              <tr>
                <th>Device</th>
                <th>State</th>
                <th>Detail</th>
                <th>Issued</th>
                <th>Resolved</th>
              </tr>
            </thead>
            <tbody>
              {detail.devices.length === 0 ? (
                <tr>
                  <td colSpan={5} className="who">
                    No devices issued yet. Only online devices are updated; offline ones are picked up when they connect.
                  </td>
                </tr>
              ) : (
                detail.devices.map((d) => (
                  <tr key={d.device_id}>
                    <td>{d.hostname}</td>
                    <td>{d.state}</td>
                    <td className="who">{d.detail}</td>
                    <td>{fmtDate(d.issued_at)}</td>
                    <td>{d.resolved_at ? fmtDate(d.resolved_at) : "—"}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 3: Typecheck and build**

Run: `npm --prefix web run build`
Expected: `tsc -b` clean, Vite build succeeds. Fix any unused-variable or type errors (e.g. if `Group` lacks fields, or `fmtDate` signature differs).

- [ ] **Step 4: Extend the Playwright smoke test**

Append to the end of the test body in `web/e2e/smoke.spec.ts` (before the closing `});`):

```ts
  // Releases: upload a dummy build, start a rollout (no devices → completes
  // on the next reconcile tick, so assert on the immediate state), cancel.
  await page.getByRole("link", { name: "Agent releases" }).click();
  await expect(page.getByRole("heading", { name: "Agent releases" })).toBeVisible();
  await expect(page.getByText("No rollout in progress.")).toBeVisible();
  await page.getByLabel("Release version").fill("9.9.9");
  await page.getByLabel("Agent binary").setInputFiles({ name: "agent.exe", mimeType: "application/octet-stream", buffer: Buffer.from("fake-agent") });
  await page.getByRole("button", { name: "Upload" }).click();
  await expect(page.getByRole("cell", { name: "9.9.9" })).toBeVisible();

  await page.getByLabel("Start rollout of 9.9.9").click();
  await page.getByLabel("Batch size").fill("2");
  await page.getByRole("button", { name: "Start", exact: true }).click();
  const card = page.getByTestId("rollout-card");
  await expect(card).toBeVisible();
  await expect(card.getByLabel("Rollout state")).toHaveText(/active|completed/);
  await card.getByRole("button", { name: "Cancel rollout" }).click();
  await expect(page.getByText("No rollout in progress.")).toBeVisible();
```

Note: if the ticker already completed the rollout before the click, "Cancel rollout" returns 409 and the card disappears anyway on reload; the final assertion still holds because the card only renders for open rollouts. If the 409 toast breaks the test, replace the cancel lines with `await expect(page.getByText("No rollout in progress.")).toBeVisible({ timeout: 90_000 });` and leave a comment.

- [ ] **Step 5: Run the E2E suite**

Follow the loop from the memory notes: drop/create the `freelocker_e2e` database, rebuild the console (`npm --prefix web run build`), start the server, then `npm --prefix web run e2e` (check `web/package.json` for the exact script name). Expected: smoke test passes.

- [ ] **Step 6: Commit**

```bash
git add web/src/api.ts web/src/pages/Releases.tsx web/e2e/smoke.spec.ts
git commit -m "console: rollouts on the Releases page — start, progress, pause/resume/cancel, rollback, devices

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 7: Docs, config sample, and merge

**Files:**
- Modify: `README.md` (capability line and any config table)
- Modify: `deploy/` sample config if one lists server options (`grep -rn release_dir deploy/ docs/`)
- Modify: `docs/agent-manual-test.md` (add a rollout section)

- [ ] **Step 1: Update docs**

In `README.md`, change the capability line that reads `... · USB storage control · self-update · self-protection` to include `staged rollouts`, e.g. `self-update (staged rollouts with pause/rollback)`. Wherever `release_dir` is documented, add:

```
release_base_url  URL agents download releases from (default: https://<first public hostname>:<console port>; http when the console has no TLS). Set it when the console sits behind a proxy or uses a self-signed cert.
```

Append to `docs/agent-manual-test.md`:

```markdown
## Staged rollout (VM)

1. Upload two builds on **Agent releases** (e.g. 0.2.1 and 0.2.2).
2. With the VM agent online and on 0.2.1, click **Start rollout** on 0.2.2, batch 1, pause after 1 failure.
3. Within a minute the card shows 1 in flight; the agent downloads, stages, and the swap helper restarts the service. On the next heartbeat the device reports 0.2.2 and the card shows 1 updated → state completed.
4. Roll back: pick 0.2.1 in **Roll back to** and click **Roll back**. The old rollout shows as cancelled in history and a new one runs to 0.2.1.
5. Failure path: upload a build whose file you then delete from `release_dir`. Start a rollout; the agent's download 404s, the device shows failed with the agent's message, and the rollout auto-pauses.
```

- [ ] **Step 2: Full verification**

Run:
```bash
go build ./... && go test ./... && npm --prefix web run build
```
Expected: all green.

- [ ] **Step 3: Commit and merge**

```bash
git add README.md docs deploy
git commit -m "docs: staged rollouts — README capability, release_base_url, VM checklist

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
git checkout master
git merge --ff-only feat/agent-rollouts
git push origin master
```

---

## Self-review notes

- **Spec coverage:** pre-existing bug fix (T1), config URL (T1), migration + one-open constraint (T2), device rows/candidates/resolution/summary (T3), reconciler incl. online filter, auto-pause audit, confirm timeout, completion, suspended tenants via `OpenRollouts` (T2+T4), ticker wiring (T4), all seven routes + audit actions (T5), console card/form/devices/history/polling (T6), docs (T7).
- **Deviation from spec to flag:** the spec listed `store.RolloutCandidates(ctx, tenantID, id, limit)`; the plan drops `limit` since the reconciler filters by presence in Go. Rollback to the same version returns 400 (spec did not say; chosen to avoid a pointless cancel+recreate).
- **Type consistency:** `SetRolloutState(ctx, tenant, id, from []string, to string, now time.Time)` is used identically in T2, T4, T5. `RolloutSummary` field names match between store, reconciler, and JSON. `ReleaseURL func(string) string` is the same shape on `config.Config` (method), `httpapi.API`, and `rollout.Service`.
