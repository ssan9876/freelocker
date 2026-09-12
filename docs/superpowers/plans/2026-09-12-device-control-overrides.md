# Per-device Control Overrides Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an admin set each device control (USB storage, network, elevation) to Inherit / Allow / Block per device, overriding the device's group.

**Architecture:** A new `device_control_overrides` table (nullable booleans; NULL = inherit) is folded into the existing `store.EffectiveControlsForDevice` query with `COALESCE(override, group, false)`. The agent already fetches controls through that function (`agentapi.GetControls`), so no protocol or agent change is needed. A console API exposes overrides/group/effective values and a device-page panel edits them.

**Tech Stack:** Go 1.x, pgx/v5, goose migrations, chi, gRPC (unchanged), React + TypeScript console.

**Spec:** `docs/superpowers/specs/2026-09-12-device-control-overrides-design.md`

## Global Constraints

- Every table has `tenant_id`; every store method takes `ctx, tenantID` first (repo convention).
- Tri-state encoding: `NULL` = inherit, `true` = block, `false` = allow. Effective value = `COALESCE(override, group value, false)`.
- A row whose three override columns are all NULL is never stored — the store deletes it.
- A device outside the caller's tenant → `store.ErrNotFound` → HTTP 404.
- GET `/api/devices/{id}/controls` is readable by any role; POST requires role `admin` (403 for `readonly`).
- Audit action for POST: `device.controls`, target type `device`.
- No agent, proto, or Windows-enforcer changes.
- Override rows are removed with their device by the FK's `ON DELETE CASCADE`. The app never deletes devices (it only revokes them), so there is no store path to test this through; the migration's FK is the guarantee.
- Tests need the dev Postgres: `docker compose -f deploy/docker-compose.dev.yml up -d` (port 55432).
- Commits: conventional messages ending with `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`. Work on branch `feat/device-overrides`.

---

### Task 1: Store — overrides table, get/set, effective resolution

**Files:**
- Create: `internal/server/store/migrations/0015_device_control_overrides.sql`
- Modify: `internal/server/store/controls.go` (add type + 2 methods, replace `EffectiveControlsForDevice` query)
- Test: `internal/server/store/overrides_test.go` (new)
- Test: `internal/server/agentapi/overrides_test.go` (new — proves the agent path picks overrides up)

**Interfaces:**
- Consumes: existing `store.DeviceControls`, `(*Store).SetControls`, `(*Store).EnrollDevice`, `ErrNotFound`, `oneRow`.
- Produces:
  - `type DeviceControlOverrides struct { USBStorageBlocked, NetworkBlocked, ElevationBlocked *bool }`
  - `func (s *Store) GetDeviceOverrides(ctx context.Context, tenantID, deviceID uuid.UUID) (DeviceControlOverrides, error)` — all-nil when no row; `ErrNotFound` if device not in tenant.
  - `func (s *Store) SetDeviceOverrides(ctx context.Context, tenantID, deviceID uuid.UUID, o DeviceControlOverrides) error` — upsert, or delete when all nil; `ErrNotFound` if device not in tenant.
  - `EffectiveControlsForDevice` (same signature) now honours overrides.

- [ ] **Step 1: Write the failing store tests**

`internal/server/store/overrides_test.go`:

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

func ptr(b bool) *bool { return &b }

// overrideEnv returns a store, tenant, the device's group, and a device in it.
func overrideEnv(t *testing.T) (*store.Store, uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	gid, _ := s.CreateDeviceGroup(ctx, tenant, "Laptops")
	s.CreateInstallToken(ctx, tenant, store.InstallToken{Name: "t", GroupID: &gid}, []byte("h"))
	dev := uuid.New()
	if _, err := s.EnrollDevice(ctx, []byte("h"), time.Now(), func(uuid.UUID) (store.NewDevice, error) {
		return store.NewDevice{ID: dev, Hostname: "pc", CertSerial: "s", CertExpiresAt: time.Now().Add(time.Hour)}, nil
	}); err != nil {
		t.Fatal(err)
	}
	return s, tenant, gid, dev
}

func TestEffectiveControlsResolution(t *testing.T) {
	ctx := context.Background()
	s, tenant, gid, dev := overrideEnv(t)
	// Group: USB blocked, network allowed, elevation has no explicit value (false).
	s.SetControls(ctx, tenant, gid, store.DeviceControls{USBStorageBlocked: true})

	cases := []struct {
		name string
		o    store.DeviceControlOverrides
		want store.DeviceControls
	}{
		{"all inherit", store.DeviceControlOverrides{}, store.DeviceControls{USBStorageBlocked: true}},
		{"allow loosens group block", store.DeviceControlOverrides{USBStorageBlocked: ptr(false)}, store.DeviceControls{}},
		{"block tightens group allow", store.DeviceControlOverrides{NetworkBlocked: ptr(true)},
			store.DeviceControls{USBStorageBlocked: true, NetworkBlocked: true}},
		{"mixed", store.DeviceControlOverrides{USBStorageBlocked: ptr(false), ElevationBlocked: ptr(true)},
			store.DeviceControls{ElevationBlocked: true}},
	}
	for _, tc := range cases {
		if err := s.SetDeviceOverrides(ctx, tenant, dev, tc.o); err != nil {
			t.Fatalf("%s: set: %v", tc.name, err)
		}
		got, err := s.EffectiveControlsForDevice(ctx, tenant, dev)
		if err != nil || got != tc.want {
			t.Errorf("%s: effective = %+v, %v; want %+v", tc.name, got, err, tc.want)
		}
	}
}

func TestEffectiveControlsOverrideWithoutGroup(t *testing.T) {
	ctx := context.Background()
	s, tenant, _, dev := overrideEnv(t)
	s.SetDeviceGroup(ctx, tenant, dev, nil)
	s.SetDeviceOverrides(ctx, tenant, dev, store.DeviceControlOverrides{NetworkBlocked: ptr(true)})
	got, _ := s.EffectiveControlsForDevice(ctx, tenant, dev)
	if got != (store.DeviceControls{NetworkBlocked: true}) {
		t.Errorf("ungrouped effective = %+v", got)
	}
}

func TestDeviceOverridesGetSet(t *testing.T) {
	ctx := context.Background()
	s, tenant, _, dev := overrideEnv(t)
	other, _ := s.CreateTenant(ctx, "Other")

	o, err := s.GetDeviceOverrides(ctx, tenant, dev)
	if err != nil || o.USBStorageBlocked != nil || o.NetworkBlocked != nil || o.ElevationBlocked != nil {
		t.Fatalf("fresh overrides = %+v, %v; want all nil", o, err)
	}
	s.SetDeviceOverrides(ctx, tenant, dev, store.DeviceControlOverrides{USBStorageBlocked: ptr(false), ElevationBlocked: ptr(true)})
	o, _ = s.GetDeviceOverrides(ctx, tenant, dev)
	if o.USBStorageBlocked == nil || *o.USBStorageBlocked || o.NetworkBlocked != nil || o.ElevationBlocked == nil || !*o.ElevationBlocked {
		t.Fatalf("overrides = %+v", o)
	}
	// All-nil removes the row: reads back as all nil again.
	if err := s.SetDeviceOverrides(ctx, tenant, dev, store.DeviceControlOverrides{}); err != nil {
		t.Fatal(err)
	}
	o, _ = s.GetDeviceOverrides(ctx, tenant, dev)
	if o.USBStorageBlocked != nil || o.ElevationBlocked != nil {
		t.Errorf("after clear = %+v", o)
	}
	// Cross-tenant and unknown devices are not found.
	if _, err := s.GetDeviceOverrides(ctx, other, dev); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("cross-tenant get err = %v", err)
	}
	if err := s.SetDeviceOverrides(ctx, other, dev, store.DeviceControlOverrides{NetworkBlocked: ptr(true)}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("cross-tenant set err = %v", err)
	}
	if err := s.SetDeviceOverrides(ctx, tenant, uuid.New(), store.DeviceControlOverrides{}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown device clear err = %v", err)
	}
}
```

- [ ] **Step 2: Write the failing agent-path test**

`internal/server/agentapi/overrides_test.go` (uses `startServer`, `hw` from existing test files in this package):

```go
package agentapi_test

import (
	"context"
	"testing"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/server/store"
	"freelocker/internal/server/tokens"
	"freelocker/internal/sim"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// TestGetControlsHonoursDeviceOverride proves an override that loosens the
// group's USB block reaches the agent through the unchanged GetControls RPC.
func TestGetControlsHonoursDeviceOverride(t *testing.T) {
	ctx := context.Background()
	ts := startServer(t)
	s, tenant := ts.Deps.Store, ts.Deps.Keys.TenantID
	gid, _ := s.CreateDeviceGroup(ctx, tenant, "Kiosks")
	s.SetControls(ctx, tenant, gid, store.DeviceControls{USBStorageBlocked: true})
	full, hash, _ := tokens.Generate(ts.Deps.Keys.CA.Pin())
	s.CreateInstallToken(ctx, tenant, store.InstallToken{Name: "k", GroupID: &gid}, hash)
	id, err := sim.Enroll(ctx, ts.Addr, full, hw)
	if err != nil {
		t.Fatal(err)
	}

	if !getControls(t, ts.Addr, id).GetUsbStorageBlocked() {
		t.Fatal("group block should apply before any override")
	}
	allow := false
	if err := s.SetDeviceOverrides(ctx, tenant, uuid.MustParse(id.DeviceID), store.DeviceControlOverrides{USBStorageBlocked: &allow}); err != nil {
		t.Fatal(err)
	}
	if getControls(t, ts.Addr, id).GetUsbStorageBlocked() {
		t.Error("device override Allow should lift the group's USB block")
	}
}

func getControls(t *testing.T, addr string, id *sim.Identity) *flv1.ControlsResponse {
	t.Helper()
	cfg, err := id.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := flv1.NewAgentClient(conn).GetControls(cctx, &flv1.GetControlsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
```

- [ ] **Step 3: Run both to verify they fail**

Run: `go test ./internal/server/store/ ./internal/server/agentapi/ -run 'Override|EffectiveControlsResolution|DeviceOverridesGetSet'`
Expected: build FAIL — `undefined: store.DeviceControlOverrides` / `s.SetDeviceOverrides undefined`.

- [ ] **Step 4: Add the migration**

`internal/server/store/migrations/0015_device_control_overrides.sql`:

```sql
-- +goose Up
-- Per-device control overrides. Each column is tri-state: NULL = inherit
-- the group's value, true = block, false = allow. A row with all three NULL
-- is never stored.
CREATE TABLE device_control_overrides (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    device_id uuid PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    usb_storage_blocked boolean,
    network_blocked boolean,
    elevation_blocked boolean,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE device_control_overrides;
```

- [ ] **Step 5: Implement the store methods and new resolution**

In `internal/server/store/controls.go`, add after `DeviceControls`:

```go
// DeviceControlOverrides is a device's per-control override: nil = inherit
// from the group, true = block, false = allow.
type DeviceControlOverrides struct {
	USBStorageBlocked *bool
	NetworkBlocked    *bool
	ElevationBlocked  *bool
}

func (o DeviceControlOverrides) empty() bool {
	return o.USBStorageBlocked == nil && o.NetworkBlocked == nil && o.ElevationBlocked == nil
}

// GetDeviceOverrides returns a device's overrides (all nil when none are
// set). ErrNotFound when the device is not in the tenant.
func (s *Store) GetDeviceOverrides(ctx context.Context, tenantID, deviceID uuid.UUID) (DeviceControlOverrides, error) {
	var o DeviceControlOverrides
	err := s.pool.QueryRow(ctx, `
		SELECT o.usb_storage_blocked, o.network_blocked, o.elevation_blocked
		FROM devices d LEFT JOIN device_control_overrides o ON o.device_id = d.id
		WHERE d.tenant_id = $1 AND d.id = $2`, tenantID, deviceID).
		Scan(&o.USBStorageBlocked, &o.NetworkBlocked, &o.ElevationBlocked)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return o, err
}

// SetDeviceOverrides stores a device's overrides, removing the row when all
// three inherit. ErrNotFound when the device is not in the tenant.
func (s *Store) SetDeviceOverrides(ctx context.Context, tenantID, deviceID uuid.UUID, o DeviceControlOverrides) error {
	var exists bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM devices WHERE tenant_id = $1 AND id = $2)`,
		tenantID, deviceID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	if o.empty() {
		_, err := s.pool.Exec(ctx, `DELETE FROM device_control_overrides WHERE tenant_id = $1 AND device_id = $2`, tenantID, deviceID)
		return err
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO device_control_overrides (tenant_id, device_id, usb_storage_blocked, network_blocked, elevation_blocked, updated_at)
		VALUES ($1, $2, $3, $4, $5, now())
		ON CONFLICT (device_id) DO UPDATE SET
			usb_storage_blocked = EXCLUDED.usb_storage_blocked,
			network_blocked = EXCLUDED.network_blocked,
			elevation_blocked = EXCLUDED.elevation_blocked,
			updated_at = now()`,
		tenantID, deviceID, o.USBStorageBlocked, o.NetworkBlocked, o.ElevationBlocked)
	return err
}
```

Replace the body of `EffectiveControlsForDevice` (keep its signature) and update its doc comment:

```go
// EffectiveControlsForDevice resolves each control as the device override if
// set, else the device's group value, else allow (nothing blocked).
func (s *Store) EffectiveControlsForDevice(ctx context.Context, tenantID, deviceID uuid.UUID) (DeviceControls, error) {
	var c DeviceControls
	err := s.pool.QueryRow(ctx, `
		SELECT COALESCE(o.usb_storage_blocked, dc.usb_storage_blocked, false),
		       COALESCE(o.network_blocked, dc.network_blocked, false),
		       COALESCE(o.elevation_blocked, dc.elevation_blocked, false)
		FROM devices d
		LEFT JOIN device_controls dc ON dc.group_id = d.group_id AND dc.tenant_id = d.tenant_id
		LEFT JOIN device_control_overrides o ON o.device_id = d.id
		WHERE d.tenant_id=$1 AND d.id=$2`, tenantID, deviceID).
		Scan(&c.USBStorageBlocked, &c.NetworkBlocked, &c.ElevationBlocked)
	if errors.Is(err, pgx.ErrNoRows) {
		return DeviceControls{}, ErrNotFound
	}
	return c, err
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./internal/server/store/ ./internal/server/agentapi/`
Expected: `ok` for both packages (new and existing tests, including `TestEffectiveControlsDefaultAllow`).

- [ ] **Step 7: Commit**

```bash
git add internal/server/store internal/server/agentapi/overrides_test.go
git commit -m "feat(controls): per-device control overrides in the store

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Console API — GET/POST /api/devices/{id}/controls

**Files:**
- Modify: `internal/server/httpapi/routes.go` (register 2 routes)
- Modify: `internal/server/httpapi/telemetry.go` (add 2 handlers next to `getControls`/`setControls`; reuse `controlsJSON`)
- Test: `internal/server/httpapi/overrides_test.go` (new)

**Interfaces:**
- Consumes (Task 1): `store.DeviceControlOverrides`, `GetDeviceOverrides`, `SetDeviceOverrides`, `EffectiveControlsForDevice`; existing `GetDevice`, `GetControls`, `controlsJSON(store.DeviceControls) map[string]bool`, `pathID`, `readJSON`, `storeErr`, `audit`.
- Produces (for Task 3):
  - `GET /api/devices/{id}/controls` → `{"overrides": {"usb_storage_blocked": bool|null, "network_blocked": bool|null, "elevation_blocked": bool|null}, "group": {…3 bools}, "effective": {…3 bools}}`
  - `POST /api/devices/{id}/controls` body `{"usb_storage_blocked": bool|null, "network_blocked": bool|null, "elevation_blocked": bool|null}` → 204.

- [ ] **Step 1: Write the failing test**

`internal/server/httpapi/overrides_test.go` (uses `newEnv`, `initialized`, `client`, `loginFull`, `fakeDevice`, `idResp` from existing test files):

```go
package httpapi_test

import "testing"

type controlsView struct {
	Overrides map[string]*bool `json:"overrides"`
	Group     map[string]bool  `json:"group"`
	Effective map[string]bool  `json:"effective"`
}

func TestDeviceControlOverridesOverHTTP(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)
	var g idResp
	c.do("POST", "/api/groups", map[string]string{"name": "Kiosks"}, &g)
	c.do("POST", "/api/groups/"+g.ID+"/controls", map[string]bool{"usb_storage_blocked": true}, nil)
	dev := e.fakeDevice(t).String()
	c.do("POST", "/api/devices/"+dev+"/group", map[string]any{"group_id": g.ID}, nil)

	var v controlsView
	if code := c.do("GET", "/api/devices/"+dev+"/controls", nil, &v); code != 200 {
		t.Fatalf("get = %d", code)
	}
	if v.Overrides["usb_storage_blocked"] != nil || !v.Group["usb_storage_blocked"] || !v.Effective["usb_storage_blocked"] {
		t.Fatalf("initial view = %+v", v)
	}

	body := map[string]any{"usb_storage_blocked": false, "network_blocked": true, "elevation_blocked": nil}
	if code := c.do("POST", "/api/devices/"+dev+"/controls", body, nil); code != 204 {
		t.Fatalf("set = %d", code)
	}
	v = controlsView{}
	c.do("GET", "/api/devices/"+dev+"/controls", nil, &v)
	usb, net := v.Overrides["usb_storage_blocked"], v.Overrides["network_blocked"]
	if usb == nil || *usb || net == nil || !*net || v.Overrides["elevation_blocked"] != nil {
		t.Errorf("overrides = %+v", v.Overrides)
	}
	if v.Effective["usb_storage_blocked"] || !v.Effective["network_blocked"] || v.Effective["elevation_blocked"] || !v.Group["usb_storage_blocked"] {
		t.Errorf("effective = %+v group = %+v", v.Effective, v.Group)
	}

	unknown := "00000000-0000-0000-0000-000000000001"
	if code := c.do("GET", "/api/devices/"+unknown+"/controls", nil, nil); code != 404 {
		t.Errorf("unknown device get = %d, want 404", code)
	}
	if code := c.do("POST", "/api/devices/"+unknown+"/controls", body, nil); code != 404 {
		t.Errorf("unknown device set = %d, want 404", code)
	}
}

func TestDeviceControlOverridesRbac(t *testing.T) {
	e := newEnv(t)
	owner := e.initialized(t)
	dev := e.fakeDevice(t).String()
	owner.do("POST", "/api/admins", map[string]string{"email": "ro@example.com", "password": "readonly-password-1", "role": "readonly"}, nil)
	ro := e.client(t)
	ro.loginFull("ro@example.com", "readonly-password-1", "")

	if code := ro.do("GET", "/api/devices/"+dev+"/controls", nil, nil); code != 200 {
		t.Errorf("readonly get = %d, want 200", code)
	}
	if code := ro.do("POST", "/api/devices/"+dev+"/controls", map[string]any{"network_blocked": true}, nil); code != 403 {
		t.Errorf("readonly set = %d, want 403", code)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/server/httpapi/ -run DeviceControlOverrides`
Expected: FAIL — `get = 404` / `405` (routes not registered).

- [ ] **Step 3: Register the routes**

In `internal/server/httpapi/routes.go`, in the top-level (any-role) block after `r.Get("/api/groups/{id}/controls", a.getControls)`:

```go
	r.Get("/api/devices/{id}/controls", a.getDeviceControls)
```

and in the `requireRole("admin")` group after `r.Post("/api/groups/{id}/controls", a.setControls)`:

```go
		r.Post("/api/devices/{id}/controls", a.setDeviceControls)
```

- [ ] **Step 4: Implement the handlers**

In `internal/server/httpapi/telemetry.go`, after `setControls`:

```go
func overridesJSON(o store.DeviceControlOverrides) map[string]*bool {
	return map[string]*bool{
		"usb_storage_blocked": o.USBStorageBlocked,
		"network_blocked":     o.NetworkBlocked,
		"elevation_blocked":   o.ElevationBlocked,
	}
}

// getDeviceControls returns a device's overrides alongside its group's
// controls and the effective result, so the console can show where each
// value comes from.
func (a *API) getDeviceControls(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	ctx, tenant := r.Context(), principalFrom(r).TenantID
	o, err := a.Store.GetDeviceOverrides(ctx, tenant, id)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	d, err := a.Store.GetDevice(ctx, tenant, id)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	var group store.DeviceControls
	if d.GroupID != nil {
		group, err = a.Store.GetControls(ctx, tenant, *d.GroupID)
		if err != nil && err != store.ErrNotFound {
			a.storeErr(w, err)
			return
		}
	}
	eff, err := a.Store.EffectiveControlsForDevice(ctx, tenant, id)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"overrides": overridesJSON(o), "group": controlsJSON(group), "effective": controlsJSON(eff),
	})
}

// setDeviceControls sets a device's overrides; null for a control means
// inherit from the group.
func (a *API) setDeviceControls(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		USBStorageBlocked *bool `json:"usb_storage_blocked"`
		NetworkBlocked    *bool `json:"network_blocked"`
		ElevationBlocked  *bool `json:"elevation_blocked"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	o := store.DeviceControlOverrides{USBStorageBlocked: req.USBStorageBlocked, NetworkBlocked: req.NetworkBlocked, ElevationBlocked: req.ElevationBlocked}
	p := principalFrom(r)
	if err := a.Store.SetDeviceOverrides(r.Context(), p.TenantID, id, o); err != nil {
		a.storeErr(w, err)
		return
	}
	detail := map[string]any{}
	for k, v := range overridesJSON(o) {
		detail[k] = v
	}
	a.audit(r, p, "device.controls", "device", id.String(), detail, "success")
	w.WriteHeader(http.StatusNoContent)
}
```

(Note: `GetControls` on a group with no controls row returns `ErrNotFound` with a zero value, which is the all-allow default we want.)

- [ ] **Step 5: Run to verify it passes**

Run: `go vet ./internal/server/... && go test ./internal/server/httpapi/`
Expected: `ok`.

- [ ] **Step 6: Commit**

```bash
git add internal/server/httpapi
git commit -m "feat(controls): console API for per-device control overrides

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Console — Device controls panel

**Files:**
- Modify: `web/src/api.ts` (add types)
- Modify: `web/src/pages/DeviceDetail.tsx` (add state, loader, panel)

**Interfaces:**
- Consumes (Task 2): the GET/POST `/api/devices/{id}/controls` shapes above; existing `api.get/api.post`, `useAuth()` from `../auth` (returns `{ me }` with `me.role`), `useToast()`, and the page's existing `groups: Group[]` state (loaded from `/api/groups` for the "Group" picker).
- Produces: UI only.

No automated frontend unit tests exist in this repo; verification is `tsc` via the build (Step 3). The Playwright smoke suite stops at MFA and does not reach this page.

- [ ] **Step 1: Add API types**

In `web/src/api.ts`, after the `DeviceDetail` type:

```ts
export type ControlKey = "usb_storage_blocked" | "network_blocked" | "elevation_blocked";
export type DeviceControlsView = {
  overrides: Record<ControlKey, boolean | null>;
  group: Record<ControlKey, boolean>;
  effective: Record<ControlKey, boolean>;
};
```

- [ ] **Step 2: Add the panel to DeviceDetail**

In `web/src/pages/DeviceDetail.tsx`:

1. Extend the `../api` import with `ControlKey, DeviceControlsView`, and add `import { useAuth } from "../auth";`.
2. Above `export function DeviceDetail()`:

```tsx
const CONTROL_LABELS: { key: ControlKey; label: string }[] = [
  { key: "usb_storage_blocked", label: "USB storage" },
  { key: "network_blocked", label: "Network" },
  { key: "elevation_blocked", label: "Elevation" },
];
```

3. Inside the component, next to the other `useState`s:

```tsx
  const { me } = useAuth();
  const canEdit = me?.role !== "readonly";
  const [ctl, setCtl] = useState<DeviceControlsView | null>(null);
```

4. In `load`, add:

```tsx
    api.get<DeviceControlsView>(`/api/devices/${id}/controls`).then(setCtl).catch(() => {});
```

5. After `moveToGroup`:

```tsx
  const setOverride = async (key: ControlKey, value: "inherit" | "allow" | "block") => {
    if (!ctl) return;
    const next = { ...ctl.overrides, [key]: value === "inherit" ? null : value === "block" };
    try {
      await api.post(`/api/devices/${id}/controls`, next);
      notify("Device controls updated");
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not update controls", "error");
    }
  };
```

6. After the closing `</div>` of `detail-grid` (before the "Recent commands" panel):

```tsx
      {ctl && (
        <div className="panel" style={{ marginTop: 20 }}>
          <h2>Device controls</h2>
          <p className="who" style={{ marginTop: -8 }}>
            Override this device's group. Inherit follows the group; Allow or Block applies to this device only.
          </p>
          <div className="table-wrap" style={{ border: "none" }}>
            <table>
              <thead>
                <tr>
                  <th>Control</th>
                  <th>Setting</th>
                  <th>Effective</th>
                </tr>
              </thead>
              <tbody>
                {CONTROL_LABELS.map(({ key, label }) => {
                  const o = ctl.overrides[key];
                  const setting = o === null ? "inherit" : o ? "block" : "allow";
                  const groupName = groups.find((g) => g.id === d.group_id)?.name;
                  const inherited = `Inherits: ${ctl.group[key] ? "Blocked" : "Allowed"} (${groupName ? `group ${groupName}` : "no group"})`;
                  return (
                    <tr key={key}>
                      <td>{label}</td>
                      <td>
                        {canEdit ? (
                          <select
                            aria-label={`${label} override`}
                            value={setting}
                            onChange={(e) => setOverride(key, e.target.value as "inherit" | "allow" | "block")}
                          >
                            <option value="inherit">{inherited}</option>
                            <option value="allow">Allow</option>
                            <option value="block">Block</option>
                          </select>
                        ) : setting === "inherit" ? (
                          inherited
                        ) : (
                          setting
                        )}
                      </td>
                      <td>
                        <span className={`badge ${ctl.effective[key] ? "fail" : "ok"}`}>
                          {ctl.effective[key] ? "Blocked" : "Allowed"}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
```

- [ ] **Step 3: Typecheck and build**

Run: `npm --prefix web run build`
Expected: `tsc -b` clean and `✓ built`. Then `git status --short internal/server/webui` shows no change (the build preserves `dist/.gitkeep`).

- [ ] **Step 4: Commit**

```bash
git add web/src
git commit -m "feat(console): device controls panel with per-device overrides

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Full verification and merge

- [ ] **Step 1:** `go vet ./... && go test ./...` — every package `ok`.
- [ ] **Step 2:** `GOOS=linux go build ./... && GOOS=windows go build -o /dev/null ./cmd/agent` — both succeed.
- [ ] **Step 3:** `git checkout master && git merge --ff-only feat/device-overrides`.
