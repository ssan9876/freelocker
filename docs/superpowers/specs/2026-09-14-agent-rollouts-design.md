# Staged agent update rollouts — design

**Status:** approved 2026-09-14.

## Goal

Let an admin push a new agent release to the fleet in controlled batches,
watch it land, pause or cancel it when something goes wrong, and roll back
to the previous release with one click. Today an update can only be sent to
one device at a time, and even that path is broken (see below).

## Current state and the pre-existing bug

The update pipeline exists at both ends but is not connected:

- The console's per-device "Update agent" button calls
  `POST /api/devices/{id}/commands` with `{type: "update_agent"}`. The handler
  issues the command with a **nil payload** for every type.
- The agent parses that payload with `commands.ParseUpdate`, which fails on
  empty bytes, so the command always fails.
- `commands.Service.IssueUpdate` (which builds the real payload) has no
  callers. `store.LatestRelease` is only used in tests.

Task 1 of the plan fixes this: `update_agent` commands are always issued
through `IssueUpdate` with a payload built from a release row.

## Non-goals

- No agent or proto change. Agents keep learning about updates only through a
  signed `COMMAND_TYPE_UPDATE_AGENT` on the existing stream.
- No semver ordering. Versions are opaque strings; "already on the target
  version" means string equality with the device's reported `agent_version`.
- No per-device pinning or update channels.
- No scheduling (start at time T). A rollout starts when created.

## Semantics

A **rollout** targets one release version at a set of device groups (or every
device in the tenant). The server issues update commands to targeted devices
in batches from its minute ticker. Progress is derived from command results
and from the version each device reports in its heartbeat.

### Rollout states

| State | Meaning |
|---|---|
| `active` | reconciler issues commands each tick |
| `paused` | nothing new is issued; in-flight devices still resolve |
| `completed` | every targeted device is `updated` or `failed` |
| `cancelled` | terminal; nothing new is issued, in-flight devices still resolve |

`completed` and `cancelled` are terminal. Only one non-terminal rollout may
exist per tenant; creating a second returns 409. This keeps the reconciler
simple and stops two rollouts fighting over one device.

### Per-device states

| State | Set when |
|---|---|
| `issued` | the reconciler issued an update command to the device |
| `updated` | the device's heartbeat reports `agent_version == rollout.version` |
| `failed` | the command completed with failure, or expired, **or** the command succeeded but the device has not reported the target version within `ConfirmTimeout` (10 min) of the command's completion |

The timeout rule matters because the agent's `UpdateAgent` action returns
success as soon as the swap helper is launched; if the helper's health check
fails it silently restores the old binary, and only the reported version
reveals that.

`updated` and `failed` are terminal for that device within the rollout.

### Targeting

Targeted devices = non-revoked devices in the tenant whose `group_id` is in
the rollout's group set, or all non-revoked devices when the set is empty.
Membership is evaluated on each tick, so a device moved into a targeted group
mid-rollout is picked up; one moved out stops being issued to (but keeps any
existing device row). Devices already reporting the target version are
skipped entirely and never get a row; the summary counts them as
`already_current`.

### Batching and auto-pause

Each tick, for each `active` rollout:

1. Count devices in `issued` state (in flight). If that count is already at
   or above `batch_size`, do nothing this tick.
2. Otherwise issue to up to `batch_size − in_flight` targeted devices that
   have no row yet and are **online** (in the hub) — an offline device would
   just accumulate a pending command and hold a batch slot for 24 h.
   Ordering is by hostname for determinism.
3. Resolve in-flight rows: a completed-failure or expired command → `failed`;
   a device reporting the target version → `updated`; a succeeded command
   older than `ConfirmTimeout` with the old version still reported → `failed`.
4. If `failed` count ≥ `max_failures` (and `max_failures > 0`), set state to
   `paused` and write audit `rollout.auto_pause`.
5. If no targeted device is left untouched-and-online-and-not-current and no
   row is `issued`, and every targeted device has a terminal row or is
   current → `completed`.

Note that step 5 cannot complete a rollout while some targeted devices are
offline and have no row; the rollout stays `active` and waits for them. An
admin can cancel it.

Defaults: `batch_size` 10, `max_failures` 3. Both must be ≥ 1 and ≥ 0
respectively; `max_failures = 0` disables auto-pause.

### Rollback

A rollback is a new rollout of an earlier release with the same group set.
The API exposes it as `POST /api/rollouts/{id}/rollback` with
`{version}`: it cancels the given rollout if non-terminal and creates a new
`active` rollout for `version` targeting the same groups and using the same
`batch_size` / `max_failures`. The console pre-fills `version` with the most
recent release other than the rollout's own.

The agent's swap helper does not care about direction, so a "downgrade" is
just another update.

### Per-device "Update agent" button

Unchanged in the UI. The handler now issues via `IssueUpdate` using the
tenant's latest release; 409 if no release has been uploaded. It does not
create a rollout.

### Download URL

`UpdatePayload.URL` must be a URL the agent can fetch with a plain HTTP
client. New config field:

```yaml
release_base_url: https://console.example.com   # no trailing slash
```

Env `FREELOCKER_RELEASE_BASE_URL`. Default: `<scheme>://<PublicHostnames[0]><port of ConsoleListen>`
where scheme is `https` unless `ConsoleTLSMode() == "plain"`. The payload URL
is `<release_base_url>/agent/releases/<version>`. Integrity comes from the
hash and Ed25519 signature the agent already verifies, so the transport need
not be trusted, but a self-signed console cert will fail the agent's default
HTTP client; deployments with self-signed console TLS should set
`release_base_url` to the plain-HTTP listener or use ACME.

## Data

Migration `0017_agent_rollouts.sql`:

```sql
CREATE TABLE agent_rollouts (
    id            uuid PRIMARY KEY,
    tenant_id     uuid NOT NULL REFERENCES tenants(id),
    version       text NOT NULL,
    group_ids     uuid[] NOT NULL DEFAULT '{}',   -- empty = all devices
    batch_size    int  NOT NULL,
    max_failures  int  NOT NULL,
    state         text NOT NULL,                  -- active|paused|completed|cancelled
    created_by    text NOT NULL,                  -- actor string
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    finished_at   timestamptz
);
CREATE UNIQUE INDEX agent_rollouts_one_open
    ON agent_rollouts (tenant_id) WHERE state IN ('active', 'paused');

CREATE TABLE agent_rollout_devices (
    rollout_id   uuid NOT NULL REFERENCES agent_rollouts(id) ON DELETE CASCADE,
    device_id    uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    command_id   uuid NOT NULL,
    state        text NOT NULL,                   -- issued|updated|failed
    detail       text NOT NULL DEFAULT '',
    issued_at    timestamptz NOT NULL,
    resolved_at  timestamptz,
    PRIMARY KEY (rollout_id, device_id)
);
```

The partial unique index enforces "one open rollout per tenant" at the
database, so concurrent creates cannot both succeed (the store maps the
unique violation to `ErrConflict`).

`group_ids` is a plain array rather than a join table: it is written once,
never queried by group, and deleted groups simply match no devices.

## Store (`internal/server/store/rollouts.go`)

```go
type Rollout struct {
    ID          uuid.UUID
    Version     string
    GroupIDs    []uuid.UUID
    BatchSize   int
    MaxFailures int
    State       string
    CreatedBy   string
    CreatedAt, UpdatedAt time.Time
    FinishedAt  *time.Time
}
type RolloutDevice struct {
    DeviceID   uuid.UUID
    Hostname   string      // joined for display
    CommandID  uuid.UUID
    State      string
    Detail     string
    IssuedAt   time.Time
    ResolvedAt *time.Time
}
type RolloutSummary struct {
    Targeted, AlreadyCurrent, Issued, Updated, Failed, Remaining int
}
```

- `CreateRollout(ctx, tenantID, r) error` — `ErrConflict` on the partial
  unique index; validates the version exists in `agent_releases` (else
  `ErrNotFound`).
- `GetRollout`, `ListRollouts(ctx, tenantID, limit)` (newest first).
- `SetRolloutState(ctx, tenantID, id, from []string, to string) error` —
  guarded transition; `ErrConflict` if the current state is not in `from`.
  Sets `finished_at` for terminal states.
- `RolloutSummary(ctx, tenantID, id)` — one query over devices + rows.
- `ListRolloutDevices(ctx, tenantID, id)`.
- `RolloutCandidates(ctx, tenantID, id, limit)` — targeted, non-revoked
  devices with `agent_version <> version` and no row, ordered by hostname.
  The reconciler filters this list by hub presence, so `limit` is applied
  after filtering in Go (the query returns all candidates).
- `AddRolloutDevice(ctx, id, deviceID, commandID, now)`.
- `ResolveRolloutDevices(ctx, tenantID, id, now, confirmTimeout) (updated, failed int, err)` —
  one UPDATE using joins to `devices` and `commands` implementing the three
  resolution rules above.
- `OpenRollouts(ctx) ([]struct{TenantID; Rollout})` — all `active` rollouts
  across tenants, for the ticker.

## Reconciler (`internal/server/rollout/rollout.go`)

```go
type Service struct {
    Store          *store.Store
    Commands       *commands.Service
    Online         func(deviceID uuid.UUID) bool   // hub presence
    ReleaseURL     func(version string) string
    Now            func() time.Time
    ConfirmTimeout time.Duration                   // default 10 min
    Log            *slog.Logger
}
func (s *Service) Tick(ctx context.Context) error            // all tenants
func (s *Service) Reconcile(ctx context.Context, tenantID uuid.UUID, r store.Rollout) error
```

`Reconcile` implements the numbered steps in "Batching and auto-pause". It
builds each `UpdatePayload` from `store.GetRelease` and issues via
`Commands.IssueUpdate` with actor `rollout:<id>`. Errors on one device are
logged and skipped; the tick continues.

Wiring: `app.go` builds the service into `Runtime` (new field `Rollouts`)
and calls `Tick` from the existing minute loop, after `ExpireStale` so
expired commands are seen in the same tick.

## HTTP API (admin role)

| Method | Path | Body / result |
|---|---|---|
| `GET` | `/api/rollouts` | `[{rollout…, summary}]` newest first, limit 50 |
| `POST` | `/api/rollouts` | `{version, group_ids?, batch_size?, max_failures?}` → 201 `{id}`; 404 unknown version; 409 one already open; 400 bad numbers |
| `GET` | `/api/rollouts/{id}` | `{rollout…, summary, devices: [...]}` |
| `POST` | `/api/rollouts/{id}/pause` | active → paused; else 409 |
| `POST` | `/api/rollouts/{id}/resume` | paused → active; else 409 |
| `POST` | `/api/rollouts/{id}/cancel` | active/paused → cancelled; else 409 |
| `POST` | `/api/rollouts/{id}/rollback` | `{version}` → cancels if open, creates new rollout → 201 `{id}` |

Audit actions: `rollout.create`, `rollout.pause`, `rollout.resume`,
`rollout.cancel`, `rollout.rollback`, and `rollout.auto_pause` (actor
`system`). Target type `rollout`.

Rollout JSON fields: `id, version, group_ids, batch_size, max_failures,
state, created_by, created_at, updated_at, finished_at` plus `summary`
with the six counts. Device rows: `device_id, hostname, command_id, state,
detail, issued_at, resolved_at`.

The `GET` routes sit with the other read routes (any role); the `POST`
routes sit in the `requireRole("admin")` group. Uploading releases stays
owner-only.

## Console

`web/src/pages/Releases.tsx` gains:

- A **Start rollout** button per release row that opens an inline form:
  groups (multi-select from `/api/groups`, none = all devices), batch size,
  max failures. Disabled while a rollout is open.
- A **Rollouts** section above the release table: the open rollout (if any)
  as a card with version, state badge, a progress bar
  (`updated / (targeted − already_current)`), the six counts, and buttons
  Pause / Resume / Cancel / Roll back as the state allows. "Roll back"
  opens a version picker pre-filled with the newest other release.
- A collapsible per-device table for the open rollout (hostname, state,
  detail, issued/resolved times).
- A short history list of terminal rollouts (version, state, finished date).

The card polls every 10 s while a rollout is open.

`web/src/api.ts` gains `Rollout`, `RolloutSummary`, `RolloutDevice` types.
Inputs get `aria-label`s so Playwright can drive them.

## Error handling

- Reconciler: a store or issue error for one device is logged with
  `rollout` and `device` and skipped; a tenant-level error aborts that
  rollout's tick only.
- If a release row exists but the file is gone from `ReleaseDir`, the agent
  gets a 404, the command fails, and the device goes `failed` with the
  agent's message — the auto-pause threshold then stops the rollout.
- Suspended tenants: `OpenRollouts` excludes them, so nothing is issued.

## Testing

- `store/rollouts_test.go` (Postgres): create/conflict on second open
  rollout, guarded state transitions, candidates exclude revoked/current/
  already-rowed devices, `ResolveRolloutDevices` for each of the three rules,
  summary counts.
- `rollout/rollout_test.go` (Postgres + fake clock, hub stub): batch cap
  respected across ticks; offline devices skipped; auto-pause at threshold;
  confirm-timeout failure; completion when all resolve; cancelled/paused
  rollouts issue nothing.
- `httpapi/rollouts_test.go`: create → pause → resume → cancel → rollback
  flow, role checks, 409 on second open rollout, per-device `update_agent`
  now carries a parseable payload.
- Console: `npm --prefix web run typecheck` and `build`. Playwright smoke
  extended with the Rollouts empty state and a create-then-cancel using an
  uploaded dummy release (no devices, so it completes immediately with zero
  targets — the assertion is on state and summary).
