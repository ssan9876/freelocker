# Interactive Approvals — Design

**Date:** 2026-09-11
**Status:** Approved for planning
**Builds on:** sub-project 2 (application control), sub-project 5 design
(`2026-09-10-kernel-driver-design.md`, "What is buildable now").

## Goal

Turn blocked / would-block program launches into an admin approval queue.
An admin approves (the hash becomes an allow rule on the policy that
blocked it) or denies (the request is closed and suppressed). This is the
server/protocol/UI half of interactive approval; the future kernel driver
only changes how fast requests arrive, not this workflow.

## Decisions

- **Source:** approval requests are created automatically from the
  `block_events` the agent already reports via `ReportBlocks`. No agent,
  protocol, or end-user UI changes.
- **Granularity:** one request per `(policy, sha256)`, aggregating across
  devices and repeat events.
- **Approve:** adds a `hash` rule to the policy that caused the block and
  recompiles it (same path as `promoteObservation`). Affects every device
  on that policy.
- **Deny:** closes the request; the hash no longer appears as pending for
  that policy. Nothing is actively blocked — the policy is already an
  allowlist.
- **Creation point:** at ingest time in `ReportBlocks`, so the policy is
  captured at the moment of the block (a later group reassignment cannot
  misattribute it).

## Data model — migration `0006_approvals.sql`

```sql
CREATE TABLE approval_requests (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    policy_id uuid NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    sha256 text NOT NULL,
    path text NOT NULL DEFAULT '',
    signer text NOT NULL DEFAULT '',
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'denied')),
    device_count int NOT NULL DEFAULT 0,
    event_count bigint NOT NULL DEFAULT 0,
    first_seen timestamptz NOT NULL,
    last_seen timestamptz NOT NULL,
    decided_by uuid REFERENCES admins(id),
    decided_at timestamptz,
    UNIQUE (policy_id, sha256)
);
CREATE INDEX approval_requests_tenant_status
    ON approval_requests (tenant_id, status, last_seen DESC);

CREATE TABLE approval_request_devices (
    request_id uuid NOT NULL REFERENCES approval_requests(id) ON DELETE CASCADE,
    device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    PRIMARY KEY (request_id, device_id)
);
```

`path` and `signer` keep the first non-empty value seen (as
`observations.signer` does). `device_count` is maintained from
`approval_request_devices` so it counts distinct devices. When a device is
deleted its link row cascades away; `device_count` is not decremented
(it is a "devices affected" figure, not live membership).

## Server

### Store (`internal/server/store/approvals.go`)

```go
type ApprovalRequest struct {
    ID, PolicyID                  uuid.UUID
    PolicyName                    string // joined for listing
    SHA256, Path, Signer, Status  string
    DeviceCount                   int
    EventCount                    int64
    FirstSeen, LastSeen           time.Time
    DecidedBy                     *uuid.UUID
    DecidedAt                     *time.Time
}

// UpsertApprovalRequests aggregates events (one device, one policy) into
// requests, in one transaction. Events with an empty SHA256 are skipped.
// Existing requests get event_count += n, last_seen advanced, the device
// linked; their status is never changed.
func (s *Store) UpsertApprovalRequests(ctx, tenantID, policyID, deviceID uuid.UUID, events []BlockEvent) error

// ListApprovalRequests lists requests by status ("" = all), newest
// last_seen first.
func (s *Store) ListApprovalRequests(ctx, tenantID uuid.UUID, status string, limit int) ([]ApprovalRequest, error)

func (s *Store) GetApprovalRequest(ctx, tenantID, id uuid.UUID) (ApprovalRequest, error)

// DecideApprovalRequest moves a pending request to approved/denied.
// Returns ErrNotFound if absent, ErrConflict if not pending.
func (s *Store) DecideApprovalRequest(ctx, tenantID, id uuid.UUID, status string, adminID uuid.UUID, now time.Time) error

func (s *Store) CountPendingApprovals(ctx, tenantID uuid.UUID) (int, error)
```

Aggregation within one batch groups events by hash first (count, min/max
time) so each hash is one statement.

### Ingest (`internal/server/agentapi/policy.go`, `ReportBlocks`)

After `RecordBlockEvents` succeeds: resolve `EffectivePolicyForDevice`.
- `ErrNotFound` (no group / assignment) → skip.
- Any error resolving or upserting → log and still return `Ack`. Block
  events are the source of truth and are never lost because of the
  approval queue.

### Console API (`internal/server/httpapi/approvals.go`)

| Method | Route | Behavior |
|---|---|---|
| GET | `/api/approvals?status=pending&limit=200` | list; `status` ∈ pending/approved/denied/"" |
| GET | `/api/approvals/count` | `{"pending": n}` for the nav badge |
| POST | `/api/approvals/{id}/approve` | add hash rule + recompile + mark approved |
| POST | `/api/approvals/{id}/deny` | mark denied |

Approve order: load request (404 if absent, 409 if not pending) → add the
hash rule via a helper shared with `promoteObservation` (an already-existing
identical rule — `AddRule` returning `store.ErrConflict` — counts as
success) → recompile → `DecideApprovalRequest`. A not-pending request is
reported as 409 `"request already decided"` (written explicitly, not via
`storeErr`, whose 409 text is "already exists").
Rule description: `approved from request <id> (<path>)`. Audit actions
`approval.approve` / `approval.deny` with `policy_id` and `sha256`.
GET routes are open to any signed-in admin; the approve/deny routes sit in
the `requireRole("admin")` group alongside the policy routes.

Response JSON uses snake_case fields matching the struct above
(`policy_name` included).

## Console (`web/`)

- `pages/Approvals.tsx`: page head "Approvals", status filter
  (Pending / Approved / Denied), dense table — Last seen, Path, Signer,
  SHA-256 (truncated, full on hover), Policy, Devices, Events, and
  Approve / Deny buttons on pending rows. Deny asks for confirmation.
  Polls every 15 s like Blocks.
- Nav entry "Approvals" with a pending-count badge from
  `/api/approvals/count`.
- Types and calls added to `api.ts`.

## Error handling

- Deciding a non-pending request → 409 with message; UI reloads the list.
- Approve when recompile fails → 500; request stays pending (rule may be
  added; retrying approve is safe because duplicate rules are tolerated).
- Policy deleted → its requests cascade away.

## Testing

- **Store:** new request created; repeat events accumulate
  `event_count`, advance `last_seen`; distinct-device `device_count`;
  empty-hash events skipped; decided requests keep their status on new
  events; decide pending→approved works, second decide → `ErrConflict`;
  tenant isolation.
- **agentapi:** `ReportBlocks` from a device with an assigned, compiled
  policy creates a pending request; from a device without one creates none
  and still acks.
- **httpapi:** approve adds the hash rule and produces a new policy
  version, request becomes approved; deny adds no rule; second decide →
  409; count endpoint.
- **Web:** `npm --prefix web run build` type-checks.

No enforcement code is touched; all verification runs against the dev
Postgres on the dev box.

## Out of scope

End-user "request access" prompts, per-device exceptions, publisher/path
approvals, approval expiry, and kernel-driver hold-and-ask.
