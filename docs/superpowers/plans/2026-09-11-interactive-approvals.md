# Interactive Approvals Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn blocked / would-block launches into an admin approval queue where Approve adds a hash allow rule to the blocking policy and Deny closes the request.

**Architecture:** `ReportBlocks` ingest aggregates each batch into `approval_requests` rows keyed by `(policy_id, sha256)`, using the device's effective policy at ingest time. Console endpoints list and decide requests; Approve reuses the `promoteObservation` add-rule-and-recompile path via a shared helper. A new React page shows the queue with a nav badge.

**Tech Stack:** Go, pgx/v5, goose migrations, chi, React + TypeScript (Vite).

**Spec:** `docs/superpowers/specs/2026-09-11-interactive-approvals-design.md`

## Global Constraints

- Every table has `tenant_id`; every store method takes `tenantID` first after `ctx`.
- Store tests use `storetest.New(t)` and need the dev Postgres on :55432 (`docker compose -f deploy/docker-compose.dev.yml up -d`).
- TDD: failing test → implement → pass → one commit per task. Conventional-commit messages ending with `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`.
- No agent, protocol (`proto/`), or enforcement code changes.
- Block events must never be lost because of the approval queue: approval errors in `ReportBlocks` are logged, never returned.
- Cross-check `GOOS=linux go build ./...` and `go vet ./...` before the final commit.

---

### Task 1: Migration + approvals store

**Files:**
- Create: `internal/server/store/migrations/0006_approvals.sql`
- Create: `internal/server/store/approvals.go`
- Test: `internal/server/store/approvals_test.go`

**Interfaces:**
- Consumes: `store.BlockEvent` (`observations.go`), `seedDevice` test helper (`observations_test.go`), `ErrNotFound`/`ErrConflict` (`store.go`).
- Produces:
  ```go
  type ApprovalRequest struct {
      ID, PolicyID                 uuid.UUID
      PolicyName                   string
      SHA256, Path, Signer, Status string
      DeviceCount                  int
      EventCount                   int64
      FirstSeen, LastSeen          time.Time
      DecidedBy                    *uuid.UUID
      DecidedAt                    *time.Time
  }
  func (s *Store) UpsertApprovalRequests(ctx context.Context, tenantID, policyID, deviceID uuid.UUID, events []BlockEvent) error
  func (s *Store) ListApprovalRequests(ctx context.Context, tenantID uuid.UUID, status string, limit int) ([]ApprovalRequest, error)
  func (s *Store) GetApprovalRequest(ctx context.Context, tenantID, id uuid.UUID) (ApprovalRequest, error)
  func (s *Store) DecideApprovalRequest(ctx context.Context, tenantID, id uuid.UUID, status string, adminID uuid.UUID, now time.Time) error
  func (s *Store) CountPendingApprovals(ctx context.Context, tenantID uuid.UUID) (int, error)
  ```

- [ ] **Step 1: Write the migration**

`internal/server/store/migrations/0006_approvals.sql`:
```sql
-- +goose Up
CREATE TABLE approval_requests (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    policy_id uuid NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    sha256 text NOT NULL,
    path text NOT NULL DEFAULT '',
    signer text NOT NULL DEFAULT '',
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied')),
    device_count int NOT NULL DEFAULT 0,
    event_count bigint NOT NULL DEFAULT 0,
    first_seen timestamptz NOT NULL,
    last_seen timestamptz NOT NULL,
    decided_by uuid REFERENCES admins(id),
    decided_at timestamptz,
    UNIQUE (policy_id, sha256)
);
CREATE INDEX approval_requests_tenant_status ON approval_requests (tenant_id, status, last_seen DESC);

CREATE TABLE approval_request_devices (
    request_id uuid NOT NULL REFERENCES approval_requests(id) ON DELETE CASCADE,
    device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    PRIMARY KEY (request_id, device_id)
);

-- +goose Down
DROP TABLE approval_request_devices, approval_requests;
```

- [ ] **Step 2: Write the failing tests**

`internal/server/store/approvals_test.go`:
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

func TestApprovalRequestsAggregate(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	pol, _ := s.CreatePolicy(ctx, tenant, "Baseline", "audit")
	dev1 := seedDevice(t, s, tenant)
	dev2 := seedDevice(t, s, tenant)
	t0 := time.Now().Add(-time.Hour).Truncate(time.Second)

	// One batch: two events for AA (first with no signer), one event with no hash.
	err := s.UpsertApprovalRequests(ctx, tenant, pol, dev1, []store.BlockEvent{
		{SHA256: "AA", Path: `C:\a.exe`, At: t0},
		{SHA256: "AA", Path: `C:\a.exe`, Signer: "Acme", At: t0.Add(time.Minute)},
		{SHA256: "", Path: `C:\nohash.exe`, At: t0},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Same device again, then a second device.
	s.UpsertApprovalRequests(ctx, tenant, pol, dev1, []store.BlockEvent{{SHA256: "AA", At: t0.Add(2 * time.Minute)}})
	s.UpsertApprovalRequests(ctx, tenant, pol, dev2, []store.BlockEvent{{SHA256: "AA", At: t0.Add(3 * time.Minute)}})

	list, err := s.ListApprovalRequests(ctx, tenant, "pending", 10)
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %+v, %v (empty-hash events must be skipped)", list, err)
	}
	r := list[0]
	if r.EventCount != 4 || r.DeviceCount != 2 {
		t.Errorf("counts = events %d devices %d, want 4 and 2", r.EventCount, r.DeviceCount)
	}
	if r.Path != `C:\a.exe` || r.Signer != "Acme" || r.PolicyName != "Baseline" || r.Status != "pending" {
		t.Errorf("fields = %+v", r)
	}
	if !r.FirstSeen.Equal(t0) || !r.LastSeen.Equal(t0.Add(3*time.Minute)) {
		t.Errorf("first/last = %v / %v", r.FirstSeen, r.LastSeen)
	}
	if n, _ := s.CountPendingApprovals(ctx, tenant); n != 1 {
		t.Errorf("pending count = %d", n)
	}
	if err := s.UpsertApprovalRequests(ctx, tenant, pol, dev1, nil); err != nil {
		t.Errorf("empty batch should be a no-op: %v", err)
	}
}

func TestApprovalRequestDecide(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	pol, _ := s.CreatePolicy(ctx, tenant, "Baseline", "audit")
	dev := seedDevice(t, s, tenant)
	admin, err := s.CreateAdmin(ctx, tenant, store.Admin{Email: "a@example.com", PasswordHash: "h", Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	s.UpsertApprovalRequests(ctx, tenant, pol, dev, []store.BlockEvent{{SHA256: "AA", At: time.Now()}})
	list, _ := s.ListApprovalRequests(ctx, tenant, "", 10)
	id := list[0].ID

	if err := s.DecideApprovalRequest(ctx, tenant, id, "approved", admin, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.DecideApprovalRequest(ctx, tenant, id, "denied", admin, time.Now()); !errors.Is(err, store.ErrConflict) {
		t.Errorf("second decide = %v, want ErrConflict", err)
	}
	if err := s.DecideApprovalRequest(ctx, tenant, uuid.New(), "denied", admin, time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown id = %v, want ErrNotFound", err)
	}

	// New events for a decided hash do not reopen it.
	s.UpsertApprovalRequests(ctx, tenant, pol, dev, []store.BlockEvent{{SHA256: "AA", At: time.Now()}})
	got, err := s.GetApprovalRequest(ctx, tenant, id)
	if err != nil || got.Status != "approved" || got.DecidedBy == nil || *got.DecidedBy != admin || got.DecidedAt == nil {
		t.Fatalf("after re-report = %+v, %v", got, err)
	}
	if pending, _ := s.ListApprovalRequests(ctx, tenant, "pending", 10); len(pending) != 0 {
		t.Errorf("pending = %+v, want none", pending)
	}

	// Tenant isolation.
	other, _ := s.CreateTenant(ctx, "Other")
	if l, _ := s.ListApprovalRequests(ctx, other, "", 10); len(l) != 0 {
		t.Errorf("other tenant sees %+v", l)
	}
	if _, err := s.GetApprovalRequest(ctx, other, id); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("other tenant get = %v, want ErrNotFound", err)
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/server/store/ -run TestApprovalRequest -v`
Expected: build failure — `s.UpsertApprovalRequests undefined`.

- [ ] **Step 4: Implement the store**

`internal/server/store/approvals.go`:
```go
package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type ApprovalRequest struct {
	ID, PolicyID                 uuid.UUID
	PolicyName                   string
	SHA256, Path, Signer, Status string
	DeviceCount                  int
	EventCount                   int64
	FirstSeen, LastSeen          time.Time
	DecidedBy                    *uuid.UUID
	DecidedAt                    *time.Time
}

// UpsertApprovalRequests aggregates one device's block events into approval
// requests for policyID, one per hash. Events without a hash are skipped.
// Existing requests accumulate counts and timestamps; their status is never
// changed, so a decided hash stays decided.
func (s *Store) UpsertApprovalRequests(ctx context.Context, tenantID, policyID, deviceID uuid.UUID, events []BlockEvent) error {
	type agg struct {
		path, signer string
		n            int64
		first, last  time.Time
	}
	byHash := map[string]*agg{}
	var order []string
	for _, e := range events {
		if e.SHA256 == "" {
			continue
		}
		at := e.At
		if at.IsZero() {
			at = time.Now()
		}
		a, ok := byHash[e.SHA256]
		if !ok {
			a = &agg{first: at, last: at}
			byHash[e.SHA256] = a
			order = append(order, e.SHA256)
		}
		a.n++
		if a.path == "" {
			a.path = e.Path
		}
		if a.signer == "" {
			a.signer = e.Signer
		}
		if at.Before(a.first) {
			a.first = at
		}
		if at.After(a.last) {
			a.last = at
		}
	}
	if len(order) == 0 {
		return nil
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, h := range order {
		a := byHash[h]
		var id uuid.UUID
		err := tx.QueryRow(ctx, `
			INSERT INTO approval_requests (id, tenant_id, policy_id, sha256, path, signer, event_count, first_seen, last_seen)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
			ON CONFLICT (policy_id, sha256) DO UPDATE SET
				event_count = approval_requests.event_count + EXCLUDED.event_count,
				first_seen = LEAST(approval_requests.first_seen, EXCLUDED.first_seen),
				last_seen = GREATEST(approval_requests.last_seen, EXCLUDED.last_seen),
				path = CASE WHEN approval_requests.path = '' THEN EXCLUDED.path ELSE approval_requests.path END,
				signer = CASE WHEN approval_requests.signer = '' THEN EXCLUDED.signer ELSE approval_requests.signer END
			RETURNING id`,
			uuid.New(), tenantID, policyID, h, a.path, a.signer, a.n, a.first, a.last).Scan(&id)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `
			INSERT INTO approval_request_devices (request_id, device_id) VALUES ($1,$2)
			ON CONFLICT DO NOTHING`, id, deviceID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 1 {
			if _, err := tx.Exec(ctx, `UPDATE approval_requests SET device_count = device_count + 1 WHERE id=$1`, id); err != nil {
				return err
			}
		}
	}
	return tx.Commit(ctx)
}

const approvalSelect = `
	SELECT ar.id, ar.policy_id, p.name, ar.sha256, ar.path, ar.signer, ar.status,
		ar.device_count, ar.event_count, ar.first_seen, ar.last_seen, ar.decided_by, ar.decided_at
	FROM approval_requests ar JOIN policies p ON p.id = ar.policy_id`

func scanApproval(row pgx.Row) (ApprovalRequest, error) {
	var a ApprovalRequest
	err := row.Scan(&a.ID, &a.PolicyID, &a.PolicyName, &a.SHA256, &a.Path, &a.Signer, &a.Status,
		&a.DeviceCount, &a.EventCount, &a.FirstSeen, &a.LastSeen, &a.DecidedBy, &a.DecidedAt)
	return a, err
}

// ListApprovalRequests lists requests with the given status ("" = all),
// most recently seen first.
func (s *Store) ListApprovalRequests(ctx context.Context, tenantID uuid.UUID, status string, limit int) ([]ApprovalRequest, error) {
	rows, _ := s.pool.Query(ctx, approvalSelect+`
		WHERE ar.tenant_id=$1 AND ($2::text = '' OR ar.status = $2)
		ORDER BY ar.last_seen DESC LIMIT $3`, tenantID, status, limit)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (ApprovalRequest, error) { return scanApproval(r) })
}

func (s *Store) GetApprovalRequest(ctx context.Context, tenantID, id uuid.UUID) (ApprovalRequest, error) {
	a, err := scanApproval(s.pool.QueryRow(ctx, approvalSelect+` WHERE ar.tenant_id=$1 AND ar.id=$2`, tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return a, err
}

// DecideApprovalRequest moves a pending request to status ("approved" or
// "denied"). It returns ErrNotFound for an unknown request and ErrConflict
// for one that is already decided.
func (s *Store) DecideApprovalRequest(ctx context.Context, tenantID, id uuid.UUID, status string, adminID uuid.UUID, now time.Time) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE approval_requests SET status=$3, decided_by=$4, decided_at=$5
		WHERE tenant_id=$1 AND id=$2 AND status='pending'`, tenantID, id, status, adminID, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	if _, err := s.GetApprovalRequest(ctx, tenantID, id); err != nil {
		return err
	}
	return ErrConflict
}

func (s *Store) CountPendingApprovals(ctx context.Context, tenantID uuid.UUID) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM approval_requests WHERE tenant_id=$1 AND status='pending'`, tenantID).Scan(&n)
	return n, err
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/server/store/ -v`
Expected: all PASS (new tests plus existing store tests — the migration must apply cleanly).

- [ ] **Step 6: Commit**

```bash
git add internal/server/store/migrations/0006_approvals.sql internal/server/store/approvals.go internal/server/store/approvals_test.go
git commit -m "feat(approvals): add approval-requests store and migration"
```

---

### Task 2: Create approval requests on ReportBlocks ingest

**Files:**
- Modify: `internal/server/agentapi/policy.go` (`ReportBlocks`, lines 45-62)
- Test: `internal/server/agentapi/policy_test.go`

**Interfaces:**
- Consumes: `Store.EffectivePolicyForDevice(ctx, tenantID, deviceID) (PolicyVersion, error)` (returns `ErrNotFound` when no group/assignment/version), `Store.UpsertApprovalRequests`, `Store.ListApprovalRequests` (Task 1).
- Produces: behavior only — a device with an effective policy that reports block events gets pending approval requests.

- [ ] **Step 1: Write the failing tests**

In `internal/server/agentapi/policy_test.go`, append to the end of `TestGetPolicyObserveAndReportBlocks` (after the `blocks` assertion):
```go
	reqs, err := ts.Deps.Store.ListApprovalRequests(ctx, tenant, "pending", 10)
	if err != nil || len(reqs) != 1 || reqs[0].SHA256 != "BB" || reqs[0].PolicyID != pid || reqs[0].DeviceCount != 1 {
		t.Fatalf("approval requests = %+v, %v", reqs, err)
	}
```

And add a new test at the end of the file:
```go
func TestReportBlocksWithoutPolicyCreatesNoApproval(t *testing.T) {
	ctx := context.Background()
	ts := startServer(t)
	tenant := ts.Deps.Keys.TenantID

	full, hash, _ := tokens.Generate(ts.Deps.Keys.CA.Pin())
	ts.Deps.Store.CreateInstallToken(ctx, tenant, store.InstallToken{Name: "nogroup"}, hash)
	id, err := sim.Enroll(ctx, ts.Addr, full, hw)
	if err != nil {
		t.Fatal(err)
	}
	client := agentClient(t, ts, id)
	if _, err := client.ReportBlocks(ctx, &flv1.ReportBlocksRequest{Events: []*flv1.BlockEvent{
		{Sha256: "CC", Path: `C:\x.exe`, AtUnix: time.Now().Unix()},
	}}); err != nil {
		t.Fatalf("report must still ack without a policy: %v", err)
	}
	if blocks, _ := ts.Deps.Store.ListBlockEvents(ctx, tenant, 10); len(blocks) != 1 {
		t.Fatalf("block events = %+v", blocks)
	}
	if reqs, _ := ts.Deps.Store.ListApprovalRequests(ctx, tenant, "", 10); len(reqs) != 0 {
		t.Fatalf("approval requests = %+v, want none", reqs)
	}
}
```

- [ ] **Step 2: Run tests to verify the first fails**

Run: `go test ./internal/server/agentapi/ -run 'ReportBlocks|GetPolicyObserve' -v`
Expected: `TestGetPolicyObserveAndReportBlocks` FAILS with `approval requests = [], <nil>`; the no-policy test passes already.

- [ ] **Step 3: Implement**

In `internal/server/agentapi/policy.go`, add `"errors"` to the imports and replace the tail of `ReportBlocks` (from the `RecordBlockEvents` call to the end of the function) with:
```go
	if err := s.d.Store.RecordBlockEvents(ctx, dev.TenantID, dev.ID, events); err != nil {
		s.d.Log.Error("record block events", "device", dev.ID, "err", err)
		return nil, status.Error(codes.Internal, "could not record block events")
	}
	s.queueApprovals(ctx, dev.TenantID, dev.ID, events)
	return &flv1.Ack{}, nil
}

// queueApprovals turns block events into approval requests against the
// device's effective policy. Failures are logged only: the block events are
// already recorded and are the source of truth.
func (s *agentService) queueApprovals(ctx context.Context, tenantID, deviceID uuid.UUID, events []store.BlockEvent) {
	pv, err := s.d.Store.EffectivePolicyForDevice(ctx, tenantID, deviceID)
	if errors.Is(err, store.ErrNotFound) {
		return
	}
	if err != nil {
		s.d.Log.Error("resolve policy for approvals", "device", deviceID, "err", err)
		return
	}
	if err := s.d.Store.UpsertApprovalRequests(ctx, tenantID, pv.PolicyID, deviceID, events); err != nil {
		s.d.Log.Error("queue approval requests", "device", deviceID, "err", err)
	}
}
```
Add `"github.com/google/uuid"` to the imports. Check `deviceFrom(ctx)`'s return type: if `dev.ID`/`dev.TenantID` are `uuid.UUID` (they are passed to store methods taking `uuid.UUID`), this compiles as written.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/server/agentapi/ -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/server/agentapi/policy.go internal/server/agentapi/policy_test.go
git commit -m "feat(approvals): queue approval requests from reported block events"
```

---

### Task 3: Console API for approvals

**Files:**
- Create: `internal/server/httpapi/approvals.go`
- Modify: `internal/server/httpapi/policies.go` (`promoteObservation`, lines 251-284 — extract shared helper)
- Modify: `internal/server/httpapi/routes.go` (register routes)
- Test: `internal/server/httpapi/approvals_test.go`

**Interfaces:**
- Consumes: Task 1 store methods; `rules.Normalize`, `rules.Hash` (`internal/appcontrol/rules`); `principalFrom(r) principal` (fields `TenantID`, `Admin.ID`); `a.audit(r, p, action, targetType, targetID, detail, result)`; `a.Runtime().Policy.Recompile(ctx, tenantID, policyID) (string, error)`; test helpers `newEnv`, `e.initialized`, `c.do`, `e.fakeDevice`, `hex64`.
- Produces (HTTP, consumed by Task 4):
  - `GET /api/approvals?status=pending&limit=200` → `200` JSON array of `{id, policy_id, policy_name, sha256, path, signer, status, device_count, event_count, first_seen, last_seen, decided_at}` (`decided_at` null when pending)
  - `GET /api/approvals/count` → `200 {"pending": n}`
  - `POST /api/approvals/{id}/approve` → `204`; `404` unknown; `409 {"error":"request already decided"}`
  - `POST /api/approvals/{id}/deny` → same codes

- [ ] **Step 1: Write the failing tests**

`internal/server/httpapi/approvals_test.go`:
```go
package httpapi_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"freelocker/internal/server/store"

	"github.com/google/uuid"
)

// seedApproval creates a pending approval request for sha on policyID.
func (e *env) seedApproval(t *testing.T, policyID, sha string) string {
	t.Helper()
	ctx := context.Background()
	tenant := e.rt().Keys.TenantID
	dev := e.fakeDevice(t)
	if err := e.store.UpsertApprovalRequests(ctx, tenant, uuid.MustParse(policyID), dev, []store.BlockEvent{
		{SHA256: sha, Path: `C:\new.exe`, At: time.Now()},
	}); err != nil {
		t.Fatal(err)
	}
	list, _ := e.store.ListApprovalRequests(ctx, tenant, "", 100)
	for _, r := range list {
		if r.SHA256 == sha {
			return r.ID.String()
		}
	}
	t.Fatalf("seeded request %s not found", sha)
	return ""
}

func TestApproveAndDenyOverHTTP(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)

	var pol struct{ ID string }
	c.do("POST", "/api/policies", map[string]string{"name": "Baseline"}, &pol)
	shaApprove, shaDeny := strings.ToUpper(hex64("c")), strings.ToUpper(hex64("d"))
	approveID := e.seedApproval(t, pol.ID, shaApprove)
	denyID := e.seedApproval(t, pol.ID, shaDeny)

	var count struct{ Pending int }
	if code := c.do("GET", "/api/approvals/count", nil, &count); code != 200 || count.Pending != 2 {
		t.Fatalf("count = %d %+v", code, count)
	}
	var pending []map[string]any
	c.do("GET", "/api/approvals?status=pending", nil, &pending)
	if len(pending) != 2 || pending[0]["policy_name"] != "Baseline" || pending[0]["decided_at"] != nil {
		t.Fatalf("pending = %+v", pending)
	}

	type detail struct {
		Rules   []map[string]any `json:"rules"`
		Version string           `json:"version"`
	}
	var before detail
	c.do("GET", "/api/policies/"+pol.ID, nil, &before)

	if code := c.do("POST", "/api/approvals/"+approveID+"/approve", nil, nil); code != 204 {
		t.Fatalf("approve = %d", code)
	}
	var after detail
	c.do("GET", "/api/policies/"+pol.ID, nil, &after)
	if len(after.Rules) != 1 || after.Rules[0]["value"] != shaApprove || after.Version == before.Version {
		t.Fatalf("after approve: rules %+v version %q (before %q)", after.Rules, after.Version, before.Version)
	}

	var errResp struct{ Error string }
	if code := c.do("POST", "/api/approvals/"+approveID+"/approve", nil, &errResp); code != 409 || errResp.Error != "request already decided" {
		t.Errorf("second approve = %d %+v, want 409", code, errResp)
	}

	if code := c.do("POST", "/api/approvals/"+denyID+"/deny", nil, nil); code != 204 {
		t.Fatalf("deny = %d", code)
	}
	c.do("GET", "/api/policies/"+pol.ID, nil, &after)
	if len(after.Rules) != 1 {
		t.Errorf("deny must not add a rule: %+v", after.Rules)
	}

	var approved, denied []map[string]any
	c.do("GET", "/api/approvals?status=approved", nil, &approved)
	c.do("GET", "/api/approvals?status=denied", nil, &denied)
	if len(approved) != 1 || len(denied) != 1 || approved[0]["decided_at"] == nil {
		t.Errorf("approved %+v denied %+v", approved, denied)
	}
	c.do("GET", "/api/approvals/count", nil, &count)
	if count.Pending != 0 {
		t.Errorf("pending after decisions = %d", count.Pending)
	}

	if code := c.do("POST", "/api/approvals/"+uuid.NewString()+"/deny", nil, nil); code != 404 {
		t.Errorf("unknown id = %d, want 404", code)
	}
	if code := c.do("GET", "/api/approvals?status=bogus", nil, nil); code != 400 {
		t.Errorf("bad status = %d, want 400", code)
	}
}

func TestApprovalsReadonlyCannotDecide(t *testing.T) {
	e := newEnv(t)
	owner := e.initialized(t)
	var pol struct{ ID string }
	owner.do("POST", "/api/policies", map[string]string{"name": "Baseline"}, &pol)
	id := e.seedApproval(t, pol.ID, strings.ToUpper(hex64("e")))
	owner.do("POST", "/api/admins", map[string]string{"email": "ro@example.com", "password": "readonly-password-1", "role": "readonly"}, nil)
	ro := e.client(t)
	ro.loginFull("ro@example.com", "readonly-password-1", "")

	if code := ro.do("GET", "/api/approvals", nil, nil); code != 200 {
		t.Errorf("readonly list = %d", code)
	}
	if code := ro.do("POST", "/api/approvals/"+id+"/approve", nil, nil); code != 403 {
		t.Errorf("readonly approve = %d, want 403", code)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/server/httpapi/ -run Approv -v`
Expected: FAIL — `count = 404` (routes not registered).

- [ ] **Step 3: Extract the shared add-hash-rule helper**

In `internal/server/httpapi/policies.go`, add `"context"` and `"errors"` to the imports and add below `promoteObservation`:
```go
// addHashRule adds a normalized hash allow rule to a policy and recompiles
// it, returning the new version. An identical rule already on the policy is
// not an error, so retrying is safe.
func (a *API) addHashRule(ctx context.Context, p principal, policyID uuid.UUID, rule rules.Rule) (string, error) {
	_, err := a.Store.AddRule(ctx, p.TenantID, policyID, store.PolicyRule{
		Kind: string(rule.Kind), Value: rule.Value, Description: rule.Description,
	}, &p.Admin.ID)
	if err != nil && !errors.Is(err, store.ErrConflict) {
		return "", err
	}
	return a.Runtime().Policy.Recompile(ctx, p.TenantID, policyID)
}
```
Then replace the `AddRule` + `Recompile` section of `promoteObservation` (from `p := principalFrom(r)` through the recompile error check) with:
```go
	p := principalFrom(r)
	version, err := a.addHashRule(r.Context(), p, pid, norm)
	if err != nil {
		a.storeErr(w, err)
		return
	}
```
(The audit and `writeJSON` lines that follow stay unchanged.)

Run: `go test ./internal/server/httpapi/ -run Promote -v` — Expected: PASS (behavior unchanged).

- [ ] **Step 4: Implement the approvals handlers**

`internal/server/httpapi/approvals.go`:
```go
package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"freelocker/internal/appcontrol/rules"
	"freelocker/internal/server/store"
)

type approvalJSON struct {
	ID          string     `json:"id"`
	PolicyID    string     `json:"policy_id"`
	PolicyName  string     `json:"policy_name"`
	SHA256      string     `json:"sha256"`
	Path        string     `json:"path"`
	Signer      string     `json:"signer"`
	Status      string     `json:"status"`
	DeviceCount int        `json:"device_count"`
	EventCount  int64      `json:"event_count"`
	FirstSeen   time.Time  `json:"first_seen"`
	LastSeen    time.Time  `json:"last_seen"`
	DecidedAt   *time.Time `json:"decided_at"`
}

func (a *API) listApprovals(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	switch status {
	case "", "pending", "approved", "denied":
	default:
		writeErr(w, http.StatusBadRequest, "status must be pending, approved, or denied")
		return
	}
	reqs, err := a.Store.ListApprovalRequests(r.Context(), principalFrom(r).TenantID, status, queryInt(r, "limit", 200, 1000))
	if err != nil {
		a.storeErr(w, err)
		return
	}
	out := make([]approvalJSON, 0, len(reqs))
	for _, q := range reqs {
		out = append(out, approvalJSON{
			ID: q.ID.String(), PolicyID: q.PolicyID.String(), PolicyName: q.PolicyName,
			SHA256: q.SHA256, Path: q.Path, Signer: q.Signer, Status: q.Status,
			DeviceCount: q.DeviceCount, EventCount: q.EventCount,
			FirstSeen: q.FirstSeen, LastSeen: q.LastSeen, DecidedAt: q.DecidedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) countApprovals(w http.ResponseWriter, r *http.Request) {
	n, err := a.Store.CountPendingApprovals(r.Context(), principalFrom(r).TenantID)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"pending": n})
}

func (a *API) approveApproval(w http.ResponseWriter, r *http.Request) {
	a.decideApproval(w, r, "approved")
}

func (a *API) denyApproval(w http.ResponseWriter, r *http.Request) {
	a.decideApproval(w, r, "denied")
}

// decideApproval resolves a pending request. Approving first adds the hash
// as an allow rule on the request's policy; if that fails the request stays
// pending and can be retried.
func (a *API) decideApproval(w http.ResponseWriter, r *http.Request, status string) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	req, err := a.Store.GetApprovalRequest(r.Context(), p.TenantID, id)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	if req.Status != "pending" {
		writeErr(w, http.StatusConflict, "request already decided")
		return
	}
	if status == "approved" {
		norm, err := rules.Normalize(rules.Rule{
			Kind: rules.Hash, Value: req.SHA256,
			Description: fmt.Sprintf("approved from request %s (%s)", req.ID, req.Path),
		})
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if _, err := a.addHashRule(r.Context(), p, req.PolicyID, norm); err != nil {
			a.storeErr(w, err)
			return
		}
	}
	err = a.Store.DecideApprovalRequest(r.Context(), p.TenantID, id, status, p.Admin.ID, time.Now())
	if errors.Is(err, store.ErrConflict) {
		writeErr(w, http.StatusConflict, "request already decided")
		return
	}
	if err != nil {
		a.storeErr(w, err)
		return
	}
	action := "approval.approve"
	if status == "denied" {
		action = "approval.deny"
	}
	a.audit(r, p, action, "approval", id.String(), map[string]any{
		"policy_id": req.PolicyID.String(), "sha256": req.SHA256,
	}, "success")
	w.WriteHeader(http.StatusNoContent)
}
```

In `internal/server/httpapi/routes.go`, add to the read-only block (after `r.Get("/api/blocks", a.listBlocks)`):
```go
	r.Get("/api/approvals", a.listApprovals)
	r.Get("/api/approvals/count", a.countApprovals)
```
and inside the `requireRole("admin")` group (after `promoteObservation`):
```go
		r.Post("/api/approvals/{id}/approve", a.approveApproval)
		r.Post("/api/approvals/{id}/deny", a.denyApproval)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/server/httpapi/ -v`
Expected: all PASS. (The version is `wdac.ContentHash(xml)`, so adding a rule always yields a new version — that is how agents learn to pull it.)

- [ ] **Step 6: Commit**

```bash
git add internal/server/httpapi/approvals.go internal/server/httpapi/approvals_test.go internal/server/httpapi/policies.go internal/server/httpapi/routes.go
git commit -m "feat(approvals): add console API to list, approve, and deny requests"
```

---

### Task 4: Console Approvals page and nav badge

**Files:**
- Modify: `web/src/api.ts` (add `ApprovalRequest` type)
- Create: `web/src/pages/Approvals.tsx`
- Modify: `web/src/App.tsx` (import + route, next to `/blocks` at line 76)
- Modify: `web/src/components/Layout.tsx` (nav entry + pending badge)

**Interfaces:**
- Consumes: Task 3 HTTP endpoints; `api`, `ApiError` (`api.ts`); `useToast().notify(msg, "error")` (`components/Toast`); `fmtDate` (`components/util`); `useAuth().me.role` (`auth`).
- Produces: `/approvals` console route.

- [ ] **Step 1: Add the type**

Append to `web/src/api.ts`:
```ts
export type ApprovalStatus = "pending" | "approved" | "denied";
export type ApprovalRequest = {
  id: string;
  policy_id: string;
  policy_name: string;
  sha256: string;
  path: string;
  signer: string;
  status: ApprovalStatus;
  device_count: number;
  event_count: number;
  first_seen: string;
  last_seen: string;
  decided_at: string | null;
};
```

- [ ] **Step 2: Create the page**

`web/src/pages/Approvals.tsx`:
```tsx
import { useEffect, useState } from "react";
import { api, ApiError, ApprovalRequest, ApprovalStatus } from "../api";
import { useAuth } from "../auth";
import { useToast } from "../components/Toast";
import { fmtDate } from "../components/util";

export function Approvals() {
  const { me } = useAuth();
  const { notify } = useToast();
  const [status, setStatus] = useState<ApprovalStatus>("pending");
  const [reqs, setReqs] = useState<ApprovalRequest[] | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const canDecide = me?.role !== "readonly";

  const load = () =>
    api
      .get<ApprovalRequest[]>(`/api/approvals?status=${status}`)
      .then(setReqs)
      .catch(() => setReqs([]));

  useEffect(() => {
    setReqs(null);
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, [status]);

  const decide = async (r: ApprovalRequest, action: "approve" | "deny") => {
    if (action === "deny" && !window.confirm(`Deny ${r.path || r.sha256}? It will stop appearing as pending.`)) return;
    setBusy(r.id);
    try {
      await api.post(`/api/approvals/${r.id}/${action}`);
      notify(action === "approve" ? `Approved — added to ${r.policy_name}` : "Denied");
    } catch (e) {
      notify(e instanceof ApiError ? e.message : `Could not ${action}`, "error");
    } finally {
      setBusy(null);
      load();
    }
  };

  return (
    <div>
      <div className="page-head">
        <h1>Approvals</h1>
        <select value={status} onChange={(e) => setStatus(e.target.value as ApprovalStatus)}>
          <option value="pending">Pending</option>
          <option value="approved">Approved</option>
          <option value="denied">Denied</option>
        </select>
      </div>
      <p className="who" style={{ marginTop: -8, marginBottom: 14 }}>
        Programs a policy blocked or would have blocked. Approving adds the file's hash to that policy's allowlist.
      </p>
      {!reqs ? (
        <div className="spin">Loading…</div>
      ) : reqs.length === 0 ? (
        <div className="empty">No {status} requests.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Last seen</th>
                <th>Path</th>
                <th>Signer</th>
                <th>SHA-256</th>
                <th>Policy</th>
                <th>Devices</th>
                <th>Events</th>
                <th>{status === "pending" ? "" : "Decided"}</th>
              </tr>
            </thead>
            <tbody>
              {reqs.map((r) => (
                <tr key={r.id}>
                  <td>{fmtDate(r.last_seen)}</td>
                  <td className="mono">{r.path || "—"}</td>
                  <td>{r.signer || "—"}</td>
                  <td className="mono" title={r.sha256}>
                    {r.sha256.slice(0, 16)}…
                  </td>
                  <td>{r.policy_name}</td>
                  <td>{r.device_count}</td>
                  <td>{r.event_count}</td>
                  <td>
                    {r.status !== "pending" ? (
                      r.decided_at ? fmtDate(r.decided_at) : "—"
                    ) : canDecide ? (
                      <div className="toolbar" style={{ margin: 0, flexWrap: "nowrap" }}>
                        <button className="primary" disabled={busy === r.id} onClick={() => decide(r, "approve")}>
                          Approve
                        </button>
                        <button className="ghost" disabled={busy === r.id} onClick={() => decide(r, "deny")}>
                          Deny
                        </button>
                      </div>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 3: Register the route**

In `web/src/App.tsx`, add `import { Approvals } from "./pages/Approvals";` next to the `Blocks` import, and add below the `/blocks` route:
```tsx
        <Route path="/approvals" element={<Approvals />} />
```

- [ ] **Step 4: Add the nav entry with a pending badge**

In `web/src/components/Layout.tsx`:
- change the first import line to `import { useEffect, useState } from "react";` plus the existing `react-router-dom` import, and add `import { api } from "../api";`
- insert `{ to: "/approvals", label: "Approvals" },` into `NAV` after the `/blocks` entry
- inside `Layout()`, after `const next = …`:
```tsx
  const [pending, setPending] = useState(0);
  useEffect(() => {
    const load = () =>
      api
        .get<{ pending: number }>("/api/approvals/count")
        .then((c) => setPending(c.pending))
        .catch(() => {});
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, []);
```
- replace `{n.label}` inside the `NavLink` with:
```tsx
            {n.label}
            {n.to === "/approvals" && pending > 0 && (
              <span className="badge fail" style={{ marginLeft: 6 }}>
                {pending}
              </span>
            )}
```

- [ ] **Step 5: Build to verify types and bundle**

Run: `npm --prefix web run build`
Expected: build succeeds with no TypeScript errors. The build clears `internal/server/webui/dist`; afterwards run `git restore internal/server/webui/dist/.gitkeep` if `git status` shows it deleted.

- [ ] **Step 6: Full verification**

Run: `go test ./... && go vet ./... && GOOS=linux go build ./...`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add web/src/api.ts web/src/pages/Approvals.tsx web/src/App.tsx web/src/components/Layout.tsx
git commit -m "feat(approvals): add console Approvals page and pending badge"
```
