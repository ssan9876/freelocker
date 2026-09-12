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

// ExpireApprovalRequests marks pending requests with no activity since
// `before` as expired, across all tenants. Returns the number expired.
func (s *Store) ExpireApprovalRequests(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE approval_requests SET status='expired'
		WHERE status='pending' AND last_seen < $1`, before)
	return tag.RowsAffected(), err
}
