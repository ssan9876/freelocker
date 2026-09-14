package store

import (
	"context"
	"errors"
	"strings"
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

// prefixCols prefixes every comma-separated column in cols with p.
func prefixCols(p, cols string) string {
	parts := strings.Split(cols, ", ")
	for i := range parts {
		parts[i] = p + parts[i]
	}
	return strings.Join(parts, ", ")
}

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
