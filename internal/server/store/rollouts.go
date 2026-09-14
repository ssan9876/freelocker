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
