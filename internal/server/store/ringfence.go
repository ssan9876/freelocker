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
