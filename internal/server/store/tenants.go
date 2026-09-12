package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Tenant struct {
	ID        uuid.UUID
	Name      string
	Suspended bool
	CreatedAt time.Time
}

func (s *Store) CreateTenant(ctx context.Context, name string) (uuid.UUID, error) {
	id := uuid.New()
	_, err := s.pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, $2)`, id, name)
	return id, err
}

// ListTenantDetails returns every tenant with its name, oldest first. Used by
// the provider tenant-management view.
func (s *Store) ListTenantDetails(ctx context.Context) ([]Tenant, error) {
	rows, _ := s.pool.Query(ctx, `SELECT id, name, suspended, created_at FROM tenants ORDER BY created_at`)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Tenant, error) {
		var t Tenant
		return t, r.Scan(&t.ID, &t.Name, &t.Suspended, &t.CreatedAt)
	})
}

func (s *Store) RenameTenant(ctx context.Context, id uuid.UUID, name string) error {
	return oneRow(s.pool.Exec(ctx, `UPDATE tenants SET name = $2 WHERE id = $1`, id, name))
}

// SetTenantSuspended suspends or restores a tenant. Suspending also deletes
// the tenant's console sessions so its admins are signed out immediately.
func (s *Store) SetTenantSuspended(ctx context.Context, id uuid.UUID, suspended bool) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := oneRow(tx.Exec(ctx, `UPDATE tenants SET suspended = $2 WHERE id = $1`, id, suspended)); err != nil {
		return err
	}
	if suspended {
		if _, err := tx.Exec(ctx, `DELETE FROM sessions WHERE tenant_id = $1`, id); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) TenantSuspended(ctx context.Context, id uuid.UUID) (bool, error) {
	var sus bool
	err := s.pool.QueryRow(ctx, `SELECT suspended FROM tenants WHERE id = $1`, id).Scan(&sus)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return sus, err
}

// ListTenants returns all tenant ids, oldest first.
func (s *Store) ListTenants(ctx context.Context) ([]uuid.UUID, error) {
	rows, _ := s.pool.Query(ctx, `SELECT id FROM tenants ORDER BY created_at`)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (uuid.UUID, error) {
		var id uuid.UUID
		return id, r.Scan(&id)
	})
}

// FirstTenant returns the oldest tenant. v1 is single-tenant.
func (s *Store) FirstTenant(ctx context.Context) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `SELECT id FROM tenants ORDER BY created_at LIMIT 1`).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return id, ErrNotFound
	}
	return id, err
}

func (s *Store) PutServerKey(ctx context.Context, tenantID uuid.UUID, name string, publicDER, privateEnc []byte) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO server_keys (tenant_id, name, public_der, private_enc) VALUES ($1, $2, $3, $4)`,
		tenantID, name, publicDER, privateEnc)
	return err
}

func (s *Store) GetServerKey(ctx context.Context, tenantID uuid.UUID, name string) (publicDER, privateEnc []byte, err error) {
	err = s.pool.QueryRow(ctx,
		`SELECT public_der, private_enc FROM server_keys WHERE tenant_id = $1 AND name = $2`,
		tenantID, name).Scan(&publicDER, &privateEnc)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return publicDER, privateEnc, err
}
