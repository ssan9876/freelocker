package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Store) CreateTenant(ctx context.Context, name string) (uuid.UUID, error) {
	id := uuid.New()
	_, err := s.pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, $2)`, id, name)
	return id, err
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
