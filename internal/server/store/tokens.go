package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type DeviceGroup struct {
	ID   uuid.UUID
	Name string
}

type InstallToken struct {
	ID        uuid.UUID
	Name      string
	GroupID   *uuid.UUID
	ExpiresAt *time.Time
	MaxUses   *int
	Uses      int
	Revoked   bool
	CreatedBy *uuid.UUID
	CreatedAt time.Time
}

func (s *Store) CreateDeviceGroup(ctx context.Context, tenantID uuid.UUID, name string) (uuid.UUID, error) {
	id := uuid.New()
	_, err := s.pool.Exec(ctx, `INSERT INTO device_groups (id, tenant_id, name) VALUES ($1, $2, $3)`, id, tenantID, name)
	return id, err
}

func (s *Store) ListDeviceGroups(ctx context.Context, tenantID uuid.UUID) ([]DeviceGroup, error) {
	rows, _ := s.pool.Query(ctx, `SELECT id, name FROM device_groups WHERE tenant_id = $1 ORDER BY name`, tenantID)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (DeviceGroup, error) {
		var g DeviceGroup
		return g, r.Scan(&g.ID, &g.Name)
	})
}

func (s *Store) CreateInstallToken(ctx context.Context, tenantID uuid.UUID, t InstallToken, hash []byte) (uuid.UUID, error) {
	id := uuid.New()
	_, err := s.pool.Exec(ctx, `
		INSERT INTO install_tokens (id, tenant_id, token_hash, name, group_id, expires_at, max_uses, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		id, tenantID, hash, t.Name, t.GroupID, t.ExpiresAt, t.MaxUses, t.CreatedBy)
	return id, err
}

func (s *Store) ListInstallTokens(ctx context.Context, tenantID uuid.UUID) ([]InstallToken, error) {
	rows, _ := s.pool.Query(ctx, `
		SELECT id, name, group_id, expires_at, max_uses, uses, revoked, created_by, created_at
		FROM install_tokens WHERE tenant_id = $1 ORDER BY created_at DESC`, tenantID)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (InstallToken, error) {
		var t InstallToken
		return t, r.Scan(&t.ID, &t.Name, &t.GroupID, &t.ExpiresAt, &t.MaxUses, &t.Uses, &t.Revoked, &t.CreatedBy, &t.CreatedAt)
	})
}

func (s *Store) RevokeInstallToken(ctx context.Context, tenantID, id uuid.UUID) error {
	return oneRow(s.pool.Exec(ctx, `UPDATE install_tokens SET revoked = true WHERE tenant_id = $1 AND id = $2`, tenantID, id))
}
