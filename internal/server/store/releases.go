package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Release struct {
	Version    string
	SHA256     []byte
	Signature  []byte
	UploadedAt time.Time
}

func (s *Store) PutRelease(ctx context.Context, tenantID uuid.UUID, r Release) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO agent_releases (tenant_id, version, sha256, signature, uploaded_at)
		VALUES ($1, $2, $3, $4, now())
		ON CONFLICT (tenant_id, version) DO UPDATE SET sha256 = EXCLUDED.sha256, signature = EXCLUDED.signature, uploaded_at = now()`,
		tenantID, r.Version, r.SHA256, r.Signature)
	return err
}

func (s *Store) GetRelease(ctx context.Context, tenantID uuid.UUID, version string) (Release, error) {
	var r Release
	err := s.pool.QueryRow(ctx, `SELECT version, sha256, signature, uploaded_at FROM agent_releases WHERE tenant_id = $1 AND version = $2`,
		tenantID, version).Scan(&r.Version, &r.SHA256, &r.Signature, &r.UploadedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return r, err
}

func (s *Store) LatestRelease(ctx context.Context, tenantID uuid.UUID) (Release, error) {
	var r Release
	err := s.pool.QueryRow(ctx, `SELECT version, sha256, signature, uploaded_at FROM agent_releases WHERE tenant_id = $1 ORDER BY uploaded_at DESC LIMIT 1`,
		tenantID).Scan(&r.Version, &r.SHA256, &r.Signature, &r.UploadedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return r, err
}

func (s *Store) ListReleases(ctx context.Context, tenantID uuid.UUID) ([]Release, error) {
	rows, _ := s.pool.Query(ctx, `SELECT version, sha256, signature, uploaded_at FROM agent_releases WHERE tenant_id = $1 ORDER BY uploaded_at DESC`, tenantID)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Release, error) {
		var rel Release
		return rel, r.Scan(&rel.Version, &rel.SHA256, &rel.Signature, &rel.UploadedAt)
	})
}
