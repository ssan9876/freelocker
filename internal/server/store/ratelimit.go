package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// RecordLoginFailure appends a failed-login timestamp for a rate-limit key
// (typically "<ip>|<email>").
func (s *Store) RecordLoginFailure(ctx context.Context, tenantID uuid.UUID, key string, at time.Time) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO login_failures (tenant_id, key, at) VALUES ($1,$2,$3)`, tenantID, key, at)
	return err
}

// CountLoginFailures counts failures for a key at or after `since`.
func (s *Store) CountLoginFailures(ctx context.Context, tenantID uuid.UUID, key string, since time.Time) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM login_failures WHERE tenant_id=$1 AND key=$2 AND at >= $3`,
		tenantID, key, since).Scan(&n)
	return n, err
}

// ClearLoginFailures removes a key's failures (called on a successful login).
func (s *Store) ClearLoginFailures(ctx context.Context, tenantID uuid.UUID, key string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM login_failures WHERE tenant_id=$1 AND key=$2`, tenantID, key)
	return err
}

// PruneLoginFailures deletes failures older than `before` (housekeeping).
func (s *Store) PruneLoginFailures(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM login_failures WHERE at < $1`, before)
	return tag.RowsAffected(), err
}

// MarkBreach records the first-breach time for a device+rule if none is
// stored, and returns the effective onset (the existing one when already
// breaching). Idempotent while the breach persists.
func (s *Store) MarkBreach(ctx context.Context, tenantID, deviceID, ruleID uuid.UUID, now time.Time) (time.Time, error) {
	var since time.Time
	err := s.pool.QueryRow(ctx, `
		INSERT INTO alert_breaches (tenant_id, device_id, rule_id, since) VALUES ($1,$2,$3,$4)
		ON CONFLICT (device_id, rule_id) DO UPDATE SET since = alert_breaches.since
		RETURNING since`, tenantID, deviceID, ruleID, now).Scan(&since)
	return since, err
}

// ClearBreach removes any stored breach onset for a device+rule.
func (s *Store) ClearBreach(ctx context.Context, tenantID, deviceID, ruleID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM alert_breaches WHERE tenant_id=$1 AND device_id=$2 AND rule_id=$3`,
		tenantID, deviceID, ruleID)
	return err
}
