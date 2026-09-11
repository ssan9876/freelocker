package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Command struct {
	ID          uuid.UUID
	DeviceID    uuid.UUID
	Type        string
	Payload     []byte
	IssuedBy    *uuid.UUID
	IssuedAt    time.Time
	ExpiresAt   time.Time
	State       string
	Result      string
	CompletedAt *time.Time
}

const commandCols = `id, device_id, type, payload, issued_by, issued_at, expires_at, state, result, completed_at`

func collectCommands(rows pgx.Rows) ([]Command, error) {
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Command, error) {
		var c Command
		return c, r.Scan(&c.ID, &c.DeviceID, &c.Type, &c.Payload, &c.IssuedBy, &c.IssuedAt, &c.ExpiresAt, &c.State, &c.Result, &c.CompletedAt)
	})
}

func (s *Store) CreateCommand(ctx context.Context, tenantID uuid.UUID, c Command) error {
	if c.Payload == nil {
		c.Payload = []byte{}
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO commands (id, tenant_id, device_id, type, payload, issued_by, issued_at, expires_at, state)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending')`,
		c.ID, tenantID, c.DeviceID, c.Type, c.Payload, c.IssuedBy, c.IssuedAt, c.ExpiresAt)
	return err
}

func (s *Store) OpenCommands(ctx context.Context, tenantID, deviceID uuid.UUID, now time.Time) ([]Command, error) {
	rows, _ := s.pool.Query(ctx, `SELECT `+commandCols+` FROM commands
		WHERE tenant_id = $1 AND device_id = $2 AND state IN ('pending', 'sent') AND expires_at > $3
		ORDER BY issued_at`, tenantID, deviceID, now)
	return collectCommands(rows)
}

func (s *Store) MarkCommandSent(ctx context.Context, tenantID, id uuid.UUID) error {
	return oneRow(s.pool.Exec(ctx, `UPDATE commands SET state = 'sent' WHERE tenant_id = $1 AND id = $2 AND state = 'pending'`, tenantID, id))
}

func (s *Store) CompleteCommand(ctx context.Context, tenantID, deviceID, id uuid.UUID, success bool, result string, now time.Time) error {
	state := "failed"
	if success {
		state = "succeeded"
	}
	return oneRow(s.pool.Exec(ctx, `
		UPDATE commands SET state = $4, result = $5, completed_at = $6
		WHERE tenant_id = $1 AND device_id = $2 AND id = $3 AND state IN ('pending', 'sent')`,
		tenantID, deviceID, id, state, result, now))
}

func (s *Store) ListDeviceCommands(ctx context.Context, tenantID, deviceID uuid.UUID, limit int) ([]Command, error) {
	rows, _ := s.pool.Query(ctx, `SELECT `+commandCols+` FROM commands
		WHERE tenant_id = $1 AND device_id = $2 ORDER BY issued_at DESC LIMIT $3`, tenantID, deviceID, limit)
	return collectCommands(rows)
}

func (s *Store) ExpireCommands(ctx context.Context, now time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE commands SET state = 'expired'
		WHERE state IN ('pending', 'sent') AND expires_at <= $1`, now)
	return tag.RowsAffected(), err
}
