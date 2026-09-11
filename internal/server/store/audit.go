package store

import (
	"context"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type AuditEntry struct {
	ID         int64
	Actor      string
	Action     string
	TargetType string
	TargetID   string
	Detail     map[string]any
	IP         string
	Result     string
	CreatedAt  time.Time
}

func (s *Store) AppendAudit(ctx context.Context, tenantID uuid.UUID, e AuditEntry) error {
	if e.Detail == nil {
		e.Detail = map[string]any{}
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO audit_log (tenant_id, actor, action, target_type, target_id, detail_json, ip, result)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		tenantID, e.Actor, e.Action, e.TargetType, e.TargetID, e.Detail, e.IP, e.Result)
	return err
}

func (s *Store) ListAudit(ctx context.Context, tenantID uuid.UUID, limit int, beforeID int64) ([]AuditEntry, error) {
	if beforeID == 0 {
		beforeID = math.MaxInt64
	}
	rows, _ := s.pool.Query(ctx, `
		SELECT id, actor, action, target_type, target_id, detail_json, ip, result, created_at
		FROM audit_log WHERE tenant_id = $1 AND id < $2 ORDER BY id DESC LIMIT $3`,
		tenantID, beforeID, limit)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (AuditEntry, error) {
		var e AuditEntry
		return e, r.Scan(&e.ID, &e.Actor, &e.Action, &e.TargetType, &e.TargetID, &e.Detail, &e.IP, &e.Result, &e.CreatedAt)
	})
}
