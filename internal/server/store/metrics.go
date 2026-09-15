package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type MetricSample struct {
	At      time.Time
	CPUPct  float64
	MemPct  float64
	DiskPct float64
}

type AlertRule struct {
	ID              uuid.UUID
	Name            string
	Metric          string // cpu|mem|disk
	Op              string // gt|lt
	Threshold       float64
	DurationSeconds int
	Enabled         bool
	CreatedAt       time.Time
}

type Alert struct {
	ID         int64
	DeviceID   uuid.UUID
	RuleID     uuid.UUID
	Metric     string
	Message    string
	At         time.Time
	ResolvedAt *time.Time
}

func (s *Store) RecordMetrics(ctx context.Context, tenantID, deviceID uuid.UUID, m MetricSample, now time.Time) error {
	at := m.At
	if at.IsZero() {
		at = now
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO device_metrics (tenant_id, device_id, at, cpu_pct, mem_pct, disk_pct)
		VALUES ($1,$2,$3,$4,$5,$6)`, tenantID, deviceID, at, m.CPUPct, m.MemPct, m.DiskPct)
	return err
}

func (s *Store) ListMetrics(ctx context.Context, tenantID, deviceID uuid.UUID, since time.Time, limit int) ([]MetricSample, error) {
	rows, _ := s.pool.Query(ctx, `SELECT at, cpu_pct, mem_pct, disk_pct FROM device_metrics
		WHERE tenant_id=$1 AND device_id=$2 AND at >= $3 ORDER BY at DESC LIMIT $4`, tenantID, deviceID, since, limit)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (MetricSample, error) {
		var m MetricSample
		return m, r.Scan(&m.At, &m.CPUPct, &m.MemPct, &m.DiskPct)
	})
}

func (s *Store) CreateAlertRule(ctx context.Context, tenantID uuid.UUID, r AlertRule) (uuid.UUID, error) {
	id := uuid.New()
	_, err := s.pool.Exec(ctx, `INSERT INTO alert_rules (id, tenant_id, name, metric, op, threshold, duration_seconds, enabled)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, id, tenantID, r.Name, r.Metric, r.Op, r.Threshold, r.DurationSeconds, r.Enabled)
	return id, err
}

func (s *Store) ListAlertRules(ctx context.Context, tenantID uuid.UUID) ([]AlertRule, error) {
	rows, _ := s.pool.Query(ctx, `SELECT id, name, metric, op, threshold, duration_seconds, enabled, created_at
		FROM alert_rules WHERE tenant_id=$1 ORDER BY created_at`, tenantID)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (AlertRule, error) {
		var a AlertRule
		return a, r.Scan(&a.ID, &a.Name, &a.Metric, &a.Op, &a.Threshold, &a.DurationSeconds, &a.Enabled, &a.CreatedAt)
	})
}

func (s *Store) ListEnabledAlertRules(ctx context.Context, tenantID uuid.UUID) ([]AlertRule, error) {
	all, err := s.ListAlertRules(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, r := range all {
		if r.Enabled {
			out = append(out, r)
		}
	}
	return out, nil
}

// UpdateAlertRule replaces a rule's editable fields. Stored breach onsets for
// the rule are cleared, since they were measured against the old definition.
func (s *Store) UpdateAlertRule(ctx context.Context, tenantID uuid.UUID, r AlertRule) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := oneRow(tx.Exec(ctx, `UPDATE alert_rules SET name=$3, metric=$4, op=$5, threshold=$6, duration_seconds=$7, enabled=$8
		WHERE tenant_id=$1 AND id=$2`, tenantID, r.ID, r.Name, r.Metric, r.Op, r.Threshold, r.DurationSeconds, r.Enabled)); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM alert_breaches WHERE tenant_id=$1 AND rule_id=$2`, tenantID, r.ID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) DeleteAlertRule(ctx context.Context, tenantID, id uuid.UUID) error {
	return oneRow(s.pool.Exec(ctx, `DELETE FROM alert_rules WHERE tenant_id=$1 AND id=$2`, tenantID, id))
}

// OpenAlertFor returns the current unresolved alert for a device+rule, or
// ErrNotFound.
func (s *Store) OpenAlertFor(ctx context.Context, tenantID, deviceID, ruleID uuid.UUID) (Alert, error) {
	var a Alert
	err := s.pool.QueryRow(ctx, `SELECT id, device_id, rule_id, metric, message, at, resolved_at FROM alerts
		WHERE tenant_id=$1 AND device_id=$2 AND rule_id=$3 AND resolved_at IS NULL`, tenantID, deviceID, ruleID).
		Scan(&a.ID, &a.DeviceID, &a.RuleID, &a.Metric, &a.Message, &a.At, &a.ResolvedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return a, err
}

// RaiseAlert opens an alert if none is open for the device+rule (the unique
// partial index also guards this). Returns true if a new alert was created.
func (s *Store) RaiseAlert(ctx context.Context, tenantID, deviceID, ruleID uuid.UUID, metric, message string, now time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx, `INSERT INTO alerts (tenant_id, device_id, rule_id, metric, message, at)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (device_id, rule_id) WHERE resolved_at IS NULL DO NOTHING`,
		tenantID, deviceID, ruleID, metric, message, now)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// ResolveAlert closes the open alert for a device+rule, if any. Returns
// true when an alert was actually closed.
func (s *Store) ResolveAlert(ctx context.Context, tenantID, deviceID, ruleID uuid.UUID, now time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE alerts SET resolved_at=$4
		WHERE tenant_id=$1 AND device_id=$2 AND rule_id=$3 AND resolved_at IS NULL`, tenantID, deviceID, ruleID, now)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (s *Store) ListAlerts(ctx context.Context, tenantID uuid.UUID, limit int) ([]Alert, error) {
	rows, _ := s.pool.Query(ctx, `SELECT id, device_id, rule_id, metric, message, at, resolved_at FROM alerts
		WHERE tenant_id=$1 ORDER BY (resolved_at IS NULL) DESC, at DESC LIMIT $2`, tenantID, limit)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Alert, error) {
		var a Alert
		return a, r.Scan(&a.ID, &a.DeviceID, &a.RuleID, &a.Metric, &a.Message, &a.At, &a.ResolvedAt)
	})
}
