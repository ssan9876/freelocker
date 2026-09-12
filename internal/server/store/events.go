package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type DeviceEvent struct {
	ID       int64
	DeviceID uuid.UUID
	Kind     string
	Summary  string
	At       time.Time
}

func (s *Store) RecordDeviceEvents(ctx context.Context, tenantID, deviceID uuid.UUID, events []DeviceEvent) error {
	if len(events) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, e := range events {
		at := e.At
		if at.IsZero() {
			at = time.Now()
		}
		batch.Queue(`INSERT INTO device_events (tenant_id, device_id, kind, summary, at) VALUES ($1,$2,$3,$4,$5)`,
			tenantID, deviceID, e.Kind, e.Summary, at)
	}
	br := s.pool.SendBatch(ctx, batch)
	defer br.Close()
	for range events {
		if _, err := br.Exec(); err != nil {
			return err
		}
	}
	return nil
}

// ListDeviceEvents lists recent events for the tenant, optionally filtered
// by kind ("" = all), newest first.
func (s *Store) ListDeviceEvents(ctx context.Context, tenantID uuid.UUID, kind string, limit int) ([]DeviceEvent, error) {
	rows, _ := s.pool.Query(ctx, `SELECT id, device_id, kind, summary, at FROM device_events
		WHERE tenant_id=$1 AND ($2::text = '' OR kind = $2) ORDER BY at DESC LIMIT $3`, tenantID, kind, limit)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (DeviceEvent, error) {
		var e DeviceEvent
		return e, r.Scan(&e.ID, &e.DeviceID, &e.Kind, &e.Summary, &e.At)
	})
}
