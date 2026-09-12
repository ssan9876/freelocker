package store

import (
	"context"
	"time"
)

// Retention deletes time-series rows older than `before` from the metrics,
// block-event, and resolved-alert tables. Observations (a per-device
// baseline, not a time series) and open alerts are kept. Returns the total
// rows removed. This bounds storage in plain Postgres; TimescaleDB
// hypertables with compression can be layered on later without code change.
func (s *Store) Retention(ctx context.Context, before time.Time) (int64, error) {
	var total int64
	for _, q := range []string{
		`DELETE FROM device_metrics WHERE at < $1`,
		`DELETE FROM block_events WHERE at < $1`,
		`DELETE FROM alerts WHERE resolved_at IS NOT NULL AND resolved_at < $1`,
	} {
		tag, err := s.pool.Exec(ctx, q, before)
		if err != nil {
			return total, err
		}
		total += tag.RowsAffected()
	}
	return total, nil
}
