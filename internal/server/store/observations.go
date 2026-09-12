package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Observation struct {
	SHA256         string
	Path           string
	Signer         string
	SignerTBS      string
	SignerVerified bool
	FirstSeen      time.Time
	LastSeen       time.Time
	Count          int64
}

type BlockEvent struct {
	ID             int64
	DeviceID       uuid.UUID
	SHA256         string
	Path           string
	Signer         string
	SignerTBS      string
	SignerVerified bool
	Blocked        bool
	At             time.Time
}

// RecordObservation upserts a learning observation, incrementing the count
// and advancing last_seen when the (device, hash, path) is already known.
func (s *Store) RecordObservation(ctx context.Context, tenantID, deviceID uuid.UUID, o Observation, now time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO observations (tenant_id, device_id, sha256, path, signer, signer_tbs, signer_verified, first_seen, last_seen, count)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$8,1)
		ON CONFLICT (device_id, sha256, path)
		DO UPDATE SET last_seen=$8, count=observations.count+1,
			signer=CASE WHEN observations.signer='' THEN EXCLUDED.signer ELSE observations.signer END,
			signer_tbs=CASE WHEN observations.signer_tbs='' THEN EXCLUDED.signer_tbs ELSE observations.signer_tbs END,
			signer_verified=(observations.signer_verified OR EXCLUDED.signer_verified)`,
		tenantID, deviceID, o.SHA256, o.Path, o.Signer, o.SignerTBS, o.SignerVerified, now)
	return err
}

func (s *Store) ListObservations(ctx context.Context, tenantID, deviceID uuid.UUID, limit int) ([]Observation, error) {
	rows, _ := s.pool.Query(ctx, `
		SELECT sha256, path, signer, signer_tbs, signer_verified, first_seen, last_seen, count
		FROM observations WHERE tenant_id=$1 AND device_id=$2 ORDER BY last_seen DESC LIMIT $3`, tenantID, deviceID, limit)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Observation, error) {
		var o Observation
		return o, r.Scan(&o.SHA256, &o.Path, &o.Signer, &o.SignerTBS, &o.SignerVerified, &o.FirstSeen, &o.LastSeen, &o.Count)
	})
}

// ObservationPublisher returns the publisher identity most recently seen for
// a hash in the tenant, preferring a verified one. ErrNotFound when no
// observation matches.
func (s *Store) ObservationPublisher(ctx context.Context, tenantID uuid.UUID, sha256 string) (string, string, bool, error) {
	var tbs, name string
	var verified bool
	err := s.pool.QueryRow(ctx, `
		SELECT signer_tbs, signer, signer_verified FROM observations
		WHERE tenant_id = $1 AND sha256 = $2
		ORDER BY signer_verified DESC, last_seen DESC LIMIT 1`, tenantID, sha256).
		Scan(&tbs, &name, &verified)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return tbs, name, verified, err
}

func (s *Store) RecordBlockEvents(ctx context.Context, tenantID, deviceID uuid.UUID, events []BlockEvent) error {
	if len(events) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, e := range events {
		at := e.At
		if at.IsZero() {
			at = time.Now()
		}
		batch.Queue(`INSERT INTO block_events (tenant_id, device_id, sha256, path, signer, signer_tbs, signer_verified, blocked, at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			tenantID, deviceID, e.SHA256, e.Path, e.Signer, e.SignerTBS, e.SignerVerified, e.Blocked, at)
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

func (s *Store) ListBlockEvents(ctx context.Context, tenantID uuid.UUID, limit int) ([]BlockEvent, error) {
	rows, _ := s.pool.Query(ctx, `
		SELECT id, device_id, sha256, path, signer, signer_tbs, signer_verified, blocked, at
		FROM block_events WHERE tenant_id=$1 ORDER BY at DESC LIMIT $2`, tenantID, limit)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (BlockEvent, error) {
		var e BlockEvent
		return e, r.Scan(&e.ID, &e.DeviceID, &e.SHA256, &e.Path, &e.Signer, &e.SignerTBS, &e.SignerVerified, &e.Blocked, &e.At)
	})
}
