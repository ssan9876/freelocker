package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var ErrTokenInvalid = errors.New("install token invalid, expired, revoked, or exhausted")

const OnlineWindow = 90 * time.Second

type NewDevice struct {
	ID            uuid.UUID
	Hostname      string
	MachineGUID   string
	OSBuild       string
	CertSerial    string
	CertExpiresAt time.Time
}

type Device struct {
	ID            uuid.UUID
	Hostname      string
	MachineGUID   string
	GroupID       *uuid.UUID
	CertSerial    string
	CertExpiresAt time.Time
	OSBuild       string
	AgentVersion  string
	IPs           []string
	LoggedOnUser  string
	UptimeSeconds int64
	LastSeenAt    *time.Time
	CleanShutdown bool
	Revoked       bool
	EnrolledAt    time.Time
}

type Inventory struct {
	Hostname      string
	OSBuild       string
	IPs           []string
	LoggedOnUser  string
	AgentVersion  string
	UptimeSeconds int64
}

func (d Device) Status(now time.Time) string {
	switch {
	case d.Revoked:
		return "revoked"
	case d.LastSeenAt == nil:
		return "never_seen"
	case now.Sub(*d.LastSeenAt) <= OnlineWindow:
		return "online"
	case d.CleanShutdown:
		return "offline"
	default:
		return "unexpected_offline"
	}
}

const deviceCols = `id, hostname, machine_guid, group_id, cert_serial, cert_expires_at, os_build,
	agent_version, ips, logged_on_user, uptime_seconds, last_seen_at, clean_shutdown, revoked, enrolled_at`

func scanDevice(r pgx.Row) (Device, error) {
	var d Device
	err := r.Scan(&d.ID, &d.Hostname, &d.MachineGUID, &d.GroupID, &d.CertSerial, &d.CertExpiresAt, &d.OSBuild,
		&d.AgentVersion, &d.IPs, &d.LoggedOnUser, &d.UptimeSeconds, &d.LastSeenAt, &d.CleanShutdown, &d.Revoked, &d.EnrolledAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return d, err
}

func (s *Store) EnrollDevice(ctx context.Context, tokenHash []byte, now time.Time, build func(tenantID uuid.UUID) (NewDevice, error)) (uuid.UUID, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)

	var (
		tokenID, tenantID uuid.UUID
		groupID           *uuid.UUID
		expiresAt         *time.Time
		maxUses           *int
		uses              int
		revoked           bool
	)
	err = tx.QueryRow(ctx, `
		SELECT id, tenant_id, group_id, expires_at, max_uses, uses, revoked
		FROM install_tokens WHERE token_hash = $1 FOR UPDATE`, tokenHash).
		Scan(&tokenID, &tenantID, &groupID, &expiresAt, &maxUses, &uses, &revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrTokenInvalid
	}
	if err != nil {
		return uuid.Nil, err
	}
	if revoked || (expiresAt != nil && !now.Before(*expiresAt)) || (maxUses != nil && uses >= *maxUses) {
		return uuid.Nil, ErrTokenInvalid
	}

	d, err := build(tenantID)
	if err != nil {
		return uuid.Nil, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO devices (id, tenant_id, hostname, machine_guid, group_id, cert_serial, cert_expires_at, os_build)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		d.ID, tenantID, d.Hostname, d.MachineGUID, groupID, d.CertSerial, d.CertExpiresAt, d.OSBuild); err != nil {
		return uuid.Nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE install_tokens SET uses = uses + 1 WHERE id = $1`, tokenID); err != nil {
		return uuid.Nil, err
	}
	return tenantID, tx.Commit(ctx)
}

func (s *Store) GetDevice(ctx context.Context, tenantID, id uuid.UUID) (Device, error) {
	return scanDevice(s.pool.QueryRow(ctx, `SELECT `+deviceCols+` FROM devices WHERE tenant_id = $1 AND id = $2`, tenantID, id))
}

func (s *Store) ListDevices(ctx context.Context, tenantID uuid.UUID) ([]Device, error) {
	rows, _ := s.pool.Query(ctx, `SELECT `+deviceCols+` FROM devices WHERE tenant_id = $1 ORDER BY hostname`, tenantID)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Device, error) { return scanDevice(r) })
}

func (s *Store) DeviceAuthState(ctx context.Context, id uuid.UUID) (uuid.UUID, string, bool, error) {
	var (
		tenantID uuid.UUID
		serial   string
		revoked  bool
	)
	err := s.pool.QueryRow(ctx, `SELECT tenant_id, cert_serial, revoked FROM devices WHERE id = $1`, id).
		Scan(&tenantID, &serial, &revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return tenantID, serial, revoked, err
}

func (s *Store) RecordHeartbeat(ctx context.Context, tenantID, id uuid.UUID, inv Inventory, now time.Time) error {
	if inv.IPs == nil {
		inv.IPs = []string{}
	}
	return oneRow(s.pool.Exec(ctx, `
		UPDATE devices SET hostname = $3, os_build = $4, ips = $5, logged_on_user = $6, agent_version = $7,
			uptime_seconds = $8, last_seen_at = $9, clean_shutdown = false
		WHERE tenant_id = $1 AND id = $2`,
		tenantID, id, inv.Hostname, inv.OSBuild, inv.IPs, inv.LoggedOnUser, inv.AgentVersion, inv.UptimeSeconds, now))
}

func (s *Store) MarkCleanShutdown(ctx context.Context, tenantID, id uuid.UUID) error {
	return oneRow(s.pool.Exec(ctx, `UPDATE devices SET clean_shutdown = true WHERE tenant_id = $1 AND id = $2`, tenantID, id))
}

func (s *Store) RevokeDevice(ctx context.Context, tenantID, id uuid.UUID) error {
	return oneRow(s.pool.Exec(ctx, `UPDATE devices SET revoked = true WHERE tenant_id = $1 AND id = $2`, tenantID, id))
}

func (s *Store) UpdateDeviceCert(ctx context.Context, tenantID, id uuid.UUID, serial string, expiresAt time.Time) error {
	return oneRow(s.pool.Exec(ctx, `UPDATE devices SET cert_serial = $3, cert_expires_at = $4 WHERE tenant_id = $1 AND id = $2`,
		tenantID, id, serial, expiresAt))
}

// oneRow converts "no rows affected" into ErrNotFound.
func oneRow(tag pgconn.CommandTag, err error) error {
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
