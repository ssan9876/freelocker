package store

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// EventKinds is every notification event a channel may subscribe to.
var EventKinds = []string{"alert.raised", "alert.resolved", "approval.new", "rollout.auto_paused", "rollout.completed"}

// ValidationError is a user-facing rejection of a channel definition.
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

type NotificationChannel struct {
	ID         uuid.UUID
	Kind       string // email|webhook|syslog
	Name       string
	Events     []string
	Enabled    bool
	Recipients []string
	URL        string
	Secret     []byte // sealed; empty = none
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

func ValidateChannel(c NotificationChannel) error {
	if strings.TrimSpace(c.Name) == "" {
		return &ValidationError{"name is required"}
	}
	if len(c.Events) == 0 {
		return &ValidationError{"subscribe to at least one event"}
	}
	for _, e := range c.Events {
		known := false
		for _, k := range EventKinds {
			known = known || k == e
		}
		if !known {
			return &ValidationError{fmt.Sprintf("unknown event %q", e)}
		}
	}
	switch c.Kind {
	case "webhook":
		u, err := url.Parse(c.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return &ValidationError{"webhook url must be http or https"}
		}
	case "syslog":
		// Transport and wire format both live in the URL, which keeps syslog
		// on the existing channel model with no schema change:
		//   udp://siem:514            (RFC 5424, the default)
		//   tcp://siem:514?format=cef (CEF, for ArcSight-lineage tools)
		u, err := url.Parse(c.URL)
		if err != nil || (u.Scheme != "udp" && u.Scheme != "tcp") || u.Host == "" {
			return &ValidationError{"syslog url must be udp://host:port or tcp://host:port"}
		}
		if f := strings.ToLower(u.Query().Get("format")); f != "" && f != "rfc5424" && f != "cef" {
			return &ValidationError{"syslog format must be rfc5424 or cef"}
		}
	case "email":
		if len(c.Recipients) == 0 {
			return &ValidationError{"at least one recipient is required"}
		}
		for _, r := range c.Recipients {
			if !strings.Contains(r, "@") {
				return &ValidationError{fmt.Sprintf("invalid recipient %q", r)}
			}
		}
	default:
		return &ValidationError{"kind must be email, webhook or syslog"}
	}
	return nil
}

const channelCols = `id, kind, name, events, enabled, recipients, url, secret, created_at, updated_at`

func scanChannel(r pgx.Row) (NotificationChannel, error) {
	var c NotificationChannel
	err := r.Scan(&c.ID, &c.Kind, &c.Name, &c.Events, &c.Enabled, &c.Recipients, &c.URL, &c.Secret, &c.CreatedAt, &c.UpdatedAt)
	if c.Events == nil {
		c.Events = []string{}
	}
	if c.Recipients == nil {
		c.Recipients = []string{}
	}
	if c.Secret == nil {
		c.Secret = []byte{}
	}
	return c, err
}

func nonNil(ss []string) []string {
	if ss == nil {
		return []string{}
	}
	return ss
}

func (s *Store) CreateChannel(ctx context.Context, tenantID uuid.UUID, c NotificationChannel) error {
	if c.Secret == nil {
		c.Secret = []byte{}
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO notification_channels (id, tenant_id, kind, name, events, enabled, recipients, url, secret)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		c.ID, tenantID, c.Kind, c.Name, nonNil(c.Events), c.Enabled, nonNil(c.Recipients), c.URL, c.Secret)
	return conflict(err)
}

func (s *Store) GetChannel(ctx context.Context, tenantID, id uuid.UUID) (NotificationChannel, error) {
	c, err := scanChannel(s.pool.QueryRow(ctx, `SELECT `+channelCols+` FROM notification_channels WHERE tenant_id=$1 AND id=$2`, tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return c, err
}

func (s *Store) ListChannels(ctx context.Context, tenantID uuid.UUID) ([]NotificationChannel, error) {
	rows, _ := s.pool.Query(ctx, `SELECT `+channelCols+` FROM notification_channels WHERE tenant_id=$1 ORDER BY name`, tenantID)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (NotificationChannel, error) { return scanChannel(r) })
}

// UpdateChannel replaces name, events, enabled, recipients, url and secret.
func (s *Store) UpdateChannel(ctx context.Context, tenantID uuid.UUID, c NotificationChannel) error {
	if c.Secret == nil {
		c.Secret = []byte{}
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE notification_channels SET name=$3, events=$4, enabled=$5, recipients=$6, url=$7, secret=$8, updated_at=now()
		WHERE tenant_id=$1 AND id=$2`,
		tenantID, c.ID, c.Name, nonNil(c.Events), c.Enabled, nonNil(c.Recipients), c.URL, c.Secret)
	if err != nil {
		return conflict(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteChannel(ctx context.Context, tenantID, id uuid.UUID) error {
	return oneRow(s.pool.Exec(ctx, `DELETE FROM notification_channels WHERE tenant_id=$1 AND id=$2`, tenantID, id))
}

// ChannelsForEvent lists the enabled channels of a non-suspended tenant that
// subscribe to kind.
func (s *Store) ChannelsForEvent(ctx context.Context, tenantID uuid.UUID, kind string) ([]NotificationChannel, error) {
	rows, _ := s.pool.Query(ctx, `
		SELECT `+prefixCols("c.", channelCols)+` FROM notification_channels c
		JOIN tenants t ON t.id = c.tenant_id
		WHERE c.tenant_id=$1 AND c.enabled AND $2 = ANY(c.events) AND NOT t.suspended
		ORDER BY c.name`, tenantID, kind)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (NotificationChannel, error) { return scanChannel(r) })
}

type Delivery struct {
	ID            int64
	TenantID      uuid.UUID
	ChannelID     uuid.UUID
	ChannelName   string
	EventKind     string
	Payload       []byte
	State         string // pending|sent|failed
	Attempts      int
	NextAttemptAt time.Time
	LastError     string
	CreatedAt     time.Time
	SentAt        *time.Time
}

const deliveryCols = `d.id, d.tenant_id, d.channel_id, coalesce(c.name, ''), d.event_kind, d.payload, d.state, d.attempts, d.next_attempt_at, d.last_error, d.created_at, d.sent_at`

func scanDelivery(r pgx.Row) (Delivery, error) {
	var d Delivery
	return d, r.Scan(&d.ID, &d.TenantID, &d.ChannelID, &d.ChannelName, &d.EventKind, &d.Payload, &d.State, &d.Attempts, &d.NextAttemptAt, &d.LastError, &d.CreatedAt, &d.SentAt)
}

// EnqueueDeliveries inserts one pending delivery per channel. No-op for an
// empty channel list.
func (s *Store) EnqueueDeliveries(ctx context.Context, tenantID uuid.UUID, channelIDs []uuid.UUID, kind string, payload []byte, now time.Time) error {
	if len(channelIDs) == 0 {
		return nil
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO notification_deliveries (tenant_id, channel_id, event_kind, payload, state, next_attempt_at)
		SELECT $1, unnest($2::uuid[]), $3, $4, 'pending', $5`,
		tenantID, channelIDs, kind, payload, now)
	return err
}

// ClaimDeliveries atomically takes up to limit due pending rows across all
// tenants, bumping attempts and leasing them until now+lease so another
// instance (or a retry after a crash) does not send them twice.
func (s *Store) ClaimDeliveries(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]Delivery, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `
		WITH due AS (
			SELECT id FROM notification_deliveries
			WHERE state = 'pending' AND next_attempt_at <= $1
			ORDER BY id LIMIT $3 FOR UPDATE SKIP LOCKED
		)
		UPDATE notification_deliveries d SET attempts = d.attempts + 1, next_attempt_at = $2
		FROM due WHERE d.id = due.id
		RETURNING d.id`, now, now.Add(lease), limit)
	if err != nil {
		return nil, err
	}
	ids, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (int64, error) {
		var id int64
		return id, r.Scan(&id)
	})
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, nil
	}
	rows, _ = s.pool.Query(ctx, `
		SELECT `+deliveryCols+` FROM notification_deliveries d
		LEFT JOIN notification_channels c ON c.id = d.channel_id
		WHERE d.id = ANY($1) ORDER BY d.id`, ids)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Delivery, error) { return scanDelivery(r) })
}

// FinishDelivery records the outcome of one attempt: state sent (sets
// sent_at), pending (schedules nextAttempt) or failed (terminal).
func (s *Store) FinishDelivery(ctx context.Context, id int64, state, lastError string, nextAttempt, now time.Time) error {
	// Truncate to 500 bytes, then drop any invalid bytes: cutting on a byte
	// boundary can split a multi-byte rune, and Postgres rejects an invalid
	// UTF-8 parameter, which would leave the delivery wedged in pending.
	if len(lastError) > 500 {
		lastError = strings.ToValidUTF8(lastError[:500], "")
	}
	var sentAt *time.Time
	if state == "sent" {
		sentAt = &now
	}
	if nextAttempt.IsZero() {
		nextAttempt = now
	}
	return oneRow(s.pool.Exec(ctx, `
		UPDATE notification_deliveries SET state=$2, last_error=$3, next_attempt_at=$4, sent_at=$5 WHERE id=$1`,
		id, state, lastError, nextAttempt, sentAt))
}

func (s *Store) ListDeliveries(ctx context.Context, tenantID uuid.UUID, limit int) ([]Delivery, error) {
	rows, _ := s.pool.Query(ctx, `
		SELECT `+deliveryCols+` FROM notification_deliveries d
		LEFT JOIN notification_channels c ON c.id = d.channel_id
		WHERE d.tenant_id = $1 ORDER BY d.id DESC LIMIT $2`, tenantID, limit)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Delivery, error) { return scanDelivery(r) })
}
