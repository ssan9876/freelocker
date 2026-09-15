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
	Kind       string // email|webhook
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
		return &ValidationError{"kind must be email or webhook"}
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
