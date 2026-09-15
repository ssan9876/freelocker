# Alert Notifications (Email + Webhook) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver alert, approval, and rollout events to per-tenant email and webhook channels through a retrying outbox, with a console page to manage channels and see deliveries.

**Architecture:** New `notification_channels` + `notification_deliveries` tables; a `notify.Service` that enqueues one delivery per subscribed channel and a dispatcher that claims rows with `FOR UPDATE SKIP LOCKED`, sends via webhook (HMAC-signed JSON POST) or SMTP, and retries with backoff; producers (`alerting`, `rollout`, `agentapi`) call a nil-safe `Emitter`; admin HTTP routes and a Notifications console page.

**Tech Stack:** Go (pgx v5, goose, chi, `net/smtp`, `net/http`), React + TypeScript (Vite), Playwright.

**Spec:** `docs/superpowers/specs/2026-09-14-notifications-design.md`

## Global Constraints

- Postgres test DB on port 55432 via `docker compose -f deploy/docker-compose.dev.yml`; tests use `storetest.New(t)`.
- Next migration number is `0018`. Goose format.
- Event kinds (exact strings): `alert.raised`, `alert.resolved`, `approval.new`, `rollout.auto_paused`, `rollout.completed`; test event kind `notify.test`.
- Channel kinds: `email`, `webhook`. Delivery states: `pending`, `sent`, `failed`.
- Backoff after failed attempt N: 1→1 min, 2→5 min, 3→30 min, 4→30 min; attempt 5 failing → `failed`. Claim lease: 2 min. Claim batch: 50. Webhook timeout: 10 s. `last_error` trimmed to 500 chars.
- Webhook headers: `Content-Type: application/json`, `X-FreeLocker-Event`, `X-FreeLocker-Delivery`, `X-FreeLocker-Signature: sha256=<hex hmac>` (only when a secret is set). Redirects are not followed.
- Email subject `[FreeLocker] <title>`; SMTP: implicit TLS on port 465, STARTTLS when `starttls`, PLAIN auth when username set.
- Webhook secret sealed at rest with `keys.NewSealer(master, "notify")`; never returned, logged, or audited.
- Audit actions: `notification_channel.create|update|delete|test`, target type `notification_channel`.
- `-race` unavailable on the dev box. Commit trailer: `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`. Branch `feat/notifications` off `master`.
- Console build: `npm --prefix web run build`; every Playwright-targeted control has an `aria-label`.

---

## File map

| File | Responsibility |
|---|---|
| `internal/server/config/config.go` | `SMTP` struct + env + `SMTPConfigured()` |
| `internal/server/store/migrations/0018_notifications.sql` | two tables |
| `internal/server/store/notifications.go` | channels CRUD, `ChannelsForEvent`, deliveries enqueue/claim/finish/list |
| `internal/server/notify/notify.go` | `Event`, `Emitter`, `Nop`, `Service` (Emit/Run/Dispatch/Test), backoff |
| `internal/server/notify/webhook.go` | signed POST |
| `internal/server/notify/email.go` | `Mailer` interface, `smtpMailer`, message formatting |
| `internal/server/alerting/alerting.go`, `rollout/rollout.go`, `agentapi/policy.go` + `server.go` | emit points |
| `internal/server/store/metrics.go`, `approvals.go` | `ResolveAlert` bool; `UpsertApprovalRequests` returns inserted ids |
| `internal/server/app/app.go` | build service, run dispatcher, ticker fallback |
| `internal/server/httpapi/notifications.go` + `routes.go` + `api.go` | routes |
| `web/src/api.ts`, `web/src/pages/Notifications.tsx`, `Layout.tsx`, `App.tsx`, `web/e2e/smoke.spec.ts` | console |
| `README.md`, `deploy/server.example.yaml` | docs |

---

### Task 1: SMTP config, migration, channel store

**Files:**
- Modify: `internal/server/config/config.go`, `internal/server/config/config_test.go`
- Create: `internal/server/store/migrations/0018_notifications.sql`
- Create: `internal/server/store/notifications.go`
- Test: `internal/server/store/notifications_test.go`

**Interfaces (produces):**
```go
// config
type SMTP struct { Host string `yaml:"host"`; Port int `yaml:"port"`; Username string `yaml:"username"`; Password string `yaml:"password"`; From string `yaml:"from"`; STARTTLS bool `yaml:"starttls"` }
Config.SMTP SMTP `yaml:"smtp"`;  func (c Config) SMTPConfigured() bool
// store
var EventKinds = []string{"alert.raised","alert.resolved","approval.new","rollout.auto_paused","rollout.completed"}
type NotificationChannel struct { ID uuid.UUID; Kind, Name string; Events []string; Enabled bool; Recipients []string; URL string; Secret []byte /*sealed*/; CreatedAt, UpdatedAt time.Time }
func ValidateChannel(c NotificationChannel) error                    // returns *ValidationError{Msg}
func (s *Store) CreateChannel(ctx, tenantID, c) error                // ErrConflict on dup name
func (s *Store) GetChannel(ctx, tenantID, id) (NotificationChannel, error)
func (s *Store) ListChannels(ctx, tenantID) ([]NotificationChannel, error)
func (s *Store) UpdateChannel(ctx, tenantID, c) error                // full replace of mutable fields
func (s *Store) DeleteChannel(ctx, tenantID, id) error
func (s *Store) ChannelsForEvent(ctx, tenantID, kind) ([]NotificationChannel, error) // enabled, subscribed, tenant not suspended
```

- [ ] **Step 1: Config test**

Append to `internal/server/config/config_test.go`:

```go
func TestSMTPConfigAndEnv(t *testing.T) {
	c := Config{}
	if c.SMTPConfigured() {
		t.Fatal("empty SMTP must not be configured")
	}
	c.SMTP = SMTP{Host: "mail.example.com", From: "a@example.com"}
	if !c.SMTPConfigured() {
		t.Fatal("host+from should be configured")
	}
	t.Setenv("FREELOCKER_SMTP_HOST", "env.example.com")
	t.Setenv("FREELOCKER_SMTP_PORT", "465")
	t.Setenv("FREELOCKER_SMTP_PASSWORD", "pw")
	t.Setenv("FREELOCKER_SMTP_STARTTLS", "false")
	t.Setenv("FREELOCKER_DATABASE_URL", "postgres://x")
	got, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if got.SMTP.Host != "env.example.com" || got.SMTP.Port != 465 || got.SMTP.Password != "pw" || got.SMTP.STARTTLS {
		t.Errorf("smtp from env = %+v", got.SMTP)
	}
}
```

- [ ] **Step 2: Run, expect failure** — `go test ./internal/server/config/ -run TestSMTP -v` → undefined `SMTP`.

- [ ] **Step 3: Implement config**

In `config.go` add the `SMTP` type and `SMTP SMTP \`yaml:"smtp"\`` field on `Config`; default in `Load`: `SMTP: SMTP{Port: 587, STARTTLS: true}`. Env block:

```go
	envStr(&c.SMTP.Host, "FREELOCKER_SMTP_HOST")
	envStr(&c.SMTP.Username, "FREELOCKER_SMTP_USERNAME")
	envStr(&c.SMTP.Password, "FREELOCKER_SMTP_PASSWORD")
	envStr(&c.SMTP.From, "FREELOCKER_SMTP_FROM")
	if v := os.Getenv("FREELOCKER_SMTP_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.SMTP.Port = n
		}
	}
	if v := os.Getenv("FREELOCKER_SMTP_STARTTLS"); v != "" {
		c.SMTP.STARTTLS = v == "true"
	}
```

```go
// SMTPConfigured reports whether outbound email can be sent at all.
func (c Config) SMTPConfigured() bool { return c.SMTP.Host != "" && c.SMTP.From != "" }
```

- [ ] **Step 4: Migration**

```sql
-- +goose Up
-- Outbound notifications: per-tenant channels and a retrying delivery outbox.
CREATE TABLE notification_channels (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    kind       text NOT NULL CHECK (kind IN ('email', 'webhook')),
    name       text NOT NULL,
    events     text[] NOT NULL DEFAULT '{}',
    enabled    boolean NOT NULL DEFAULT true,
    recipients text[] NOT NULL DEFAULT '{}',
    url        text NOT NULL DEFAULT '',
    secret     bytea NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE TABLE notification_deliveries (
    id              bigserial PRIMARY KEY,
    tenant_id       uuid NOT NULL REFERENCES tenants(id),
    channel_id      uuid NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
    event_kind      text NOT NULL,
    payload         jsonb NOT NULL,
    state           text NOT NULL CHECK (state IN ('pending', 'sent', 'failed')),
    attempts        int  NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL,
    last_error      text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    sent_at         timestamptz
);
CREATE INDEX notification_deliveries_due ON notification_deliveries (next_attempt_at) WHERE state = 'pending';
CREATE INDEX notification_deliveries_tenant ON notification_deliveries (tenant_id, id DESC);

-- +goose Down
DROP TABLE notification_deliveries;
DROP TABLE notification_channels;
```

- [ ] **Step 5: Store tests**

Create `internal/server/store/notifications_test.go`:

```go
package store_test

import (
	"context"
	"errors"
	"testing"

	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"

	"github.com/google/uuid"
)

func TestValidateChannel(t *testing.T) {
	cases := []struct {
		name string
		c    store.NotificationChannel
		ok   bool
	}{
		{"webhook ok", store.NotificationChannel{Kind: "webhook", Name: "Slack", Events: []string{"alert.raised"}, URL: "https://h.example/x"}, true},
		{"email ok", store.NotificationChannel{Kind: "email", Name: "Ops", Events: []string{"approval.new"}, Recipients: []string{"ops@example.com"}}, true},
		{"no name", store.NotificationChannel{Kind: "webhook", Events: []string{"alert.raised"}, URL: "https://h"}, false},
		{"no events", store.NotificationChannel{Kind: "webhook", Name: "x", URL: "https://h"}, false},
		{"unknown event", store.NotificationChannel{Kind: "webhook", Name: "x", Events: []string{"nope"}, URL: "https://h"}, false},
		{"bad scheme", store.NotificationChannel{Kind: "webhook", Name: "x", Events: []string{"alert.raised"}, URL: "ftp://h"}, false},
		{"email no recipients", store.NotificationChannel{Kind: "email", Name: "x", Events: []string{"alert.raised"}}, false},
		{"email bad address", store.NotificationChannel{Kind: "email", Name: "x", Events: []string{"alert.raised"}, Recipients: []string{"nope"}}, false},
		{"bad kind", store.NotificationChannel{Kind: "sms", Name: "x", Events: []string{"alert.raised"}}, false},
	}
	for _, tc := range cases {
		err := store.ValidateChannel(tc.c)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok=%v", tc.name, err, tc.ok)
		}
		var ve *store.ValidationError
		if err != nil && !errors.As(err, &ve) {
			t.Errorf("%s: error must be *ValidationError, got %T", tc.name, err)
		}
	}
}

func TestChannelCRUDAndForEvent(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	other, _ := s.CreateTenant(ctx, "Beta")

	c := store.NotificationChannel{ID: uuid.New(), Kind: "webhook", Name: "Slack", Events: []string{"alert.raised", "rollout.auto_paused"}, Enabled: true, URL: "https://h.example/x", Secret: []byte("sealed")}
	if err := s.CreateChannel(ctx, tenant, c); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateChannel(ctx, tenant, store.NotificationChannel{ID: uuid.New(), Kind: "email", Name: "Slack", Events: []string{"alert.raised"}, Recipients: []string{"a@b.c"}}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("dup name err = %v", err)
	}
	got, err := s.GetChannel(ctx, tenant, c.ID)
	if err != nil || got.Name != "Slack" || len(got.Events) != 2 || string(got.Secret) != "sealed" || !got.Enabled || got.Recipients == nil {
		t.Fatalf("get = %+v, %v (Recipients must be non-nil)", got, err)
	}
	if _, err := s.GetChannel(ctx, other, c.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("cross-tenant get err = %v", err)
	}

	// ForEvent: subscribed + enabled only.
	chs, _ := s.ChannelsForEvent(ctx, tenant, "alert.raised")
	if len(chs) != 1 || chs[0].ID != c.ID {
		t.Fatalf("for alert.raised = %+v", chs)
	}
	if chs, _ = s.ChannelsForEvent(ctx, tenant, "approval.new"); len(chs) != 0 {
		t.Errorf("unsubscribed kind returned %+v", chs)
	}
	got.Enabled = false
	got.Name = "Slack ops"
	if err := s.UpdateChannel(ctx, tenant, got); err != nil {
		t.Fatal(err)
	}
	if chs, _ = s.ChannelsForEvent(ctx, tenant, "alert.raised"); len(chs) != 0 {
		t.Errorf("disabled channel returned %+v", chs)
	}
	list, _ := s.ListChannels(ctx, tenant)
	if len(list) != 1 || list[0].Name != "Slack ops" {
		t.Errorf("list = %+v", list)
	}
	// Suspended tenant → nothing.
	got.Enabled = true
	s.UpdateChannel(ctx, tenant, got)
	s.SetTenantSuspended(ctx, tenant, true)
	if chs, _ = s.ChannelsForEvent(ctx, tenant, "alert.raised"); len(chs) != 0 {
		t.Errorf("suspended tenant returned %+v", chs)
	}
	s.SetTenantSuspended(ctx, tenant, false)

	if err := s.DeleteChannel(ctx, other, c.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("cross-tenant delete err = %v", err)
	}
	if err := s.DeleteChannel(ctx, tenant, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetChannel(ctx, tenant, c.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("after delete err = %v", err)
	}
}
```

Verify the suspend helper name: `grep -n "Suspend" internal/server/store/tenants.go` (Task 2 of the rollouts plan found it is `SetTenantSuspended(ctx, id, bool)`).

- [ ] **Step 6: Run, expect failure** — `go test ./internal/server/store/ -run 'TestValidateChannel|TestChannelCRUD' -v`.

- [ ] **Step 7: Implement store**

Create `internal/server/store/notifications.go`:

```go
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
```

Check `oneRow` returns `ErrNotFound` on zero rows (`grep -n "func oneRow" -A8 internal/server/store/*.go`). `prefixCols` exists from the rollouts work.

- [ ] **Step 8: Run** — `go test ./internal/server/config/ ./internal/server/store/` → PASS.

- [ ] **Step 9: Commit**

```bash
git checkout -b feat/notifications
git add internal/server/config internal/server/store
git commit -m "notifications: SMTP config, channels table + store, validation

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 2: Delivery outbox store

**Files:**
- Modify: `internal/server/store/notifications.go`
- Test: `internal/server/store/notifications_test.go`

**Interfaces (produces):**
```go
type Delivery struct { ID int64; ChannelID uuid.UUID; ChannelName string; EventKind string; Payload []byte; State string; Attempts int; NextAttemptAt time.Time; LastError string; CreatedAt time.Time; SentAt *time.Time }
func (s *Store) EnqueueDeliveries(ctx, tenantID, channelIDs []uuid.UUID, kind string, payload []byte, now) error
func (s *Store) ClaimDeliveries(ctx, now, lease time.Duration, limit int) ([]Delivery, error)   // cross-tenant; sets attempts+1, next_attempt_at=now+lease; returns TenantID via Delivery.TenantID
func (s *Store) FinishDelivery(ctx, id int64, state string, lastError string, nextAttempt time.Time, now) error
func (s *Store) ListDeliveries(ctx, tenantID, limit) ([]Delivery, error)
```
(`Delivery` also carries `TenantID uuid.UUID`.)

- [ ] **Step 1: Tests**

Append to `notifications_test.go`:

```go
func mkChannel(t *testing.T, s *store.Store, tenant uuid.UUID, name string) uuid.UUID {
	t.Helper()
	c := store.NotificationChannel{ID: uuid.New(), Kind: "webhook", Name: name, Events: []string{"alert.raised"}, Enabled: true, URL: "https://h.example/" + name}
	if err := s.CreateChannel(context.Background(), tenant, c); err != nil {
		t.Fatal(err)
	}
	return c.ID
}

func TestDeliveryOutbox(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	a := mkChannel(t, s, tenant, "a")
	b := mkChannel(t, s, tenant, "b")
	now := time.Now().Truncate(time.Second)

	if err := s.EnqueueDeliveries(ctx, tenant, []uuid.UUID{a, b}, "alert.raised", []byte(`{"kind":"alert.raised"}`), now); err != nil {
		t.Fatal(err)
	}
	if err := s.EnqueueDeliveries(ctx, tenant, nil, "alert.raised", []byte(`{}`), now); err != nil {
		t.Fatalf("empty channel list must be a no-op: %v", err)
	}

	// Not due yet.
	if got, _ := s.ClaimDeliveries(ctx, now.Add(-time.Second), 2*time.Minute, 50); len(got) != 0 {
		t.Fatalf("claimed before due: %+v", got)
	}
	got, err := s.ClaimDeliveries(ctx, now, 2*time.Minute, 50)
	if err != nil || len(got) != 2 {
		t.Fatalf("claim = %+v, %v", got, err)
	}
	if got[0].Attempts != 1 || got[0].TenantID != tenant || got[0].ChannelName == "" || !got[0].NextAttemptAt.Equal(now.Add(2*time.Minute)) || string(got[0].Payload) == "" {
		t.Errorf("claimed row = %+v", got[0])
	}
	// Leased: a second claim now returns nothing.
	if again, _ := s.ClaimDeliveries(ctx, now, 2*time.Minute, 50); len(again) != 0 {
		t.Errorf("double claim = %+v", again)
	}
	// Lease expiry brings it back.
	if again, _ := s.ClaimDeliveries(ctx, now.Add(3*time.Minute), 2*time.Minute, 1); len(again) != 1 || again[0].Attempts != 2 {
		t.Errorf("after lease = %+v", again)
	}

	if err := s.FinishDelivery(ctx, got[0].ID, "sent", "", time.Time{}, now); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishDelivery(ctx, got[1].ID, "pending", "500 boom", now.Add(time.Minute), now); err != nil {
		t.Fatal(err)
	}
	list, _ := s.ListDeliveries(ctx, tenant, 10)
	if len(list) != 2 {
		t.Fatalf("list = %+v", list)
	}
	states := map[int64]store.Delivery{}
	for _, d := range list {
		states[d.ID] = d
	}
	if d := states[got[0].ID]; d.State != "sent" || d.SentAt == nil {
		t.Errorf("sent row = %+v", d)
	}
	if d := states[got[1].ID]; d.State != "pending" || d.LastError != "500 boom" || !d.NextAttemptAt.Equal(now.Add(time.Minute)) {
		t.Errorf("retry row = %+v", d)
	}
	// Failed terminal.
	s.FinishDelivery(ctx, got[1].ID, "failed", "gave up", time.Time{}, now)
	if c, _ := s.ClaimDeliveries(ctx, now.Add(time.Hour), time.Minute, 50); len(c) != 0 {
		t.Errorf("failed row claimed: %+v", c)
	}
	// Deleting the channel cascades.
	s.DeleteChannel(ctx, tenant, a)
	list, _ = s.ListDeliveries(ctx, tenant, 10)
	if len(list) != 1 {
		t.Errorf("after cascade = %+v", list)
	}
}

func TestClaimDeliveriesConcurrent(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	ch := mkChannel(t, s, tenant, "a")
	now := time.Now()
	for i := 0; i < 20; i++ {
		s.EnqueueDeliveries(ctx, tenant, []uuid.UUID{ch}, "alert.raised", []byte(`{}`), now)
	}
	var mu sync.Mutex
	seen := map[int64]int{}
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := s.ClaimDeliveries(ctx, now, time.Minute, 10)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			for _, d := range got {
				seen[d.ID]++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	if len(seen) != 20 {
		t.Fatalf("claimed %d distinct rows, want 20", len(seen))
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("row %d claimed %d times", id, n)
		}
	}
}
```

Add `"sync"` and `"time"` to the test imports.

- [ ] **Step 2: Run, expect failure.**

- [ ] **Step 3: Implement**

Append to `notifications.go`:

```go
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
	if len(lastError) > 500 {
		lastError = lastError[:500]
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
```

- [ ] **Step 4: Run** — `go test ./internal/server/store/ -run 'Deliver' -v` → PASS.
- [ ] **Step 5: Commit** — `git commit -m "notifications: delivery outbox store — enqueue, leased claim, finish, list"` + trailer.

---

### Task 3: notify package — events, dispatcher, webhook, email

**Files:**
- Create: `internal/server/notify/notify.go`, `webhook.go`, `email.go`
- Test: `internal/server/notify/notify_test.go`, `internal/server/notify/smtp_test.go`

**Interfaces (produces):** as in the spec's Delivery section, plus:
```go
type Nop struct{}; func (Nop) Emit(context.Context, Event) {}
type Mailer interface { Send(ctx context.Context, to []string, subject, body string) error }
func New(store *store.Store, sealer *keys.Sealer, smtp config.SMTP, log *slog.Logger) *Service
func Backoff(attempt int) (next time.Duration, giveUp bool)   // 1→1m, 2→5m, 3,4→30m, 5→giveUp
func Sign(secret, body []byte) string                          // "sha256=<hex>"
```

- [ ] **Step 1: Tests (`notify_test.go`)**

```go
package notify_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"freelocker/internal/server/config"
	"freelocker/internal/server/keys"
	"freelocker/internal/server/notify"
	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"

	"github.com/google/uuid"
)

type fakeMailer struct {
	mu   sync.Mutex
	sent []struct{ To []string; Subject, Body string }
	err  error
}

func (m *fakeMailer) Send(_ context.Context, to []string, subject, body string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.sent = append(m.sent, struct{ To []string; Subject, Body string }{to, subject, body})
	return nil
}

type fx struct {
	s      *store.Store
	tenant uuid.UUID
	svc    *notify.Service
	mail   *fakeMailer
	sealer *keys.Sealer
	now    time.Time
}

func newFx(t *testing.T) *fx {
	t.Helper()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(context.Background(), "Acme")
	sealer, _ := keys.NewSealer(bytes.Repeat([]byte{9}, 32), "notify")
	f := &fx{s: s, tenant: tenant, mail: &fakeMailer{}, sealer: sealer, now: time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)}
	f.svc = notify.New(s, sealer, config.SMTP{Host: "mail", From: "fl@example.com"}, nil)
	f.svc.Mailer = f.mail
	f.svc.Now = func() time.Time { return f.now }
	return f
}

func (f *fx) webhook(t *testing.T, name, url, secret string, events ...string) store.NotificationChannel {
	t.Helper()
	c := store.NotificationChannel{ID: uuid.New(), Kind: "webhook", Name: name, Events: events, Enabled: true, URL: url}
	if secret != "" {
		c.Secret = f.sealer.Seal([]byte(secret))
	}
	if err := f.s.CreateChannel(context.Background(), f.tenant, c); err != nil {
		t.Fatal(err)
	}
	return c
}

func (f *fx) email(t *testing.T, name string, to []string, events ...string) store.NotificationChannel {
	t.Helper()
	c := store.NotificationChannel{ID: uuid.New(), Kind: "email", Name: name, Events: events, Enabled: true, Recipients: to}
	if err := f.s.CreateChannel(context.Background(), f.tenant, c); err != nil {
		t.Fatal(err)
	}
	return c
}

func (f *fx) event(kind string) notify.Event {
	return notify.Event{Kind: kind, TenantID: f.tenant, Title: "CPU high on pc-1", Body: "cpu 95% above 90%", Detail: map[string]any{"hostname": "pc-1"}, At: f.now}
}

type received struct {
	mu      sync.Mutex
	bodies  [][]byte
	headers []http.Header
}

func receiver(t *testing.T, status int, rec *received) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		rec.mu.Lock()
		rec.bodies = append(rec.bodies, b)
		rec.headers = append(rec.headers, r.Header.Clone())
		rec.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestWebhookSignedAndSent(t *testing.T) {
	f := newFx(t)
	rec := &received{}
	srv := receiver(t, 200, rec)
	f.webhook(t, "hook", srv.URL+"/in", "topsecret", "alert.raised")
	f.email(t, "mail", []string{"ops@example.com"}, "alert.raised")
	f.webhook(t, "other", srv.URL+"/no", "", "approval.new") // not subscribed

	f.svc.Emit(context.Background(), f.event("alert.raised"))
	sent, failed, err := f.svc.Dispatch(context.Background())
	if err != nil || sent != 2 || failed != 0 {
		t.Fatalf("dispatch = %d sent, %d failed, %v", sent, failed, err)
	}
	if len(rec.bodies) != 1 {
		t.Fatalf("receiver got %d requests", len(rec.bodies))
	}
	h := rec.headers[0]
	mac := hmac.New(sha256.New, []byte("topsecret"))
	mac.Write(rec.bodies[0])
	if want := "sha256=" + hex.EncodeToString(mac.Sum(nil)); h.Get("X-FreeLocker-Signature") != want {
		t.Errorf("signature = %q, want %q", h.Get("X-FreeLocker-Signature"), want)
	}
	if h.Get("X-FreeLocker-Event") != "alert.raised" || h.Get("X-FreeLocker-Delivery") == "" || h.Get("Content-Type") != "application/json" {
		t.Errorf("headers = %v", h)
	}
	var ev notify.Event
	if err := json.Unmarshal(rec.bodies[0], &ev); err != nil || ev.Kind != "alert.raised" || ev.Title != "CPU high on pc-1" || ev.Detail["hostname"] != "pc-1" {
		t.Errorf("body = %s (%v)", rec.bodies[0], err)
	}
	if len(f.mail.sent) != 1 || f.mail.sent[0].Subject != "[FreeLocker] CPU high on pc-1" || f.mail.sent[0].To[0] != "ops@example.com" || !bytes.Contains([]byte(f.mail.sent[0].Body), []byte("cpu 95% above 90%")) {
		t.Errorf("mail = %+v", f.mail.sent)
	}
	list, _ := f.s.ListDeliveries(context.Background(), f.tenant, 10)
	if len(list) != 2 || list[0].State != "sent" || list[1].State != "sent" {
		t.Errorf("deliveries = %+v", list)
	}
}

func TestWebhookNoSecretNoSignatureHeader(t *testing.T) {
	f := newFx(t)
	rec := &received{}
	srv := receiver(t, 204, rec)
	f.webhook(t, "hook", srv.URL, "", "alert.raised")
	f.svc.Emit(context.Background(), f.event("alert.raised"))
	f.svc.Dispatch(context.Background())
	if len(rec.headers) != 1 || rec.headers[0].Get("X-FreeLocker-Signature") != "" {
		t.Errorf("headers = %v", rec.headers)
	}
}

func TestWebhookRetryBackoffThenFailed(t *testing.T) {
	f := newFx(t)
	rec := &received{}
	srv := receiver(t, 500, rec)
	f.webhook(t, "hook", srv.URL, "", "alert.raised")
	f.svc.Emit(context.Background(), f.event("alert.raised"))
	ctx := context.Background()

	wantNext := []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute, 30 * time.Minute}
	for i, d := range wantNext {
		sent, failed, _ := f.svc.Dispatch(ctx)
		if sent != 0 || failed != 0 {
			t.Fatalf("attempt %d: sent=%d failed=%d (a retry is neither)", i+1, sent, failed)
		}
		list, _ := f.s.ListDeliveries(ctx, f.tenant, 1)
		if list[0].State != "pending" || list[0].Attempts != i+1 || !list[0].NextAttemptAt.Equal(f.now.Add(d)) || list[0].LastError == "" {
			t.Fatalf("after attempt %d: %+v (want next +%s)", i+1, list[0], d)
		}
		f.now = f.now.Add(d)
	}
	_, failed, _ := f.svc.Dispatch(ctx)
	list, _ := f.s.ListDeliveries(ctx, f.tenant, 1)
	if failed != 1 || list[0].State != "failed" || list[0].Attempts != 5 {
		t.Fatalf("final = failed %d, row %+v", failed, list[0])
	}
	if len(rec.bodies) != 5 {
		t.Errorf("receiver got %d requests, want 5", len(rec.bodies))
	}
}

func TestWebhookDoesNotFollowRedirect(t *testing.T) {
	f := newFx(t)
	hit := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit++
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	f.webhook(t, "hook", srv.URL, "", "alert.raised")
	f.svc.Emit(context.Background(), f.event("alert.raised"))
	f.svc.Dispatch(context.Background())
	list, _ := f.s.ListDeliveries(context.Background(), f.tenant, 1)
	if hit != 1 || list[0].State != "pending" {
		t.Errorf("hits=%d row=%+v (302 must count as failure, not be followed)", hit, list[0])
	}
}

func TestDisabledOrDeletedChannelFails(t *testing.T) {
	f := newFx(t)
	rec := &received{}
	srv := receiver(t, 200, rec)
	c := f.webhook(t, "hook", srv.URL, "", "alert.raised")
	f.svc.Emit(context.Background(), f.event("alert.raised"))
	c.Enabled = false
	f.s.UpdateChannel(context.Background(), f.tenant, c)
	_, failed, _ := f.svc.Dispatch(context.Background())
	list, _ := f.s.ListDeliveries(context.Background(), f.tenant, 1)
	if failed != 1 || list[0].State != "failed" || len(rec.bodies) != 0 {
		t.Errorf("disabled: failed=%d row=%+v hits=%d", failed, list[0], len(rec.bodies))
	}
}

func TestEmitNoSubscribersInsertsNothing(t *testing.T) {
	f := newFx(t)
	f.svc.Emit(context.Background(), f.event("alert.raised"))
	list, _ := f.s.ListDeliveries(context.Background(), f.tenant, 10)
	if len(list) != 0 {
		t.Errorf("deliveries = %+v", list)
	}
}

func TestMailerErrorRetries(t *testing.T) {
	f := newFx(t)
	f.mail.err = io.ErrUnexpectedEOF
	f.email(t, "mail", []string{"a@b.c"}, "alert.raised")
	f.svc.Emit(context.Background(), f.event("alert.raised"))
	f.svc.Dispatch(context.Background())
	list, _ := f.s.ListDeliveries(context.Background(), f.tenant, 1)
	if list[0].State != "pending" || list[0].LastError == "" {
		t.Errorf("row = %+v", list[0])
	}
}

func TestEmailWithoutSMTPFails(t *testing.T) {
	f := newFx(t)
	f.svc.SMTP = config.SMTP{}
	f.email(t, "mail", []string{"a@b.c"}, "alert.raised")
	f.svc.Emit(context.Background(), f.event("alert.raised"))
	_, failed, _ := f.svc.Dispatch(context.Background())
	list, _ := f.s.ListDeliveries(context.Background(), f.tenant, 1)
	if failed != 1 || list[0].State != "failed" || list[0].LastError != "smtp is not configured on this server" {
		t.Errorf("row = %+v", list[0])
	}
}

func TestTestSendReturnsReceiverError(t *testing.T) {
	f := newFx(t)
	rec := &received{}
	srv := receiver(t, 401, rec)
	c := f.webhook(t, "hook", srv.URL, "s", "alert.raised")
	if err := f.svc.Test(context.Background(), c); err == nil || !bytes.Contains([]byte(err.Error()), []byte("401")) {
		t.Errorf("test err = %v", err)
	}
	ok := receiver(t, 200, rec)
	c.URL = ok.URL
	if err := f.svc.Test(context.Background(), c); err != nil {
		t.Errorf("test ok err = %v", err)
	}
	if list, _ := f.s.ListDeliveries(context.Background(), f.tenant, 10); len(list) != 0 {
		t.Errorf("test sends must not be recorded: %+v", list)
	}
	var ev notify.Event
	json.Unmarshal(rec.bodies[len(rec.bodies)-1], &ev)
	if ev.Kind != "notify.test" {
		t.Errorf("test event kind = %q", ev.Kind)
	}
}

func TestBackoff(t *testing.T) {
	for _, tc := range []struct {
		attempt int
		next    time.Duration
		giveUp  bool
	}{{1, time.Minute, false}, {2, 5 * time.Minute, false}, {3, 30 * time.Minute, false}, {4, 30 * time.Minute, false}, {5, 0, true}, {9, 0, true}} {
		next, giveUp := notify.Backoff(tc.attempt)
		if next != tc.next || giveUp != tc.giveUp {
			t.Errorf("Backoff(%d) = %s, %v", tc.attempt, next, giveUp)
		}
	}
}
```

- [ ] **Step 2: SMTP wire test (`smtp_test.go`)**

```go
package notify_test

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"

	"freelocker/internal/server/config"
	"freelocker/internal/server/notify"
)

// fakeSMTP speaks just enough SMTP (no TLS, no auth) to capture one message.
func fakeSMTP(t *testing.T) (addr string, got *strings.Builder) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got = &strings.Builder{}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		w := func(s string) { conn.Write([]byte(s + "\r\n")) }
		w("220 fake ESMTP")
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if inData {
				if line == "." {
					inData = false
					w("250 queued")
					continue
				}
				got.WriteString(line + "\n")
				continue
			}
			got.WriteString("> " + line + "\n")
			switch {
			case strings.HasPrefix(line, "EHLO"):
				w("250-fake")
				w("250 8BITMIME")
			case strings.HasPrefix(line, "HELO"):
				w("250 fake")
			case strings.HasPrefix(line, "MAIL FROM"), strings.HasPrefix(line, "RCPT TO"):
				w("250 ok")
			case line == "DATA":
				w("354 go")
				inData = true
			case line == "QUIT":
				w("221 bye")
				return
			default:
				w("250 ok")
			}
		}
	}()
	return ln.Addr().String(), got
}

func TestSMTPMailerPlain(t *testing.T) {
	addr, got := fakeSMTP(t)
	host, port, _ := net.SplitHostPort(addr)
	var p int
	for _, ch := range port {
		p = p*10 + int(ch-'0')
	}
	m := notify.NewSMTPMailer(config.SMTP{Host: host, Port: p, From: "FreeLocker <fl@example.com>", STARTTLS: false})
	if err := m.Send(context.Background(), []string{"a@example.com", "b@example.com"}, "[FreeLocker] hi", "line one\nline two"); err != nil {
		t.Fatal(err)
	}
	s := got.String()
	for _, want := range []string{"> MAIL FROM:<fl@example.com>", "> RCPT TO:<a@example.com>", "> RCPT TO:<b@example.com>", "Subject: [FreeLocker] hi", "To: a@example.com, b@example.com", "line two"} {
		if !strings.Contains(s, want) {
			t.Errorf("transcript missing %q:\n%s", want, s)
		}
	}
}
```

- [ ] **Step 3: Run, expect failure** — package missing.

- [ ] **Step 4: Implement `notify.go`**

```go
// Package notify fans events out to a tenant's notification channels through
// a retrying outbox: producers Emit, a dispatcher sends.
package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"freelocker/internal/server/config"
	"freelocker/internal/server/keys"
	"freelocker/internal/server/store"

	"github.com/google/uuid"
)

type Event struct {
	Kind     string         `json:"kind"`
	TenantID uuid.UUID      `json:"tenant_id"`
	Title    string         `json:"title"`
	Body     string         `json:"body"`
	Detail   map[string]any `json:"detail"`
	At       time.Time      `json:"at"`
}

// Emitter is what producers depend on. Emit never returns an error: a
// notification failure must not fail the thing being notified about.
type Emitter interface {
	Emit(ctx context.Context, e Event)
}

// Nop is the Emitter for tests and unconfigured servers.
type Nop struct{}

func (Nop) Emit(context.Context, Event) {}

const (
	ClaimLease   = 2 * time.Minute
	ClaimBatch   = 50
	MaxAttempts  = 5
	errNoSMTP    = "smtp is not configured on this server"
	testKind     = "notify.test"
	runFallback  = 30 * time.Second
)

// Backoff returns how long to wait after failed attempt n, or giveUp when
// the delivery should be marked failed.
func Backoff(attempt int) (time.Duration, bool) {
	switch {
	case attempt >= MaxAttempts:
		return 0, true
	case attempt == 1:
		return time.Minute, false
	case attempt == 2:
		return 5 * time.Minute, false
	default:
		return 30 * time.Minute, false
	}
}

type Service struct {
	Store  *store.Store
	Sealer *keys.Sealer
	SMTP   config.SMTP
	Mailer Mailer
	Client *http.Client
	Now    func() time.Time
	Log    *slog.Logger
	wake   chan struct{}
}

func New(s *store.Store, sealer *keys.Sealer, smtp config.SMTP, log *slog.Logger) *Service {
	return &Service{
		Store: s, Sealer: sealer, SMTP: smtp, Mailer: NewSMTPMailer(smtp),
		Client: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		Log:    log, wake: make(chan struct{}, 1),
	}
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// Emit enqueues one delivery per subscribed channel and wakes the
// dispatcher. Errors are logged only.
func (s *Service) Emit(ctx context.Context, e Event) {
	if e.At.IsZero() {
		e.At = s.now()
	}
	chs, err := s.Store.ChannelsForEvent(ctx, e.TenantID, e.Kind)
	if err != nil {
		s.log().Error("notify: list channels", "kind", e.Kind, "err", err)
		return
	}
	if len(chs) == 0 {
		return
	}
	payload, err := json.Marshal(e)
	if err != nil {
		s.log().Error("notify: marshal event", "kind", e.Kind, "err", err)
		return
	}
	ids := make([]uuid.UUID, 0, len(chs))
	for _, c := range chs {
		ids = append(ids, c.ID)
	}
	if err := s.Store.EnqueueDeliveries(ctx, e.TenantID, ids, e.Kind, payload, s.now()); err != nil {
		s.log().Error("notify: enqueue", "kind", e.Kind, "err", err)
		return
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Run drains the outbox whenever woken and every runFallback regardless,
// until ctx is done.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(runFallback)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		case <-t.C:
		}
		for {
			sent, failed, err := s.Dispatch(ctx)
			if err != nil {
				s.log().Error("notify: dispatch", "err", err)
				break
			}
			if sent+failed == 0 {
				break
			}
		}
	}
}

// Dispatch claims one batch of due deliveries and sends them. Returns how
// many were sent and how many became terminally failed (retries are neither).
func (s *Service) Dispatch(ctx context.Context) (sent, failed int, err error) {
	now := s.now()
	rows, err := s.Store.ClaimDeliveries(ctx, now, ClaimLease, ClaimBatch)
	if err != nil {
		return 0, 0, err
	}
	for _, d := range rows {
		sendErr := s.deliver(ctx, d)
		switch {
		case sendErr == nil:
			sent++
			err = s.Store.FinishDelivery(ctx, d.ID, "sent", "", time.Time{}, now)
		default:
			var perm permanentError
			if next, giveUp := Backoff(d.Attempts); giveUp || errors.As(sendErr, &perm) {
				failed++
				err = s.Store.FinishDelivery(ctx, d.ID, "failed", sendErr.Error(), time.Time{}, now)
			} else {
				err = s.Store.FinishDelivery(ctx, d.ID, "pending", sendErr.Error(), now.Add(next), now)
			}
		}
		if err != nil {
			s.log().Error("notify: finish delivery", "id", d.ID, "err", err)
		}
	}
	return sent, failed, nil
}

// permanentError marks a failure no retry can fix (channel gone/disabled).
type permanentError struct{ msg string }

func (e permanentError) Error() string { return e.msg }

func (s *Service) deliver(ctx context.Context, d store.Delivery) error {
	ch, err := s.Store.GetChannel(ctx, d.TenantID, d.ChannelID)
	if errors.Is(err, store.ErrNotFound) {
		return permanentError{"channel was deleted"}
	}
	if err != nil {
		return err
	}
	if !ch.Enabled {
		return permanentError{"channel is disabled"}
	}
	var e Event
	if err := json.Unmarshal(d.Payload, &e); err != nil {
		return permanentError{"bad payload: " + err.Error()}
	}
	return s.send(ctx, ch, e, fmt.Sprint(d.ID))
}

func (s *Service) send(ctx context.Context, ch store.NotificationChannel, e Event, deliveryID string) error {
	switch ch.Kind {
	case "webhook":
		var secret []byte
		if len(ch.Secret) > 0 {
			var err error
			if secret, err = s.Sealer.Open(ch.Secret); err != nil {
				return permanentError{"cannot unseal webhook secret"}
			}
		}
		return s.postWebhook(ctx, ch.URL, secret, e, deliveryID)
	case "email":
		if !s.SMTP.Configured() {
			return permanentError{errNoSMTP}
		}
		return s.Mailer.Send(ctx, ch.Recipients, "[FreeLocker] "+e.Title, formatEmailBody(e))
	default:
		return permanentError{"unknown channel kind " + ch.Kind}
	}
}

// Test sends a synthetic event through the channel synchronously and
// returns the delivery error, if any. Nothing is recorded.
func (s *Service) Test(ctx context.Context, ch store.NotificationChannel) error {
	e := Event{Kind: testKind, TenantID: uuid.Nil, Title: "Test notification from FreeLocker",
		Body: "If you can read this, the channel \"" + ch.Name + "\" works.", Detail: map[string]any{"channel": ch.Name}, At: s.now()}
	return s.send(ctx, ch, e, "test")
}
```

Note `s.SMTP.Configured()` — add to `config.SMTP` a method `func (m SMTP) Configured() bool { return m.Host != "" && m.From != "" }` and make `Config.SMTPConfigured()` call it.

- [ ] **Step 5: `webhook.go`**

```go
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Sign returns the X-FreeLocker-Signature value for body.
func Sign(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func (s *Service) postWebhook(ctx context.Context, url string, secret []byte, e Event, deliveryID string) error {
	body, err := json.Marshal(e)
	if err != nil {
		return permanentError{"marshal: " + err.Error()}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return permanentError{"bad url: " + err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "FreeLocker-Notify/1")
	req.Header.Set("X-FreeLocker-Event", e.Kind)
	req.Header.Set("X-FreeLocker-Delivery", deliveryID)
	if len(secret) > 0 {
		req.Header.Set("X-FreeLocker-Signature", Sign(secret, body))
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}
```

- [ ] **Step 6: `email.go`**

```go
package notify

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"sort"
	"strings"
	"time"

	"freelocker/internal/server/config"
)

type Mailer interface {
	Send(ctx context.Context, to []string, subject, body string) error
}

type smtpMailer struct{ cfg config.SMTP }

func NewSMTPMailer(cfg config.SMTP) Mailer { return &smtpMailer{cfg: cfg} }

func (m *smtpMailer) Send(ctx context.Context, to []string, subject, body string) error {
	cfg := m.cfg
	if cfg.Port == 0 {
		cfg.Port = 587
	}
	fromAddr := cfg.From
	if a, err := mail.ParseAddress(cfg.From); err == nil {
		fromAddr = a.Address
	}
	addr := net.JoinHostPort(cfg.Host, fmt.Sprint(cfg.Port))
	d := net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	var err error
	if cfg.Port == 465 {
		conn, err = tls.DialWithDialer(&d, "tcp", addr, &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12})
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return err
	}
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	c, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if cfg.Port != 465 && cfg.STARTTLS {
		if err := c.StartTLS(&tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}
	if cfg.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)); err != nil {
			return err
		}
	}
	if err := c.Mail(fromAddr); err != nil {
		return err
	}
	for _, r := range to {
		if err := c.Rcpt(r); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	msg := "From: " + cfg.From + "\r\n" +
		"To: " + strings.Join(to, ", ") + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
		strings.ReplaceAll(body, "\n", "\r\n")
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// formatEmailBody renders the event body followed by its detail map.
func formatEmailBody(e Event) string {
	var b strings.Builder
	b.WriteString(e.Body)
	b.WriteString("\n\n")
	keys := make([]string, 0, len(e.Detail))
	for k := range e.Detail {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s: %v\n", k, e.Detail[k])
	}
	fmt.Fprintf(&b, "\nEvent: %s at %s\n", e.Kind, e.At.UTC().Format(time.RFC3339))
	return b.String()
}
```

- [ ] **Step 7: Run** — `go test ./internal/server/notify/ -v` → PASS. If `smtp.NewClient` complains about the fake's greeting, make the fake send `220 fake ESMTP` exactly once before reading.

- [ ] **Step 8: Commit** — `notify: outbox dispatcher, signed webhooks, SMTP mailer, test send` + trailer.

---

### Task 4: Producers and wiring

**Files:**
- Modify: `internal/server/store/metrics.go` (`ResolveAlert` → `(bool, error)`), `internal/server/store/approvals.go` (`UpsertApprovalRequests` → `([]uuid.UUID, error)`), their tests
- Modify: `internal/server/alerting/alerting.go` + test, `internal/server/rollout/rollout.go` + test, `internal/server/agentapi/server.go` + `policy.go`
- Modify: `internal/server/app/app.go`, `internal/server/httpapi/api.go` (`Runtime.Notify *notify.Service`, `API.NotifySealer`), `internal/server/httpapi/helpers_test.go`

**Interfaces:**
- Consumes: `notify.Emitter`, `notify.Nop`, `notify.New`, `Service.Run`, `Service.Dispatch`.
- Produces: `alerting.Service.Notify`, `rollout.Service.Notify`, `agentapi.Deps.Notify` (all `notify.Emitter`, nil-safe); `httpapi.Runtime.Notify *notify.Service`; `httpapi.API.NotifySealer *keys.Sealer`.

- [ ] **Step 1: Store return-value changes with tests**

In `metrics.go`:

```go
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
```

In `approvals.go`, change the signature to `(inserted []uuid.UUID, err error)`, change the `RETURNING id` to `RETURNING id, (xmax = 0)` scanning `&id, &isNew`, append `id` to `inserted` when `isNew`, return `inserted, tx.Commit(ctx)` at the end (and `nil, nil` for the empty-order early return). Fix every caller (`grep -rn "UpsertApprovalRequests\|ResolveAlert(" internal/ test/`).

Add to `store/approvals_test.go`:

```go
func TestUpsertApprovalRequestsReportsNew(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	pol, _ := s.CreatePolicy(ctx, tenant, "Baseline", "audit")
	dev := seedDevice(t, s, tenant)
	ev := []store.BlockEvent{{SHA256: "AA", Path: `C:\a.exe`, At: time.Now()}}
	first, err := s.UpsertApprovalRequests(ctx, tenant, pol, dev, ev)
	if err != nil || len(first) != 1 {
		t.Fatalf("first = %v, %v", first, err)
	}
	again, err := s.UpsertApprovalRequests(ctx, tenant, pol, dev, ev)
	if err != nil || len(again) != 0 {
		t.Fatalf("second upsert must report nothing new: %v, %v", again, err)
	}
}
```

Add to `store/metrics_test.go` (or wherever `RaiseAlert` is tested):

```go
func TestResolveAlertReportsClosed(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	dev := seedDevice(t, s, tenant)
	rid, _ := s.CreateAlertRule(ctx, tenant, store.AlertRule{Name: "r", Metric: "cpu", Op: "gt", Threshold: 1, Enabled: true})
	now := time.Now()
	s.RaiseAlert(ctx, tenant, dev, rid, "cpu", "m", now)
	if ok, err := s.ResolveAlert(ctx, tenant, dev, rid, now); err != nil || !ok {
		t.Fatalf("first resolve = %v, %v", ok, err)
	}
	if ok, _ := s.ResolveAlert(ctx, tenant, dev, rid, now); ok {
		t.Error("second resolve must report false")
	}
}
```

(`seedDevice` exists in `store_test` — `grep -n "func seedDevice" internal/server/store/*_test.go`.)

- [ ] **Step 2: Alerting emits**

`alerting.go`: add `Notify notify.Emitter` to `Service`; add a helper:

```go
func (s *Service) emit(ctx context.Context, e notify.Event) {
	if s.Notify != nil {
		s.Notify.Emit(ctx, e)
	}
}
```

In `Evaluate`, after `RaiseAlert`:

```go
				created, err := s.Store.RaiseAlert(ctx, tenantID, deviceID, r.ID, r.Metric, msg, now)
				if err != nil {
					return err
				}
				if created {
					s.emit(ctx, s.alertEvent(ctx, "alert.raised", tenantID, deviceID, r, msg, now))
				}
```

and after `ResolveAlert`:

```go
			closed, err := s.Store.ResolveAlert(ctx, tenantID, deviceID, r.ID, now)
			if err != nil {
				return err
			}
			if closed {
				s.emit(ctx, s.alertEvent(ctx, "alert.resolved", tenantID, deviceID, r, "", now))
			}
```

```go
func (s *Service) alertEvent(ctx context.Context, kind string, tenantID, deviceID uuid.UUID, r store.AlertRule, msg string, now time.Time) notify.Event {
	host := deviceID.String()
	if d, err := s.Store.GetDevice(ctx, tenantID, deviceID); err == nil && d.Hostname != "" {
		host = d.Hostname
	}
	title := fmt.Sprintf("Alert: %s on %s", r.Name, host)
	body := fmt.Sprintf("%s is %s on %s.", r.Name, map[string]string{"alert.raised": "breaching", "alert.resolved": "resolved"}[kind], host)
	if msg != "" {
		body += "\n" + msg
	}
	if kind == "alert.resolved" {
		title = fmt.Sprintf("Resolved: %s on %s", r.Name, host)
	}
	return notify.Event{Kind: kind, TenantID: tenantID, Title: title, Body: body, At: now,
		Detail: map[string]any{"device_id": deviceID.String(), "hostname": host, "rule_id": r.ID.String(), "rule_name": r.Name, "metric": r.Metric, "message": msg}}
}
```

Test in `alerting_test.go`:

```go
type recEmitter struct{ events []notify.Event }

func (r *recEmitter) Emit(_ context.Context, e notify.Event) { r.events = append(r.events, e) }

func TestEvaluateEmitsOnTransitionsOnly(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	dev := seedDevice(t, s, tenant)
	s.CreateAlertRule(ctx, tenant, store.AlertRule{Name: "High CPU", Metric: "cpu", Op: "gt", Threshold: 90, Enabled: true})
	rec := &recEmitter{}
	svc := alerting.New(s)
	svc.Notify = rec
	now := time.Now()
	svc.Evaluate(ctx, tenant, dev, store.MetricSample{CPUPct: 95}, now)
	svc.Evaluate(ctx, tenant, dev, store.MetricSample{CPUPct: 96}, now.Add(time.Second)) // still breaching: no new event
	svc.Evaluate(ctx, tenant, dev, store.MetricSample{CPUPct: 10}, now.Add(time.Minute))
	svc.Evaluate(ctx, tenant, dev, store.MetricSample{CPUPct: 10}, now.Add(2*time.Minute)) // still fine: no event
	if len(rec.events) != 2 || rec.events[0].Kind != "alert.raised" || rec.events[1].Kind != "alert.resolved" {
		t.Fatalf("events = %+v", rec.events)
	}
	if rec.events[0].Detail["hostname"] != "pc" || rec.events[0].Detail["rule_name"] != "High CPU" || rec.events[0].Title != "Alert: High CPU on pc" {
		t.Errorf("raised event = %+v", rec.events[0])
	}
}
```

- [ ] **Step 3: Rollout emits**

`rollout.go`: add `Notify notify.Emitter` and the same nil-safe `emit` helper. At auto-pause (after the audit write):

```go
		s.emit(ctx, notify.Event{Kind: "rollout.auto_paused", TenantID: tenantID, At: now,
			Title: fmt.Sprintf("Rollout of %s auto-paused after %d failures", r.Version, sum.Failed),
			Body:  fmt.Sprintf("The rollout of agent %s was paused automatically: %d devices failed to update (threshold %d). Review the failures in the console, then resume or roll back.", r.Version, sum.Failed, r.MaxFailures),
			Detail: map[string]any{"rollout_id": r.ID.String(), "version": r.Version, "failed": sum.Failed, "max_failures": r.MaxFailures}})
```

At completion (after `SetRolloutState(...completed...)`):

```go
		s.emit(ctx, notify.Event{Kind: "rollout.completed", TenantID: tenantID, At: now,
			Title: fmt.Sprintf("Rollout of %s completed", r.Version),
			Body:  fmt.Sprintf("Agent %s reached every targeted device: %d updated, %d failed.", r.Version, sum.Updated, sum.Failed),
			Detail: map[string]any{"rollout_id": r.ID.String(), "version": r.Version, "updated": sum.Updated, "failed": sum.Failed}})
```

Test in `rollout_test.go`: add the same `recEmitter` type (package `rollout_test`), set `f.svc.Notify = rec` in a new test `TestRolloutEmitsPauseAndCompletion` that reuses the `TestAutoPauseOnFailures` steps to reach auto-pause (assert one `rollout.auto_paused` event with `Detail["failed"] == 2`) and the `TestResolvesAndCompletes` steps in a second fixture to reach completion (assert one `rollout.completed`).

- [ ] **Step 4: Approvals emit**

`agentapi/server.go`: add `Notify notify.Emitter // optional` to `Deps`. In `policy.go` `queueApprovals`:

```go
	newIDs, err := s.d.Store.UpsertApprovalRequests(ctx, tenantID, pv.PolicyID, deviceID, events)
	if err != nil {
		s.d.Log.Error("queue approval requests", "device", deviceID, "err", err)
		return
	}
	if s.d.Notify == nil || len(newIDs) == 0 {
		return
	}
	host := deviceID.String()
	if d, err := s.d.Store.GetDevice(ctx, tenantID, deviceID); err == nil && d.Hostname != "" {
		host = d.Hostname
	}
	for _, id := range newIDs {
		req, err := s.d.Store.GetApprovalRequest(ctx, tenantID, id)
		if err != nil {
			continue
		}
		s.d.Notify.Emit(ctx, notify.Event{Kind: "approval.new", TenantID: tenantID, At: req.FirstSeen,
			Title: fmt.Sprintf("Approval requested: %s on %s", filepath.Base(req.Path), host),
			Body:  fmt.Sprintf("%s was blocked on %s by policy %s and is waiting for approval.\nPath: %s\nSigner: %s", filepath.Base(req.Path), host, req.PolicyName, req.Path, req.Signer),
			Detail: map[string]any{"request_id": id.String(), "policy_id": req.PolicyID.String(), "policy_name": req.PolicyName, "sha256": req.SHA256, "path": req.Path, "signer": req.Signer, "device_id": deviceID.String(), "hostname": host}})
	}
```

Use `path/filepath` — on the Linux CI runner `filepath.Base` of a Windows path returns the whole string; use a small helper `baseName(p string) string` that splits on both `\` and `/` (`p[strings.LastIndexAny(p, `\/`)+1:]`) instead of `filepath.Base`.

Find the existing agentapi test that exercises `ReportBlocks` (`grep -rn "ReportBlocks\|queueApprovals" internal/server/agentapi/*_test.go`) and add an assertion that with `Deps.Notify` set to a recording emitter, one `approval.new` event arrives on the first report and none on a repeat of the same hash. If no such test exists, add `TestReportBlocksEmitsApprovalNew` following the package's existing gRPC test fixture.

- [ ] **Step 5: Wiring**

`httpapi/api.go`: `Runtime` gains `Notify *notify.Service`; `API` gains `NotifySealer *keys.Sealer` and `SMTPConfigured bool`.

`app/app.go`:
- In `NewWithStore`: `notifySealer, err := keys.NewSealer(master, "notify")`; store it on `App` (`notifySealer *keys.Sealer`); set `api.NotifySealer = notifySealer` and `api.SMTPConfigured = cfg.SMTPConfigured()`.
- In `activate`: `notifier := notify.New(a.store, a.notifySealer, a.cfg.SMTP, a.log)`; pass `Notify: notifier` into `alerting` (`alerts := alerting.New(a.store); alerts.Notify = notifier`), `rollouts` (`Notify: notifier`), `agentapi.Deps{..., Notify: notifier}`; `Runtime{..., Notify: notifier}`; start `go notifier.Run(a.runCtx)`. `activate` has no ctx today: add a field `runCtx context.Context` set at the top of `Run` (`a.runCtx = ctx`) and for the `setup` path use `context.Background()` if `runCtx` is nil. Keep it simple: store `ctx` in `Run` before calling `activate`; in `setup` fall back to `context.Background()`.
- In the ticker, after `Rollouts.Tick`: `if _, _, err := rt.Notify.Dispatch(ctx); err != nil { a.log.Error("notify dispatch", "err", err) }`.

`httpapi/helpers_test.go`: in the `API` literal add `NotifySealer: func() *keys.Sealer { s, _ := keys.NewSealer(master, "notify"); return s }(), SMTPConfigured: false`; in the `Runtime` literal add `Notify: notify.New(s, notifySealer, config.SMTP{}, nil)` (create `notifySealer` once next to `sealer`).

- [ ] **Step 6: Build + tests** — `go build ./... && go test ./internal/server/...` → PASS.
- [ ] **Step 7: Commit** — `notifications: producers emit alert/approval/rollout events; dispatcher wired into app` + trailer.

---

### Task 5: HTTP API

**Files:**
- Create: `internal/server/httpapi/notifications.go`
- Modify: `internal/server/httpapi/routes.go`
- Test: `internal/server/httpapi/notifications_test.go`

- [ ] **Step 1: Test**

```go
package httpapi_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

type channelJSON struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`
	Name       string   `json:"name"`
	Events     []string `json:"events"`
	Enabled    bool     `json:"enabled"`
	Recipients []string `json:"recipients"`
	URL        string   `json:"url"`
	HasSecret  bool     `json:"has_secret"`
}

func TestNotificationChannelsOverHTTP(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)

	var st struct {
		SMTPConfigured bool     `json:"smtp_configured"`
		EventKinds     []string `json:"event_kinds"`
	}
	if code := c.do("GET", "/api/notifications/status", nil, &st); code != 200 || st.SMTPConfigured || len(st.EventKinds) != 5 {
		t.Fatalf("status = %d %+v", code, st)
	}

	// Validation + smtp gate.
	if code := c.do("POST", "/api/notification-channels", map[string]any{"kind": "webhook", "name": "x", "events": []string{"alert.raised"}, "url": "ftp://nope"}, nil); code != 400 {
		t.Errorf("bad url = %d", code)
	}
	if code := c.do("POST", "/api/notification-channels", map[string]any{"kind": "email", "name": "mail", "events": []string{"alert.raised"}, "recipients": []string{"a@b.c"}}, nil); code != 400 {
		t.Errorf("email without smtp = %d, want 400", code)
	}

	hits := 0
	var gotSig string
	recv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		gotSig = r.Header.Get("X-FreeLocker-Signature")
		w.WriteHeader(200)
	}))
	defer recv.Close()

	var created idResp
	body := map[string]any{"kind": "webhook", "name": "Slack", "events": []string{"alert.raised", "approval.new"}, "url": recv.URL, "secret": "s3cret"}
	if code := c.do("POST", "/api/notification-channels", body, &created); code != 201 {
		t.Fatalf("create = %d", code)
	}
	if code := c.do("POST", "/api/notification-channels", body, nil); code != 409 {
		t.Errorf("dup name = %d", code)
	}
	var list []channelJSON
	c.do("GET", "/api/notification-channels", nil, &list)
	if len(list) != 1 || list[0].Name != "Slack" || !list[0].HasSecret || !list[0].Enabled || len(list[0].Events) != 2 || list[0].Recipients == nil {
		t.Fatalf("list = %+v", list)
	}

	// Test send: signed, hits the receiver, not recorded.
	var tr struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if code := c.do("POST", "/api/notification-channels/"+created.ID+"/test", nil, &tr); code != 200 || !tr.OK || hits != 1 || gotSig == "" {
		t.Fatalf("test = %d %+v hits=%d sig=%q", code, tr, hits, gotSig)
	}
	var dl []map[string]any
	c.do("GET", "/api/notification-deliveries", nil, &dl)
	if len(dl) != 0 {
		t.Errorf("test send recorded: %+v", dl)
	}

	// Patch: disable, keep secret with "", clear with null.
	if code := c.do("PATCH", "/api/notification-channels/"+created.ID, map[string]any{"enabled": false, "secret": ""}, nil); code != 204 {
		t.Errorf("patch = %d", code)
	}
	c.do("GET", "/api/notification-channels", nil, &list)
	if list[0].Enabled || !list[0].HasSecret {
		t.Errorf("after patch = %+v", list[0])
	}
	if code := c.do("PATCH", "/api/notification-channels/"+created.ID, map[string]any{"secret": nil}, nil); code != 204 {
		t.Errorf("clear secret = %d", code)
	}
	c.do("GET", "/api/notification-channels", nil, &list)
	if list[0].HasSecret {
		t.Errorf("secret not cleared: %+v", list[0])
	}
	// Test on a disabled channel still sends (admin is explicitly asking).
	c.do("POST", "/api/notification-channels/"+created.ID+"/test", nil, &tr)
	if !tr.OK || hits != 2 {
		t.Errorf("test disabled = %+v hits=%d", tr, hits)
	}
	// Failing receiver → ok:false with the error, status still 200.
	recv.Close()
	if code := c.do("POST", "/api/notification-channels/"+created.ID+"/test", nil, &tr); code != 200 || tr.OK || tr.Error == "" {
		t.Errorf("test failing = %d %+v", code, tr)
	}

	if code := c.do("DELETE", "/api/notification-channels/"+created.ID, nil, nil); code != 204 {
		t.Errorf("delete = %d", code)
	}
	c.do("GET", "/api/notification-channels", nil, &list)
	if len(list) != 0 {
		t.Errorf("after delete = %+v", list)
	}

	// Audit trail, no secret in detail.
	k := e.rt().Keys
	entries, _ := e.store.ListAudit(context.Background(), k.TenantID, 100, 0)
	seen := map[string]bool{}
	for _, en := range entries {
		seen[en.Action] = true
		if b, _ := json.Marshal(en.Detail); bytes.Contains(b, []byte("s3cret")) {
			t.Errorf("secret leaked into audit: %s", b)
		}
	}
	for _, a := range []string{"notification_channel.create", "notification_channel.update", "notification_channel.delete", "notification_channel.test"} {
		if !seen[a] {
			t.Errorf("missing audit %s", a)
		}
	}
}

func TestNotificationRbac(t *testing.T) {
	e := newEnv(t)
	owner := e.initialized(t)
	owner.do("POST", "/api/admins", map[string]string{"email": "ro@example.com", "password": "readonly-password-1", "role": "readonly"}, nil)
	ro := e.client(t)
	ro.loginFull("ro@example.com", "readonly-password-1", "")
	if code := ro.do("GET", "/api/notification-channels", nil, nil); code != 200 {
		t.Errorf("readonly list = %d", code)
	}
	if code := ro.do("POST", "/api/notification-channels", map[string]any{"kind": "webhook", "name": "x", "events": []string{"alert.raised"}, "url": "https://h"}, nil); code != 403 {
		t.Errorf("readonly create = %d", code)
	}
}
```

Add imports `bytes`, `context`, `encoding/json`.

- [ ] **Step 2: Run, expect 404s.**

- [ ] **Step 3: Implement `notifications.go`**

```go
package httpapi

import (
	"errors"
	"net/http"
	"time"

	"freelocker/internal/server/store"

	"github.com/google/uuid"
)

type channelJSON struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"`
	Name       string    `json:"name"`
	Events     []string  `json:"events"`
	Enabled    bool      `json:"enabled"`
	Recipients []string  `json:"recipients"`
	URL        string    `json:"url"`
	HasSecret  bool      `json:"has_secret"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func toChannelJSON(c store.NotificationChannel) channelJSON {
	return channelJSON{ID: c.ID.String(), Kind: c.Kind, Name: c.Name, Events: c.Events, Enabled: c.Enabled, Recipients: c.Recipients, URL: c.URL, HasSecret: len(c.Secret) > 0, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt}
}

func (a *API) notificationStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"smtp_configured": a.SMTPConfigured, "event_kinds": store.EventKinds})
}

func (a *API) listChannels(w http.ResponseWriter, r *http.Request) {
	list, err := a.Store.ListChannels(r.Context(), principalFrom(r).TenantID)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	out := make([]channelJSON, 0, len(list))
	for _, c := range list {
		out = append(out, toChannelJSON(c))
	}
	writeJSON(w, http.StatusOK, out)
}

type channelReq struct {
	Kind       *string   `json:"kind"`
	Name       *string   `json:"name"`
	Events     []string  `json:"events"`
	Enabled    *bool     `json:"enabled"`
	Recipients []string  `json:"recipients"`
	URL        *string   `json:"url"`
	Secret     *string   `json:"secret"`
	secretSet  bool
}

// channelErr maps validation, smtp-gate and store errors to responses.
func (a *API) channelErr(w http.ResponseWriter, err error) {
	var ve *store.ValidationError
	if errors.As(err, &ve) {
		writeErr(w, http.StatusBadRequest, ve.Msg)
		return
	}
	a.storeErr(w, err)
}

func (a *API) createChannel(w http.ResponseWriter, r *http.Request) {
	var req channelReq
	if !readJSON(w, r, &req) {
		return
	}
	p := principalFrom(r)
	c := store.NotificationChannel{ID: uuid.New(), Enabled: true, Events: req.Events, Recipients: req.Recipients}
	if req.Kind != nil {
		c.Kind = *req.Kind
	}
	if req.Name != nil {
		c.Name = *req.Name
	}
	if req.URL != nil {
		c.URL = *req.URL
	}
	if req.Enabled != nil {
		c.Enabled = *req.Enabled
	}
	if req.Secret != nil && *req.Secret != "" {
		c.Secret = a.NotifySealer.Seal([]byte(*req.Secret))
	}
	if err := store.ValidateChannel(c); err != nil {
		a.channelErr(w, err)
		return
	}
	if c.Kind == "email" && !a.SMTPConfigured {
		writeErr(w, http.StatusBadRequest, "smtp is not configured on this server")
		return
	}
	if err := a.Store.CreateChannel(r.Context(), p.TenantID, c); err != nil {
		a.channelErr(w, err)
		return
	}
	a.audit(r, p, "notification_channel.create", "notification_channel", c.ID.String(), map[string]any{"kind": c.Kind, "name": c.Name, "events": c.Events}, "success")
	writeJSON(w, http.StatusCreated, map[string]string{"id": c.ID.String()})
}

func (a *API) updateChannel(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	c, err := a.Store.GetChannel(r.Context(), p.TenantID, id)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	// Decode twice: once for values, once to learn whether "secret" was present
	// (null clears, "" keeps, non-empty replaces).
	var raw map[string]any
	if !readJSON(w, r, &raw) {
		return
	}
	if v, ok := raw["name"].(string); ok {
		c.Name = v
	}
	if v, ok := raw["url"].(string); ok {
		c.URL = v
	}
	if v, ok := raw["enabled"].(bool); ok {
		c.Enabled = v
	}
	if v, ok := raw["events"].([]any); ok {
		c.Events = toStrings(v)
	}
	if v, ok := raw["recipients"].([]any); ok {
		c.Recipients = toStrings(v)
	}
	if sv, present := raw["secret"]; present {
		switch s := sv.(type) {
		case nil:
			c.Secret = []byte{}
		case string:
			if s != "" {
				c.Secret = a.NotifySealer.Seal([]byte(s))
			}
		}
	}
	if err := store.ValidateChannel(c); err != nil {
		a.channelErr(w, err)
		return
	}
	if c.Kind == "email" && c.Enabled && !a.SMTPConfigured {
		writeErr(w, http.StatusBadRequest, "smtp is not configured on this server")
		return
	}
	if err := a.Store.UpdateChannel(r.Context(), p.TenantID, c); err != nil {
		a.channelErr(w, err)
		return
	}
	a.audit(r, p, "notification_channel.update", "notification_channel", id.String(), map[string]any{"name": c.Name, "enabled": c.Enabled, "events": c.Events}, "success")
	w.WriteHeader(http.StatusNoContent)
}

func toStrings(v []any) []string {
	out := make([]string, 0, len(v))
	for _, x := range v {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func (a *API) deleteChannel(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	if err := a.Store.DeleteChannel(r.Context(), p.TenantID, id); err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "notification_channel.delete", "notification_channel", id.String(), nil, "success")
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) testChannel(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	c, err := a.Store.GetChannel(r.Context(), p.TenantID, id)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	result := "success"
	out := map[string]any{"ok": true}
	if err := a.Runtime().Notify.Test(r.Context(), c); err != nil {
		result = "failure"
		out = map[string]any{"ok": false, "error": err.Error()}
	}
	a.audit(r, p, "notification_channel.test", "notification_channel", id.String(), map[string]any{"name": c.Name}, result)
	writeJSON(w, http.StatusOK, out)
}

func (a *API) listDeliveries(w http.ResponseWriter, r *http.Request) {
	list, err := a.Store.ListDeliveries(r.Context(), principalFrom(r).TenantID, queryInt(r, "limit", 50, 500))
	if err != nil {
		a.storeErr(w, err)
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, d := range list {
		var ev struct {
			Title string `json:"title"`
		}
		_ = json.Unmarshal(d.Payload, &ev)
		out = append(out, map[string]any{
			"id": d.ID, "channel_id": d.ChannelID.String(), "channel_name": d.ChannelName, "event_kind": d.EventKind, "title": ev.Title,
			"state": d.State, "attempts": d.Attempts, "last_error": d.LastError, "created_at": d.CreatedAt, "sent_at": d.SentAt, "next_attempt_at": d.NextAttemptAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}
```

(add `encoding/json` import; remove the unused `channelReq.secretSet` field — `createChannel` uses `channelReq`, `updateChannel` uses the raw map.)

Routes: read group gets `GET /api/notifications/status`, `GET /api/notification-channels`, `GET /api/notification-deliveries`; admin group gets `POST /api/notification-channels`, `PATCH`/`DELETE /api/notification-channels/{id}`, `POST /api/notification-channels/{id}/test`.

- [ ] **Step 4: Run** — `go test ./internal/server/httpapi/ -run TestNotification -v` then `go test ./...` → PASS.
- [ ] **Step 5: Commit** — `httpapi: notification channels CRUD, test send, deliveries listing` + trailer.

---

### Task 6: Console — Notifications page

**Files:**
- Modify: `web/src/api.ts`, `web/src/components/Layout.tsx` (NAV entry `{ to: "/notifications", label: "Notifications" }` after Alerts), `web/src/App.tsx` (route)
- Create: `web/src/pages/Notifications.tsx`
- Modify: `web/e2e/smoke.spec.ts`

- [ ] **Step 1: Types** (append to `api.ts`):

```ts
export type NotificationStatus = { smtp_configured: boolean; event_kinds: string[] };
export type NotificationChannel = {
  id: string;
  kind: "email" | "webhook";
  name: string;
  events: string[];
  enabled: boolean;
  recipients: string[];
  url: string;
  has_secret: boolean;
  created_at: string;
  updated_at: string;
};
export type NotificationDelivery = {
  id: number;
  channel_id: string;
  channel_name: string;
  event_kind: string;
  title: string;
  state: "pending" | "sent" | "failed";
  attempts: number;
  last_error: string;
  created_at: string;
  sent_at: string | null;
  next_attempt_at: string;
};
```

- [ ] **Step 2: Page** — create `web/src/pages/Notifications.tsx`:

```tsx
import { FormEvent, useCallback, useEffect, useState } from "react";
import { api, ApiError, NotificationChannel, NotificationDelivery, NotificationStatus } from "../api";
import { useToast } from "../components/Toast";
import { fmtDate } from "../components/util";

const EVENT_LABELS: Record<string, string> = {
  "alert.raised": "Alert raised",
  "alert.resolved": "Alert resolved",
  "approval.new": "New approval request",
  "rollout.auto_paused": "Rollout auto-paused",
  "rollout.completed": "Rollout completed",
};

export function Notifications() {
  const { notify } = useToast();
  const [status, setStatus] = useState<NotificationStatus | null>(null);
  const [channels, setChannels] = useState<NotificationChannel[] | null>(null);
  const [deliveries, setDeliveries] = useState<NotificationDelivery[]>([]);
  const [kind, setKind] = useState<"webhook" | "email">("webhook");
  const [name, setName] = useState("");
  const [recipients, setRecipients] = useState("");
  const [url, setUrl] = useState("");
  const [secret, setSecret] = useState("");
  const [events, setEvents] = useState<string[]>(["alert.raised", "approval.new", "rollout.auto_paused"]);
  const [busy, setBusy] = useState(false);
  const [testResult, setTestResult] = useState<Record<string, string>>({});

  const load = useCallback(() => {
    api.get<NotificationStatus>("/api/notifications/status").then(setStatus).catch(() => {});
    api.get<NotificationChannel[]>("/api/notification-channels").then(setChannels).catch(() => setChannels([]));
    api.get<NotificationDelivery[]>("/api/notification-deliveries?limit=50").then(setDeliveries).catch(() => {});
  }, []);
  useEffect(() => {
    load();
    const t = setInterval(() => api.get<NotificationDelivery[]>("/api/notification-deliveries?limit=50").then(setDeliveries).catch(() => {}), 15_000);
    return () => clearInterval(t);
  }, [load]);

  const toggleEvent = (k: string) => setEvents((cur) => (cur.includes(k) ? cur.filter((x) => x !== k) : [...cur, k]));

  const create = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      const body: Record<string, unknown> = { kind, name, events };
      if (kind === "webhook") {
        body.url = url;
        if (secret) body.secret = secret;
      } else {
        body.recipients = recipients.split(",").map((s) => s.trim()).filter(Boolean);
      }
      await api.post("/api/notification-channels", body);
      notify(`Added ${name}`);
      setName("");
      setUrl("");
      setSecret("");
      setRecipients("");
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not add channel", "error");
    } finally {
      setBusy(false);
    }
  };

  const setEnabled = async (c: NotificationChannel, enabled: boolean) => {
    try {
      await api.patch(`/api/notification-channels/${c.id}`, { enabled });
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not update channel", "error");
    }
  };

  const test = async (c: NotificationChannel) => {
    setTestResult((r) => ({ ...r, [c.id]: "Sending…" }));
    try {
      const res = await api.post<{ ok: boolean; error?: string }>(`/api/notification-channels/${c.id}/test`);
      setTestResult((r) => ({ ...r, [c.id]: res.ok ? "Delivered" : `Failed: ${res.error}` }));
    } catch (e) {
      setTestResult((r) => ({ ...r, [c.id]: e instanceof ApiError ? e.message : "Request failed" }));
    }
  };

  const del = async (c: NotificationChannel) => {
    try {
      await api.del(`/api/notification-channels/${c.id}`);
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not delete channel", "error");
    }
  };

  const smtp = status?.smtp_configured ?? false;

  return (
    <div>
      <div className="page-head">
        <h1>Notifications</h1>
      </div>
      <p className="who" style={{ marginTop: -6 }}>
        Email delivery: {status ? (smtp ? "configured" : "not configured on this server (set smtp in the server config)") : "…"}
      </p>

      <div className="panel" style={{ marginBottom: 20 }}>
        <h2>Add channel</h2>
        <form onSubmit={create}>
          <div className="toolbar" style={{ alignItems: "flex-end", flexWrap: "wrap" }}>
            <div>
              <label>Kind</label>
              <select aria-label="Channel kind" value={kind} onChange={(e) => setKind(e.target.value as "webhook" | "email")}>
                <option value="webhook">Webhook</option>
                <option value="email" disabled={!smtp}>
                  Email{smtp ? "" : " (SMTP not configured)"}
                </option>
              </select>
            </div>
            <div>
              <label>Name</label>
              <input aria-label="Channel name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Ops Slack" />
            </div>
            {kind === "webhook" ? (
              <>
                <div>
                  <label>URL</label>
                  <input aria-label="Webhook URL" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://hooks.example.com/…" />
                </div>
                <div>
                  <label>Signing secret (optional)</label>
                  <input aria-label="Webhook secret" type="password" value={secret} onChange={(e) => setSecret(e.target.value)} />
                </div>
              </>
            ) : (
              <div>
                <label>Recipients (comma-separated)</label>
                <input aria-label="Recipients" value={recipients} onChange={(e) => setRecipients(e.target.value)} placeholder="ops@example.com" />
              </div>
            )}
          </div>
          <div className="toolbar" style={{ flexWrap: "wrap", marginTop: 10 }}>
            {(status?.event_kinds ?? Object.keys(EVENT_LABELS)).map((k) => (
              <label key={k} style={{ display: "flex", gap: 6, alignItems: "center" }}>
                <input type="checkbox" aria-label={`Event ${k}`} checked={events.includes(k)} onChange={() => toggleEvent(k)} />
                {EVENT_LABELS[k] ?? k}
              </label>
            ))}
          </div>
          <button className="primary" style={{ marginTop: 10 }} disabled={busy || !name || events.length === 0 || (kind === "webhook" ? !url : !recipients)}>
            Add channel
          </button>
        </form>
      </div>

      <h2>Channels</h2>
      {!channels ? (
        <div className="spin">Loading…</div>
      ) : channels.length === 0 ? (
        <div className="empty">No channels yet.</div>
      ) : (
        <div className="table-wrap" style={{ marginBottom: 20 }}>
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Kind</th>
                <th>Target</th>
                <th>Events</th>
                <th>Enabled</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {channels.map((c) => (
                <tr key={c.id}>
                  <td>{c.name}</td>
                  <td>{c.kind}</td>
                  <td className="mono">{c.kind === "webhook" ? c.url + (c.has_secret ? " (signed)" : "") : c.recipients.join(", ")}</td>
                  <td>{c.events.map((k) => EVENT_LABELS[k] ?? k).join(", ")}</td>
                  <td>
                    <input type="checkbox" aria-label={`Channel ${c.name} enabled`} checked={c.enabled} onChange={(e) => setEnabled(c, e.target.checked)} />
                  </td>
                  <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                    <button onClick={() => test(c)} aria-label={`Test ${c.name}`}>
                      Test
                    </button>{" "}
                    <button onClick={() => del(c)} aria-label={`Delete ${c.name}`}>
                      Delete
                    </button>
                    {testResult[c.id] && (
                      <div className="who" aria-label={`Test result ${c.name}`}>
                        {testResult[c.id]}
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <h2>Recent deliveries</h2>
      {deliveries.length === 0 ? (
        <div className="empty">No deliveries yet.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Channel</th>
                <th>Event</th>
                <th>Title</th>
                <th>State</th>
                <th>Attempts</th>
                <th>Last error</th>
              </tr>
            </thead>
            <tbody>
              {deliveries.map((d) => (
                <tr key={d.id}>
                  <td>{fmtDate(d.created_at)}</td>
                  <td>{d.channel_name || "(deleted)"}</td>
                  <td>{EVENT_LABELS[d.event_kind] ?? d.event_kind}</td>
                  <td>{d.title}</td>
                  <td>
                    <span className={`badge ${d.state === "sent" ? "ok" : d.state === "failed" ? "fail" : ""}`}>{d.state}</span>
                  </td>
                  <td>{d.attempts}</td>
                  <td className="who">{d.last_error}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
```

Check the badge class names used elsewhere (`grep -rn 'className="badge' web/src | head`) and match them.

- [ ] **Step 3: Route + nav**, then `npm --prefix web run build` clean.

- [ ] **Step 4: E2E** — append to the smoke test before the closing `});`:

```ts
  // Notifications: email disabled without SMTP; add a webhook to a closed port, test shows failure, toggle, delete.
  await page.getByRole("link", { name: "Notifications" }).click();
  await expect(page.getByRole("heading", { name: "Notifications" })).toBeVisible();
  await expect(page.getByText("not configured on this server")).toBeVisible();
  await expect(page.getByLabel("Channel kind").locator("option", { hasText: "Email" })).toBeDisabled();
  await page.getByLabel("Channel name").fill("Dead hook");
  await page.getByLabel("Webhook URL").fill("http://127.0.0.1:9/");
  await page.getByRole("button", { name: "Add channel" }).click();
  await expect(page.getByRole("cell", { name: "Dead hook", exact: true })).toBeVisible();
  await page.getByLabel("Test Dead hook").click();
  await expect(page.getByLabel("Test result Dead hook")).toContainText("Failed", { timeout: 20_000 });
  await page.getByLabel("Channel Dead hook enabled").uncheck();
  await expect(page.getByLabel("Channel Dead hook enabled")).not.toBeChecked();
  await page.getByLabel("Delete Dead hook").click();
  await expect(page.getByText("No channels yet.")).toBeVisible();
```

Run the E2E loop (fresh `freelocker_e2e` DB, rebuild console, start server, `npm run test:e2e`, stop server).

- [ ] **Step 5: Commit** — `console: Notifications page — channels, test send, deliveries` + trailer.

---

### Task 7: Docs and verification

- [ ] README capability line: add `email + webhook notifications`. `deploy/server.example.yaml`: add the commented `smtp:` block from the spec with the env names. `docs/agent-manual-test.md`: add a short "Notifications" section (create a webhook to a request-bin URL, trigger a CPU alert rule at 1%, confirm the signed POST arrives; resume a rollout drill and watch the auto-pause email/webhook).
- [ ] `go build ./... && go test ./... && npm --prefix web run build` green.
- [ ] Commit `docs: notifications — README, smtp config sample, manual test` + trailer. Merge and push are the controller's job after the final review.

---

## Self-review notes

- **Spec coverage:** events + new-detection (T4), channels table/validation/sealing (T1, T5 seals), outbox/claim/backoff/lease (T2, T3), webhook headers/signature/no-redirect (T3), SMTP config + mailer + fake server test (T1, T3), Test send (T3, T5), producers + Nop + wiring + ticker fallback + Run goroutine (T4), API table + audit + secret redaction (T5), console + e2e (T6), docs (T7).
- **Deviations to flag:** `ClaimDeliveries` is cross-tenant by design (the dispatcher is deployment-wide), so `Delivery` carries `TenantID`. `UpdateChannel` is a full replace; the handler merges the PATCH into the loaded row. Test send on a disabled channel still sends (explicit admin action).
- **Type consistency:** `notify.Event` field names match the JSON the console reads (`title` via payload in deliveries listing). `ValidationError` → 400 in one helper. `SMTP.Configured()` used by both `config.Config.SMTPConfigured` and `notify.send`.
