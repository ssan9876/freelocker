# Alert notifications (email + webhook) — design

**Status:** approved 2026-09-14.

## Goal

Get important events out of the console and into the places admins already
watch: email inboxes and webhook receivers (Slack, Teams, PagerDuty, a SIEM).
Today alert breaches, pending approvals, and rollout auto-pauses are visible
only when someone opens the console.

## Events

| Kind | Emitted when | Detail fields |
|---|---|---|
| `alert.raised` | `store.RaiseAlert` inserts a new open alert | `device_id, hostname, rule_id, rule_name, metric, message` |
| `alert.resolved` | `store.ResolveAlert` closes an open alert (rows affected = 1) | same |
| `approval.new` | `store.UpsertApprovalRequests` inserts a brand-new request (not an update) | `request_id, policy_id, policy_name, sha256, path, signer, device_id, hostname` |
| `rollout.auto_paused` | reconciler pauses on failures | `rollout_id, version, failed, max_failures` |
| `rollout.completed` | reconciler completes a rollout | `rollout_id, version, updated, failed` |

Every event carries `kind`, `tenant_id`, `title` (one line), `body` (plain
text, a few lines), `detail` (the map above), and `at`.

**Detecting "new"**:
- `ResolveAlert` changes to return `(bool, error)` from `RowsAffected`.
- `UpsertApprovalRequests` changes to return `([]uuid.UUID, error)`: the ids
  of requests that were *inserted* this call, using `RETURNING id, (xmax = 0)
  AS inserted`. Updates to an existing request emit nothing, so a noisy
  binary does not spam.

## Channels

Migration `0018_notifications.sql`:

```sql
CREATE TABLE notification_channels (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    kind       text NOT NULL CHECK (kind IN ('email', 'webhook')),
    name       text NOT NULL,
    events     text[] NOT NULL DEFAULT '{}',   -- subscribed event kinds
    enabled    boolean NOT NULL DEFAULT true,
    recipients text[] NOT NULL DEFAULT '{}',   -- email: To addresses
    url        text NOT NULL DEFAULT '',       -- webhook
    secret     text NOT NULL DEFAULT '',       -- webhook HMAC key; never returned by the API
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE TABLE notification_deliveries (
    id              bigserial PRIMARY KEY,
    tenant_id       uuid NOT NULL REFERENCES tenants(id),
    channel_id      uuid NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
    event_kind      text NOT NULL,
    payload         jsonb NOT NULL,            -- the full event
    state           text NOT NULL CHECK (state IN ('pending', 'sent', 'failed')),
    attempts        int  NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL,
    last_error      text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    sent_at         timestamptz
);
CREATE INDEX notification_deliveries_due ON notification_deliveries (next_attempt_at) WHERE state = 'pending';
CREATE INDEX notification_deliveries_tenant ON notification_deliveries (tenant_id, id DESC);
```

Validation (store + API): `name` non-empty; `events` non-empty, each a
known kind; email needs ≥ 1 recipient containing `@`; webhook needs an
`http`/`https` URL. The webhook `secret` is optional; when empty, no
signature header is sent.

The secret is stored in plaintext in Postgres, like the Ed25519 keys the
server already keeps there (sealed with the master secret). To stay
consistent with those, the secret is sealed with `keys.Sealer(master,
"notify")` at rest and unsealed at send time.

## SMTP configuration (deployment-level)

```yaml
smtp:
  host: smtp.example.com
  port: 587
  username: freelocker
  password: ""            # prefer FREELOCKER_SMTP_PASSWORD
  from: "FreeLocker <alerts@example.com>"
  starttls: true          # false = plain (port 25 relays) ; implicit TLS when port == 465
```

Env: `FREELOCKER_SMTP_HOST`, `_PORT`, `_USERNAME`, `_PASSWORD`, `_FROM`,
`_STARTTLS` (`true`/`false`). `Config.SMTPConfigured()` is `Host != "" &&
From != ""`. Creating or enabling an email channel while SMTP is not
configured returns 400 `smtp is not configured on this server`. Existing
email channels on a server that later loses SMTP config fail delivery with
that message.

## Delivery — package `internal/server/notify`

```go
type Event struct {
    Kind     string            `json:"kind"`
    TenantID uuid.UUID         `json:"tenant_id"`
    Title    string            `json:"title"`
    Body     string            `json:"body"`
    Detail   map[string]any    `json:"detail"`
    At       time.Time         `json:"at"`
}

// Emitter is what producers depend on; nil-safe wrappers let alerting,
// rollout and agentapi keep working with no notifier configured.
type Emitter interface{ Emit(ctx context.Context, e Event) }

type Service struct {
    Store   *store.Store
    Sealer  *keys.Sealer
    SMTP    config.SMTP
    Mailer  Mailer          // default: smtpMailer; tests inject a fake
    Client  *http.Client    // default: 10 s timeout
    Now     func() time.Time
    Log     *slog.Logger
    wake    chan struct{}   // 1-slot, non-blocking
}
func (s *Service) Emit(ctx context.Context, e Event)                 // enqueue + wake
func (s *Service) Run(ctx context.Context)                            // dispatcher loop
func (s *Service) Dispatch(ctx context.Context) (sent, failed int, err error) // one pass
func (s *Service) Test(ctx context.Context, ch store.NotificationChannel) error // synchronous send of a test event
```

**Emit**: loads enabled channels of the tenant subscribed to `e.Kind`
(`store.ChannelsForEvent`), inserts one `pending` delivery per channel with
`next_attempt_at = now`, then does a non-blocking send on `wake`. Errors are
logged, never returned to the producer.

**Run**: loops until ctx is done; on `wake` or every 30 s, calls
`Dispatch` until it makes no progress. Started as a goroutine in
`app.activate`; the minute ticker also calls `Dispatch` as a belt-and-braces
path so a wake lost across instances still drains.

**Dispatch**: `store.ClaimDeliveries(ctx, now, limit 50)` runs
`SELECT … WHERE state='pending' AND next_attempt_at <= now ORDER BY id FOR
UPDATE SKIP LOCKED` in a transaction and bumps `attempts` + sets
`next_attempt_at = now + 2 min` (a lease, so a crashed instance's rows come
back). For each claimed row: load the channel, send, then
`store.FinishDelivery(id, ok, errMsg, nextAttempt)`. Backoff by attempt:
1 min, 5 min, 30 min; after attempt 5 the row becomes `failed`. Channel
deleted or disabled between enqueue and send → `failed` with that reason.

**Webhook**: `POST url`, `Content-Type: application/json`, body = the
event JSON, headers `X-FreeLocker-Event: <kind>`, `X-FreeLocker-Delivery:
<id>`, and when a secret is set `X-FreeLocker-Signature: sha256=<hex
HMAC-SHA256(secret, body)>`. 2xx = sent; anything else (or a transport
error) = retry with the status/err text as `last_error`. Redirects are not
followed (so a signed body cannot be replayed to another host).

**Email**: one message per delivery to all recipients; subject
`[FreeLocker] <title>`, plain-text body = `body` plus a `detail` block.
`smtpMailer` uses `net/smtp`: implicit TLS when port 465, STARTTLS when
`starttls`, PLAIN auth when a username is set. `Mailer` is an interface so
tests use an in-memory fake; one integration-style test runs a minimal
in-process SMTP server (a small handler speaking `EHLO/MAIL/RCPT/DATA/QUIT`)
to check the real client's wire behaviour without STARTTLS.

**Test send**: `Test` builds a `notify.test` event ("Test notification from
FreeLocker") and sends it synchronously through the same webhook/email code,
returning the error, so the API can show the admin a bad URL, a 401 from the
receiver, or an SMTP auth failure right away. Test sends are not recorded as
deliveries.

## Producers

- `alerting.Service` gains `Notify notify.Emitter` (nil = no-op). After
  `RaiseAlert` returns true → emit `alert.raised`; after `ResolveAlert`
  returns true → emit `alert.resolved`. Hostname and rule name come from
  the rule list already loaded and one `GetDevice`.
- `rollout.Service` gains `Notify notify.Emitter`; emits at the auto-pause
  and completion transitions.
- `agentapi.Deps` gains `Notify notify.Emitter`; `queueApprovals` emits
  `approval.new` for each id returned by `UpsertApprovalRequests`, reading
  the request via `GetApprovalRequest` for policy name and path.

`notify.Nop{}` implements `Emitter` for tests and for `helpers_test.go`.

## HTTP API (admin role; reads any role)

| Method | Path | Body / result |
|---|---|---|
| `GET` | `/api/notifications/status` | `{smtp_configured: bool, event_kinds: [...]}` |
| `GET` | `/api/notification-channels` | `[channel]` (no secret; `has_secret: bool`) |
| `POST` | `/api/notification-channels` | `{kind, name, events, recipients?, url?, secret?}` → 201 `{id}`; 400 validation; 409 duplicate name |
| `PATCH` | `/api/notification-channels/{id}` | any of `{name, events, enabled, recipients, url, secret}`; empty `secret` string keeps the existing one, `null` clears it |
| `DELETE` | `/api/notification-channels/{id}` | 204; cascades deliveries |
| `POST` | `/api/notification-channels/{id}/test` | 200 `{ok: true}` or 200 `{ok: false, error}` (the send failing is a result, not an API error) |
| `GET` | `/api/notification-deliveries?limit=` | recent deliveries newest first: `id, channel_id, channel_name, event_kind, title, state, attempts, last_error, created_at, sent_at, next_attempt_at` |

Audit: `notification_channel.create|update|delete|test` (target type
`notification_channel`). The secret never appears in audit detail.

## Console — `web/src/pages/Notifications.tsx`, nav "Notifications"

- **Status line**: "Email delivery: configured / not configured on this
  server" from `/status`. Email option in the form is disabled when not
  configured, with that reason.
- **Add channel** form: kind (email | webhook), name, recipients (comma-
  separated) or URL + secret, event checkboxes (all five, labelled in plain
  words: "Alert raised", "Alert resolved", "New approval request", "Rollout
  auto-paused", "Rollout completed"). `aria-label`s: `Channel kind`,
  `Channel name`, `Recipients`, `Webhook URL`, `Webhook secret`, `Event
  <kind>` per checkbox, button `Add channel`.
- **Channels table**: name, kind, target (recipients or URL), events,
  enabled toggle (`aria-label="Channel <name> enabled"`), Test button
  (`Test <name>`) showing the result inline, Delete (`Delete <name>`).
- **Recent deliveries** table (last 50, polled every 15 s while the page is
  open): time, channel, event, state badge, attempts, last error.

## Error handling

- Producers never fail because of notifications: `Emit` logs and returns.
- Dispatch errors on one delivery are recorded on that row; a claim error
  aborts the pass and is retried on the next wake.
- Secrets: never logged, never returned, never audited; `last_error` is
  trimmed to 500 chars and comes from status codes / `err.Error()`, which
  for `net/http` never includes request headers.
- Suspended tenants: `ChannelsForEvent` joins `tenants` and returns nothing
  for suspended ones, so nothing is enqueued.

## Testing

- `store/notifications_test.go`: channel CRUD + validation + secret sealing
  round-trip; `ChannelsForEvent` filters by kind/enabled/suspended;
  `ClaimDeliveries` claims only due rows, leases them, and two concurrent
  claims never return the same row; `FinishDelivery` state/backoff.
- `notify/notify_test.go`: webhook against `httptest.NewServer` — headers,
  HMAC verifies, 2xx sent, 500 → retry with backoff, 5th failure → failed;
  redirect not followed; email via fake `Mailer` — recipients, subject,
  body; disabled/deleted channel → failed; `Test` returns the receiver's
  error; `Emit` on a tenant with no subscribed channels inserts nothing.
- `notify/smtp_test.go`: real `smtpMailer` against an in-process minimal
  SMTP server (plain, no TLS) asserting MAIL FROM / RCPT TO / DATA.
- `alerting_test.go`: raise emits once, repeat sample emits nothing,
  resolve emits once. `store/approvals_test.go`: first upsert returns the
  id, second returns nothing. `rollout_test.go`: auto-pause and completion
  emit.
- `httpapi/notifications_test.go`: lifecycle, validation codes, secret
  redaction (`has_secret`), test endpoint against an httptest receiver,
  deliveries listing, RBAC (readonly can list, cannot create).
- Playwright: Notifications page — add a webhook channel pointing at
  `http://127.0.0.1:9/` (closed port), Test shows a failure message, toggle
  enabled, delete; email option disabled when SMTP is not configured.
