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
