-- +goose Up
CREATE TABLE device_events (
    id bigserial PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    kind text NOT NULL,
    summary text NOT NULL DEFAULT '',
    at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX device_events_tenant_at ON device_events (tenant_id, at DESC);

-- +goose Down
DROP TABLE device_events;
