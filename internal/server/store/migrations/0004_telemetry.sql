-- +goose Up
CREATE TABLE device_metrics (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    at timestamptz NOT NULL DEFAULT now(),
    cpu_pct real NOT NULL,
    mem_pct real NOT NULL,
    disk_pct real NOT NULL
);
CREATE INDEX device_metrics_device_at ON device_metrics (device_id, at DESC);

CREATE TABLE alert_rules (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    name text NOT NULL,
    metric text NOT NULL CHECK (metric IN ('cpu', 'mem', 'disk')),
    op text NOT NULL CHECK (op IN ('gt', 'lt')),
    threshold real NOT NULL,
    duration_seconds int NOT NULL DEFAULT 0,
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE alerts (
    id bigserial PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    rule_id uuid NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    metric text NOT NULL,
    message text NOT NULL,
    at timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz
);
-- At most one open (unresolved) alert per device+rule.
CREATE UNIQUE INDEX alerts_one_open ON alerts (device_id, rule_id) WHERE resolved_at IS NULL;

-- +goose Down
DROP TABLE alerts, alert_rules, device_metrics;
