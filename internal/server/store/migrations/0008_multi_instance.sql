-- +goose Up
-- Login failures, shared across server instances so the rate limit holds
-- fleet-wide rather than per process.
CREATE TABLE login_failures (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    key text NOT NULL,
    at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX login_failures_key_at ON login_failures (tenant_id, key, at DESC);

-- Alert breach onset, shared so a sustained-duration rule is evaluated
-- consistently no matter which instance receives the metric sample.
CREATE TABLE alert_breaches (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    rule_id uuid NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    since timestamptz NOT NULL,
    PRIMARY KEY (device_id, rule_id)
);

-- +goose Down
DROP TABLE alert_breaches, login_failures;
