-- +goose Up
CREATE TABLE ringfence_policies (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    name text NOT NULL,
    mode text NOT NULL DEFAULT 'audit' CHECK (mode IN ('audit', 'enforce')),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE TABLE ringfence_programs (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    ringfence_id uuid NOT NULL REFERENCES ringfence_policies(id) ON DELETE CASCADE,
    path text NOT NULL,
    network_blocked boolean NOT NULL DEFAULT true,
    note text NOT NULL DEFAULT '',
    UNIQUE (ringfence_id, path)
);

CREATE TABLE ringfence_protections (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    ringfence_id uuid NOT NULL REFERENCES ringfence_policies(id) ON DELETE CASCADE,
    asr_rule text NOT NULL,
    action text NOT NULL CHECK (action IN ('audit', 'block')),
    PRIMARY KEY (ringfence_id, asr_rule)
);

CREATE TABLE ringfence_assignments (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    group_id uuid PRIMARY KEY REFERENCES device_groups(id) ON DELETE CASCADE,
    ringfence_id uuid NOT NULL REFERENCES ringfence_policies(id) ON DELETE CASCADE
);

CREATE TABLE ringfence_events (
    id bigserial PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('network', 'child_process')),
    program text NOT NULL DEFAULT '',
    detail text NOT NULL DEFAULT '',
    enforced boolean NOT NULL DEFAULT false,
    at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ringfence_events_tenant_at ON ringfence_events (tenant_id, at DESC);

-- +goose Down
DROP TABLE ringfence_events, ringfence_assignments, ringfence_protections, ringfence_programs, ringfence_policies;
