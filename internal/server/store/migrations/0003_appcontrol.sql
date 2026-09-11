-- +goose Up
CREATE TABLE policies (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    name text NOT NULL,
    mode text NOT NULL DEFAULT 'audit' CHECK (mode IN ('audit', 'enforce')),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE TABLE policy_rules (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    policy_id uuid NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('hash', 'publisher', 'path')),
    value text NOT NULL,
    publisher_name text NOT NULL DEFAULT '',
    description text NOT NULL DEFAULT '',
    added_by uuid REFERENCES admins(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (policy_id, kind, value)
);

CREATE TABLE policy_versions (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    policy_id uuid NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    version text NOT NULL,
    mode text NOT NULL,
    xml bytea NOT NULL,
    signature bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (policy_id, version)
);

CREATE TABLE policy_assignments (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    group_id uuid NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
    policy_id uuid NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id)
);

CREATE TABLE observations (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    sha256 text NOT NULL,
    path text NOT NULL,
    signer text NOT NULL DEFAULT '',
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen timestamptz NOT NULL DEFAULT now(),
    count bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (device_id, sha256, path)
);

CREATE TABLE block_events (
    id bigserial PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    sha256 text NOT NULL DEFAULT '',
    path text NOT NULL DEFAULT '',
    signer text NOT NULL DEFAULT '',
    blocked boolean NOT NULL DEFAULT false,
    at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX block_events_tenant_at ON block_events (tenant_id, at DESC);

ALTER TABLE devices ADD COLUMN policy_version text NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE devices DROP COLUMN policy_version;
DROP TABLE block_events, observations, policy_assignments, policy_versions, policy_rules, policies;
