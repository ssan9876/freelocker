-- +goose Up
CREATE TABLE tenants (
    id uuid PRIMARY KEY,
    name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE server_keys (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    name text NOT NULL,
    public_der bytea NOT NULL,
    private_enc bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, name)
);

CREATE TABLE admins (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    email text NOT NULL,
    password_hash text NOT NULL,
    totp_secret_enc bytea,
    totp_confirmed boolean NOT NULL DEFAULT false,
    role text NOT NULL CHECK (role IN ('owner', 'admin', 'readonly')),
    disabled boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, email)
);

CREATE TABLE sessions (
    id text PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    admin_id uuid NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    csrf_token text NOT NULL,
    mfa_passed boolean NOT NULL DEFAULT false,
    expires_at timestamptz NOT NULL,
    ip text NOT NULL,
    user_agent text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE device_groups (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    name text NOT NULL,
    UNIQUE (tenant_id, name)
);

CREATE TABLE install_tokens (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    token_hash bytea NOT NULL UNIQUE,
    name text NOT NULL,
    group_id uuid REFERENCES device_groups(id),
    expires_at timestamptz,
    max_uses int,
    uses int NOT NULL DEFAULT 0,
    revoked boolean NOT NULL DEFAULT false,
    created_by uuid REFERENCES admins(id),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE devices (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    hostname text NOT NULL,
    machine_guid text NOT NULL DEFAULT '',
    group_id uuid REFERENCES device_groups(id),
    cert_serial text NOT NULL,
    cert_expires_at timestamptz NOT NULL,
    os_build text NOT NULL DEFAULT '',
    agent_version text NOT NULL DEFAULT '',
    ips text[] NOT NULL DEFAULT '{}',
    logged_on_user text NOT NULL DEFAULT '',
    uptime_seconds bigint NOT NULL DEFAULT 0,
    last_seen_at timestamptz,
    clean_shutdown boolean NOT NULL DEFAULT false,
    revoked boolean NOT NULL DEFAULT false,
    enrolled_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE commands (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    type text NOT NULL,
    payload bytea NOT NULL DEFAULT '',
    issued_by uuid REFERENCES admins(id),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    state text NOT NULL CHECK (state IN ('pending', 'sent', 'succeeded', 'failed', 'expired')),
    result text NOT NULL DEFAULT '',
    completed_at timestamptz
);
CREATE INDEX commands_open ON commands (device_id) WHERE state IN ('pending', 'sent');

CREATE TABLE audit_log (
    id bigserial PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    actor text NOT NULL,
    action text NOT NULL,
    target_type text NOT NULL DEFAULT '',
    target_id text NOT NULL DEFAULT '',
    detail_json jsonb NOT NULL DEFAULT '{}',
    ip text NOT NULL DEFAULT '',
    result text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- +goose StatementBegin
CREATE FUNCTION audit_log_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER audit_log_no_modify BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();

-- +goose Down
DROP TRIGGER audit_log_no_modify ON audit_log;
DROP FUNCTION audit_log_immutable();
DROP TABLE audit_log, commands, devices, install_tokens, device_groups, sessions, admins, server_keys, tenants;
