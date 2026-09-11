-- +goose Up
CREATE TABLE agent_releases (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    version text NOT NULL,
    sha256 bytea NOT NULL,
    signature bytea NOT NULL,
    uploaded_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, version)
);

-- +goose Down
DROP TABLE agent_releases;
