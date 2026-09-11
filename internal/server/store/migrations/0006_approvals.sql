-- +goose Up
CREATE TABLE approval_requests (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    policy_id uuid NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    sha256 text NOT NULL,
    path text NOT NULL DEFAULT '',
    signer text NOT NULL DEFAULT '',
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied')),
    device_count int NOT NULL DEFAULT 0,
    event_count bigint NOT NULL DEFAULT 0,
    first_seen timestamptz NOT NULL,
    last_seen timestamptz NOT NULL,
    decided_by uuid REFERENCES admins(id),
    decided_at timestamptz,
    UNIQUE (policy_id, sha256)
);
CREATE INDEX approval_requests_tenant_status ON approval_requests (tenant_id, status, last_seen DESC);

CREATE TABLE approval_request_devices (
    request_id uuid NOT NULL REFERENCES approval_requests(id) ON DELETE CASCADE,
    device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    PRIMARY KEY (request_id, device_id)
);

-- +goose Down
DROP TABLE approval_request_devices, approval_requests;
