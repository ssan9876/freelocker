-- +goose Up
-- Staged agent update rollouts: one open (active|paused) rollout per tenant,
-- per-device progress rows resolved from command results + reported version.
CREATE TABLE agent_rollouts (
    id            uuid PRIMARY KEY,
    tenant_id     uuid NOT NULL REFERENCES tenants(id),
    version       text NOT NULL,
    group_ids     uuid[] NOT NULL DEFAULT '{}',
    batch_size    int  NOT NULL,
    max_failures  int  NOT NULL,
    state         text NOT NULL,
    created_by    text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    finished_at   timestamptz,
    CONSTRAINT agent_rollouts_state_chk CHECK (state IN ('active', 'paused', 'completed', 'cancelled'))
);
CREATE UNIQUE INDEX agent_rollouts_one_open ON agent_rollouts (tenant_id) WHERE state IN ('active', 'paused');
CREATE INDEX agent_rollouts_tenant_created ON agent_rollouts (tenant_id, created_at DESC);

CREATE TABLE agent_rollout_devices (
    rollout_id   uuid NOT NULL REFERENCES agent_rollouts(id) ON DELETE CASCADE,
    device_id    uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    command_id   uuid NOT NULL,
    state        text NOT NULL,
    detail       text NOT NULL DEFAULT '',
    issued_at    timestamptz NOT NULL,
    resolved_at  timestamptz,
    PRIMARY KEY (rollout_id, device_id),
    CONSTRAINT agent_rollout_devices_state_chk CHECK (state IN ('issued', 'updated', 'failed'))
);

-- +goose Down
DROP TABLE agent_rollout_devices;
DROP TABLE agent_rollouts;
