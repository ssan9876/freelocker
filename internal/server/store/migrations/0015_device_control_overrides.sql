-- +goose Up
-- Per-device control overrides. Each column is tri-state: NULL = inherit
-- the group's value, true = block, false = allow. A row with all three NULL
-- is never stored.
CREATE TABLE device_control_overrides (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    device_id uuid PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    usb_storage_blocked boolean,
    network_blocked boolean,
    elevation_blocked boolean,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE device_control_overrides;
