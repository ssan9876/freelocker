-- +goose Up
CREATE TABLE device_controls (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    group_id uuid NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
    usb_storage_blocked boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id)
);

-- +goose Down
DROP TABLE device_controls;
