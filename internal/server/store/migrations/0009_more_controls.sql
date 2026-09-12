-- +goose Up
ALTER TABLE device_controls ADD COLUMN network_blocked boolean NOT NULL DEFAULT false;
ALTER TABLE device_controls ADD COLUMN elevation_blocked boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE device_controls DROP COLUMN elevation_blocked;
ALTER TABLE device_controls DROP COLUMN network_blocked;
