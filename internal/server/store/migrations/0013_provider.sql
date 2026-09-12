-- +goose Up
-- MSP Phase 3: a provider is an admin allowed to create and list tenants
-- (the MSP operator). The first owner created at setup is the provider.
ALTER TABLE admins ADD COLUMN provider boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE admins DROP COLUMN provider;
