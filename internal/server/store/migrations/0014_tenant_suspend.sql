-- +goose Up
-- A provider can suspend a tenant: its admins cannot log in, its agents'
-- RPCs are refused, and its install tokens stop enrolling. Reversible.
ALTER TABLE tenants ADD COLUMN suspended boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE tenants DROP COLUMN suspended;
