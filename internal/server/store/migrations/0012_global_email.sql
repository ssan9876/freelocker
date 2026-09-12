-- +goose Up
-- MSP Phase 2: admin email becomes globally unique so login can resolve the
-- tenant from the email alone (no tenant hint in the login form). The existing
-- per-tenant UNIQUE (tenant_id, email) is subsumed by this stricter constraint
-- but kept, since it is harmless and documents intent.
CREATE UNIQUE INDEX admins_email_global ON admins (email);

-- +goose Down
DROP INDEX admins_email_global;
