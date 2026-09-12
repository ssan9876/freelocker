-- +goose Up
-- Publisher identity: the signing certificate's TBS hash (what WDAC matches)
-- and whether Windows verified the signature. Existing rows keep empty/false
-- and so offer no publisher rule.
ALTER TABLE observations
    ADD COLUMN signer_tbs text NOT NULL DEFAULT '',
    ADD COLUMN signer_verified boolean NOT NULL DEFAULT false;
ALTER TABLE block_events
    ADD COLUMN signer_tbs text NOT NULL DEFAULT '',
    ADD COLUMN signer_verified boolean NOT NULL DEFAULT false;
ALTER TABLE approval_requests
    ADD COLUMN signer_tbs text NOT NULL DEFAULT '',
    ADD COLUMN signer_verified boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE approval_requests DROP COLUMN signer_verified, DROP COLUMN signer_tbs;
ALTER TABLE block_events DROP COLUMN signer_verified, DROP COLUMN signer_tbs;
ALTER TABLE observations DROP COLUMN signer_verified, DROP COLUMN signer_tbs;
