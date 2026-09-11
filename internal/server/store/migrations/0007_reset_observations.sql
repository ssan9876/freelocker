-- +goose Up
-- Agents before 0.2.0 reported observations with a plain file SHA-256,
-- which WDAC hash rules never match (they use the Authenticode hash).
-- Nothing records which hash an observation used, so clear them all once;
-- agents 0.2.0+ repopulate them with Authenticode hashes on their next scans.
DELETE FROM observations;

-- +goose Down
-- Deleted observations cannot be restored; nothing to undo.
SELECT 1;
