-- +goose Up
-- Mark-of-the-Web provenance for observed binaries: was this fetched from
-- outside the machine, and where from.
--
-- Nullable rather than defaulted to false, because "no agent has reported
-- provenance for this binary yet" and "the agent looked and found no mark"
-- are different facts. An older agent reports neither, and showing those as
-- "not downloaded" would be an assertion nothing made.
ALTER TABLE observations
    ADD COLUMN downloaded boolean,
    ADD COLUMN download_source text NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE observations
    DROP COLUMN downloaded,
    DROP COLUMN download_source;
