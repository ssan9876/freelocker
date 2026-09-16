-- +goose Up
-- Nullable so "never reported" is distinguishable from "reported false": an
-- agent that has never run a ringfence has not told us anything about
-- Defender/ASR availability, and defaulting it to false or true would be
-- dishonest either way.
ALTER TABLE devices ADD COLUMN asr_available boolean;

-- +goose Down
ALTER TABLE devices DROP COLUMN asr_available;
