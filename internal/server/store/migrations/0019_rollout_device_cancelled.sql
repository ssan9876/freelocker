-- +goose Up
-- A device revoked mid-rollout leaves the rollout: its progress row is
-- resolved as 'cancelled' rather than left issued (which would block
-- completion) or marked failed (which would count toward max_failures).
ALTER TABLE agent_rollout_devices DROP CONSTRAINT agent_rollout_devices_state_chk;
ALTER TABLE agent_rollout_devices ADD CONSTRAINT agent_rollout_devices_state_chk
    CHECK (state IN ('issued', 'updated', 'failed', 'cancelled'));

-- +goose Down
ALTER TABLE agent_rollout_devices DROP CONSTRAINT agent_rollout_devices_state_chk;
UPDATE agent_rollout_devices SET state = 'failed', detail = 'device revoked' WHERE state = 'cancelled';
ALTER TABLE agent_rollout_devices ADD CONSTRAINT agent_rollout_devices_state_chk
    CHECK (state IN ('issued', 'updated', 'failed'));
