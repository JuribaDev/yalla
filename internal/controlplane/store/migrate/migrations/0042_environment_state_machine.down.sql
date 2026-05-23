DROP TRIGGER IF EXISTS environment_events_no_update ON environment_events;
DROP FUNCTION IF EXISTS environment_events_reject_update();
DROP INDEX IF EXISTS environment_events_org_occurred_idx;
DROP INDEX IF EXISTS environment_events_environment_occurred_idx;
DROP TABLE IF EXISTS environment_events;

ALTER TABLE environments
    DROP COLUMN IF EXISTS status;
