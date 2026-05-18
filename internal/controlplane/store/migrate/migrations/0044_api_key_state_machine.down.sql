DROP TRIGGER IF EXISTS api_key_events_no_update ON api_key_events;
DROP FUNCTION IF EXISTS api_key_events_reject_update();

DROP INDEX IF EXISTS api_key_events_org_occurred_idx;
DROP INDEX IF EXISTS api_key_events_key_occurred_idx;
DROP TABLE IF EXISTS api_key_events;

ALTER TABLE api_keys
    DROP COLUMN IF EXISTS status;
