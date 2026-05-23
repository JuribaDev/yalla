DROP TRIGGER IF EXISTS service_events_no_update ON service_events;
DROP FUNCTION IF EXISTS service_events_reject_update();
DROP INDEX IF EXISTS service_events_org_occurred_idx;
DROP INDEX IF EXISTS service_events_service_occurred_idx;
DROP TABLE IF EXISTS service_events;

ALTER TABLE services
    DROP COLUMN IF EXISTS status;
