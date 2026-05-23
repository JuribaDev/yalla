DROP TRIGGER IF EXISTS deployment_events_no_update ON deployment_events;
DROP FUNCTION IF EXISTS deployment_events_reject_update();
DROP INDEX IF EXISTS deployment_events_org_occurred_idx;
DROP INDEX IF EXISTS deployment_events_deployment_occurred_idx;
DROP TABLE IF EXISTS deployment_events;
