DROP TRIGGER IF EXISTS provisioning_job_events_no_update ON provisioning_job_events;
DROP FUNCTION IF EXISTS provisioning_job_events_reject_update();
DROP INDEX IF EXISTS provisioning_job_events_org_occurred_idx;
DROP INDEX IF EXISTS provisioning_job_events_job_occurred_idx;
DROP TABLE IF EXISTS provisioning_job_events;
