DROP TRIGGER IF EXISTS drift_finding_events_no_update ON drift_finding_events;
DROP FUNCTION IF EXISTS drift_finding_events_reject_update();
DROP INDEX IF EXISTS drift_finding_events_org_occurred_idx;
DROP INDEX IF EXISTS drift_finding_events_finding_occurred_idx;
DROP TABLE IF EXISTS drift_finding_events;

ALTER TABLE drift_findings
    DROP CONSTRAINT IF EXISTS drift_findings_status_resolution_consistent;

ALTER TABLE drift_findings
    DROP COLUMN IF EXISTS status;
