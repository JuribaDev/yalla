DROP TRIGGER IF EXISTS drift_findings_set_updated_at ON drift_findings;
DROP INDEX IF EXISTS drift_findings_environment_id_idx;
DROP INDEX IF EXISTS drift_findings_service_id_idx;
DROP INDEX IF EXISTS drift_findings_org_detected_idx;
DROP INDEX IF EXISTS drift_findings_org_open_idx;
DROP TABLE IF EXISTS drift_findings;
