DROP TRIGGER IF EXISTS job_attempts_no_update ON job_attempts;
DROP FUNCTION IF EXISTS job_attempts_reject_update();
DROP INDEX IF EXISTS job_attempts_org_finished_idx;
DROP INDEX IF EXISTS job_attempts_job_attempt_idx;
DROP TABLE IF EXISTS job_attempts;
