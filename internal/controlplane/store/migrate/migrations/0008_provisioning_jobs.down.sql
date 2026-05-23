-- Reverse of 0008_provisioning_jobs: drop the deferred quota_reservations
-- foreign key first (it depends on provisioning_jobs' composite unique key),
-- then drop the table. DROP TABLE also drops the table's indexes and the
-- set_updated_at trigger.

ALTER TABLE quota_reservations DROP CONSTRAINT IF EXISTS quota_reservations_job_fk;
DROP TABLE IF EXISTS provisioning_jobs;
