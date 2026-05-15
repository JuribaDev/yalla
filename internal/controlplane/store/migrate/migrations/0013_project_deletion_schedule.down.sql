-- Reverse of 0013_project_deletion_schedule: drop the soft-delete marker.
-- DROP COLUMN also drops the partial index that depends on it.

ALTER TABLE projects
    DROP COLUMN IF EXISTS deletion_scheduled_at;
