-- Reverse the environment deletion-scheduling column. The partial index is
-- dropped first because it depends on the column.

DROP INDEX IF EXISTS environments_deletion_scheduled_at_idx;

ALTER TABLE environments
    DROP COLUMN IF EXISTS deletion_scheduled_at;
