-- Reverse the service deletion-scheduling column. The partial index is
-- dropped first because it depends on the column.

DROP INDEX IF EXISTS services_deletion_scheduled_at_idx;

ALTER TABLE services
    DROP COLUMN IF EXISTS deletion_scheduled_at;
