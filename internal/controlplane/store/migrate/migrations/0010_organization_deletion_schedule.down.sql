-- Reverse of 0010_organization_deletion_schedule: drop the soft-delete marker.
-- DROP COLUMN also drops the partial index that depends on it.

ALTER TABLE organizations
    DROP COLUMN IF EXISTS deletion_scheduled_at;
