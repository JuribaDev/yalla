-- Organization deletion scheduling: the soft-delete marker that lets the
-- control plane accept a "delete this organization" request without tearing
-- the tenant down synchronously.
--
-- Design rules enforced here:
--
--   * Scheduled, not immediate. DELETE /v1/organizations/{org_id} records the
--     intent by stamping deletion_scheduled_at; the destructive teardown -- the
--     organizations ON DELETE CASCADE that removes projects, environments,
--     services, and the audit log -- is a later worker story. Until then the
--     row, and its audit trail, still exist, so the organization.delete audit
--     event is never cascaded away by the very request that wrote it.
--   * Nullable, and write-once in spirit. A NULL deletion_scheduled_at is a
--     live organization; a non-NULL value is one already scheduled for
--     teardown. The store layer treats a second schedule request as a typed
--     conflict rather than moving the timestamp.
--   * No secrets. The column is a timestamp; it carries no credential material.

ALTER TABLE organizations
    ADD COLUMN deletion_scheduled_at timestamptz;

-- The worker that performs tenant teardown will scan for organizations pending
-- deletion. A partial index keeps that scan off a sequential pass while staying
-- tiny, because the overwhelming majority of organizations are live (NULL).
CREATE INDEX organizations_deletion_scheduled_at_idx
    ON organizations (deletion_scheduled_at)
    WHERE deletion_scheduled_at IS NOT NULL;
