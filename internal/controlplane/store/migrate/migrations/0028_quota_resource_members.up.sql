-- Add members to the quota_resource Postgres DOMAIN.
--
-- members is the per-organization quota dimension that counts every
-- live row in memberships for the tenant — one human or service-account
-- principal per unit. It is the count-axis sibling of the api_keys
-- dimension (BE-0337): every MembershipService.Add reserves one unit
-- on this dimension inside the same *Tx as the desired-state insert
-- and the immutable audit append, so an organization that exhausts
-- the dimension can never half-write a memberships row whose quota
-- reservation rolled back.
--
-- The closed-set rule from migration 0006 still holds: every value
-- a row can carry in the resource column on quota_policies,
-- quota_usage, quota_reservations, and usage_events must appear in
-- the quota_resource DOMAIN, otherwise the database refuses the
-- insert. The original CHECK constraint was created inline by the
-- 0006 CREATE DOMAIN statement and so its name was assigned by
-- Postgres rather than chosen by us; we look it up from
-- pg_constraint inside a DO block so the migration is robust to
-- any future Postgres naming-policy change rather than depending on
-- the conventional quota_resource_check label.
--
-- This is a structural superset of the 0027 set: every value that
-- was valid before is still valid, plus 'members'. No existing
-- row's resource column changes, no existing policy or reservation
-- is invalidated, and the migration is therefore safe against any
-- prod data that the 0027 set already accepted.

DO $$
DECLARE
    cname text;
BEGIN
    SELECT conname
      INTO cname
      FROM pg_constraint
     WHERE contypid = 'quota_resource'::regtype
       AND contype  = 'c'
     LIMIT 1;
    IF cname IS NOT NULL THEN
        EXECUTE format('ALTER DOMAIN quota_resource DROP CONSTRAINT %I', cname);
    END IF;
END;
$$;

ALTER DOMAIN quota_resource ADD CONSTRAINT quota_resource_check
    CHECK (VALUE IN (
        'projects',
        'environments',
        'services',
        'applications',
        'compose_stacks',
        'databases',
        'domains',
        'preview_environments',
        'cpu_millicores',
        'memory_mb',
        'storage_gb',
        'backups',
        'backup_schedules',
        'api_keys',
        'members',
        'concurrent_deployments',
        'monthly_deployments'
    ));
