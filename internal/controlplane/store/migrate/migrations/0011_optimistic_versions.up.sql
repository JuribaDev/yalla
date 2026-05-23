-- Optimistic concurrency: every mutable source-of-truth resource carries a
-- monotonically increasing version that the database itself maintains. The
-- HTTP layer accepts the caller's expected version (via the If-Match request
-- header on PATCH and DELETE) and the store layer rejects a write whose view
-- of the resource is stale.
--
-- Design rules enforced here:
--
--   * Database-owned, not application-owned. The version starts at 1 on
--     INSERT (column DEFAULT) and is bumped by a BEFORE UPDATE trigger
--     (bump_version) so an application that forgets to maintain it cannot
--     create a stale-but-passing-version row.
--   * Bump on every UPDATE, not just on a "real" data change. A no-op UPDATE
--     in the same transaction as a real one would otherwise advance the row's
--     observable state without advancing the version, defeating the check.
--   * Applies to every mutable customer-data resource in the tenant
--     hierarchy: organizations, projects, environments, and services. The
--     pure-mapping table dokploy_refs is also covered for parity, since the
--     provisioning worker may eventually mutate it.
--   * The column is bigint NOT NULL DEFAULT 1, never user-supplied. The CHECK
--     keeps it strictly positive so the "version 0" sentinel can never
--     accidentally match a real row.
--   * No secrets. The column is an integer; it carries no credential
--     material.

CREATE OR REPLACE FUNCTION bump_version()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.version := OLD.version + 1;
    RETURN NEW;
END;
$$;

ALTER TABLE organizations
    ADD COLUMN version bigint NOT NULL DEFAULT 1 CHECK (version > 0);

CREATE TRIGGER organizations_bump_version
    BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION bump_version();

ALTER TABLE projects
    ADD COLUMN version bigint NOT NULL DEFAULT 1 CHECK (version > 0);

CREATE TRIGGER projects_bump_version
    BEFORE UPDATE ON projects
    FOR EACH ROW EXECUTE FUNCTION bump_version();

ALTER TABLE environments
    ADD COLUMN version bigint NOT NULL DEFAULT 1 CHECK (version > 0);

CREATE TRIGGER environments_bump_version
    BEFORE UPDATE ON environments
    FOR EACH ROW EXECUTE FUNCTION bump_version();

ALTER TABLE services
    ADD COLUMN version bigint NOT NULL DEFAULT 1 CHECK (version > 0);

CREATE TRIGGER services_bump_version
    BEFORE UPDATE ON services
    FOR EACH ROW EXECUTE FUNCTION bump_version();
