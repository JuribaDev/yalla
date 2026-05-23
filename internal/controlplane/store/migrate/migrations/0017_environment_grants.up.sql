-- Environment-scoped grants: a scoped grant that confers a built-in role on a
-- principal at a specific (environment, optional service) target. Environment
-- grants narrow or widen a principal's authority below the project level: a
-- developer with an environment-scoped Viewer grant for one environment
-- cannot mutate sibling environments, and a viewer with an environment-scoped
-- Admin grant for one environment can mutate it without becoming an admin of
-- the whole project. The policy engine already consumes this shape through
-- policy.Grant on the resolved Principal; this table is the source of truth
-- those Grants are loaded from at the environment layer.
--
-- Design rules enforced here:
--
--   * Tenant-scoped at the database. The composite FK
--     (organization_id, environment_id) -> environments (organization_id, id)
--     is MATCH SIMPLE: it makes a cross-tenant child structurally
--     unrepresentable, so a row whose environment belongs to one tenant
--     cannot advertise itself as another tenant's grant. ON DELETE CASCADE
--     means environment teardown removes its grants — a deleted environment
--     cannot leak an orphaned grant carrying its old role.
--
--   * Composite uniqueness (organization_id, id) is exposed as the FK target
--     a future per-row PATCH / DELETE endpoint will use to address one grant
--     by id without losing tenant scoping.
--
--   * Principal kind is closed to ('usr','sa') — the two principal kinds the
--     policy engine resolves. A grant cannot target an organization, project,
--     environment, or service.
--
--   * Role is closed to the six built-in roles
--     ('owner','admin','developer','viewer','ci','support'). Custom roles
--     are resolved through the policy engine's CustomRoleResolver hook and
--     do not land in this column today; adding custom-role support is a
--     future migration that widens the CHECK predicate.
--
--   * service_id is optional further scoping. It is a plain text identifier
--     without an FK to services — an environment-scoped grant must outlive
--     a recreated service of the same id, and a grant whose nested id no
--     longer resolves is simply unreachable through the policy engine (a
--     defensive ignore, not a hard error). The composite FK to environments
--     still pins the parent environment's tenant.
--
--   * One principal cannot hold two grants at the same scope tuple. The
--     unique index uses COALESCE so NULL service_id values deduplicate
--     cleanly across rows (Postgres unique constraints treat NULLs as
--     distinct by default), so a single principal has at most one grant at
--     any given (environment, svc?) target.
--
--   * Optimistic concurrency. Every row carries a bigint version that the
--     bump_version() trigger from migration 0011 maintains, mirroring
--     projects/environments/services/organization_variables/project_grants.
--     Future PATCH / DELETE stories will accept If-Match against this column.
--
--   * No secrets in the schema. A grant row stores only structural
--     identifiers and a role enum, so the resource is safe to project onto
--     the wire and audit verbatim — the redaction chokepoints other
--     resources rely on are not needed here.

CREATE TABLE environment_grants (
    id              text        PRIMARY KEY CHECK (length(id) > 0),
    organization_id text        NOT NULL,
    environment_id  text        NOT NULL,
    principal_id    text        NOT NULL CHECK (length(principal_id) > 0),
    principal_kind  text        NOT NULL CHECK (principal_kind IN ('usr', 'sa')),
    role            text        NOT NULL CHECK (role IN ('owner', 'admin', 'developer', 'viewer', 'ci', 'support')),
    service_id      text                 CHECK (service_id IS NULL OR length(service_id) > 0),
    version         bigint      NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, environment_id)
        REFERENCES environments (organization_id, id) ON DELETE CASCADE,
    UNIQUE (organization_id, id)
);

CREATE UNIQUE INDEX environment_grants_principal_scope_idx
    ON environment_grants (
        organization_id,
        environment_id,
        principal_id,
        COALESCE(service_id, '')
    );

CREATE INDEX environment_grants_environment_idx
    ON environment_grants (organization_id, environment_id);

CREATE INDEX environment_grants_principal_idx
    ON environment_grants (organization_id, principal_id);

CREATE TRIGGER environment_grants_set_updated_at
    BEFORE UPDATE ON environment_grants
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER environment_grants_bump_version
    BEFORE UPDATE ON environment_grants
    FOR EACH ROW EXECUTE FUNCTION bump_version();
