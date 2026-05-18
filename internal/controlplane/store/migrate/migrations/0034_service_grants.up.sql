-- Service-scoped grants: a scoped grant that confers a built-in role on a
-- principal at a specific service. Service grants narrow or widen a
-- principal's authority below the environment level: a developer with a
-- service-scoped Viewer grant for one service cannot mutate sibling services,
-- and a viewer with a service-scoped Admin grant for one service can mutate
-- it without becoming an admin of the whole environment. The policy engine
-- already consumes this shape through policy.Grant on the resolved
-- Principal; this table is the source of truth those Grants are loaded from
-- at the service layer.
--
-- Design rules enforced here:
--
--   * Tenant-scoped at the database. The composite FK
--     (organization_id, service_id) -> services (organization_id, id) is
--     MATCH SIMPLE: it makes a cross-tenant child structurally
--     unrepresentable, so a row whose service belongs to one tenant cannot
--     advertise itself as another tenant's grant. ON DELETE CASCADE means
--     service teardown removes its grants — a deleted service cannot leak
--     an orphaned grant carrying its old role.
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
--   * No further nested scoping. Unlike project_grants (optional environment
--     and service scope) and environment_grants (optional service scope), a
--     service is already the leaf of the
--     Organization -> Project -> Environment -> Service hierarchy: a grant
--     scoped to one service cannot be narrowed further. The unique index
--     therefore needs no COALESCE; one principal has at most one grant on
--     any given service.
--
--   * Optimistic concurrency. Every row carries a bigint version that the
--     bump_version() trigger from migration 0011 maintains, mirroring
--     projects/environments/services/organization_variables/project_grants/
--     environment_grants. Future PATCH / DELETE stories will accept
--     If-Match against this column.
--
--   * No secrets in the schema. A grant row stores only structural
--     identifiers and a role enum, so the resource is safe to project onto
--     the wire and audit verbatim — the redaction chokepoints other
--     resources rely on are not needed here.

CREATE TABLE service_grants (
    id              text        PRIMARY KEY CHECK (length(id) > 0),
    organization_id text        NOT NULL,
    service_id      text        NOT NULL,
    principal_id    text        NOT NULL CHECK (length(principal_id) > 0),
    principal_kind  text        NOT NULL CHECK (principal_kind IN ('usr', 'sa')),
    role            text        NOT NULL CHECK (role IN ('owner', 'admin', 'developer', 'viewer', 'ci', 'support')),
    version         bigint      NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, service_id)
        REFERENCES services (organization_id, id) ON DELETE CASCADE,
    UNIQUE (organization_id, id),
    UNIQUE (organization_id, service_id, principal_id)
);

CREATE INDEX service_grants_service_idx
    ON service_grants (organization_id, service_id);

CREATE INDEX service_grants_principal_idx
    ON service_grants (organization_id, principal_id);

CREATE TRIGGER service_grants_set_updated_at
    BEFORE UPDATE ON service_grants
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER service_grants_bump_version
    BEFORE UPDATE ON service_grants
    FOR EACH ROW EXECUTE FUNCTION bump_version();
