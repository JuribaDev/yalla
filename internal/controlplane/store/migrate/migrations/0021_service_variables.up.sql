-- Service-scoped variables: the highest precedence (lowest level) layer of
-- the Organization -> Project -> Environment -> Service variable hierarchy
-- the Dokploy renderer composes. A variable here is bound to a single
-- service and shadows the environment-, project-, and organization-scoped
-- variables of the same key for that service only — a key set here cannot
-- leak into sibling services in the same environment, the same project, or
-- the same tenant.
--
-- Design rules enforced here:
--
--   * Tenant-scoped at the database. The composite FK
--     (organization_id, service_id) references the matching composite
--     UNIQUE (organization_id, id) on services with ON DELETE CASCADE, so
--     a service teardown removes its variables and a row can never sit
--     under a foreign tenant's service (the FK refuses the insert
--     structurally before the application layer's tenant predicate runs).
--     The transitive parents (environment, project) are reached through
--     services — this table does not duplicate environment_id or
--     project_id, the same way environment_variables does not duplicate
--     project_id and environment_grants does not duplicate project_id.
--   * Key uniqueness is per-service, never global. A service variable
--     named DATABASE_URL on two services is two distinct rows; a service
--     variable with the same key in two organizations and the same
--     service_id (which is impossible because service ids are
--     tenant-unique) is similarly two distinct rows.
--   * Composite uniqueness (organization_id, id) is exposed as the FK
--     target any future override or audit table can use to enforce
--     "an override row's organization_id must match its referenced
--     parent variable's organization_id".
--   * Optimistic concurrency. Every row carries a bigint version that the
--     bump_version() trigger from migration 0011 maintains, mirroring
--     organization_variables/project_variables/environment_variables/
--     projects/environments/services/project_grants/environment_grants.
--     Future PATCH / DELETE stories will accept If-Match against this
--     column.
--   * No secrets in the schema. The value column stores the variable's
--     literal value, but every value reaching this table is treated as
--     sensitive by the HTTP and audit layers — non-secret values are
--     still never logged. The is_secret column drives wire-level
--     redaction (the read endpoint redacts secret values; non-secret
--     values project verbatim) and audit metadata redaction (every
--     variable value the audit layer ever sees is redacted regardless
--     of is_secret).

CREATE TABLE service_variables (
    id              text        PRIMARY KEY CHECK (length(id) > 0),
    organization_id text        NOT NULL,
    service_id      text        NOT NULL,
    key             text        NOT NULL CHECK (length(key) > 0),
    value           text        NOT NULL,
    is_secret       boolean     NOT NULL DEFAULT false,
    version         bigint      NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, service_id)
        REFERENCES services (organization_id, id) ON DELETE CASCADE,
    UNIQUE (organization_id, service_id, key),
    UNIQUE (organization_id, id)
);

CREATE INDEX service_variables_service_idx
    ON service_variables (organization_id, service_id);

CREATE TRIGGER service_variables_set_updated_at
    BEFORE UPDATE ON service_variables
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER service_variables_bump_version
    BEFORE UPDATE ON service_variables
    FOR EACH ROW EXECUTE FUNCTION bump_version();
