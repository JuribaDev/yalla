-- Organization-scoped variables: the lowest-precedence layer of the
-- Organization -> Project -> Environment -> Service variable hierarchy the
-- Dokploy renderer composes. A variable here is an organization-wide default
-- every service in the tenant inherits unless overridden by a higher-scope
-- variable.
--
-- Design rules enforced here:
--
--   * Tenant-scoped at the database. organization_id FKs into organizations
--     with ON DELETE CASCADE, so a tenant teardown removes its variables.
--   * Key uniqueness is per-organization, never global. An env var named
--     DATABASE_URL in two organizations is two distinct rows.
--   * Composite uniqueness (organization_id, id) is exposed as the FK target
--     a future scope-narrowing override table (project_variables /
--     environment_variables / service_variables) can use to enforce
--     "an override row's organization_id must match its referenced parent
--     variable's organization_id".
--   * Optimistic concurrency. Every row carries a bigint version that the
--     bump_version() trigger from migration 0011 maintains, mirroring the
--     pattern organizations/projects/environments/services use. PATCH /
--     DELETE in later stories will accept If-Match against this column.
--   * No secrets in the schema. The value column stores the variable's
--     literal value, but every value reaching this table is treated as
--     sensitive by the HTTP and audit layers — non-secret values are still
--     never logged. The is_secret column drives wire-level redaction (the
--     read endpoint redacts secret values; non-secret values project
--     verbatim) and audit metadata redaction (every variable value the
--     audit layer ever sees is redacted regardless of is_secret).

CREATE TABLE organization_variables (
    id              text        PRIMARY KEY CHECK (length(id) > 0),
    organization_id text        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    key             text        NOT NULL CHECK (length(key) > 0),
    value           text        NOT NULL,
    is_secret       boolean     NOT NULL DEFAULT false,
    version         bigint      NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, key),
    UNIQUE (organization_id, id)
);

CREATE INDEX organization_variables_organization_id_idx
    ON organization_variables (organization_id);

CREATE TRIGGER organization_variables_set_updated_at
    BEFORE UPDATE ON organization_variables
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER organization_variables_bump_version
    BEFORE UPDATE ON organization_variables
    FOR EACH ROW EXECUTE FUNCTION bump_version();
