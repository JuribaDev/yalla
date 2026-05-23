-- Environment-scoped variables: the third-from-lowest precedence layer of the
-- Organization -> Project -> Environment -> Service variable hierarchy the
-- Dokploy renderer composes. A variable here is an environment-wide default
-- every service in the environment inherits unless overridden by a
-- higher-scope (service) variable; it shadows the project-scoped variable of
-- the same key for services inside this environment, which in turn shadows
-- the organization-scoped variable of the same key.
--
-- Design rules enforced here:
--
--   * Tenant-scoped at the database. The composite FK
--     (organization_id, environment_id) references the matching composite
--     UNIQUE (organization_id, id) on environments with ON DELETE CASCADE,
--     so an environment teardown removes its variables and a row can never
--     sit under a foreign tenant's environment (the FK refuses the insert
--     structurally before the application layer's tenant predicate runs).
--     The transitive parent (project) is reached through environments —
--     this table does not duplicate project_id, the same way
--     environment_grants does not.
--   * Key uniqueness is per-environment, never global. An env var named
--     DATABASE_URL in two environments is two distinct rows; an env var
--     with the same key in two organizations and the same environment_id
--     (which is impossible because environment ids are tenant-unique) is
--     similarly two distinct rows.
--   * Composite uniqueness (organization_id, id) is exposed as the FK
--     target a future scope-narrowing override table (service_variables)
--     can use to enforce "an override row's organization_id must match its
--     referenced parent variable's organization_id".
--   * Optimistic concurrency. Every row carries a bigint version that the
--     bump_version() trigger from migration 0011 maintains, mirroring
--     organization_variables/project_variables/projects/environments/
--     services/project_grants/environment_grants. Future PATCH / DELETE
--     stories will accept If-Match against this column.
--   * No secrets in the schema. The value column stores the variable's
--     literal value, but every value reaching this table is treated as
--     sensitive by the HTTP and audit layers — non-secret values are
--     still never logged. The is_secret column drives wire-level
--     redaction (the read endpoint redacts secret values; non-secret
--     values project verbatim) and audit metadata redaction (every
--     variable value the audit layer ever sees is redacted regardless
--     of is_secret).

CREATE TABLE environment_variables (
    id              text        PRIMARY KEY CHECK (length(id) > 0),
    organization_id text        NOT NULL,
    environment_id  text        NOT NULL,
    key             text        NOT NULL CHECK (length(key) > 0),
    value           text        NOT NULL,
    is_secret       boolean     NOT NULL DEFAULT false,
    version         bigint      NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, environment_id)
        REFERENCES environments (organization_id, id) ON DELETE CASCADE,
    UNIQUE (organization_id, environment_id, key),
    UNIQUE (organization_id, id)
);

CREATE INDEX environment_variables_environment_idx
    ON environment_variables (organization_id, environment_id);

CREATE TRIGGER environment_variables_set_updated_at
    BEFORE UPDATE ON environment_variables
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER environment_variables_bump_version
    BEFORE UPDATE ON environment_variables
    FOR EACH ROW EXECUTE FUNCTION bump_version();
