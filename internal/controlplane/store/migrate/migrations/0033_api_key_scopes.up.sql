-- API key scopes: a normalised, tenant-scoped child of api_keys carrying
-- one capability string per row. The api_keys.scopes text[] column is the
-- legacy embedded representation the authentication path reads today; this
-- table is the long-term source of truth a future per-scope endpoint will
-- mutate without rewriting an entire array, and lets the audit trail record
-- per-scope created_at / updated_at / version stamps. Until the per-scope
-- write endpoint lands, the two surfaces coexist: the embedded array stays
-- authoritative for the auth read path, and the normalised table is the
-- target of future scope-management code.
--
-- Design rules enforced here:
--
--   * Tenant-scoped at the database. Composite FK
--     (organization_id, api_key_id) -> api_keys (organization_id, id) is
--     MATCH SIMPLE, so a row whose api_key belongs to one tenant cannot
--     advertise itself as another tenant's scope. ON DELETE CASCADE means
--     api-key teardown removes its scope rows — a revoked or rotated key
--     cannot leak an orphaned scope that survives it. The companion
--     UNIQUE (organization_id, id) constraint added to api_keys is the
--     composite FK target a child table can pin against.
--
--   * One scope string per api_key. The UNIQUE
--     (organization_id, api_key_id, scope) constraint prevents two rows
--     with the same scope text on the same key and surfaces a duplicate
--     insert as the typed Conflict the repository's mapWriteError produces.
--
--   * Scope strings carry the same lexical envelope the apikeyservice
--     scope validator enforces at the wire (length > 0 and <= 64). The
--     CHECK is the database-side defence so a customer-data row can never
--     hold a zero-length or oversized scope even if a future caller forgot
--     to validate.
--
--   * Composite uniqueness (organization_id, id) is exposed as the FK
--     target a future per-row PATCH / DELETE endpoint will use to address
--     one scope by id without losing tenant scoping.
--
--   * Optimistic concurrency. Every row carries a bigint version that the
--     api_key_scopes_bump_version trigger maintains, mirroring projects /
--     environments / services / project_grants / organization_variables.
--     Future PATCH / DELETE stories will accept If-Match against this
--     column.
--
--   * No secrets in the schema. A scope row stores only a tenant id, an
--     api-key id, the public capability string the wire surface already
--     accepts in clear text, and lifecycle stamps; nothing in this table
--     holds credential material and the row body is safe to project to
--     the wire and the audit log verbatim.

ALTER TABLE api_keys
    ADD CONSTRAINT api_keys_organization_id_id_key UNIQUE (organization_id, id);

CREATE TABLE api_key_scopes (
    id              text        PRIMARY KEY CHECK (length(id) > 0),
    organization_id text        NOT NULL,
    api_key_id      text        NOT NULL,
    scope           text        NOT NULL CHECK (length(scope) > 0 AND length(scope) <= 64),
    version         bigint      NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, api_key_id)
        REFERENCES api_keys (organization_id, id) ON DELETE CASCADE,
    UNIQUE (organization_id, id),
    UNIQUE (organization_id, api_key_id, scope)
);

CREATE INDEX api_key_scopes_api_key_idx
    ON api_key_scopes (organization_id, api_key_id);

CREATE INDEX api_key_scopes_organization_idx
    ON api_key_scopes (organization_id);

CREATE TRIGGER api_key_scopes_set_updated_at
    BEFORE UPDATE ON api_key_scopes
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER api_key_scopes_bump_version
    BEFORE UPDATE ON api_key_scopes
    FOR EACH ROW EXECUTE FUNCTION bump_version();
