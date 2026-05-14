-- API keys: the customer-facing credentials for the Yalla Control Plane API.
--
-- Security model enforced here:
--
--   * Only a HASH of the secret is ever stored. The plaintext token is shown
--     to its owner exactly once, at creation time, and is never persisted or
--     logged. No column in this table holds a usable credential — secret_hash
--     is a one-way hash, prefix is public.
--   * Every key carries a public, unguessable `prefix`. Authentication looks a
--     key up by prefix (an indexed, UNIQUE lookup) and then verifies the
--     secret with a constant-time hash comparison: the prefix is safe to log,
--     the secret never reaches the database.
--   * Each key is tenant-scoped. organization_id ties it to exactly one
--     organization and ON DELETE CASCADE removes a tenant's keys with the
--     tenant. The prefix lookup is the one deliberate exception to "scope by
--     organization first" — authentication runs before the tenant is known,
--     and the row it finds carries its own organization_id.
--   * Keys have a lifecycle: expires_at (time-bound keys), revoked_at
--     (explicit revocation), and last_used_at (observability). A key is usable
--     only while it is neither expired nor revoked.
--   * created_by records the user who minted the key. It is nullable and
--     ON DELETE SET NULL so a key survives — but loses attribution — if its
--     creator's global user row is removed.

CREATE TABLE api_keys (
    id              text        PRIMARY KEY CHECK (length(id) > 0),
    organization_id text        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    prefix          text        NOT NULL UNIQUE CHECK (length(prefix) > 0),
    secret_hash     text        NOT NULL CHECK (length(secret_hash) > 0),
    name            text        NOT NULL CHECK (length(name) > 0),
    scopes          text[]      NOT NULL DEFAULT '{}',
    created_by      text        REFERENCES users (id) ON DELETE SET NULL,
    expires_at      timestamptz,
    revoked_at      timestamptz,
    last_used_at    timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

-- Tenant-scoped listing ("every key for this organization") is a common query;
-- the prefix authentication lookup is already covered by the UNIQUE index.
CREATE INDEX api_keys_organization_id_idx ON api_keys (organization_id);

CREATE TRIGGER api_keys_set_updated_at
    BEFORE UPDATE ON api_keys
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
