-- Service accounts: non-human principals for CI and automation.
--
-- A service account lets CI pipelines and automation authenticate to the Yalla
-- Control Plane without a human user and without ever holding a Dokploy token.
-- Like every customer-data row it is tenant-scoped: it belongs to exactly one
-- organization and ON DELETE CASCADE removes it with the tenant.
--
--   * A service account owns API keys. api_keys gains a nullable
--     service_account_id: a key is owned by a service account, attributed to a
--     human (created_by), or neither — but a service-account-owned key can
--     never cross the tenant boundary. The composite foreign key
--     (organization_id, service_account_id) pins the key's organization to its
--     service account's, making a cross-tenant service-account key
--     unrepresentable in the database, not just in the application.
--   * Service accounts have a disable lifecycle (disabled_at) so automation
--     credentials can be parked without being destroyed.
--   * What a service account principal may *do* — and the rule that it cannot
--     manage billing, owners, or break-glass access unless a policy grant
--     explicitly allows it — is enforced by the policy engine, not this
--     schema. This migration owns only the identity and ownership model.

CREATE TABLE service_accounts (
    id              text        PRIMARY KEY CHECK (length(id) > 0),
    organization_id text        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    slug            citext      NOT NULL CHECK (length(slug::text) > 0),
    display_name    text        NOT NULL CHECK (length(display_name) > 0),
    disabled_at     timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    -- Slugs are unique within the owning organization, never globally.
    UNIQUE (organization_id, slug),
    -- The composite-FK target the api_keys ownership link references.
    UNIQUE (organization_id, id)
);

CREATE INDEX service_accounts_organization_id_idx ON service_accounts (organization_id);

CREATE TRIGGER service_accounts_set_updated_at
    BEFORE UPDATE ON service_accounts
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- api_keys can now be owned by a service account. The column is nullable: a
-- key minted for a human has no service_account_id. The composite foreign key
-- on (organization_id, service_account_id) is MATCH SIMPLE, so it is enforced
-- only when service_account_id is set — and when it is, it pins the key's
-- organization to its service account's, so a cross-tenant service-account key
-- is rejected by the database.
ALTER TABLE api_keys
    ADD COLUMN service_account_id text;

ALTER TABLE api_keys
    ADD CONSTRAINT api_keys_service_account_id_fkey
    FOREIGN KEY (organization_id, service_account_id)
    REFERENCES service_accounts (organization_id, id) ON DELETE CASCADE;

-- Tenant-scoped listing ("every key for this service account") is a common
-- query; the partial index skips the human-owned keys with a NULL link.
CREATE INDEX api_keys_service_account_id_idx
    ON api_keys (service_account_id)
    WHERE service_account_id IS NOT NULL;
