DROP TABLE IF EXISTS api_key_scopes;

ALTER TABLE api_keys
    DROP CONSTRAINT IF EXISTS api_keys_organization_id_id_key;
