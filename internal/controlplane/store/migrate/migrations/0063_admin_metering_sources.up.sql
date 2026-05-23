-- Backoffice metering source configuration. These rows are global operator-
-- owned runtime configuration; credentials are write-only and sealed at rest.

CREATE DOMAIN metering_source_type AS text
    CHECK (VALUE IN ('traefik', 'prometheus', 'dokploy', 'container', 'storage', 'backup'));

CREATE TABLE admin_metering_sources (
    id                        text                  PRIMARY KEY CHECK (length(id) > 0),
    source_key                citext                NOT NULL CHECK (source_key ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    source_type               metering_source_type  NOT NULL,
    endpoint_url              text                  NOT NULL CHECK (length(btrim(endpoint_url)) BETWEEN 1 AND 2048),
    auth_scheme               text                  NOT NULL DEFAULT 'none' CHECK (auth_scheme IN ('none', 'bearer', 'basic', 'api_key', 'mtls', 'custom')),
    auth_reference            text                  NOT NULL DEFAULT '' CHECK (length(auth_reference) <= 512),
    credential_value          text                  NOT NULL DEFAULT '',
    credential_provider       text,
    credential_key_id         text,
    credential_ciphertext     bytea,
    scrape_interval_seconds   integer               NOT NULL DEFAULT 60 CHECK (scrape_interval_seconds BETWEEN 10 AND 86400),
    query_interval_seconds    integer               NOT NULL DEFAULT 300 CHECK (query_interval_seconds BETWEEN 10 AND 86400),
    timeout_seconds           integer               NOT NULL DEFAULT 10 CHECK (timeout_seconds BETWEEN 1 AND 300),
    labels                    jsonb                 NOT NULL DEFAULT '{}'::jsonb,
    enabled                   boolean               NOT NULL DEFAULT true,
    revision                  bigint                NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at                timestamptz           NOT NULL DEFAULT now(),
    updated_at                timestamptz           NOT NULL DEFAULT now(),
    UNIQUE (source_key),
    CONSTRAINT admin_metering_sources_credential_consistent CHECK (
        (
            credential_value = ''
            AND credential_provider IS NULL
            AND credential_key_id IS NULL
            AND credential_ciphertext IS NULL
        ) OR (
            credential_value = ''
            AND credential_provider IS NOT NULL
            AND credential_key_id IS NOT NULL
            AND credential_ciphertext IS NOT NULL
        )
    )
);

CREATE INDEX admin_metering_sources_runtime_idx
    ON admin_metering_sources (enabled, source_type, source_key);

CREATE INDEX admin_metering_sources_secret_routing_idx
    ON admin_metering_sources (credential_provider, credential_key_id)
    WHERE credential_ciphertext IS NOT NULL;

CREATE TRIGGER admin_metering_sources_set_updated_at
    BEFORE UPDATE ON admin_metering_sources
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
