-- Backoffice billing provider configuration. Rows are global operator-owned
-- runtime contracts consumed by billing export workers/adapters.

CREATE DOMAIN billing_provider_type AS text
    CHECK (VALUE IN ('disabled', 'manual', 'stripe'));

CREATE TABLE admin_billing_providers (
    id                            text                  PRIMARY KEY CHECK (length(id) > 0),
    provider_key                  citext                NOT NULL CHECK (provider_key ~ '^[a-z0-9][a-z0-9_-]{0,127}$'),
    provider_type                 billing_provider_type NOT NULL,
    display_name                  text                  NOT NULL DEFAULT '' CHECK (length(display_name) <= 200),
    secret_reference              text                  NOT NULL DEFAULT '' CHECK (length(secret_reference) <= 512),
    credential_value              text                  NOT NULL DEFAULT '',
    credential_provider           text,
    credential_key_id             text,
    credential_ciphertext         bytea,
    export_cadence_seconds        integer               NOT NULL CHECK (export_cadence_seconds BETWEEN 300 AND 2678400),
    retry_max_attempts            integer               NOT NULL CHECK (retry_max_attempts BETWEEN 0 AND 20),
    retry_initial_backoff_seconds integer               NOT NULL CHECK (retry_initial_backoff_seconds BETWEEN 1 AND 86400),
    dry_run                       boolean               NOT NULL DEFAULT true,
    metadata                      jsonb                 NOT NULL DEFAULT '{}'::jsonb,
    enabled                       boolean               NOT NULL DEFAULT true,
    revision                      bigint                NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at                    timestamptz           NOT NULL DEFAULT now(),
    updated_at                    timestamptz           NOT NULL DEFAULT now(),
    UNIQUE (provider_key),
    CHECK (
        (credential_provider IS NULL AND credential_key_id IS NULL AND credential_ciphertext IS NULL)
        OR
        (credential_provider IS NOT NULL AND length(credential_provider) > 0
         AND credential_key_id IS NOT NULL AND length(credential_key_id) > 0
         AND credential_ciphertext IS NOT NULL AND length(credential_ciphertext) > 0)
    )
);

CREATE INDEX admin_billing_providers_runtime_idx
    ON admin_billing_providers (enabled, provider_type, provider_key);

CREATE TRIGGER admin_billing_providers_set_updated_at
    BEFORE UPDATE ON admin_billing_providers
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
