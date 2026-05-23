-- Backoffice feature flags. These rows are global operator-owned runtime
-- contracts evaluated for plan and tenant hierarchy scopes.

CREATE DOMAIN feature_flag_value_type AS text
    CHECK (VALUE IN ('boolean', 'string', 'number', 'json'));

CREATE TABLE admin_feature_flags (
    id                    text                    PRIMARY KEY CHECK (length(id) > 0),
    flag_key              citext                  NOT NULL CHECK (flag_key ~ '^[a-z0-9][a-z0-9_.-]{0,127}$'),
    value_type            feature_flag_value_type NOT NULL,
    default_value         jsonb                   NOT NULL,
    targeting_rules       jsonb                   NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(targeting_rules) = 'array'),
    rollout_percentage    integer                 NOT NULL DEFAULT 0 CHECK (rollout_percentage BETWEEN 0 AND 10000),
    admin_sensitive       boolean                 NOT NULL DEFAULT false,
    enabled               boolean                 NOT NULL DEFAULT true,
    revision              bigint                  NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at            timestamptz             NOT NULL DEFAULT now(),
    updated_at            timestamptz             NOT NULL DEFAULT now(),
    UNIQUE (flag_key)
);

CREATE INDEX admin_feature_flags_runtime_idx
    ON admin_feature_flags (enabled, flag_key);

CREATE TRIGGER admin_feature_flags_set_updated_at
    BEFORE UPDATE ON admin_feature_flags
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
