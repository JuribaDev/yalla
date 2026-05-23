CREATE TABLE service_build_configs (
    organization_id text NOT NULL,
    service_id text NOT NULL,
    build_type text NOT NULL,
    source_type text NOT NULL,
    source_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    config_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, service_id),
    CHECK (build_type IN ('static', 'dockerfile', 'compose', 'image')),
    CHECK (length(source_type) > 0),
    FOREIGN KEY (organization_id, service_id)
        REFERENCES services (organization_id, id)
        ON DELETE CASCADE
);

CREATE TRIGGER service_build_configs_set_updated_at
BEFORE UPDATE ON service_build_configs
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER service_build_configs_bump_version
BEFORE UPDATE ON service_build_configs
FOR EACH ROW EXECUTE FUNCTION bump_version();

