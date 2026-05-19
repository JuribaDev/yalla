-- Backoffice runtime configuration versioning. These tables are global
-- operator-owned configuration, not tenant data: runtime pricing, metering,
-- billing, quota, and feature services read only published versions whose
-- effective_at is active.

CREATE DOMAIN admin_config_domain AS text
    CHECK (VALUE IN ('pricing', 'metering', 'billing', 'quota', 'features'));

CREATE DOMAIN admin_config_version_status AS text
    CHECK (VALUE IN ('draft', 'published', 'archived'));

CREATE TABLE admin_config_sets (
    id          text                PRIMARY KEY CHECK (length(id) > 0),
    slug        citext              NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    domain      admin_config_domain NOT NULL,
    name        text                NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 120),
    description text                NOT NULL DEFAULT '' CHECK (length(description) <= 1000),
    revision    bigint              NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at  timestamptz         NOT NULL DEFAULT now(),
    updated_at  timestamptz         NOT NULL DEFAULT now(),
    UNIQUE (slug),
    UNIQUE (domain, slug)
);

CREATE INDEX admin_config_sets_domain_slug_idx ON admin_config_sets (domain, slug);

CREATE TRIGGER admin_config_sets_set_updated_at
    BEFORE UPDATE ON admin_config_sets
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE admin_config_versions (
    id                     text                        PRIMARY KEY CHECK (length(id) > 0),
    config_set_id          text                        NOT NULL REFERENCES admin_config_sets (id) ON DELETE CASCADE,
    version                integer                     NOT NULL CHECK (version > 0),
    status                 admin_config_version_status NOT NULL DEFAULT 'draft',
    payload                jsonb                       NOT NULL DEFAULT '{}'::jsonb,
    effective_at           timestamptz,
    published_at           timestamptz,
    published_by           text,
    rollback_of_version_id text                        REFERENCES admin_config_versions (id) ON DELETE SET NULL,
    rollback_reason        text                        NOT NULL DEFAULT '' CHECK (length(rollback_reason) <= 1000),
    archived_at            timestamptz,
    created_at             timestamptz                 NOT NULL DEFAULT now(),
    updated_at             timestamptz                 NOT NULL DEFAULT now(),
    CONSTRAINT admin_config_versions_publish_consistent CHECK (
        (
            status = 'draft'
            AND effective_at IS NULL
            AND published_at IS NULL
            AND published_by IS NULL
            AND archived_at IS NULL
        ) OR (
            status = 'published'
            AND effective_at IS NOT NULL
            AND published_at IS NOT NULL
            AND published_by IS NOT NULL
            AND archived_at IS NULL
        ) OR (
            status = 'archived'
            AND archived_at IS NOT NULL
        )
    ),
    CONSTRAINT admin_config_versions_published_by_nonblank CHECK (
        published_by IS NULL OR length(btrim(published_by)) BETWEEN 1 AND 160
    ),
    UNIQUE (config_set_id, version)
);

-- One editable draft per configuration set. Publishing converts the draft into
-- an immutable runtime candidate; later edits create the next draft version.
CREATE UNIQUE INDEX admin_config_versions_one_draft_idx
    ON admin_config_versions (config_set_id)
    WHERE status = 'draft';

CREATE INDEX admin_config_versions_runtime_idx
    ON admin_config_versions (config_set_id, effective_at DESC, version DESC)
    WHERE status = 'published';

CREATE INDEX admin_config_versions_status_idx
    ON admin_config_versions (status, effective_at);

CREATE TRIGGER admin_config_versions_set_updated_at
    BEFORE UPDATE ON admin_config_versions
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
