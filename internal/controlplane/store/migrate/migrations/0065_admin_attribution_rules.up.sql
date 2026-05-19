-- Backoffice metric attribution rules. These rows are global operator-owned
-- runtime contracts used to decide when source metrics may be mapped to Yalla
-- resources and when they must be quarantined for review.

CREATE DOMAIN attribution_rule_source AS text
    CHECK (VALUE IN ('traefik', 'dokploy'));

CREATE DOMAIN attribution_rule_match_kind AS text
    CHECK (VALUE IN ('traefik_service_label', 'dokploy_app_name_pattern', 'explicit_dokploy_ref'));

CREATE DOMAIN attribution_rule_confidence AS text
    CHECK (VALUE IN ('low', 'medium', 'high'));

CREATE TABLE admin_attribution_rules (
    id                     text                         PRIMARY KEY CHECK (length(id) > 0),
    rule_key               citext                       NOT NULL CHECK (rule_key ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    source                 attribution_rule_source      NOT NULL,
    priority               integer                      NOT NULL CHECK (priority BETWEEN 1 AND 10000),
    match_kind             attribution_rule_match_kind  NOT NULL,
    label_key              text                         NOT NULL DEFAULT '' CHECK (length(label_key) <= 160),
    pattern                text                         NOT NULL DEFAULT '' CHECK (length(pattern) <= 512),
    dokploy_resource       text                         NOT NULL DEFAULT '' CHECK (dokploy_resource = '' OR dokploy_resource IN ('application', 'compose', 'database')),
    min_confidence         attribution_rule_confidence  NOT NULL DEFAULT 'medium',
    quarantine_unmatched   boolean                      NOT NULL DEFAULT true,
    quarantine_ambiguous   boolean                      NOT NULL DEFAULT true,
    enabled                boolean                      NOT NULL DEFAULT true,
    revision               bigint                       NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at             timestamptz                  NOT NULL DEFAULT now(),
    updated_at             timestamptz                  NOT NULL DEFAULT now(),
    UNIQUE (rule_key),
    CONSTRAINT admin_attribution_rules_match_shape CHECK (
        (match_kind = 'traefik_service_label' AND label_key <> '' AND pattern = '' AND dokploy_resource = '')
        OR (match_kind = 'dokploy_app_name_pattern' AND pattern <> '' AND label_key = '' AND dokploy_resource = '')
        OR (match_kind = 'explicit_dokploy_ref' AND dokploy_resource <> '' AND label_key = '' AND pattern = '')
    )
);

CREATE INDEX admin_attribution_rules_runtime_idx
    ON admin_attribution_rules (enabled, source, priority, rule_key);

CREATE TRIGGER admin_attribution_rules_set_updated_at
    BEFORE UPDATE ON admin_attribution_rules
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
