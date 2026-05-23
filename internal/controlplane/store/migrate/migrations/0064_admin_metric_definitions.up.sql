-- Backoffice metric definition configuration. Rows are global operator-owned
-- runtime contracts; billing-grade unit changes are versioned instead of
-- mutating historical definitions in place.

CREATE DOMAIN metric_aggregation_function AS text
    CHECK (VALUE IN ('sum', 'max', 'avg', 'p95', 'last'));

CREATE TABLE admin_metric_definitions (
    id                         text                         PRIMARY KEY CHECK (length(id) > 0),
    metric_key                 citext                       NOT NULL CHECK (metric_key ~ '^[a-z0-9][a-z0-9_]{0,127}$'),
    version                    integer                      NOT NULL CHECK (version > 0),
    unit                       text                         NOT NULL CHECK (unit ~ '^[a-z0-9][a-z0-9_]{0,63}$'),
    source                     text                         NOT NULL CHECK (source ~ '^[a-z0-9][a-z0-9_]{0,127}$'),
    aggregation_function       metric_aggregation_function  NOT NULL,
    aggregation_window_seconds integer                      NOT NULL CHECK (aggregation_window_seconds BETWEEN 1 AND 2678400),
    billing_grade              boolean                      NOT NULL DEFAULT false,
    retention_days             integer                      NOT NULL CHECK (retention_days BETWEEN 1 AND 3650),
    enforcement_link           text                         NOT NULL DEFAULT '' CHECK (length(enforcement_link) <= 160),
    enabled                    boolean                      NOT NULL DEFAULT true,
    revision                   bigint                       NOT NULL DEFAULT 1 CHECK (revision > 0),
    published_at               timestamptz                  NOT NULL DEFAULT now(),
    superseded_at              timestamptz,
    created_at                 timestamptz                  NOT NULL DEFAULT now(),
    updated_at                 timestamptz                  NOT NULL DEFAULT now(),
    UNIQUE (metric_key, version),
    CONSTRAINT admin_metric_definitions_enforcement_link_token CHECK (
        enforcement_link = '' OR enforcement_link ~ '^[a-z0-9][a-z0-9_.-]{0,159}$'
    )
);

CREATE INDEX admin_metric_definitions_runtime_idx
    ON admin_metric_definitions (enabled, source, metric_key)
    WHERE superseded_at IS NULL;

CREATE UNIQUE INDEX admin_metric_definitions_current_unique
    ON admin_metric_definitions (metric_key)
    WHERE superseded_at IS NULL;

CREATE TRIGGER admin_metric_definitions_set_updated_at
    BEFORE UPDATE ON admin_metric_definitions
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
