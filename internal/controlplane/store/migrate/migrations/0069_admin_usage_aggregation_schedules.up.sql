-- Backoffice usage aggregation schedules. Rows are global operator-owned
-- runtime contracts that tell aggregators how to replay, close, and handle
-- late events for each source metric.

CREATE DOMAIN usage_late_event_mode AS text
    CHECK (VALUE IN ('ignore', 'adjust', 'quarantine'));

CREATE TABLE admin_usage_aggregation_schedules (
    id                           text                   PRIMARY KEY CHECK (length(id) > 0),
    schedule_key                 citext                 NOT NULL CHECK (schedule_key ~ '^[a-z0-9][a-z0-9_]{0,127}$'),
    version                      integer                NOT NULL CHECK (version > 0),
    source                       text                   NOT NULL CHECK (source ~ '^[a-z0-9][a-z0-9_]{0,127}$'),
    metric_key                   citext                 NOT NULL CHECK (metric_key ~ '^[a-z0-9][a-z0-9_]{0,127}$'),
    aggregation_interval_seconds integer                NOT NULL CHECK (aggregation_interval_seconds BETWEEN 60 AND 2678400),
    replay_lookback_seconds      integer                NOT NULL CHECK (replay_lookback_seconds BETWEEN 0 AND 2678400),
    close_delay_seconds          integer                NOT NULL CHECK (close_delay_seconds BETWEEN 0 AND 2678400),
    late_event_mode              usage_late_event_mode  NOT NULL,
    enabled                      boolean                NOT NULL DEFAULT true,
    revision                     bigint                 NOT NULL DEFAULT 1 CHECK (revision > 0),
    published_at                 timestamptz            NOT NULL DEFAULT now(),
    created_at                   timestamptz            NOT NULL DEFAULT now(),
    updated_at                   timestamptz            NOT NULL DEFAULT now(),
    UNIQUE (schedule_key),
    UNIQUE (source, metric_key)
);

CREATE INDEX admin_usage_aggregation_schedules_runtime_idx
    ON admin_usage_aggregation_schedules (enabled, source, metric_key);

CREATE TRIGGER admin_usage_aggregation_schedules_set_updated_at
    BEFORE UPDATE ON admin_usage_aggregation_schedules
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
