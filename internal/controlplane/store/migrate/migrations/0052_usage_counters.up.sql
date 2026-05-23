CREATE TABLE usage_counters (
    id text PRIMARY KEY,
    organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    key text NOT NULL,
    unit text NOT NULL,
    period_start timestamptz NOT NULL,
    period_end timestamptz NOT NULL,
    quantity double precision NOT NULL DEFAULT 0,
    source text NOT NULL,
    aggregation_version integer NOT NULL,
    last_aggregated_at timestamptz NOT NULL,
    closed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT usage_counters_key_valid CHECK (key ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    CONSTRAINT usage_counters_unit_valid CHECK (unit ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    CONSTRAINT usage_counters_source_valid CHECK (source ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    CONSTRAINT usage_counters_quantity_finite CHECK (quantity = quantity AND quantity NOT IN ('Infinity'::double precision, '-Infinity'::double precision)),
    CONSTRAINT usage_counters_period_valid CHECK (period_end > period_start),
    CONSTRAINT usage_counters_aggregation_version_positive CHECK (aggregation_version > 0),
    CONSTRAINT usage_counters_closed_after_period CHECK (closed_at IS NULL OR closed_at >= period_end),
    UNIQUE (organization_id, id),
    UNIQUE (organization_id, key, unit, period_start, period_end, source)
);

CREATE TRIGGER usage_counters_set_updated_at
    BEFORE UPDATE ON usage_counters
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE INDEX usage_counters_org_period_idx ON usage_counters (organization_id, period_start, period_end);

CREATE TABLE usage_counter_adjustments (
    id text PRIMARY KEY,
    organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    counter_id text NOT NULL,
    key text NOT NULL,
    unit text NOT NULL,
    source text NOT NULL,
    period_start timestamptz NOT NULL,
    period_end timestamptz NOT NULL,
    delta_quantity double precision NOT NULL,
    aggregation_version integer NOT NULL,
    reason text NOT NULL DEFAULT 'late_event',
    last_event_occurred_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT usage_counter_adjustments_counter_fk
        FOREIGN KEY (organization_id, counter_id)
        REFERENCES usage_counters (organization_id, id)
        ON DELETE CASCADE,
    CONSTRAINT usage_counter_adjustments_key_valid CHECK (key ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    CONSTRAINT usage_counter_adjustments_unit_valid CHECK (unit ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    CONSTRAINT usage_counter_adjustments_source_valid CHECK (source ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    CONSTRAINT usage_counter_adjustments_delta_finite CHECK (delta_quantity = delta_quantity AND delta_quantity NOT IN ('Infinity'::double precision, '-Infinity'::double precision)),
    CONSTRAINT usage_counter_adjustments_delta_nonzero CHECK (delta_quantity <> 0),
    CONSTRAINT usage_counter_adjustments_period_valid CHECK (period_end > period_start),
    CONSTRAINT usage_counter_adjustments_aggregation_version_positive CHECK (aggregation_version > 0)
);

CREATE INDEX usage_counter_adjustments_org_period_idx ON usage_counter_adjustments (organization_id, period_start, period_end);
