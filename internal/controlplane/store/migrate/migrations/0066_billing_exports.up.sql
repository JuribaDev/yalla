CREATE TABLE billing_exports (
    id text PRIMARY KEY,
    organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    subscription_id text NOT NULL,
    provider text NOT NULL,
    period_start timestamptz NOT NULL,
    period_end timestamptz NOT NULL,
    status text NOT NULL DEFAULT 'pending',
    attempt_count integer NOT NULL DEFAULT 0,
    requested_at timestamptz NOT NULL,
    last_attempt_at timestamptz,
    next_attempt_at timestamptz,
    exported_at timestamptz,
    provider_response_id text,
    last_error_summary text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT billing_exports_subscription_fk
        FOREIGN KEY (organization_id, subscription_id)
        REFERENCES subscriptions (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT billing_exports_provider_valid CHECK (provider ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    CONSTRAINT billing_exports_period_valid CHECK (period_end > period_start),
    CONSTRAINT billing_exports_status_valid CHECK (status IN ('pending', 'succeeded', 'failed')),
    CONSTRAINT billing_exports_attempt_count_valid CHECK (attempt_count >= 0),
    CONSTRAINT billing_exports_provider_response_id_valid CHECK (provider_response_id IS NULL OR length(provider_response_id) BETWEEN 1 AND 200),
    CONSTRAINT billing_exports_error_summary_valid CHECK (last_error_summary IS NULL OR length(last_error_summary) <= 500),
    UNIQUE (organization_id, id),
    UNIQUE (organization_id, subscription_id, period_start, period_end, provider)
);

CREATE TRIGGER billing_exports_set_updated_at
    BEFORE UPDATE ON billing_exports
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE INDEX billing_exports_due_idx
    ON billing_exports (provider, next_attempt_at)
    WHERE status = 'failed';

CREATE TABLE billing_export_items (
    id text PRIMARY KEY,
    organization_id text NOT NULL,
    export_id text NOT NULL,
    counter_id text NOT NULL,
    key text NOT NULL,
    unit text NOT NULL,
    quantity double precision NOT NULL,
    source text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT billing_export_items_export_fk
        FOREIGN KEY (organization_id, export_id)
        REFERENCES billing_exports (organization_id, id)
        ON DELETE CASCADE,
    CONSTRAINT billing_export_items_counter_fk
        FOREIGN KEY (organization_id, counter_id)
        REFERENCES usage_counters (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT billing_export_items_key_valid CHECK (key ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    CONSTRAINT billing_export_items_unit_valid CHECK (unit ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    CONSTRAINT billing_export_items_source_valid CHECK (source ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    CONSTRAINT billing_export_items_quantity_finite CHECK (quantity = quantity AND quantity NOT IN ('Infinity'::double precision, '-Infinity'::double precision)),
    UNIQUE (organization_id, export_id, counter_id)
);

CREATE INDEX billing_export_items_export_idx ON billing_export_items (organization_id, export_id);
