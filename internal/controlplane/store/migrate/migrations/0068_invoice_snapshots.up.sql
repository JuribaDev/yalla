CREATE TABLE invoice_snapshots (
    id text PRIMARY KEY,
    organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    subscription_id text NOT NULL,
    billing_export_id text,
    period_start timestamptz NOT NULL,
    period_end timestamptz NOT NULL,
    status text NOT NULL DEFAULT 'closed',
    close_version integer NOT NULL,
    aggregation_version integer NOT NULL,
    closed_at timestamptz NOT NULL,
    reopened_at timestamptz,
    reopened_by_actor_id text,
    plan_id text NOT NULL REFERENCES plans(id) ON DELETE RESTRICT,
    plan_slug text NOT NULL,
    plan_version integer NOT NULL,
    entitlement_revision text NOT NULL,
    usage_event_checksum text NOT NULL,
    adjustment_checksum text NOT NULL,
    export_status text NOT NULL DEFAULT 'none',
    request_id text NOT NULL,
    correlation_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT invoice_snapshots_subscription_fk
        FOREIGN KEY (organization_id, subscription_id)
        REFERENCES subscriptions (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT invoice_snapshots_export_fk
        FOREIGN KEY (organization_id, billing_export_id)
        REFERENCES billing_exports (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT invoice_snapshots_status_valid CHECK (status IN ('closed', 'reopened')),
    CONSTRAINT invoice_snapshots_export_status_valid CHECK (export_status IN ('none', 'pending', 'succeeded', 'failed')),
    CONSTRAINT invoice_snapshots_period_valid CHECK (period_end > period_start),
    CONSTRAINT invoice_snapshots_close_version_positive CHECK (close_version > 0),
    CONSTRAINT invoice_snapshots_aggregation_version_positive CHECK (aggregation_version > 0),
    CONSTRAINT invoice_snapshots_closed_after_period CHECK (closed_at >= period_end),
    CONSTRAINT invoice_snapshots_reopened_consistent CHECK (
        (status = 'reopened' AND reopened_at IS NOT NULL AND reopened_by_actor_id IS NOT NULL AND length(reopened_by_actor_id) > 0)
        OR (status = 'closed' AND reopened_at IS NULL AND reopened_by_actor_id IS NULL)
    ),
    CONSTRAINT invoice_snapshots_plan_slug_valid CHECK (plan_slug ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    CONSTRAINT invoice_snapshots_plan_version_positive CHECK (plan_version > 0),
    CONSTRAINT invoice_snapshots_request_id_valid CHECK (length(request_id) BETWEEN 1 AND 128),
    CONSTRAINT invoice_snapshots_correlation_id_valid CHECK (length(correlation_id) BETWEEN 1 AND 128),
    UNIQUE (organization_id, id),
    UNIQUE (organization_id, subscription_id, period_start, period_end, close_version)
);

CREATE TRIGGER invoice_snapshots_set_updated_at
    BEFORE UPDATE ON invoice_snapshots
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE INDEX invoice_snapshots_org_period_idx
    ON invoice_snapshots (organization_id, period_start, period_end, close_version DESC);

CREATE TABLE invoice_snapshot_items (
    id text PRIMARY KEY,
    organization_id text NOT NULL,
    snapshot_id text NOT NULL,
    counter_id text NOT NULL,
    key text NOT NULL,
    unit text NOT NULL,
    source text NOT NULL,
    counter_quantity double precision NOT NULL,
    adjustment_quantity double precision NOT NULL DEFAULT 0,
    final_quantity double precision NOT NULL,
    aggregation_version integer NOT NULL,
    entitlement_key text,
    overage_policy_mode text,
    overage_decision text,
    included_quantity double precision,
    overage_quantity double precision,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT invoice_snapshot_items_snapshot_fk
        FOREIGN KEY (organization_id, snapshot_id)
        REFERENCES invoice_snapshots (organization_id, id)
        ON DELETE CASCADE,
    CONSTRAINT invoice_snapshot_items_counter_fk
        FOREIGN KEY (organization_id, counter_id)
        REFERENCES usage_counters (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT invoice_snapshot_items_key_valid CHECK (key ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    CONSTRAINT invoice_snapshot_items_unit_valid CHECK (unit ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    CONSTRAINT invoice_snapshot_items_source_valid CHECK (source ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    CONSTRAINT invoice_snapshot_items_counter_quantity_finite CHECK (counter_quantity = counter_quantity AND counter_quantity NOT IN ('Infinity'::double precision, '-Infinity'::double precision)),
    CONSTRAINT invoice_snapshot_items_adjustment_quantity_finite CHECK (adjustment_quantity = adjustment_quantity AND adjustment_quantity NOT IN ('Infinity'::double precision, '-Infinity'::double precision)),
    CONSTRAINT invoice_snapshot_items_final_quantity_finite CHECK (final_quantity = final_quantity AND final_quantity NOT IN ('Infinity'::double precision, '-Infinity'::double precision)),
    CONSTRAINT invoice_snapshot_items_aggregation_version_positive CHECK (aggregation_version > 0),
    CONSTRAINT invoice_snapshot_items_entitlement_key_valid
        CHECK (entitlement_key IS NULL OR entitlement_key ~ '^[a-z0-9][a-z0-9_.-]{0,127}$'),
    CONSTRAINT invoice_snapshot_items_overage_policy_mode_valid
        CHECK (overage_policy_mode IS NULL OR overage_policy_mode IN ('allow', 'warn', 'block', 'require_admin_review')),
    CONSTRAINT invoice_snapshot_items_overage_decision_valid
        CHECK (overage_decision IS NULL OR overage_decision IN ('within_included', 'allowed', 'warned', 'blocked', 'admin_review_required')),
    CONSTRAINT invoice_snapshot_items_included_quantity_finite
        CHECK (included_quantity IS NULL OR (included_quantity = included_quantity AND included_quantity NOT IN ('Infinity'::double precision, '-Infinity'::double precision))),
    CONSTRAINT invoice_snapshot_items_overage_quantity_finite
        CHECK (overage_quantity IS NULL OR (overage_quantity = overage_quantity AND overage_quantity NOT IN ('Infinity'::double precision, '-Infinity'::double precision))),
    CONSTRAINT invoice_snapshot_items_overage_quantity_nonnegative
        CHECK (overage_quantity IS NULL OR overage_quantity >= 0),
    UNIQUE (organization_id, snapshot_id, counter_id)
);

CREATE INDEX invoice_snapshot_items_snapshot_idx
    ON invoice_snapshot_items (organization_id, snapshot_id);
