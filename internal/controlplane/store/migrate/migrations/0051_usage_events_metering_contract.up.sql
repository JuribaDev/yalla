ALTER TABLE services
    ADD CONSTRAINT services_hierarchy_identity_key
    UNIQUE (organization_id, project_id, environment_id, id);

ALTER TABLE usage_events
    ADD COLUMN project_id text,
    ADD COLUMN environment_id text,
    ADD COLUMN service_id text,
    ADD COLUMN quantity double precision,
    ADD COLUMN unit text NOT NULL DEFAULT 'count',
    ADD COLUMN source text NOT NULL DEFAULT 'quota',
    ADD COLUMN idempotency_key text,
    ADD COLUMN period_start timestamptz,
    ADD COLUMN period_end timestamptz;

UPDATE usage_events
   SET quantity = delta::double precision,
       period_start = date_trunc('month', occurred_at AT TIME ZONE 'UTC') AT TIME ZONE 'UTC',
       period_end = (date_trunc('month', occurred_at AT TIME ZONE 'UTC') + interval '1 month') AT TIME ZONE 'UTC'
 WHERE quantity IS NULL;

ALTER TABLE usage_events
    ALTER COLUMN quantity SET DEFAULT 0,
    ALTER COLUMN quantity SET NOT NULL,
    ALTER COLUMN period_start SET DEFAULT (date_trunc('month', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'),
    ALTER COLUMN period_end SET DEFAULT ((date_trunc('month', now() AT TIME ZONE 'UTC') + interval '1 month') AT TIME ZONE 'UTC'),
    ALTER COLUMN period_start SET NOT NULL,
    ALTER COLUMN period_end SET NOT NULL,
    ADD CONSTRAINT usage_events_quantity_finite CHECK (quantity = quantity AND quantity NOT IN ('Infinity'::double precision, '-Infinity'::double precision)),
    ADD CONSTRAINT usage_events_unit_valid CHECK (unit ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    ADD CONSTRAINT usage_events_source_valid CHECK (source ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    ADD CONSTRAINT usage_events_idempotency_key_valid CHECK (idempotency_key IS NULL OR length(idempotency_key) BETWEEN 1 AND 200),
    ADD CONSTRAINT usage_events_period_valid CHECK (period_end > period_start AND occurred_at >= period_start AND occurred_at < period_end),
    ADD CONSTRAINT usage_events_scope_shape CHECK (
        (environment_id IS NULL OR project_id IS NOT NULL) AND
        (service_id IS NULL OR (project_id IS NOT NULL AND environment_id IS NOT NULL))
    ),
    ADD CONSTRAINT usage_events_project_fk
        FOREIGN KEY (organization_id, project_id)
        REFERENCES projects (organization_id, id),
    ADD CONSTRAINT usage_events_environment_fk
        FOREIGN KEY (organization_id, project_id, environment_id)
        REFERENCES environments (organization_id, project_id, id),
    ADD CONSTRAINT usage_events_service_fk
        FOREIGN KEY (organization_id, project_id, environment_id, service_id)
        REFERENCES services (organization_id, project_id, environment_id, id);

ALTER TABLE usage_events DROP CONSTRAINT IF EXISTS usage_events_event_type_check;
ALTER TABLE usage_events
    ADD CONSTRAINT usage_events_event_type_check
    CHECK (event_type IN ('reserved', 'committed', 'released', 'expired', 'consumed', 'adjusted'));

CREATE UNIQUE INDEX usage_events_org_source_idempotency_idx
    ON usage_events (organization_id, source, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

CREATE INDEX usage_events_org_period_idx ON usage_events (organization_id, period_start, period_end);
CREATE INDEX usage_events_project_id_idx ON usage_events (project_id) WHERE project_id IS NOT NULL;
CREATE INDEX usage_events_environment_id_idx ON usage_events (environment_id) WHERE environment_id IS NOT NULL;
CREATE INDEX usage_events_service_id_idx ON usage_events (service_id) WHERE service_id IS NOT NULL;

CREATE FUNCTION usage_events_reject_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'usage_events is append-only: UPDATE is not permitted';
END;
$$;

CREATE TRIGGER usage_events_no_update
    BEFORE UPDATE ON usage_events
    FOR EACH ROW EXECUTE FUNCTION usage_events_reject_update();
