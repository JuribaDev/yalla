DROP TRIGGER IF EXISTS usage_events_no_update ON usage_events;
DROP FUNCTION IF EXISTS usage_events_reject_update();

DROP INDEX IF EXISTS usage_events_service_id_idx;
DROP INDEX IF EXISTS usage_events_environment_id_idx;
DROP INDEX IF EXISTS usage_events_project_id_idx;
DROP INDEX IF EXISTS usage_events_org_period_idx;
DROP INDEX IF EXISTS usage_events_org_source_idempotency_idx;

ALTER TABLE usage_events
    DROP CONSTRAINT IF EXISTS usage_events_service_fk,
    DROP CONSTRAINT IF EXISTS usage_events_environment_fk,
    DROP CONSTRAINT IF EXISTS usage_events_project_fk,
    DROP CONSTRAINT IF EXISTS usage_events_scope_shape,
    DROP CONSTRAINT IF EXISTS usage_events_period_valid,
    DROP CONSTRAINT IF EXISTS usage_events_idempotency_key_valid,
    DROP CONSTRAINT IF EXISTS usage_events_source_valid,
    DROP CONSTRAINT IF EXISTS usage_events_unit_valid,
    DROP CONSTRAINT IF EXISTS usage_events_quantity_finite;

ALTER TABLE usage_events DROP CONSTRAINT IF EXISTS usage_events_event_type_check;
ALTER TABLE usage_events
    ADD CONSTRAINT usage_events_event_type_check
    CHECK (event_type IN ('reserved', 'committed', 'released', 'expired', 'consumed', 'adjusted'));

ALTER TABLE usage_events
    DROP COLUMN IF EXISTS period_end,
    DROP COLUMN IF EXISTS period_start,
    DROP COLUMN IF EXISTS idempotency_key,
    DROP COLUMN IF EXISTS source,
    DROP COLUMN IF EXISTS unit,
    DROP COLUMN IF EXISTS quantity,
    DROP COLUMN IF EXISTS service_id,
    DROP COLUMN IF EXISTS environment_id,
    DROP COLUMN IF EXISTS project_id;
