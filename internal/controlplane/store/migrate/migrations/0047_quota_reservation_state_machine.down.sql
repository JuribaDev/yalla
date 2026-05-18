DROP TRIGGER IF EXISTS quota_reservation_events_no_update ON quota_reservation_events;
DROP FUNCTION IF EXISTS quota_reservation_events_reject_update();
DROP INDEX IF EXISTS quota_reservation_events_org_occurred_idx;
DROP INDEX IF EXISTS quota_reservation_events_reservation_occurred_idx;
DROP TABLE IF EXISTS quota_reservation_events;
