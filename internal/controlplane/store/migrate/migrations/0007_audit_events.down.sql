-- Reverse of 0007_audit_events: drop the audit table and its immutability
-- trigger function. DROP TABLE also drops the table's indexes and the
-- BEFORE UPDATE trigger; the trigger function is dropped explicitly afterwards.

DROP TABLE IF EXISTS audit_events;
DROP FUNCTION IF EXISTS audit_events_reject_update();
