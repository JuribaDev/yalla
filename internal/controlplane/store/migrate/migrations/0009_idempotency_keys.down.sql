-- Reverse of 0009_idempotency_keys: drop the table. DROP TABLE also drops the
-- table's indexes.

DROP TABLE IF EXISTS idempotency_keys;
