-- Reverse of 0001_baseline.up.sql.
--
-- Extensions and the trigger function are dropped in reverse dependency order.
-- This down script is safe only against a database where no later migration
-- has created objects that depend on these primitives; the migration runner
-- enforces that by applying down scripts strictly newest-first.

DROP FUNCTION IF EXISTS set_updated_at();
DROP EXTENSION IF EXISTS citext;
DROP EXTENSION IF EXISTS pgcrypto;
