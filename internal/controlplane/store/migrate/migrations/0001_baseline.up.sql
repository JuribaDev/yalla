-- Baseline migration for the Yalla control-plane database.
--
-- This migration does not create domain tables. It establishes the shared
-- conventions that every later migration depends on:
--
--   * extensions used by domain tables (gen_random_uuid / digest from pgcrypto,
--     case-insensitive text from citext for emails and slugs), and
--   * the set_updated_at() trigger function that enforces the timestamp
--     convention uniformly across every table.
--
-- Domain tables (organizations, users, projects, environments, services, quota,
-- audit, jobs, ...) are added by later, focused migrations.

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

-- set_updated_at keeps an updated_at column current on every UPDATE. Every
-- control-plane table that carries an updated_at column attaches a BEFORE
-- UPDATE trigger that calls this function, so timestamp maintenance is uniform
-- and cannot be forgotten by an individual migration author.
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;
