-- Drop the api_keys table. DROP TABLE removes its index and BEFORE UPDATE
-- trigger with it; the shared set_updated_at() function belongs to the
-- baseline migration and is left in place.
DROP TABLE IF EXISTS api_keys;
