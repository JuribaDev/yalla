DROP INDEX IF EXISTS billing_export_items_export_idx;
DROP TABLE IF EXISTS billing_export_items;

DROP INDEX IF EXISTS billing_exports_due_idx;
DROP TRIGGER IF EXISTS billing_exports_set_updated_at ON billing_exports;
DROP TABLE IF EXISTS billing_exports;
