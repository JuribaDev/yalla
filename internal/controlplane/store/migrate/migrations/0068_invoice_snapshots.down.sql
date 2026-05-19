DROP INDEX IF EXISTS invoice_snapshot_items_snapshot_idx;
DROP TABLE IF EXISTS invoice_snapshot_items;

DROP INDEX IF EXISTS invoice_snapshots_org_period_idx;
DROP TRIGGER IF EXISTS invoice_snapshots_set_updated_at ON invoice_snapshots;
DROP TABLE IF EXISTS invoice_snapshots;
