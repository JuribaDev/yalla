// Package retention is the central authority for Yalla's soft-delete and
// retention policy across every customer-data resource. It is pure, has no
// I/O, and depends only on the standard library; store, worker, and admin
// callers consume it to decide whether a soft-deleted row can be restored,
// when it becomes eligible for hard delete, and whether its slug is held or
// free.
//
// # Soft-delete contract
//
// Every customer-facing tenant resource (organization, project, environment,
// service) records the customer's intent to delete by stamping a
// deletion_scheduled_at column rather than removing the row. API keys mirror
// the same pattern through a revoked_at column. Memberships are the one
// exception: they are hard-deleted at the SQL layer, with the user_role
// version counter invalidating outstanding session tokens and the
// audit_events row preserving the historical trail.
//
// The retention package names each shape through ResourceKind. SupportsSoftDelete
// reports whether the kind's schema carries a deletion_scheduled_at or
// revoked_at column, and Restorable reports whether a customer-facing restore
// endpoint reverses the stamp.
//
// # Retention windows
//
// Each kind has a Window with two durations:
//
//   - RestoreWindow — the time after the lifecycle stamp during which a
//     customer or admin can restore the row. Past this window, restoration is
//     refused even though the row physically remains.
//   - ReapAfter — the time after the lifecycle stamp at which the destructive
//     teardown worker is permitted to hard-delete the row and free its
//     slug for reuse. ReapAfter must be greater than or equal to
//     RestoreWindow; the gap between the two is the operator's grace period
//     for an out-of-band restore.
//
// Policy.RestorableAt and Policy.ReapableAt are pure time-based predicates
// over (kind, stampedAt, now). They are the contract every restore endpoint
// and every teardown worker must use; a divergent inline calculation in a
// caller is a bug.
//
// # Name reuse
//
// Slugs are unique within their parent scope. The schema does not carry a
// partial unique index excluding soft-deleted rows, so a slug stays reserved
// for the lifetime of its row. Policy.AllowsSlugReuse reports true only once
// the row is reapable: that is the earliest moment a teardown worker may
// hard-delete the row and free its slug. Customers therefore observe the
// slug as held during the retention window and as free only after the row
// is gone, which matches the schema-level enforcement.
//
// # Audit addressability
//
// Audit events outlive the resources they describe. The audit_events table
// has no FK to projects/environments/services/api_keys/memberships — it only
// cascades on organization deletion — so a hard-deleted resource is still
// addressable by its id in the audit trail until its tenant is itself
// hard-deleted. The retention policy preserves this guarantee by never
// asking a caller to delete audit rows.
package retention
