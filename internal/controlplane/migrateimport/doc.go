// Package migrateimport plans and applies the import of pre-existing Dokploy
// resources into Yalla's source-of-truth hierarchy.
//
// A live Dokploy deployment may already host organizations, projects,
// environments, and services that pre-date Yalla. Customers cannot see those
// resources through Yalla's customer-facing surfaces until a Yalla operator
// has explicitly assigned them to a Yalla organization, because Yalla's policy
// engine — not Dokploy — is authoritative for tenant isolation. This package
// is the workflow that produces, and then (best-effort) applies, that
// assignment.
//
// # Boundary
//
// The package is pure: it depends on small port interfaces (Scanner,
// Repository) and performs no Dokploy or Postgres I/O of its own. The concrete
// Dokploy-backed Scanner and store-backed Repository live in their own
// packages; this package's stable surface — Snapshot, Plan, PlanItem, Result,
// ItemStatus, ItemReason — is the contract those adapters sit behind.
//
// # Plan and apply
//
// Plan reads the live Dokploy snapshot and the operator-supplied
// OwnerAssignment, then returns an ordered Plan of PlanItems. Each PlanItem
// names a Dokploy resource (organization, project, environment, or service),
// proposes a deterministic Yalla slug and display name derived from the
// Dokploy name, and classifies the item as one of:
//
//   - StatusReady              — owner is assigned, parent is known or also
//     about to be imported, type is supported, no name collision. Apply will
//     persist the row.
//   - StatusPendingOwner       — no explicit owner is assigned. The item is
//     listed for review but never reaches Apply.
//   - StatusSkipDuplicate      — a Yalla resource with the same slug already
//     exists under the resolved parent. Apply skips it; the operator must
//     reconcile manually before importing.
//   - StatusSkipMissingParent  — the parent was not imported (or was itself
//     skipped). Apply cannot honour an orphaned child.
//   - StatusSkipUnsupported    — Dokploy reported a service type Yalla does
//     not support. Apply skips it.
//   - StatusSkipAlreadyImported — a Yalla row already records this Dokploy
//     resource. Apply skips it as an idempotent no-op.
//
// Plan is pure: it produces the same Plan for the same (Snapshot, Assignment,
// Repository state) on every call and never writes anything.
//
// Apply iterates the StatusReady items in hierarchy order (organization,
// project, environment, service) and asks the Repository to persist each one.
// Apply is best-effort — a single failure does not stop the rest of the plan;
// every failure is collected in Result.Failures with its error string
// scrubbed through the configured output.Redactor.
//
// # Redaction
//
// Dokploy resources may carry env vars and other secret-shaped fields. The
// importer's classification surface (Reason, Status, slug, display name) is
// value-free for sensitive fields: env var keys and values never reach a
// PlanItem, a log attribute, or an audit metadata bag. The deterministic slug
// is derived from the human-authored Dokploy resource name only, and that name
// is itself bounded and sanitised through domain.NormalizeSlug.
//
// # Dry run
//
// "Dry run" is just calling Plan without calling Apply. The Plan is fully
// serialisable as JSON (PlanItem fields are stable and named) and is the
// payload of the eventual POST /v1/admin/dokploy/import dry-run response.
package migrateimport
