// Package reconcile detects and resolves drift between Yalla's source-of-truth
// hierarchy in Postgres and the actual state of the provisioning backend
// (Dokploy).
//
// The engine is pure: it depends on small port interfaces (DesiredStateReader,
// ActualStateReader, Repairer, ReviewRecorder, UnmanagedRecorder) and performs
// no I/O of its own. Postgres-backed and Dokploy-backed adapters land in the
// store/worker layers; the reconcile package never imports them. The
// diff/classify step is a pure function over data structures and is heavily
// unit-tested without any database or live Dokploy connection.
//
// # Drift classification
//
// The engine classifies every divergence between desired and actual state into
// exactly one of three buckets:
//
//   - Safe drift  — repair is reversible and cannot cause data loss. The
//     engine asks the Repairer to converge actual back to desired (re-create a
//     missing managed domain, update an environment variable on a known
//     service, etc.). Repairs are recorded for the audit trail.
//   - Dangerous drift — repair could destroy data, mask compromise, or
//     resurrect resources the customer intentionally removed. The engine never
//     auto-repairs; it records a ReviewEvent and lets a human operator decide.
//     Missing managed services, missing managed databases, host renames,
//     service-type changes, and removed domains all land here.
//   - Unmanaged — a Dokploy resource exists with no Yalla counterpart. The
//     engine records it through the UnmanagedRecorder; unmanaged resources are
//     never exposed to customers by default and are never auto-deleted.
//
// # Reason codes
//
// Every Action, ReviewEvent, and UnmanagedResource carries a stable Reason
// code (DriftReason* constants). Reasons name what was detected, never the
// submitted value, so an env var whose value is a secret can be classified as
// "env_var_changed" without its value ever reaching a log, error, audit
// metadata bag, or test output.
//
// # Process lifecycle
//
// A Reconciler is constructed once at worker startup with concrete adapters,
// then drives Reconcile(ctx, orgID) per scheduled tick. Each tick:
//
//  1. Reads desired state from Yalla (DesiredStateReader.Read).
//  2. Reads actual state from Dokploy (ActualStateReader.Read).
//  3. Computes a Plan (pure Diff).
//  4. Applies safe repairs (Repairer.*), records dangerous drift through the
//     ReviewRecorder, and marks unmanaged resources through the
//     UnmanagedRecorder.
//
// Apply is best-effort and continues past per-action failures, returning a
// Result that names every failed action with a redacted error. The caller (the
// worker loop) decides whether to retry the whole tick.
package reconcile
