# retention

Central authority for Yalla's soft-delete and retention policy. The package is
pure: it has no I/O and depends only on the standard library, so its
predicates are cheap to call from anywhere — handlers, services, repositories,
workers, and admin tooling — without dragging a database or network
dependency along.

## Boundary

- `retention` defines a closed `ResourceKind` set, a `Window` struct of
  durations, and a `Policy` that maps each kind to its window.
- `retention` answers three time-based predicates over `(kind, stampedAt,
  now)`: `RestorableAt`, `ReapableAt`, and `AllowsSlugReuse`, plus two
  convenience getters (`RestoreDeadline`, `ReapDeadline`) and one diagnostic
  (`RemainingRestore`).
- `retention` never imports `store`, `httpapi`, `worker`, `dokploy`,
  `apierr`, or `audit`. The package is a leaf — callers depend on it; it
  depends on no Yalla code.
- Tests cover every kind, every transition (restore window → grace →
  reapable), every terminal kind (api_key, membership), and the zero
  `Policy` so the package is safe to embed in any future caller.

## Conventions

- The set of `ResourceKind` values is closed. Adding a new kind requires
  updating `allKinds`, `Valid`, `SoftDeleteColumn`, the default Window in
  `DefaultPolicy`, and the closed-set tests. If you forget any of these, a
  test fails — there is no silent extension path.
- `Window.validate` runs on every `NewPolicy` entry. A restorable kind must
  have a positive `RestoreWindow`; a non-restorable kind must have zero
  `RestoreWindow`; `ReapAfter` must be non-negative and (when non-zero) at
  least as large as `RestoreWindow`. These invariants keep the lifecycle
  predicates monotone: restorable → held → reapable, in that order.
- The strict `<` comparison at the upper bound of `RestorableAt` and the
  `>=` comparison at the lower bound of `ReapableAt` mean a row becomes
  reapable at exactly the moment it stops being restorable. A worker that
  wakes up every minute picks the row up on the first tick at or after the
  reap deadline.
- Slug reuse is a function of `ReapableAt`. The schema does not carry a
  partial unique index excluding soft-deleted rows, so the slug is held
  until the row is physically gone. `AllowsSlugReuse` reflects this exactly.

## Wiring

- Handlers and services should call `retention.Policy.RestorableAt(kind,
  stampedAt, time.Now())` instead of inlining a duration comparison.
- The future teardown worker should iterate `retention.AllKinds()`, look up
  each kind's `SoftDeleteColumn`, scan rows where the column is non-NULL
  and the timestamp is older than `ReapAfter`, and call the kind-specific
  hard-delete repository method.
- A custom policy (e.g. shorter windows in tests, longer windows in
  enterprise plans) flows through `retention.NewPolicy`. The constructor
  copies the input map, so caller mutation cannot tamper with a live
  Policy.

## Audit-addressability

The retention policy does not delete audit rows. Audit events are addressed
by `(organization_id, id)` and outlive every resource referenced by them
until the tenant itself is purged. A hard-deleted resource is still
audit-addressable by id; `retention` only governs the resource rows, never
the audit trail.
