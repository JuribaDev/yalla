# migrateimport — Dokploy import workflow

`internal/controlplane/migrateimport` plans and applies the import of
pre-existing Dokploy resources into Yalla's source-of-truth hierarchy. It is
the workflow the eventual `POST /v1/admin/dokploy/import` endpoint hosts; the
package itself is pure and has no HTTP, Dokploy, or Postgres dependency.

## Conventions

- **Pure orchestrator.** The package depends on small port interfaces
  (`Scanner`, `Repository`) and performs no I/O of its own. The concrete
  Dokploy-backed Scanner and store-backed Repository live in their own
  packages — they never reach back into this one. The stable surface
  (`Snapshot`, `Plan`, `PlanItem`, `Result`, `ItemStatus`, `ItemReason`,
  `OwnerAssignment`) is the contract those adapters sit behind.
- **Plan is pure.** `Importer.Plan` returns the same `Plan` for the same
  (`Snapshot`, `OwnerAssignment`, Repository state). Plan never writes; "dry
  run" is just calling Plan without Apply, and the JSON shape of `Plan` is
  what the eventual admin endpoint surfaces inside a `yalla.output.v1`
  envelope.
- **Explicit owner only.** A blank or mismatched `OwnerAssignment` short-
  circuits to a plan of `StatusPendingOwner` items; the Repository is not
  queried and `Apply` always skips them. "Customer-visible by default" is
  prevented at the planner, not the persistence layer.
- **Value-free classification.** `Reason`, `Status`, and every other
  classification field carry only stable codes. Dokploy resource *names*
  travel through `ProposedDisplay`/`ProposedSlug` (intentionally — that is
  the importer's only product), but env vars, tokens, and other secret-shaped
  fields never reach a `PlanItem`. Add a "never leaks the value" assertion
  to any new classification rule that ingests a sensitive field.
- **Deterministic order.** Plan iterates resources sorted by Dokploy
  resource ID at each hierarchy depth, then emits items in
  `organization -> project -> environment -> service` order. The hierarchy
  order is also what Apply iterates so a child's parent is always resolved
  before the child is persisted.
- **Best-effort Apply.** `Importer.Apply` continues past per-item failures;
  each failure is collected in `Result.Failures` with its error string
  scrubbed through the configured `output.Redactor`. Apply returns a non-nil
  top-level error only on `ctx.Err()` or a structurally invalid plan
  (missing owner with `StatusReady` items).
- **Validation surface.** The only request inputs the planner validates are
  the Dokploy organization ID, the optional Yalla organization ID
  (`domain.ParseID` plus a kind check), and the Dokploy↔Yalla cross-binding
  in `OwnerAssignment`. Scanner/Repository failures are returned as their
  catalogued `apierr.*` code; an untyped error is upgraded to
  `apierr.DokployUnavailable` (scanner) or `apierr.StoreUnavailable`
  (repository).
- **Slug derivation.** Yalla slugs are derived from Dokploy resource names
  only via `domain.NormalizeSlug`. A name that does not normalise to a valid
  slug becomes a `StatusSkipDuplicate` item with reason `duplicate_name`
  (the operator must rename the Dokploy resource — the importer never invents
  a slug).
- **Unsupported services skip, not fail.** A Dokploy service type Yalla does
  not support (anything other than `application`, `compose`, or `database`),
  or a database service missing its engine, classifies as
  `StatusSkipUnsupported`. Apply skips it; the rest of the plan still runs.
- **No process-level I/O.** Concrete adapters (Dokploy-backed Scanner, store-
  backed Repository) land in their own packages once the service-level
  persistence schema ships. This package's stable surface is the contract
  those adapters sit behind.

## Testing

- Use the in-package `fakeScanner` + `fakeRepo` from `importer_test.go` as
  the template for new test doubles. Both are concurrent-safe and record
  every call for ordering / partial-failure assertions.
- Cover every new classification rule with at least one positive case (the
  planner emits the rule's `ItemStatus`+`ItemReason`) and one negative case
  (a sibling input does *not* fire the rule). Reason codes are public
  contract.
- Any new sensitive field added to `Snapshot*` or `PlanItem` needs a
  redaction test (`output.NewRedactor(secret)` + assert the secret never
  appears in `err.Error()`, `Result.Failures`, or the log buffer).
