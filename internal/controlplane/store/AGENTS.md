# internal/controlplane/store

Postgres persistence for control-plane source-of-truth state.

## Migrations (`store/migrate`)

- Schema changes are **versioned SQL files**, never ad-hoc DDL. They live in
  `store/migrate/migrations/` named `NNNN_name.up.sql` (required) and
  `NNNN_name.down.sql` (optional — present only when the migration is safely
  reversible). They are embedded into the binary via `//go:embed`.
- The runner owns the `schema_migrations` ledger directly (it is bootstrapped
  by `Migrator`, not by a migration file). Every applied migration is recorded
  with a sha256 checksum of the file it ran.
- `Migrator.Up` refuses to run against a **dirty**, **unknown-version**, or
  **checksum-mismatched** database — these are `errors.Is`-matchable sentinels
  (`ErrDirtyDatabase`, `ErrUnknownVersion`, `ErrChecksumMismatch`). Never "fix"
  a checksum mismatch by editing the recorded checksum; edit the migration back
  or add a new migration.
- **Never edit a migration file that may already be applied anywhere.** Add a
  new, higher-versioned migration instead. Changing applied SQL trips
  `ErrChecksumMismatch` by design.
- Each migration runs in its own transaction, so a failed migration leaves no
  partial schema and no ledger row.
- Migrations with no `args` go through pgx's simple query protocol, so a single
  `.up.sql` file may contain multiple `;`-separated statements.

## Adding a domain table

- Give it a `created_at timestamptz NOT NULL DEFAULT now()` and an
  `updated_at timestamptz NOT NULL DEFAULT now()`, and attach a
  `BEFORE UPDATE` trigger calling `set_updated_at()` (installed by the baseline
  migration) so timestamp maintenance is uniform.
- Every customer-data table must be tenant-scoped: carry an `organization_id`
  (or a verified parent FK chain to one) and a foreign key with the right
  `ON DELETE` behaviour. Add the uniqueness constraints that enforce the
  hierarchy (e.g. unique slug *within* a parent, not globally).

## Tenant hierarchy schema

- The `Organization -> Project -> Environment -> Service` chain is in
  `0002_tenant_hierarchy`. Every child carries its parent IDs **and**
  `organization_id`, and the tenant boundary is enforced by the database via
  **composite foreign keys**: a child references
  `parent (organization_id, ..., id)`, so it can never attach to a parent in a
  different organization. That requires the parent to expose a matching
  `UNIQUE (organization_id, [project_id,] id)` constraint — add one when a new
  table needs to be a composite-FK target.
- `users` is a **global identity table**; users are linked to organizations
  through `memberships`, never owned by one organization directly. Deleting an
  organization cascades to its projects/environments/services/memberships/
  dokploy_refs but leaves `users` rows intact.
- Slugs are `citext` and unique **within the parent scope** — never globally.
- `dokploy_refs` is the polymorphic Yalla-resource -> Dokploy-object mapping.
  It cannot use a single FK (the target table varies), so tenant scoping is the
  `organization_id` FK; `(dokploy_resource, dokploy_id)` is globally unique.
- The schema does **not** pin resource-ID prefix formats with CHECK
  constraints — `internal/controlplane/domain` owns ID well-formedness, and
  `testutil` fixtures deliberately use independent prefixes.

## Testing

- Persistence tests are **integration tests**: they connect with
  `YALLA_TEST_DATABASE_URL`, create an **isolated throwaway database per test**,
  and drop it on cleanup. They `t.Skip` when the env var is unset, so
  `go test ./...` stays green without Postgres.
- `docker compose up -d postgres` provisions a local Postgres; the compose user
  has `CREATE DATABASE` (required by the per-test isolation helper).
- Pure parsing/validation logic (e.g. `LoadMigrations`) is unit-tested with
  `fstest.MapFS` — no database required.
- Schema-level integration tests live in `package store_test` (e.g.
  `store/schema_test.go`) and use `testutil.RequireMigratedDB` +
  `testutil.NewFactory`. They cannot live in `package migrate` (that package is
  the bootstrap layer and cannot import `testutil`). Constraint-violation
  assertions match `*pgconn.PgError` SQLSTATE class `23`.
- When you add a migration, audit `store/migrate/migrate_test.go` for
  assertions that hard-code the latest version (e.g. `Status().Current`); make
  them derive from `m.Migrations()` instead of a literal.
