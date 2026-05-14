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

## Testing

- Persistence tests are **integration tests**: they connect with
  `YALLA_TEST_DATABASE_URL`, create an **isolated throwaway database per test**,
  and drop it on cleanup. They `t.Skip` when the env var is unset, so
  `go test ./...` stays green without Postgres.
- `docker compose up -d postgres` provisions a local Postgres; the compose user
  has `CREATE DATABASE` (required by the per-test isolation helper).
- Pure parsing/validation logic (e.g. `LoadMigrations`) is unit-tested with
  `fstest.MapFS` — no database required.
