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

## API keys (`0003_api_keys`, `apikey.go`)

- `api_keys` stores **only a hash** of the secret (`secret_hash`) plus the
  public `prefix`. No column ever holds a usable credential — the plaintext
  token is minted by `internal/controlplane/auth`, shown once, never persisted.
- `APIKeyRepository.FindByPrefix` is the **one deliberate exception** to "scope
  by `organization_id` first": it is the authentication lookup, which runs
  before the caller's tenant is known. The `prefix` is globally `UNIQUE` and
  unguessable, and the returned row carries its own `OrganizationID`, so callers
  scope subsequent work by `key.OrganizationID`. Every other read/mutation
  (`Get`, `ListByOrganization`, `TouchLastUsed`, `Revoke`) is tenant-scoped.
- Tenant-scoped mutations that may match zero rows (`TouchLastUsed`, `Revoke`)
  report `apierr.NotFound` via `tag.RowsAffected() == 0` — a cross-tenant id
  simply does not match. `Revoke` is idempotent (`COALESCE(revoked_at, $3)`).

## Repository transaction pattern (`store.go`, `project.go`, `projectservice.go`)

- The `store` package is the **only** place repository code reaches the
  database, and only via `Store.Read` (read-only transaction → `Querier`) or
  `Store.Write` (read/write transaction → `*Tx`). `Store.Write` commits on a
  nil return and rolls back on **any** error or panic.
- `*Tx` can only be obtained inside `Store.Write`. **Repository mutation
  methods take `*Tx`; read methods take `Querier`.** That makes it
  structurally impossible to run a mutation outside a transaction — which is
  what makes the authorization and quota checks that share that transaction
  impossible to bypass. When you add a repository, follow this split.
- The unit of work (see `ProjectService.Create`) composes, inside one
  `Store.Write`: authorize → reserve quota → write desired state → enqueue
  durable job. Validate input **before** opening the transaction. The policy,
  quota, and jobs dependencies are narrow **port interfaces** (`Authorizer`,
  `QuotaReserver`, `JobEnqueuer`) defined here — the real engines land in later
  stories; tests use fakes. Do not import `policy`/`quota`/`jobs` from `store`.
- Error mapping is uniform: `pgx.ErrNoRows` → `apierr.NotFound`; constraint
  violations (SQLSTATE class 23) → `apierr.Conflict`; any other driver error →
  `apierr.StoreUnavailable`. The raw driver error is wrapped as the cause for
  logging only and never reaches the user-facing message — `mapWriteError` is
  the shared helper. Never build SQL by concatenating caller input; every
  statement is fully parameterized.
- `ProjectRepository`/`ProjectService` are the **reference implementation** of
  this pattern, not a one-off. New customer-data repositories and unit-of-work
  orchestrators copy their shape.

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
- `testutil.Factory` IDs deliberately use **non-canonical** prefixes
  (`org_<16hex>0001`), so they are rejected by `domain.ParseID`. Tests that
  feed a service whose input validation calls `domain.ParseID`/`ParseSlug`
  must seed rows with real `domain.NewID(...)` values, not factory IDs — see
  `seedDomainOrg` in `projectservice_test.go`. Factory fixtures are still fine
  for direct repository/SQL tests that do not go through domain validation.
- Unit tests for the store's pure decision logic (input validation, error
  mapping, constraint classification, constructor guards) live in
  `package store` (`internal_test.go`) and run without a database. Everything
  that touches Postgres is a `package store_test` integration test.
