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
  Domain mappings use `yalla_kind = 'service_domain'` and `yalla_id =
  service_domains.id`, not the parent service id, so domain sync jobs can
  replay idempotently per desired hostname.
- The schema does **not** pin resource-ID prefix formats with CHECK
  constraints — `internal/controlplane/domain` owns ID well-formedness, and
  `testutil` fixtures deliberately use independent prefixes.

## API keys (`0003_api_keys`, `apikey.go`)

- `api_keys` stores **only a hash** of the secret (`secret_hash`) plus the
  public `prefix`. No column ever holds a usable credential — the plaintext
  token is minted by `internal/controlplane/auth`, shown once, never persisted.
- `api_keys.status` is the explicit lifecycle state machine
  (`active -> revoked|expired`; terminal states do not transition). Lifecycle
  changes should go through `APIKeyRepository.Transition`: it locks the
  tenant-scoped row, rejects invalid edges with
  `E_INVALID_STATE_TRANSITION` before any write, updates `api_keys.status`,
  stamps `revoked_at` for the revoked transition, and appends an
  `api_key_events` row with actor/request/previous/next/reason metadata in
  the same transaction. Customer-facing revocation uses this transition path
  before writing the separate audit event.
- `APIKeyRepository.FindByPrefix` is the **one deliberate exception** to "scope
  by `organization_id` first": it is the authentication lookup, which runs
  before the caller's tenant is known. The `prefix` is globally `UNIQUE` and
  unguessable, and the returned row carries its own `OrganizationID`, so callers
  scope subsequent work by `key.OrganizationID`. Every other read/mutation
  (`Get`, `ListByOrganization`, `TouchLastUsed`, `Revoke`) is tenant-scoped.
- Tenant-scoped mutations that may match zero rows (`TouchLastUsed`, `Revoke`)
  report `apierr.NotFound` via `tag.RowsAffected() == 0` — a cross-tenant id
  simply does not match. `Revoke` is idempotent (`COALESCE(revoked_at, $3)`).

## API key scopes (`0033_api_key_scopes`, `api_key_scope.go`)

- `api_key_scopes` is a tenant-scoped child of `api_keys` carrying one
  capability string per row, the long-term source of truth a future per-scope
  endpoint will mutate without rewriting the embedded `api_keys.scopes text[]`
  array. The embedded array stays authoritative for the authentication read
  path until that endpoint lands; the two surfaces coexist deliberately.
- Migration `0033` ALSO adds `UNIQUE (organization_id, id)` to `api_keys` so
  the child can use the composite-FK pattern `(organization_id, api_key_id) ->
  api_keys (organization_id, id) ON DELETE CASCADE`. This is the
  **adopt-the-constraint-when-the-first-child-lands** pattern: when creating
  the first child of a tenant-scoped table that lacks
  `UNIQUE (organization_id, id)`, add the constraint in the child's migration
  (safe additive change because the parent's PK already makes id unique).
- The schema-side `CHECK (length(scope) BETWEEN 1 AND 64)` mirrors the wire
  validator in `apikeyservice.go` (`apiKeyScopeMaxLen`); a future caller that
  forgets the validator cannot persist an out-of-band scope.
- `APIKeyScopeRepository` follows the `MembershipRepository` /
  `ProjectGrantRepository` shape: stateless struct, `*Tx` for mutations
  (nil-Tx -> typed `apierr.Internal`), `Querier` for reads,
  `pgx.ErrNoRows` -> `apierr.NotFound` on `Get`/`UpdateScope`, `Delete` via
  `tag.RowsAffected() == 0` -> `apierr.NotFound` (mirrors `api_keys.Revoke`'s
  idempotent-tag pattern). Conflict mapping for BOTH the duplicate
  `(api_key_id, scope)` tuple AND the cross-tenant / unknown `api_key_id`
  composite-FK violation goes through `mapWriteError` — both are
  constraint-violation class 23 errors and both surface as
  `apierr.Conflict`.

## Break-glass sessions (`0019_break_glass_sessions`, `0045_break_glass_session_state_machine`)

- `break_glass_sessions.status` is the explicit lifecycle state machine:
  `active -> revoked|expired`, with `revoked` and `expired` terminal.
  Lifecycle changes should go through `BreakGlassRepository.Transition`: it
  locks the tenant-scoped row, rejects invalid edges with
  `E_INVALID_STATE_TRANSITION` before any write, updates status/revocation
  fields, and appends a tenant-scoped `break_glass_session_events` row in the
  same transaction.
- `break_glass_session_events` uses a composite FK
  `(organization_id, session_id) -> break_glass_sessions (organization_id, id)`.
  When adding an event child to an older table whose primary key is globally
  unique but lacks `UNIQUE (organization_id, id)`, add that tenant-scoped
  unique constraint in the child migration before declaring the composite FK.

## Service accounts (`0004_service_accounts`, `serviceaccount.go`, `serviceaccountservice.go`)

- `service_accounts` is a tenant-scoped table for **non-human principals** (CI
  and automation). It carries `organization_id` directly and exposes
  `UNIQUE (organization_id, id)` so it can be a composite-FK target. It has a
  `disabled_at` lifecycle (`Disable` is idempotent via `COALESCE`).
- `api_keys.service_account_id` is a **nullable** ownership link. The composite
  foreign key `(organization_id, service_account_id)` is `MATCH SIMPLE`: it is
  enforced only when the column is set, and then it pins the key's organization
  to its service account's — a cross-tenant service-account key is
  unrepresentable. This is the reference pattern for any **optional**
  cross-table ownership link.
- `ServiceAccountService` mirrors `ProjectService` but has **no
  `JobEnqueuer`** — a service account provisions nothing in Dokploy, so its
  unit of work is `authorize → reserve quota → write` only. Not every
  unit-of-work needs every port.

## Memberships & credential lookup (`0005_membership_role_version`, `membership.go`, `credentials.go`)

- `memberships.role_version` (added in `0005`) is the counter behind
  version-based **session-token revocation**: `NOT NULL DEFAULT 1`, monotonic
  (`CHECK >= 1`). Bumping it on a role/membership change or forced sign-out
  invalidates every outstanding session token at once, without a denylist.
- `MembershipRepository.Get` is a tenant-scoped read (`organization_id` before
  `user_id`) returning `apierr.NotFound` for a non-member — a cross-tenant
  user id can never reveal another org's membership.
- `UserRepository` (`user.go`) is the CRUD surface for the **global identity
  table** users. It has **no version column** and no `If-Match` path —
  optimistic concurrency for organization-scoped session-token revocation
  lives on `memberships.role_version` instead. The plain `Get(userID)` /
  `GetByEmail(email)` reads target the global row; tenant-scoped reads must
  go through `GetInOrganization(organizationID, userID)`, which JOINs against
  memberships so a non-member surfaces as the same `apierr.NotFound` an
  unknown id would produce. `Delete` cascades into memberships via the
  `memberships(user_id) ON DELETE CASCADE` FK and reports `NotFound` when
  `RowsAffected() == 0` — the same idempotent-tag pattern `api_keys.Revoke`
  uses.
- `CredentialReader` is the **production adapter** that satisfies the
  `auth.CredentialStore` port — the BE-0020 "store wiring" for the auth
  middleware. The dependency direction is deliberate: `auth` defines the port
  and never imports `store`; `store` imports `auth` and implements it by
  composing the existing tenant-scoped repository methods (no new SQL), so the
  tenant-scoping guarantees are inherited. `OrganizationRoleVersion` maps a
  missing membership to `(0, false, nil)` but propagates a datastore failure as
  a non-nil error, so an outage surfaces as a dependency failure, not a silent
  auth denial.

## Quota schema (`0006_quota_policy_schema`)

- The quota dimensions are a **closed set**, modelled as a Postgres `DOMAIN`
  (`quota_resource` over text + `CHECK`) reused by all four quota tables — an
  unknown dimension is rejected by the database, not at runtime. `DROP DOMAIN`
  goes in the `.down.sql` **after** the tables that use it. `quota_enforcement_mode`
  (`hard`/`soft`/`metered`/`disabled`) is the second shared domain. Adding a
  dimension is a new migration running `ALTER DOMAIN`.
- `quota_policies` holds **one limit per (scope, resource)**. A row is *either*
  a `plan_default` (keyed by the text `plan` column — there is **no FK to a
  plans table yet**) *or* an `organization` override (keyed by
  `organization_id`). The single `quota_policies_scope_consistent` CHECK plus
  two **partial unique indexes** (`WHERE scope_kind = '...'`) keep the two
  scopes independent: a plan default and an org override for the same resource
  coexist. The quota checker resolves "org override if present, else plan
  default".
- `quota_usage` is the actual allocated amount: one counter row per
  `(organization_id, resource)` via `UNIQUE`. The quota checker locks this row
  (`SELECT ... FOR UPDATE`) to make an allocation decision.
- `quota_reservations` are short-lived claims: `amount > 0`, a status lifecycle
  (`active -> committed | released | expired`), `expires_at` so a crashed job
  cannot strand quota, and `quota_reservations_settled_consistent` ties
  `settled_at` to non-active status. `job_id` is nullable with **no FK yet**
  (`provisioning_jobs` lands later — a future migration adds the composite
  `(organization_id, job_id)` FK). It exposes `UNIQUE (organization_id, id)` as
  a composite-FK target.
- `usage_events` is **append-only**: no `updated_at`, no update trigger, signed
  `delta`. Its optional `reservation_id` link uses a composite FK
  `(organization_id, reservation_id)` → `quota_reservations` (MATCH SIMPLE), so
  a cross-tenant reservation reference is unrepresentable. Note: an optional
  cross-table link inside a tenant uses a **plain** composite FK — *not*
  `ON DELETE SET NULL`, which would null the `NOT NULL organization_id`; the
  org-level `ON DELETE CASCADE` already cleans both sides.
- `QuotaRepository` (`quota.go`) is the persistence half of the quota checker:
  `EffectiveLimit` (org override else plan default, one ordered query),
  `LockUsage` (`INSERT ... ON CONFLICT DO NOTHING` then `SELECT ... FOR UPDATE`
  — the concurrency primitive), `SumActiveReservations`, `InsertReservation`.
  Reads take `Querier`, mutations take `*Tx`, every query tenant-scoped. The
  `store.QuotaReserver` *service* lives in `internal/controlplane/quota`
  (`quota.Checker`), not here — `store` only owns the persistence and the port.
  `QuotaResource`/`EnforcementMode` are typed mirrors of the SQL `DOMAIN`s.
  Quota accounting rows (`quota_usage`, `quota_reservations`) are **not** domain
  resources — `newQuotaID` mints their ids locally, no `domain.Kind`.

## Service lifecycle (`0041_service_state_machine`, `service.go`, `service_event.go`)

- `services.status` is the source-of-truth lifecycle state for the service row
  itself; Dokploy runtime status remains an upstream concern. Existing rows
  default to `active`.
- Service lifecycle changes should go through `ServiceRepository.Transition`:
  it locks `(organization_id, service_id)`, validates the edge with
  `ServiceStatus.CanTransitionTo`, rejects invalid edges as
  `E_INVALID_STATE_TRANSITION` before any write, updates `services.status`,
  and appends a tenant-scoped `service_events` row in the same transaction.
- `service_events` is append-only and stores redacted transition reason
  metadata. Do not update/delete individual event rows; removal happens only
  through parent service/tenant cascade.

## Environment lifecycle (`0042_environment_state_machine`, `environment.go`, `environment_event.go`)

- `environments.status` mirrors the service lifecycle taxonomy for
  source-of-truth environment state: `pending`, `active`, `suspended`,
  `deleting`, and terminal `deleted`. Existing rows default to `active`.
- Environment lifecycle changes should go through
  `EnvironmentRepository.Transition`: it locks `(organization_id,
  environment_id)`, validates the edge with `EnvironmentStatus.CanTransitionTo`,
  rejects invalid edges as `E_INVALID_STATE_TRANSITION` before any write,
  updates `environments.status`, and appends the matching `environment_events`
  row in the same transaction.
- `environment_events` is append-only and stores redacted transition reason
  metadata. Do not update/delete individual event rows; removal happens only
  through parent environment/tenant cascade.

## Project lifecycle (`0043_project_state_machine`, `project.go`, `project_event.go`)

- `projects.status` uses the same lifecycle taxonomy as environments and
  services: `pending`, `active`, `suspended`, `deleting`, and terminal
  `deleted`. Existing rows default to `active`.
- Project lifecycle changes should go through `ProjectRepository.Transition`:
  it locks `(organization_id, project_id)`, validates the edge with
  `ProjectStatus.CanTransitionTo`, rejects invalid edges as
  `E_INVALID_STATE_TRANSITION` before any write, updates `projects.status`,
  and appends the matching `project_events` row in the same transaction.
- `project_events` is append-only and stores redacted transition reason
  metadata. Do not update/delete individual event rows; removal happens only
  through parent project/tenant cascade.

## Service backups (`0024_service_backups`, `service_backup.go`)

- The PRD may call this surface `backup_schedules`; the actual source-of-truth
  table is `service_backups`, and the quota dimension is
  `backup_schedules`. The row is service-scoped desired-state policy plus
  worker-projected run state; it stores no backup artefacts or secrets.
- `ServiceBackupRepository` follows the service-scoped leaf-table shape:
  `Insert`, `GetByID`, `ListByService`, `Update`, `MarkPending`, and
  `DeleteByID` all predicate on `(organization_id, service_id[, id])`.
  `Update` only writes customer policy fields
  `(display_name, schedule, retention_count, enabled)` and must preserve
  worker state `(status, last_run_at, last_succeeded_at)`.
- A zero `RetentionCount` on `Insert` means "omitted" and is normalized to the
  stable default `7`; negative or out-of-range values still flow to the
  database CHECK and surface as typed `E_CONFLICT`.

## Preview environments (`0038_preview_environments`, `preview_environment.go`)

- `preview_environments` is a project-scoped lifecycle wrapper around the real
  cloned `environments` row. Repository methods predicate directly on
  `(organization_id, project_id[, id])`; do not infer tenant scope solely from
  the wrapped environment id.
- Customer metadata updates write only `display_name`, `change_ref`, and
  `expires_at`. Lifecycle fields (`status`, `deletion_scheduled_at`) move
  through `ScheduleDeletion` or later worker-owned transitions; hard
  `DeleteByID` is for worker cleanup after Dokploy teardown.
- Read paths intentionally include rows after `ScheduleDeletion` marks them
  `status='deleting'`; tenant-isolation tests for preview environments must
  include a scheduled-deletion row so soft-deleted previews cannot leak across
  `(organization_id, project_id)` boundaries.
- The table uses `penv_` ids (`domain.KindPreviewEnvironment`) and composite
  FKs to `environments (organization_id, project_id, id)` for both the preview
  clone and source environment. Migration `0038` also has a trigger enforcing
  that the wrapped environment row has `kind='preview'`; plain FKs cannot
  express that row-body invariant.

## Audit log (`0007_audit_events`, `audit.go`)

- `audit_events` is the **immutable** audit log: one row per security-relevant
  authorization decision, allowed *or* denied. Immutability is enforced at two
  layers — the table has **no `updated_at`** and a `BEFORE UPDATE` trigger
  (`audit_events_reject_update`) that rejects every UPDATE at the database
  level, and `AuditRepository` exposes **only** `Append` + tenant-scoped reads
  (`ListByOrganization`), no update/delete. Row DELETE stays reachable solely
  through the organizations `ON DELETE CASCADE` for tenant teardown.
- Actor columns (`actor_id`, `actor_kind`) default to empty: an unauthenticated
  request that is **denied** is still audited, with no actor. `decision` is
  `allowed`/`denied`; `metadata` is `jsonb` and is expected to arrive **already
  redacted** — redaction is the `internal/controlplane/audit` service's
  contract, not the repository's.
- `AuditEvent`/`AuditDecision` are the persistence shapes. `scanAuditEvent`
  takes `pgx.Row` and serves both the `Append` RETURNING and the
  `ListByOrganization` loop (`pgx.Rows` satisfies `pgx.Row`). Audit rows are
  internal accounting, not domain resources — `newAuditID` mints their ids
  locally (`aud_<32hex>`), no `domain.Kind`.
- **Tamper resistance** (BE-0353) is verified by THREE static guards plus a
  runtime probe — adding any one in isolation is silently weakening:
  (1) `migrate/audit_immutability_static_test.go` pins the migration shape
  (the `audit_events_reject_update` function RAISEs `ERRCODE =
  'restrict_violation'`; the `BEFORE UPDATE ... FOR EACH ROW` trigger
  exists; the `CREATE TABLE audit_events` block has no `updated_at` column;
  the down migration drops both table and function).
  (2) `audit_tamper_static_test.go` pins the Go surface (`AuditRepository`
  exposes exactly `{Append, ListByOrganization}`; `AuditEvent` has no
  `UpdatedAt/ModifiedAt/RevisedAt/LastModifiedAt` field; no non-test `.go`
  file in `store/` issues `UPDATE/DELETE/TRUNCATE/ALTER/DROP audit_events`
  SQL — only the `INSERT INTO audit_events` carve-out in `audit.go` is
  allowed).
  (3) `audit_test.go::TestAuditUpdateBlockedByDatabaseTriggerWithRestrictViolation`
  pins the wire shape (`SQLSTATE 23001` and the canonical message
  `audit_events is append-only: UPDATE is not permitted`, plus a byte-
  identical row snapshot after every rejected UPDATE shape — by id, by
  org id, table-wide, metadata-rewrite, verdict-reclassification — and a
  no-echo redaction probe so the trigger's wire surface stays value-free).
  A future change that weakens any layer is caught by another.

## SQL injection resistance (`sql_injection_static_test.go`, `sql_injection_test.go`)

- The parameterization invariant — "every SQL statement is fully parameterized;
  caller input is bound through pgx placeholders ($1, $2, …) only, never
  interpolated into the SQL string" — is enforced by two complementary tests
  in this package:
  - `sql_injection_static_test.go` is the **regression backstop**. It parses
    every non-test `.go` file in this package and asserts the SQL argument
    passed to `.Exec`/`.Query`/`.QueryRow` is a compile-time-constant string
    expression (string literal, `const` identifier, parenthesised wrapper,
    or `+`-concatenation of those). Anything else — `fmt.Sprintf`,
    `string(x)`, a method call, a function parameter, a `var`-typed local
    — fails the test with file:line. A companion check rejects
    `fmt.Sprintf` calls whose string-literal first argument contains
    uppercase SQL keywords (`SELECT`/`INSERT INTO`/`UPDATE …`/
    `DELETE FROM`/…), catching the indirect "build a query string first,
    then run it" pattern. A self-check
    (`TestSQLInjectionStaticAnalyzerDetectsRegressions`) parses synthetic
    bad sources to prove the analyzer fires when the control is removed.
  - `sql_injection_test.go` is the **runtime evidence**. It runs against
    an isolated migrated Postgres and feeds canonical injection payloads
    (`'; DROP TABLE …`, `' OR 1=1 --`, UNION/UPDATE/INSERT stacks, dollar-
    quoted strings, multi-line, URL-encoded) through every customer-input
    string field of representative repository methods. Read paths must
    return typed `E_NOT_FOUND` (or empty), **never** `E_UNAVAILABLE` —
    that code is the store's mapping for raw driver errors and a SQL
    syntax error escaping the parameter binder would surface there.
    After the loop, row counts on `organizations`/`projects`/
    `environments`/`services`/`api_keys`/`audit_events`/`service_accounts`
    are asserted byte-identical to the pre-loop baseline (DROP/TRUNCATE/
    UPDATE/DELETE side effects would visibly move them). A separate test
    (`TestSQLInjectionPayloadsStoredVerbatim`) inserts each payload as a
    free-text column value (`display_name`) and reads it back, asserting
    the round-trip is byte-identical — the strongest possible evidence
    that pgx is the security boundary and the server stored the payload
    as data, did not execute it.
- One exemption is encoded structurally in the static analyzer: the three
  methods on `*Tx` (`Exec`/`Query`/`QueryRow`) that define the Querier
  surface are thin pass-through wrappers forwarding the SQL string parameter
  to pgx. The SQL safety contract is satisfied at the **callers** of those
  methods, every one of which is itself a repository site this scan visits.
  Inside the wrapper the SQL argument is — and must be — the function
  parameter named `sql`. The exemption is recognised by the receiver shape
  and method name; no other shape is exempt.
- The runtime tests deliberately omit NUL bytes from the payload list: pgx
  rejects NUL in a `text` parameter before it reaches the server, which
  would surface as `E_UNAVAILABLE` for reasons unrelated to SQL injection
  resistance and pollute the load-bearing negative assertion. NUL handling
  is a separate input-rejection concern.

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
  durable job → append audit. Validate input **before** opening the
  transaction. The policy, quota, jobs, and audit dependencies are narrow
  **port interfaces** (`Authorizer`, `QuotaReserver`, `JobEnqueuer`,
  `AuditAppender`) defined here — the real engines land in later stories;
  tests use fakes. Do not import `policy`/`quota`/`jobs` from `store`.
  `cmd/yalla-api` wires placeholder `alwaysAllowAuthorizer`/
  `noopQuotaReserver`/`noopJobEnqueuer` adapters until the real engines
  land; the HTTP `RequireAuth` middleware is the authoritative gate for
  customer traffic today. `NewProjectService` rejects a nil dependency
  (including nil audit), so a misconfigured binary fails at startup.
- A unit of work that records an audit event (see `OrganizationService.Create`)
  composes the desired-state write + `AuditRepository.Append` inside the one
  `Store.Write`, so a created row can never exist without its audit record.
  Audit lives *inside* `store` — the narrow `AuditAppender` port is satisfied by
  `*AuditRepository` directly, no import cycle. The orchestrator builds the
  `store.AuditEvent` from **plain-string** actor/correlation fields the caller
  passes in the `CreateXInput` (`ActorID`/`ActorKind`/`ActorOrgID`/`RequestID`/
  `CorrelationID`) — `store` still imports neither `policy` nor `telemetry`.
  Keep recorded `Metadata` to structurally-safe values (a canonical slug);
  richer, redacted context is `audit.Auditor`'s job, not `store`'s.
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
- `testutil.DB` embeds `*pgxpool.Pool`, so `db.Begin(ctx)` yields a real
  `pgx.Tx`. Row-lock behaviour is tested with **two independent transactions**:
  `SELECT ... FOR UPDATE NOWAIT` raises `*pgconn.PgError` with SQLSTATE `55P03`
  (`lock_not_available`) when another transaction holds the row — see
  `quota_schema_test.go`'s `TestQuotaReservationConcurrentRowLock`.
- **Wallclock-window assertions** against DB-stamped timestamps
  (`created_at`/`updated_at` via `now()`, or repository-filled defaults
  like `BreakGlassRepository.Append` filling a zero `StartedAt`) MUST
  allow a ±2s margin between the test runner and the Postgres
  container clock. The right pattern is
  `before := time.Now().UTC().Add(-2 * time.Second)` /
  `after := time.Now().UTC().Add(2 * time.Second)` bracketing the
  mutating call, then `if got.Before(before) || got.After(after)`.
  A `Truncate(time.Microsecond)` without a margin is NOT safe — a few
  milliseconds of skew between the Go process and the Postgres
  container will flake the bracket assertion (see BE-0473's
  `TestBreakGlassRepositoryAppendMintsRowShape`).
- **Repository tenant-isolation tests** for a tenant-scoped table live in
  `<table>_tenant_isolation_test.go` (e.g. `organization_tenant_isolation_test.go`),
  separate from CRUD tests, and follow the byte-identical-snapshot pattern:
  seed two organizations, snapshot the OTHER tenant's row, run the mutation
  against THIS tenant, re-read the OTHER tenant, and assert every field
  unchanged (slug/display_name/version/updated_at/deletion_scheduled_at).
  Anchor on BOTH `version` (trigger-bumped on UPDATE) AND `updated_at`
  (trigger-refreshed) — either catches a WHERE-less UPDATE independently.
  Cover Get/Update/Update-with-stale-If-Match/ScheduleDeletion plus, for
  child tables, a cross-tenant parent-id probe that must render NotFound
  (never the other tenant's row, never a 500). Tenant-root tables
  (organizations) have no `ListByParent` to test — document that absence in
  the test file's package-doc comment so a future reader does not look for
  a missing test. The story-template file for this pattern is
  `organization_tenant_isolation_test.go` (BE-0426).
- **Multi-mutation-path extension** (BE-0438 pattern,
  `project_tenant_isolation_test.go`): when a tenant-scoped table has
  more than two mutation paths (projects has FOUR: Update,
  UpdateDisplayName, ScheduleDeletion, Restore), every path needs its
  own `OnOrgADoesNotTouchOrgB` + `CrossTenantBystanderIsByteIdentical`
  pair — even when one path (Update) already has a cross-tenant
  typed-NotFound test in the CRUD file. The dedicated tenant-isolation
  file's contribution is the BYTE-IDENTICAL projection (the
  trigger-managed `updated_at` and trigger-bumped `version` did not
  drift on the peer's row) and the EXISTENCE-LEAK projection
  (cross-tenant probe vs unknown-id probe surface identical Code AND
  Hint — `apierr.NotFound` echoes the caller's id in `Message`
  verbatim, never the foreign row's id, so the assertion belongs on
  Hint+Code, NOT on Message). If the table exposes a count surface the
  quota layer reads (`CountByOrganization`), add a dedicated
  `CountByOrganizationIsTenantScoped` test — `ListByOrganization`
  coverage is not transitive to the count path. If the per-tenant
  UNIQUE constraint allows two tenants to share the column text (e.g.
  `projects.slug`, `api_key_scopes.scope`), add an
  `InsertSameXInTwoTenantsBothSucceed` leg AND force both fixtures to
  carry the SAME text via direct `.Field = "shared"` overrides AFTER
  the `f.Project(...)` / `f.APIKeyScope(...)` factory call — the
  per-factory token derives unique text per tenant by default, which
  leaves a WHERE-on-`X`-only regression invisible to the
  byte-identical-bystander helper. For tables with a soft-delete
  column where ALL read paths expose the soft-deleted row to the
  owning tenant (no `WHERE deletion_scheduled_at IS NULL` repo
  filter), add ONE composite `SoftDeletedRowIsTenantScopedOnReadPaths`
  test proving cross-tenant invisibility across Get + List + Count AND
  owner-tenant visibility across the same three — the projection
  collapses into a single test because the SAME WHERE
  `organization_id` predicate isolates the row on every read surface.
- **List-only read surface extension** (BE-0440 pattern,
  `project_grant_tenant_isolation_test.go`): when the repository
  exposes NO per-id `Get` and NO per-id `Delete` — only a parent-scoped
  list (e.g. `ListByProject`) and a composite-conflict upsert and a
  bulk delete-by-exclusion — the byte-identical-bystander projection
  must be observed THROUGH the list response, not a per-id Get. Add a
  `get<X>FromListOrFail(ctx, t, s, repo, parentScope, rowID, label)`
  helper that scans the list and `t.Fatalf`s on absence; the lists
  are 1–2 rows by construction so the linear scan is fine. The
  cross-tenant indistinguishability projection at a list path is
  `(len==0 + non-nil-slice + same shape under "unknown parentID in
  own tenant")`, NOT the `(Code, Hint)` projection used by per-id
  Get paths — `ListBy*` does not surface a typed `NotFound` for an
  unknown parent id. If the table also has nullable `*string` scope
  columns (`environment_id`, `service_id` on `project_grants`), the
  byte-identical helper needs a `stringPtrEqual` + `fmtStringPtr`
  pair so a failing pointer-column assertion shows `<nil>` vs the
  quoted value side-by-side. And if the only mutation surface is an
  `INSERT ... ON CONFLICT DO UPDATE` upsert PLUS a bulk
  `DeleteByParentExceptIDs`, BOTH conflict branches AND BOTH delete
  codepaths (`len(keepIDs)==0` → unconditional `DELETE`; `len>0` →
  `DELETE WHERE id NOT IN ANY`) need their own
  `OnOrgADoesNotTouchOrgB` test — the non-empty-keepIDs test is the
  load-bearing one because the bystander's id is NOT in keepIDs and
  would have been eligible for deletion if the tenant predicate had
  been dropped. The fixture for the Upsert-UPDATE-branch bystander
  test MUST share the WHOLE conflict scope tuple across both tenants
  on their OWN respective parent rows (`(principal_id, env, svc)` on
  `project_grants`), because the conflict target itself carries
  `organization_id` + the parent FK — a regression that resolved the
  conflict by scope-tuple alone would fire the UPDATE on the peer
  tenant's row through the trigger and bump its version/updated_at.
- **Secret-bearing column extension** (BE-0434 pattern,
  `api_key_tenant_isolation_test.go`): when the table carries a column
  holding a secret (e.g. `api_keys.secret_hash`, or `variables.value`
  when `is_secret=true`), the byte-identical-snapshot rule extends with
  two extra probes. (a) A raw-SQL
  `SELECT <secret_column> FROM <table> WHERE id=$1` probe that bypasses
  the typed read path — a regression that scanned a non-secret column
  into the struct, or skipped the secret field on `Get`, would otherwise
  pass the typed snapshot check while the underlying row drifted.
  (b) A `strings.Contains(err.Error(), secretNeedle)` redaction probe
  over every cross-tenant typed error's `Error()`, `Message`, and `Hint`
  for every tenant-scoped mutation surface, ensuring a future
  error-formatter regression cannot embed the row body and hand a peer
  tenant's credential to a probing caller. For a cross-tenant
  INSERT-conflict path on a globally-UNIQUE column (e.g.
  `api_keys.prefix`), add a `SELECT COUNT(*) FROM <table>` global probe
  AND a `WHERE <secret_column> = $1` needle-absence probe AFTER the
  conflicting Insert — the per-id probe alone cannot prove the
  rolled-back row did not land in some other tenant's slot, because the
  failing row's id is unknown to the probe.
- **Claim-protocol + nullable-completion-columns extension** (BE-0470
  pattern, `idempotency_repository_tenant_isolation_test.go`): when a
  tenant-scoped table's repository surface is a claim protocol (Claim
  upsert / Complete state-transitioning UPDATE / Release
  state-conditioned DELETE / Find composite-tuple read) where every
  mutating WHERE has `organization_id` as the leading column of a
  composite predicate tuple AND the row body carries nullable
  completion columns distinguished by nil-ness under a
  completion-consistent CHECK, the byte-identical-snapshot rule
  extends with four extra probes. (a) Every mutating surface needs
  its own `OnOrgADoesNotTouchOrgB` test — Claim, Complete, Release.
  The Complete probe asserts that `Complete(orgA, orgB's
  principal+key)` falls off the `organization_id` leg of the WHERE
  before the status leg runs and surfaces `apierr.Conflict` ("no
  longer pending") WITHOUT touching orgB's row. The Release probe
  asserts the dual: Release is "safe to call defensively" and returns
  `nil` on a zero-row DELETE, so the cross-tenant Release must return
  nil AND leave orgB's pending row byte-identical AND the per-tenant
  count unchanged — three separate assertions because a regression
  that dropped `organization_id` from the Release WHERE would delete
  orgB's row, which the bystander byte-identity loader catches as a
  missing-row error inside `loadIdempotencyRowByID`'s `t.Fatalf`. The
  forged Complete envelope MUST carry a recognisable canary string
  (e.g. `"forged":"orgA-tries-to-complete-orgB-claim"`) so a future
  reader sees immediately what the test was protecting against, and
  so the canary doubles as a redaction-leak probe across the typed
  error's `Error()` / `Message` / `Hint`. (b) The byte-identity
  comparator MUST switch on pointer nil-ness FIRST and dereference
  value SECOND for every nullable column. A naive field-equality
  loop would silently round-trip a regression that flipped a pending
  row's NULL completion columns to zero-value scalars
  (`response_status=0`, `response_body=[]byte{}`,
  `completed_at=epoch`). The pattern: switch on `(after==nil,
  baseline==nil)` into three branches — both-nil OK, one-nil diff
  "nil-ness drifted", both-non-nil dereference-compare — and emit a
  fmt-printer-pair (`fmtIntPtr` / `fmtTimePtr`) so the diagnostic
  reads `before=<nil> after=200` rather than pointer noise.
  Forward-applicable to every future tenant-isolation file whose row
  carries nullable columns: `job_attempts` (nullable `error_summary`
  / `finished_at` / `result`), `quota_reservations` (nullable
  `released_at` / `job_id`), `break_glass_sessions` (nullable
  `revoked_at`). (c) The Claim "mirror tuple" probe is the
  load-bearing per-tenant uniqueness assertion of the `ON CONFLICT`
  target. orgB seeds a row at `(orgB, usr_mirror, mirror-key)`; orgA
  Claims a row at `(orgA, usr_mirror, mirror-key)` — same
  `(principal_id, idempotency_key)`, different `organization_id`. A
  regression that dropped `organization_id` from the `ON CONFLICT`
  target would resolve the conflict onto orgB's mirror-tuple row and
  silently rewrite it through the `DO UPDATE` branch — the worst-case
  cross-tenant data-corruption shape. The assertion: orgA's Claim
  returns `owned=true` (fresh INSERT, never `DO UPDATE` on a foreign
  row), orgA's new row carries orgA's `organization_id` and a
  distinct id, AND orgB's mirror row remains byte-identical. The
  seed comment for the mirror row MUST explicitly call out the
  rationale because the failure mode is the kind a future reader
  rationalises away. (d) The Claim cross-tenant id-collision probe
  MUST (i) use DIFFERENT `(principal_id, idempotency_key)` tuples
  across the two tenants so the `ON CONFLICT` target does NOT match
  and the PK violation flows through `mapWriteError`, and (ii) carry
  a GLOBAL row-count probe (`SELECT count(*) FROM <table>` with no
  WHERE) in addition to the per-tenant counts. The per-tenant probe
  alone cannot prove the failing row's absence because the failing
  INSERT's `organization_id` is unknown to the probe — a regression
  that landed the row in a third unrelated tenant's slot would pass
  the per-tenant probe. The story-template file for this pattern is
  `idempotency_repository_tenant_isolation_test.go` (BE-0470).
- A state-machine table (`provisioning_jobs`, `store/job.go`) keeps the
  authoritative transition graph in Go (`JobStatus.CanTransitionTo`, backed by
  the `jobTransitions` map) and lets the DB CHECK only the *closed status set*
  and per-status invariants ("terminal iff `finished_at` set", "lease held iff
  `status='running'`"). The mutating method (`Transition`) locks the row
  `FOR UPDATE`, validates the edge **before** any write (illegal edge =
  `E_INVALID_STATE_TRANSITION`), derives every dependent column (lease,
  attempts, timestamps) from the target status, and appends the matching
  `provisioning_job_events` row in the same transaction with actor/request/
  previous/next/reason metadata. A caller passes an options struct
  (`JobTransition`), never a full row, so it cannot produce a CHECK-violating
  shape.
- Deployment lifecycle transitions follow the same pure-table pattern via
  `DeploymentStatus.CanTransitionTo`, but invalid edges surface as the public
  `E_INVALID_STATE_TRANSITION` code. Use `DeploymentRepository.Transition` for
  new lifecycle writers so the status update and matching `deployment_events`
  append commit atomically with actor/request/previous/next/reason metadata;
  redact free-text reason and error summaries before persistence.
- When a migration **wires a foreign key an earlier migration deferred** (e.g.
  `0008` adds `quota_reservations.job_id -> provisioning_jobs` that `0006` left
  unconstrained), add it with a plain `ALTER TABLE ... ADD CONSTRAINT` in the
  later `*.up.sql`, and `DROP CONSTRAINT ... IF EXISTS` it **first** in that
  migration's `*.down.sql` — it depends on the new table's composite `UNIQUE`
  key.
- Customer-facing `DELETE` endpoints on **tenant-root or tree-owning
  resources** schedule a soft delete, they do not hard-delete:
  `OrganizationService.ScheduleDeletion` stamps
  `organizations.deletion_scheduled_at` (migration `0010`) inside the same
  transaction as the `organization.delete` audit record. A hard delete
  cascades (`ON DELETE CASCADE`) through projects/environments/services *and
  the audit log itself* — so the destructive teardown is a later worker
  story; the endpoint only records intent. Re-scheduling an already-stamped
  row is `apierr.Conflict`, detected with a `Get` inside the tx (the
  repository's `ScheduleDeletion` is an unconditional `UPDATE`, mirroring
  `Update`).
- **Join rows that own no child tree are exempt** — they hard-delete inside
  the same transaction as their audit record. `MembershipService.Remove`
  follows this pattern: read the current `OrganizationMember` inside the
  tx (so the audit metadata can capture the role the member held at
  removal time and a missing row is a typed `NotFound`), call
  `MembershipRepository.Delete` (tenant-scoped on `(organization_id,
  user_id)`; `tag.RowsAffected()==0` is also `NotFound`), append the
  audit event, return the pre-delete row. The httpapi layer renders that
  pre-delete row through the same wire shape every other membership
  endpoint uses — agents get the audit-grade terminal view in one round
  trip instead of a bodyless 204. A membership owns no child tree, so
  there is no soft-delete state to track; the audit row is the only
  surviving trace.
- The store layer is the redaction chokepoint for **error-summary-style**
  free-text columns it owns (`provisioning_jobs.error_summary` is run through
  `output.NewRedactor()` on every `Insert`/`Transition`). This differs from
  `audit_events.metadata`, which the *service* (`internal/controlplane/audit`)
  redacts and the store treats as already-clean — match whichever contract the
  column's existing owner documents.

## Dokploy refs (`0002_tenant_hierarchy`, `dokploy_ref.go`)

- `dokploy_refs` is the polymorphic Yalla-resource → Dokploy-object mapping.
  Its PK is a `bigint GENERATED ALWAYS AS IDENTITY`, not a domain-prefixed
  text id — it is the **only** int64 PK in this package. Repository methods
  that surface ids in error payloads format the int64 via a private helper
  (`dokployRefIDString`) rather than reaching for `strconv`/`fmt`, keeping
  the import surface uniform across the package.
- `dokploy_refs` has **no version column**, even though migration
  `0011_optimistic_versions`'s preamble claims it covers the table "for
  parity". The actual `ALTER TABLE` statements only touch organizations /
  projects / environments / services. The Go surface reflects reality:
  `DokployRef` carries no `Version` field, there is no per-row `Update`
  method, and the optimistic-versioning acceptance criterion for the
  CRUD-and-invariants story reads as "not applicable here". If a future
  worker remap story needs an update surface it must land a new migration
  AND the typed `Update` method together.
- `Insert` uses `RETURNING` to capture the database-minted bigint id; a
  caller cannot smuggle one in via `DokployRef{ID: ...}`. The closed-set
  `yalla_kind` and `dokploy_resource` columns are validated by CHECK in the
  database; the application boundary additionally rejects a blank typed
  value as `apierr.Internal` (a programming error, not a customer-rejection
  conflict).
- The schema's two UNIQUE constraints both map to `apierr.Conflict` via
  `mapWriteError`, but they are observably distinct surfaces and **both**
  must be exercised by tests: the *global* `(dokploy_resource, dokploy_id)`
  — a Dokploy object cannot be claimed twice even across tenants, the only
  place the dokploy_refs schema reasons about a foreign tenant's rows —
  and the *per-tenant* `(organization_id, yalla_id, dokploy_resource,
  dokploy_id)`. A single service may own multiple rows of the same
  `dokploy_resource` (e.g. several `domain` mappings for one service); the
  per-tenant UNIQUE includes `dokploy_id` precisely so this is allowed.
