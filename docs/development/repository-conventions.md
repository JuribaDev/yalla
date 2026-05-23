# Repository conventions - Yalla Control Plane

This document is the backend contract for adding or changing persistence
repositories in the Yalla Control Plane. Repositories own source-of-truth
Postgres access for tenant, hierarchy, desired-state, audit, quota, billing,
and durable job data. They do not call Dokploy directly and they do not expose
raw Dokploy operations. Do not expose raw Dokploy operations through
customer-facing repository-backed workflows; worker and provisioner code call
typed Dokploy clients after Yalla auth, policy, quota, idempotency, audit, and
desired-state writes have completed.

## Architecture boundary

Repository code lives in the source-of-truth layer:

```text
Customer / Agent / CI
  -> Yalla Control Plane API
  -> Postgres source of truth
  -> Provisioning worker
  -> private Dokploy API
```

HTTP responses that sit above a repository continue to use stable JSON envelopes:
success responses carry `schema_version: yalla.output.v1`, error
responses carry `schema_version: yalla.error.v1`, and every response includes
`request_id`. Repository errors must be typed through `apierr` so handlers can
render deterministic statuses and stable error codes.

## Add or change a repository

Repository implementation belongs under:

```text
internal/controlplane/store
```

Schema changes belong under:

```text
internal/controlplane/store/migrate/migrations
```

Use this workflow for a new table or a new repository method:

1. Add the paired migration first when the schema is new or changing.
2. Model the persisted row with typed Go fields and closed-set domain values.
3. Add repository methods that run inside `Store.Read` or `Store.Write`.
4. Keep every customer-data query tenant-scoped by `organization_id` or by a
   verified parent join with composite foreign keys.
5. Return `apierr.NotFound` for missing or cross-tenant IDs. Do not reveal
   whether a row exists in another organization.
6. Use `apierr.Conflict` for uniqueness, optimistic concurrency, check, and
   foreign-key conflicts that represent client-visible state conflicts.
7. Keep business decisions out of SQL string assembly; validate input before
   opening the transaction whenever possible.
8. Add repository integration tests with `testutil.RequireMigratedDB` and the
   shared deterministic fixtures. Normal tests use fake Dokploy dependencies
   only.

The required tenant isolation proof is a byte-identical bystander test where
practical: a cross-tenant write attempt must not change another organization's
row, count, timestamps, or version.

For mutating methods, write the source-of-truth row and any required audit,
quota reservation, idempotency, event, or job row in one `Store.Write`
transaction. A repository method must not enqueue a Dokploy mutation outside
the durable job path.

## Query and transaction rules

Required repository rules:

- Every customer-data query must be tenant-scoped. Prefer direct
  `organization_id` predicates; otherwise join through the verified parent
  hierarchy.
- Composite foreign keys should include `organization_id` plus the parent IDs
  needed to prove hierarchy ownership.
- Cross-tenant IDs collapse to not found. Error messages and details must not
  echo foreign row fields.
- Optimistic concurrency uses the row `version` where the schema has one.
  Stale `If-Match` style callers receive a typed conflict with the current
  version only when that disclosure is already authorized for the tenant.
- State-machine transitions lock the tenant-scoped row first, validate the
  transition, update the row, and append the event in the same transaction.
- Rollback and rollback safety tests prove a failed transaction does not leave
  partial rows.
- List methods must have deterministic ordering and stable pagination.
- Do not print SQL bind values, request bodies, metadata blobs, DSNs, rendered
  environment variables, tokens, cookies, or API keys from repository errors or
  tests. Do not log DSNs.

## Required environment variables

This section lists the required environment variables for local repository
verification.

Start the local Postgres dependency when running integration tests:

```bash
export YALLA_POSTGRES_PASSWORD=<redacted:postgres-password>
docker compose up -d postgres
docker compose ps postgres
```

expected output: the `postgres` service appears with `STATUS` containing
`healthy`.

Point repository tests at the local admin database without printing the
rendered value:

```bash
export YALLA_TEST_DATABASE_URL=<redacted:postgres-dsn>
```

`testutil.RequireMigratedDB` creates a fresh isolated database, applies the
embedded migrations, and drops the database during cleanup. When the variable
is not configured, expected output includes
`YALLA_TEST_DATABASE_URL not set; skipping Postgres integration test`.

Live Dokploy credentials are never required for repository tests. The only
allowed live smoke is explicit and external:

```bash
YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...
```

That command must never run against production.

## Verification commands

Run these from the repository root before marking a repository story complete:

```bash
gofmt -w .
go mod tidy
go test ./internal/controlplane/store/...
go test -run TestMigrations ./...
go test -run TestTenantIsolation ./...
go test ./...
go test -race ./...
go vet ./...
scripts/verify.sh
```

expected output: Go reports `ok` for packages with runnable tests. Packages
whose Postgres integration tests are gated by missing local configuration
report the documented skip instead of touching a shared database.

The release gate for this document is:

```bash
go test ./internal/release/... -run TestRepositoryConventionsArtifact
```

When a repository supports a public endpoint, preserve the API contract in the
same change. Unit tests cover success, validation failure, authorization failure, and not-found behavior.
Integration tests run against isolated Postgres migrations and never require a live Dokploy server unless explicitly marked external.

## Failure recovery

If Postgres is unavailable:

```bash
docker compose logs postgres
docker compose ps postgres
```

Fix the local dependency first. Do not point repository tests at production,
staging, or any shared database.

If tests are returning stale results:

```bash
go clean -testcache
go test ./internal/controlplane/store/...
```

If migrations or repository tests fail after local schema experiments:

```bash
docker compose down
docker compose up -d postgres
go clean -testcache
go test -run TestMigrations ./...
go test ./internal/controlplane/store/...
```

If a repository error, test log, audit metadata payload, or dry-run output
contains secret-shaped data, stop the run, rotate the local value if needed,
add or fix a redaction test, and remove the output before committing. Secrets, tokens, API keys, cookies, and rendered environment variable values are redacted
in logs, errors, audit metadata, and test output.

## Change log

| Date       | Change                                      | Owner              |
|------------|---------------------------------------------|--------------------|
| 2026-05-19 | Initial repository conventions doc (BE-0544). | Backend Operations |
