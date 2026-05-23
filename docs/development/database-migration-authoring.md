# Database migration authoring - Yalla Control Plane

This document is the backend contract for creating and verifying PostgreSQL
migrations in the Yalla Control Plane. Migrations change the Postgres source of
truth used by the API and worker before any private Dokploy API action can
mirror desired state. Keep real customer identifiers, database URLs, API keys,
cookies, Dokploy credentials, and rendered environment variable values out of
this file and out of migration SQL.

## Architecture boundary

Database migrations belong to the control-plane source-of-truth layer:

```text
Customer / Agent / CI
  -> Yalla Control Plane API
  -> Postgres source of truth
  -> Provisioning worker
  -> private Dokploy API
```

The migration runner is embedded in `yalla-api` and records applied versions in
`schema_migrations`. Customer-facing endpoints continue to return stable JSON
envelopes; stable JSON envelopes mean success responses use schema_version yalla.output.v1, errors use
schema_version yalla.error.v1, and every response includes a request_id. A
schema change must preserve tenant scoping and must never expose broad Dokploy
access.

## Create a migration

Migration files live in:

```text
internal/controlplane/store/migrate/migrations
```

Create both files for the next gap-free version:

```text
NNNN_description.up.sql
NNNN_description.down.sql
```

Use a short snake-case description such as
`0079_service_runtime_indexes.up.sql`. The matching down file is mandatory for
rollback and for the downgrade-safety gate. Keep each migration focused on one
schema concern.

Authoring rules:

- The up migration must be non-empty and deterministic.
- The down migration must reverse only what the paired up migration introduced.
- Every customer-data table must include an organization scope directly or via
  a verified parent join path.
- Indexes and constraints should support the repository query shape that will
  use them.
- Do not include secret defaults, live identifiers, rendered environment
  values, customer names, external tokens, or sample credentials.
- If a public API behavior changes with the schema, update handlers, OpenAPI,
  audit events, and contract tests in the same story.

## Required environment

Start the local Postgres dependency:

```bash
export YALLA_POSTGRES_PASSWORD=<redacted:postgres-password>
docker compose up -d postgres
docker compose ps postgres
```

expected output: the `postgres` service appears with `STATUS` containing
`healthy`.

Point integration tests at the local admin database without printing the
rendered value:

```bash
export YALLA_TEST_DATABASE_URL=<redacted:postgres-dsn>
```

The migration test harness creates isolated throwaway databases from
`YALLA_TEST_DATABASE_URL`, applies embedded migrations, and drops each database
on cleanup. Tests skip with a clear message when the variable is unset.

## Verification commands

Run these from the repository root before marking a migration story complete:

```bash
gofmt -w .
go mod tidy
go test -run TestMigrations ./...
go test -run TestMigrationsEmptyDB ./...
go test -run TestMigrationsDowngradeSafety ./...
go test ./internal/controlplane/store/...
go test ./...
go test -race ./...
go vet ./...
scripts/verify.sh
```

expected output: Go reports `ok` for packages with runnable tests. Packages
without configured Postgres report a documented skip such as
`YALLA_TEST_DATABASE_URL not set; skipping Postgres integration test`. A
missing row lookup should stay an expected `no rows in result set` condition
inside tests, not a leaked customer identifier. The release gate for this
document is:

```bash
go test ./internal/release/... -run TestDatabaseMigrationAuthoringArtifact
```

When a migration supports a public endpoint, preserve the API contract in the
same change. Unit tests cover success, validation failure, authorization failure, and not-found behavior.
Integration tests run against isolated Postgres migrations and never require a live Dokploy server unless explicitly marked external.

## Failure recovery

If Postgres is not healthy:

```bash
docker compose logs postgres
docker compose ps postgres
```

Fix the local dependency first. Do not bypass migration tests by pointing at a
shared or production database.

If the migration ladder fails while developing:

```bash
docker compose down
docker volume rm yalla_yalla_pgdata
docker compose up -d postgres
go clean -testcache
go test -run TestMigrations ./...
```

If a migration fails after writing a `schema_migrations` row marked dirty
migration, treat it as a dirty migration and stop to inspect the failing
version. In local development, reset the throwaway database and re-run the
ladder. In production, do not edit the ledger by hand; stop the deploy,
restore from backup if data may be affected, or ship a forward fix through the
normal migration command.

If a down migration cannot restore the previous schema cleanly, fix the down
file before continuing. A migration with no safe rollback path must be handled
as an explicit production rollout decision and documented before merge.

If logs, test failures, dry-run output, or audit metadata contain secret-shaped
data, stop the run, rotate the local value, add or fix a redaction test, and
remove the output before committing. Secrets, tokens, API keys, cookies, and rendered environment variable values are redacted
in logs, errors, audit metadata, and test output.

## Change log

| Date       | Change                                            | Owner              |
|------------|---------------------------------------------------|--------------------|
| 2026-05-19 | Initial database migration authoring doc (BE-0542). | Backend Operations |
