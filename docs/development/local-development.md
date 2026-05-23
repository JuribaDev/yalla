# Local development setup — Yalla Control Plane

This document is the local backend setup contract for developers working on
the Yalla Control Plane API and worker. It covers the normal laptop path, the
Postgres-backed integration-test path, and the opt-in full control-plane
stack. Keep real customer identifiers, live Dokploy credentials, database
URLs, API keys, cookies, and rendered environment values out of this file.

## Architecture boundary

Local development must preserve the production boundary:

```text
Customer / Agent / CI
  -> Yalla Control Plane API
  -> Postgres source of truth
  -> Provisioning worker
  -> private Dokploy API
```

Customers must never receive Dokploy API tokens. The API and worker read
operator-managed configuration, enforce Yalla auth/policy/quota first, persist
desired state in Postgres, and call Dokploy only through typed internal
clients. Normal local tests use fake Dokploy fixtures; external Dokploy smoke
tests are opt-in and must never run against production.

## Prerequisites

- Go matching `go.mod`
- Docker with the Compose plugin
- A shell that can export environment variables
- Optional tools for the full local verification gate: `goimports`,
  `golangci-lint`, `staticcheck`, `govulncheck`, and `goreleaser`

Check the toolchain:

```bash
go version
docker compose version
```

expected output: both commands print their version and exit with status `0`.

## Postgres for integration tests

Start the local Postgres dependency:

```bash
export YALLA_POSTGRES_PASSWORD=<redacted:postgres-password>
docker compose up -d postgres
docker compose ps postgres
```

expected output: the `postgres` service appears with `STATUS` containing
`healthy`.

Set the test database URL without committing or logging the rendered value:

```bash
export YALLA_TEST_DATABASE_URL=<redacted:postgres-dsn>
```

The test harness creates an isolated throwaway database per test from
`YALLA_TEST_DATABASE_URL`, runs embedded migrations when requested, and drops
the database during cleanup. Tests that need Postgres skip cleanly when this
variable is unset.

Run the normal backend checks:

```bash
go test ./...
go test ./internal/controlplane/...
go test -run TestMigrations ./...
```

expected output: Go reports `ok` for packages with runnable tests. Packages
whose Postgres tests are not configured report the documented skip reason
rather than reaching a live customer database.

## Full local control-plane stack

Use the full stack only when you want to run the API and worker processes
against local Postgres. Use non-production Dokploy infrastructure or fake
fixtures; never point this stack at production Dokploy.

```bash
export YALLA_POSTGRES_PASSWORD=<redacted:postgres-password>
export YALLA_SIGNING_KEYS=<redacted:signing-keys>
export YALLA_SECRET_KEYS=<redacted:secret-keys>
export YALLA_DOKPLOY_BASE_URL=https://dokploy.internal.example
export YALLA_DOKPLOY_TOKEN=<redacted:dokploy-token>
docker compose --profile control-plane up --build
```

expected output: Docker builds `yalla-api` from `Dockerfile`, builds
`yalla-worker` from `Dockerfile.worker`, starts `postgres`, and keeps the API
listening on `localhost:8080`. The worker has no HTTP listener.

Probe the API:

```bash
curl -fsS http://localhost:8080/healthz
curl -fsS http://localhost:8080/readyz
curl -fsS http://localhost:8080/version
```

Successful public responses use stable JSON envelopes with
`schema_version: yalla.output.v1`; failed probes use
`schema_version: yalla.error.v1`. Every response includes a stable
`request_id`. `/readyz` reports dependency gates such as `database`,
`migrations`, `queue`, and `Dokploy` when configured.

Inspect diagnostics only through structured JSON logs:

```bash
docker compose logs -f yalla-api yalla-worker
```

Logs should contain `service`, `request_id`, `correlation_id`, route or job
metadata, status class, and stable error codes.
Secrets, tokens, API keys, cookies, and rendered environment variable values are redacted
in logs, errors, audit metadata, and test output. Logs must not contain
request bodies or response bodies.

## Required quality checks

Before committing backend changes, run:

```bash
gofmt -w .
goimports -w .
go mod tidy
go test ./...
go test -race ./...
go vet ./...
```

If `goimports` is not installed, record that in `ralph/progress.txt` and keep
the rest of the gate explicit. For one-command local verification, run:

```bash
scripts/verify.sh
```

Documentation artifacts are pinned by focused release tests. This document is
covered by:

```bash
go test ./internal/release/... -run TestLocalDevelopmentSetupArtifact
```

When a public endpoint changes, preserve stable JSON envelopes and add tests
for success, validation failure, authorization failure, and not-found behavior.
Unit tests cover success, validation failure, authorization failure, and not-found behavior.
Integration tests run against isolated Postgres migrations and never require a live Dokploy server unless explicitly marked external.

Optional external smoke tests require deliberate operator configuration:

```bash
YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...
```

External smoke tests must never run against production.

## Failure recovery

If Postgres does not become healthy, inspect the local service:

```bash
docker compose logs postgres
docker compose ps postgres
```

Common causes are a missing `YALLA_POSTGRES_PASSWORD` export or an existing
local Postgres process already using port `5432`.

If migrations fail in tests, reset local containers and the Compose volume:

```bash
docker compose down
docker volume rm yalla_yalla_pgdata
docker compose up -d postgres
go clean -testcache
go test -run TestMigrations ./...
```

If `/readyz` fails, read the `schema_version: yalla.error.v1` envelope and use
its `request_id` to join the response to structured JSON logs. The dependency
gate names are fixed identifiers; fix the named dependency instead of
bypassing readiness.

If the API or worker prints a secret-shaped value, stop the local stack, rotate
that local credential, add or fix the redaction test, and do not commit the
output.

## Change log

| Date       | Change                                      | Owner              |
|------------|---------------------------------------------|--------------------|
| 2026-05-19 | Initial local development setup (BE-0541). | Backend Operations |
