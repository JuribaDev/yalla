# Fake Dokploy usage - Yalla Control Plane

This document is the backend contract for using fake Dokploy fixtures in
Yalla Control Plane tests. Fake Dokploy is the normal test dependency for any
code that needs Dokploy-shaped behavior; live Dokploy access is only for the
explicit external smoke path.

## Architecture boundary

Dokploy remains private infrastructure behind Yalla source of truth:

```text
Customer / Agent / CI -> Yalla API -> Postgres source of truth -> provisioning worker -> private Dokploy API
```

Tests that cross this boundary should use the in-process fake server under:

```text
internal/controlplane/dokploy/dokployfake
```

Use `dokployfake.New` from tests in `internal/controlplane/dokploy`,
`internal/controlplane/worker`, `internal/controlplane/httpapi`, or focused
service packages that need a typed Dokploy dependency. Do not expose raw Dokploy operations through customer-facing tests, fixtures, or endpoints. Do not call Dokploy from handlers; handlers should create or read Yalla source of truth and let worker/provisioner code use the typed Dokploy client.

## Use fake Dokploy

Use this workflow when a test needs Dokploy behavior:

1. Create a fresh `dokployfake.New` server inside the test or fixture setup.
   Do not share fake instances across tests; per-test state keeps request
   recording, fault injection, and deterministic resource IDs isolated.
2. Point the typed client at the fake server URL. Keep authentication material
   synthetic and assert recorded `Authorization` data is redacted to
   `output.Sentinel`.
3. Drive behavior through the same public package seam production uses:
   `internal/controlplane/dokploy` for typed client behavior,
   `internal/controlplane/worker` for provisioning jobs, and
   `internal/controlplane/httpapi` for endpoint contract tests.
4. Persist and read tenant-owned state through Postgres repositories when the
   path touches source of truth. Tests must verify tenant isolation before a
   Dokploy-shaped action can observe or mutate child resources such as
   `dokploy_refs`.
5. Cover success, validation failure, authorization failure, and not-found
   behavior at the API or service layer. Worker tests should also cover
   malformed payloads, dependency failure, replay, and idempotency where the
   job can be retried.
6. Keep quota, idempotency, and audit assertions near the source-of-truth write
   that creates or changes provisioning intent.

The canonical fake-Dokploy contract tests are:

- `TestFakeDokployContractDeterministicHierarchyIDs`
- `TestFakeDokployContractRecordedRequestsRedactCredentials`

The first pins deterministic hierarchy IDs across independent fake servers.
The second pins recorder redaction for credentials in headers, projections,
and request bodies.

## Required environment variables

This section lists the required environment variables for local fake-Dokploy
and Postgres-backed verification.

Normal fake-Dokploy unit tests do not need live Dokploy environment variables.

Postgres-backed integration tests need a local database dependency and a
redacted test DSN:

```bash
export YALLA_POSTGRES_PASSWORD=<redacted:postgres-password>
docker compose up -d postgres
docker compose ps postgres
export YALLA_TEST_DATABASE_URL=<redacted:postgres-dsn>
```

expected output: the `postgres` service appears with `STATUS` containing
`healthy`. If the test DSN is not configured, expected output includes
`YALLA_TEST_DATABASE_URL not set; skipping Postgres integration test`.

Only the opt-in live smoke path uses Dokploy-shaped runtime variables:

```bash
export YALLA_DOKPLOY_BASE_URL=https://dokploy.internal.example
export YALLA_DOKPLOY_TOKEN=<redacted:dokploy-token>
YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...
```

That command must never run against production. Use a disposable Dokploy
instance with throwaway resources and credentials.

## Verification commands

Run the focused fake-Dokploy checks while developing:

```bash
go test -run TestFakeDokploy ./...
go test ./internal/controlplane/dokploy/...
go test ./internal/controlplane/worker/...
go test ./internal/controlplane/httpapi/...
```

expected output: each command prints `ok` for the relevant package, or skips
Postgres integration cases with the documented
`YALLA_TEST_DATABASE_URL not set; skipping Postgres integration test` message
when the local database is not configured.

Run the commit gate before marking the story complete:

```bash
gofmt -w .
goimports -w .
go mod tidy
go test ./...
go test -race ./...
go vet ./...
scripts/verify.sh
```

If `goimports` is not installed, document that in `ralph/progress.txt` and
still run the rest of the required checks.

## Contracts and safety checklist

HTTP-facing tests that observe worker or provisioning state must preserve
stable JSON envelopes.

Every fake-Dokploy-backed test must preserve these contracts:

- Stable JSON envelopes remain `schema_version yalla.output.v1` and
  `schema_version yalla.error.v1` at HTTP boundaries, and every response
  includes `request_id`.
- Unit tests cover success, validation failure, authorization failure, and not-found behavior for any API or service path they exercise.
- Integration tests run against isolated Postgres migrations and never require a live Dokploy server unless explicitly marked external.
- Secrets, tokens, API keys, cookies, and rendered environment variable values are redacted from logs, errors, audit metadata, dry-run output, docs, and test output.
- Fake request records replace credential-shaped values with `output.Sentinel`
  before assertions, failure messages, or CI output can read them.
- Tenant isolation is proved before reads, writes, Dokploy-shaped calls, and
  `dokploy_refs` persistence. Cross-tenant IDs collapse to not found.
- Idempotency keys guard customer-initiated mutations, and replay tests should
  converge through existing source-of-truth rows instead of duplicate Dokploy
  resources.
- Quota is reserved before enqueueing provisioning work that creates or expands
  billable resources.
- Audit events are appended in the same transaction as desired-state writes
  and job creation for mutating customer or admin actions.

## Failure recovery

Use these recovery steps before changing code:

1. Clear stale test results:

   ```bash
   go clean -testcache
   ```

2. Restart the local database if integration tests cannot connect:

   ```bash
   docker compose up -d postgres
   docker compose logs postgres
   ```

3. Stop the local dependency stack after debugging:

   ```bash
   docker compose down
   ```

4. If a fake-Dokploy assertion fails on recorded requests, inspect the
   method, path, and request index from the failure. Do not print raw headers,
   bodies, tokens, cookies, API keys, or rendered environment variable values
   while debugging. Add redaction at the recorder or renderer boundary first,
   then rerun `go test -run TestFakeDokploy ./...`.

5. If the external smoke path fails, confirm `YALLA_EXTERNAL_DOKPLOY=1` was
   intentional, the target is disposable, and the Dokploy variables point at a
   non-production instance. Default CI and local commit gates should remain on
   fake Dokploy only.
