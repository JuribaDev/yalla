# Yalla Control Plane security review checklist

Use this checklist before approving backend changes that affect
`/usr/local/bin/yalla-api`, `/usr/local/bin/yalla-worker`, PostgreSQL
migrations, public API contracts, auth, policy, quota, audit, jobs,
secrets, billing-grade metering, backoffice configuration, or the private
Dokploy integration.

## Scope

The security boundary remains:

```text
Customer / Agent / CI
  -> Yalla Control Plane API
  -> Postgres source of truth
  -> Provisioning worker
  -> private Dokploy API
```

Yalla owns tenant identity, scoped grants, desired state, durable jobs,
audit events, limits, and metered usage. Dokploy is private infrastructure.
Customers, agents, CI jobs, screenshots, logs, tests, and dry-run output must
never receive Dokploy credentials, database credentials, API keys, cookies,
signing keys, secret-encryption keys, or rendered environment values.

## Required environment

Normal security review uses local or isolated test infrastructure. Use
redacted placeholders in review notes and command transcripts:

```bash
YALLA_DATABASE_URL=<redacted:YALLA_DATABASE_URL>
YALLA_DOKPLOY_BASE_URL=<redacted:YALLA_DOKPLOY_BASE_URL>
YALLA_DOKPLOY_TOKEN=<redacted:YALLA_DOKPLOY_TOKEN>
```

Do not paste resolved values. If a focused integration suite needs Postgres,
start only the local dependency stack and keep the database isolated from
production:

```bash
docker compose up -d postgres
```

Normal security review gates must never require a live Dokploy server. The
external smoke test is opt-in, non-production only, and must never run against production:

```bash
YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...
```

## Contract checks

Confirm public API behavior stays stable and agent-friendly:

- Success responses use `schema_version: yalla.output.v1`.
- Error responses use `schema_version: yalla.error.v1`.
- Every response, log record, audit record, and request-created job carries a
  `request_id`.
- Error responses use stable error codes, stable HTTP statuses, and typed
  backend errors rather than handler-local JSON.
- New or changed public routes update OpenAPI and include the required action.
- Mutating routes enforce auth, policy, quota, idempotency, source-of-truth
  persistence, durable job enqueue, and audit before any Dokploy action.
- Customer-facing endpoints never expose raw Dokploy operations or broad
  Dokploy credentials.

Expected envelope probes look like:

```text
HTTP/1.1 200 OK
{"schema_version":"yalla.output.v1","request_id":"<request_id>","data":{}}
{"schema_version":"yalla.error.v1","request_id":"<request_id>","error":{"code":"E_EXAMPLE"}}
```

## Test matrix

For every touched endpoint, service, repository, policy rule, quota path,
worker job, or migration, confirm focused tests cover:

- success
- validation failure
- unauthenticated request
- authorization failure
- not-found
- conflict when applicable
- quota failure when applicable
- tenant isolation and cross-tenant IDs
- idempotency replay when a mutating request accepts an idempotency key
- audit event append for allowed, denied, and quota-failure decisions where
  applicable

Integration tests must run against isolated Postgres migrations. They must use
fake Dokploy fixtures by default and must not depend on live Dokploy unless the
suite is explicitly guarded by `YALLA_EXTERNAL_DOKPLOY=1`.

## Required commands

Run the required repository gates from the repository root:

```bash
gofmt -w .
goimports -w .
go mod tidy
go test ./...
go test -race ./...
go vet ./...
scripts/verify.sh
```

If `goimports` is not installed, record that fact in the review notes and
keep `gofmt -w .` passing. For backend security-sensitive changes, also run
the relevant focused suites:

```bash
go test ./internal/controlplane/...
go test -race ./internal/controlplane/...
go test -run TestMigrations ./...
go test -run TestPolicyMatrix ./...
go test -run TestQuotaConcurrency ./...
go test -run TestFakeDokploy ./...
go test ./internal/release/... -run TestSecurityReviewChecklistArtifact
```

Expected successful command output is the standard Go test result:

```text
ok  	github.com/JuribaDev/yalla/internal/controlplane/httpapi	0.123s
PASS
```

Expected formatting and module cleanup result is a clean worktree for generated
formatting and dependency metadata, or no changes when the tree was already
formatted:

```text
no changes
```

## Redaction checks

Logs, errors, audit metadata, metrics hints, test output, dry-run output,
review notes, incident annotations, and screenshots must never contain
tokens, cookies, API keys, database URLs, Dokploy tokens, authorization headers,
request bodies, response bodies, secret variable values, credential ciphertext,
or rendered environment values.

Use redacted variable names when the operator needs to know which setting is
involved, for example `<redacted:YALLA_DATABASE_URL>`. Do not redact by
truncating a real secret; replace the whole value.

Before approving, inspect changed tests and fixtures for hard-coded secret
shapes and confirm any metadata assertions use redacted values.

## Failure recovery

Use this failure recovery section when any required security gate fails.

If a gate fails, stop the review decision and fix forward:

- Formatting or module cleanup failure: run the exact formatter or
  `go mod tidy`, inspect the diff, and re-run the full required gate.
- Contract test failure: preserve the stable schema, status, or error code
  unless the PRD story explicitly changes the compatibility contract.
- Tenant isolation failure: treat as blocking; verify every customer-data
  query is scoped by organization or a verified parent join before re-running.
- Redaction failure: rotate any exposed real credential through the owning
  secret manager, remove it from history or artifacts where practical, and add
  a regression assertion before re-running.
- Migration failure: reset only the isolated test database, fix the paired
  migration, and re-run migration tests from an empty database.
- Fake Dokploy failure: fix the typed Yalla contract or fixture. Do not switch
  the normal suite to a live Dokploy dependency.

Record failed gate names and stable error codes only. Do not copy raw command
output that includes request headers, request bodies, response bodies, rendered
environment values, or credentials.

## Change log

| Date       | Change                                      | Owner            |
|------------|---------------------------------------------|------------------|
| 2026-05-19 | Initial security review checklist (BE-0550). | Backend Security |
