# API Handler Conventions

This guide is the backend contract for adding or changing Yalla Control Plane
HTTP handlers. It is for production-grade API work in `internal/controlplane`,
especially `internal/controlplane/httpapi`.

The request path remains:

```text
Customer / Agent / CI
  -> Yalla Control Plane API
  -> Postgres source of truth
  -> worker
  -> private Dokploy API
```

Short form: Yalla API -> Postgres source of truth -> worker -> private Dokploy API.

Do not expose raw Dokploy operations from a customer-facing handler. Do not hand
customers Dokploy credentials. Handlers express Yalla intent, persist desired
state, enqueue durable work when needed, and let the worker call the typed
Dokploy client.

## Add or change an API handler

1. Define the public contract first: method, path, request body, response
   fields, `policy.Action`, required idempotency key behavior, audit event,
   quota resource, job type, stable error codes, and compatibility impact.
2. Add the route in `internal/controlplane/httpapi/routes.go`. Use
   `newRouteTable` as the single source of truth and add the matching
   `openapi.Endpoint` metadata there. Do not register routes directly on the
   mux from `NewHandler`.
3. Keep the handler thin. Decode and validate request input, derive the actor
   and request context, delegate to a focused service or repository-backed
   manager, then render the response.
4. Decode JSON bodies only through `validate.DecodeJSON`. Do not read request
   bodies outside validate.DecodeJSON unless you are editing the existing
   idempotency middleware's bounded `io.LimitReader` pattern.
5. Return typed backend errors from `apierr`. Do not create ad hoc error
   strings, do not call the shared CLI error package directly from handlers,
   and do not leak submitted secret values in validation details.
6. Render success through `apienvelope.WriteData` or the warning/status variant
   already used by the package. Render errors through `apienvelope.WriteError`.
   Do not marshal JSON directly in handlers.
7. Resolve tenant scope before reading or mutating customer data. Unknown and
   cross-tenant identifiers must collapse to the same not-found shape unless
   the endpoint is explicitly support-only.
8. Authorize with the exact `policy.Action` for the operation. Mutating paths
   must enforce auth, scoped grants, quota, idempotency, and audit before any
   provisioning side effect can happen.
9. When a Dokploy mutation is needed, write desired state and enqueue a durable
   provisioning job in the same source-of-truth transaction. The API handler
   does not call Dokploy directly.
10. Add or update OpenAPI metadata, contract tests, policy matrix coverage, and
    tenant-isolation tests. Public response schemas are compatibility
    contracts.

## Handler shape

Use this flow for normal authenticated handlers:

```text
route table
  -> auth middleware
  -> scope resolver
  -> policy authorize
  -> handler
  -> service/repository transaction
  -> envelope renderer
```

The handler should only coordinate edge concerns:

- Path and query parsing.
- Size-bounded body decoding with `validate.DecodeJSON`.
- Stable validation error construction with `apierr.Invalid` or the local
  validation helpers already used in `httpapi`.
- Actor, request, and correlation context from auth and telemetry. Read
  request identifiers with `telemetry.RequestID(ctx)` and correlation values
  from `telemetry`.
- Delegation to the package-owned service interface.
- Rendering through `apienvelope`.

Business logic belongs outside handlers. Policy decisions belong in `policy`.
Quota reservations belong in `quota` and repository-backed services. Source of
truth writes belong in `store`. Worker behavior belongs in `worker` or the
provisioning package. Dokploy calls belong behind the typed internal Dokploy
client.

## Stable outputs

All public responses use stable JSON envelopes:

```yaml
schema_version: yalla.output.v1
ok: true
request_id: req_example
data:
  id: resource_example
```

```yaml
schema_version: yalla.error.v1
ok: false
request_id: req_example
error:
  code: E_VALIDATION
  message: request validation failed
  docs_url: https://docs.yalla.example/errors/E_VALIDATION
```

Every response includes `request_id`. Handlers must preserve stable HTTP status
codes, stable error codes, stable field names, and stable pagination ordering.
If a route creates a provisioning job, the same request ID must reach the job
metadata and audit event.

## Required environment variables

The required environment variables for persistence-backed handler tests and
optional external smoke tests are listed below.

Most handler tests use fakes and do not need external services. Persistence or
tenant-isolation tests need an isolated local Postgres base DSN:

```bash
docker compose up -d postgres
export YALLA_TEST_DATABASE_URL=<redacted:postgres-dsn>
```

Only opt-in live Dokploy smoke tests use the Dokploy environment. They are not
normal handler tests and must never run against production:

```bash
export YALLA_DOKPLOY_BASE_URL=https://dokploy.internal.example
export YALLA_DOKPLOY_TOKEN=<redacted:dokploy-token>
YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...
```

Do not put real database URLs, API keys, cookies, customer identifiers, session
tokens, rendered environment variable values, or live Dokploy credentials in
docs, logs, errors, audit metadata, test output, or dry-run output.

## Verification commands

Run focused checks while developing the handler:

```bash
go test ./internal/controlplane/httpapi/...
go test ./internal/controlplane/openapi/...
go test -run TestEveryRegisteredRouteIsDocumented ./internal/controlplane/httpapi/...
go test -run TestPolicyMatrix ./...
go test -run TestQuotaConcurrency ./...
```

For the required pre-commit gate, run:

```bash
gofmt -w .
goimports -w .
go mod tidy
go test ./...
go test -race ./...
go vet ./...
scripts/verify.sh
```

If `goimports` is not installed, document that in `ralph/progress.txt` and keep
the remaining checks explicit. If the route touches persistence, migrations,
jobs, quota, policy, or worker behavior, also run the focused suites named by
the story.

The expected output for passing Go checks is the standard package summary ending in
`ok` or `?` for packages with no tests. Expected HTTP contract output uses
`schema_version: yalla.output.v1` for success and `schema_version:
yalla.error.v1` for errors.

## Contract tests

Every public endpoint should add tests for the paths that apply:

- Success response, including status code, envelope, `request_id`, and stable
  response fields.
- Validation failure with stable field paths and no submitted secret values.
- Unauthenticated response.
- Unauthorized response for a principal without the required `policy.Action`.
- Not-found response for unknown IDs and cross-tenant IDs.
- Conflict response for duplicate or stale requests.
- Quota failure path when the route reserves quota.
- Tenant isolation with at least two organizations when the route reads or
  mutates customer-owned resources.
- Idempotency replay for mutating endpoints that accept an idempotency key.
- Audit event and job metadata assertions for mutating endpoints.

Unit tests cover success, validation failure, authorization failure, and not-found behavior.
Integration tests run against isolated Postgres migrations and never require a live Dokploy server unless explicitly marked external.
Secrets, tokens, API keys, cookies, and rendered environment variable values are redacted in logs, errors, audit metadata, and test output.

## Safety rules

- Do not marshal JSON directly in handlers.
- Do not read request bodies outside validate.DecodeJSON.
- Do not write Access-Control-* headers from a handler.
- Do not read Cookie as a credential.
- Do not log headers or bodies.
- Do not include raw DSNs, tokens, API keys, cookies, submitted secrets, or
  Dokploy credentials in errors, logs, audit metadata, tests, or docs.
- Do not authorize against placeholder organization scope when the route
  targets a real tenant resource.
- Do not call Dokploy from the handler.
- Do not add route-specific shortcuts around policy, quota, idempotency, audit,
  or tenant isolation.

## Failure recovery

- If route documentation drifts, run
  `go test -run TestEveryRegisteredRouteIsDocumented ./internal/controlplane/httpapi/...`
  and update `internal/controlplane/httpapi/routes.go` plus the
  `openapi.Endpoint` metadata together.
- If a handler contract test fails after a route change, inspect the envelope
  and status first. Public behavior changes require a deliberate PRD/story
  decision, not a test-only update.
- If a persistence-backed test fails because Postgres is unavailable, run
  `docker compose up -d postgres`, confirm with `docker compose logs postgres`,
  export `YALLA_TEST_DATABASE_URL=<redacted:postgres-dsn>`, then rerun the
  focused package test.
- If migration-backed tests fail, follow
  `docs/development/database-migration-authoring.md` before changing handler
  code. Dirty or incompatible migrations should be fixed at the migration
  boundary.
- If Go test caching hides a stale result, run `go clean -testcache` and repeat
  the focused command.
- If the local dependency stack is unhealthy, run `docker compose down`, then
  start Postgres again. Remove local volumes only when you do not need the data.
- If a live Dokploy smoke test is needed, use only the opt-in
  `YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...` command
  against a non-production target.
