# Quota Implementation Guide

This guide is the backend contract for adding or changing quota-protected
Yalla Control Plane behavior. It applies to API-backed resource creation,
durable provisioning requests, metered usage, and any repository service that
must prevent a tenant from exceeding plan or organization limits.

The request path remains:

```text
Customer / Agent / CI
  -> Yalla Control Plane API
  -> Postgres source of truth
  -> worker
  -> private Dokploy API
```

Short form: Yalla API -> Postgres source of truth -> worker -> private Dokploy API.

Do not expose raw Dokploy operations from quota code. Do not call Dokploy from
quota code. The quota layer protects Yalla source-of-truth writes; workers call
typed Dokploy clients only after auth, policy, idempotency, quota, audit, and
desired-state persistence have succeeded.

## Add or change quota enforcement

1. Define the contract first: protected resource, `policy.Action`, quota
   dimension, enforcement mode, stable error code, audit event, idempotency
   behavior, and compatibility impact.
2. Use the closed `store.QuotaResource` set for the dimension. Adding a new
   dimension requires a migration for the `quota_resource` domain, a Go
   constant in `internal/controlplane/store`, membership in the `Valid` map,
   and tests that prove the value is accepted end to end.
3. Keep quota policy and usage data in `internal/controlplane/store`.
   Repository-backed services should depend on the `store.QuotaReserver` port,
   while production wiring uses `quota.Checker` from `internal/controlplane/quota`.
4. Call `Reserve` for count-based dimensions and `ReserveAmount` for magnitude
   dimensions such as CPU, memory, storage, deployment counts, or usage-derived
   allocations.
5. Quota reservations happen in the same transaction as the desired-state write.
   Use `Store.Write` so the quota check, `quota_reservations` insert, source
   row mutation, idempotency row, audit row, and job enqueue commit or roll back
   together.
6. Every customer-data query must be tenant-scoped by `organization_id` or a
   verified parent join. Unknown and cross-tenant IDs must collapse to typed
   not-found behavior rather than leaking another tenant's existence.
7. Return quota failures through `apierr.QuotaExceeded`. The wrapped
   `quota.ExceededDetail` is recoverable with `quota.DetailOf` and carries only
   bounded counters: resource, current, reserved, requested, and limit.
8. Emit quota decision telemetry through `telemetry.QuotaUsageMetrics`. Keep
   labels low-cardinality; request, correlation, organization, principal, and
   job identifiers are incident hints only.
9. Keep handlers thin. HTTP routes authorize with the exact `policy.Action`,
   delegate to repository-backed services, and render stable JSON envelopes.
10. Normal tests use fake Dokploy or no Dokploy dependency. Live Dokploy smoke
    tests are explicitly external and must never be part of quota validation.

## Data model

Quota implementation pivots on these source-of-truth tables and types:

- `quota_policies`: effective hard, soft, metered, or disabled limits by plan
  or organization override.
- `usage_counters`: current usage that is locked for hard-limit decisions.
- `quota_reservations`: active and settled reservations that bridge the quota
  decision to the resource mutation.
- `quota_reservation_events`: audited state-machine events for reservation
  lifecycle changes.
- `store.QuotaRepository`: the repository that resolves limits, locks usage,
  sums active reservations, inserts reservations, and transitions lifecycle
  state.
- `store.QuotaReserver`: the service port used by repository services so quota
  enforcement stays testable.
- `quota.Checker`: the production quota checker service that implements the
  port using `store.QuotaRepository`.

Hard-limit rejection must happen before a resource row, provisioning job, or
Dokploy mutation is committed. soft-limit warnings are allowed to proceed but
must be surfaced as structured `yalla.output.v1.warnings`, not as ad hoc
response fields. Metered limits record usage for billing and review without a
ceiling. Disabled limits do not reserve.

## Stable outputs

All public HTTP responses above quota code use stable JSON envelopes:

```yaml
schema_version: yalla.output.v1
ok: true
request_id: req_example
data:
  id: resource_example
```

Quota rejections use the stable error envelope and HTTP 429:

```yaml
schema_version: yalla.error.v1
ok: false
request_id: req_example
error:
  code: E_QUOTA_EXCEEDED
  message: quota exceeded
  docs_url: https://docs.yalla.example/errors/E_QUOTA_EXCEEDED
```

Do not expose raw counters from another tenant. Only return quota details after
auth and policy have already established the caller can act on the scoped
organization.

## Required environment variables

This section lists the required environment variables for local quota
verification.

Most quota unit tests use fakes and need no external services. Persistence,
tenant-isolation, and concurrency tests require an isolated local Postgres base
DSN:

```bash
export YALLA_POSTGRES_PASSWORD=<redacted:postgres-password>
docker compose up -d postgres
docker compose ps postgres
export YALLA_TEST_DATABASE_URL=<redacted:postgres-dsn>
```

expected output: the `postgres` service reports a healthy status, and Go test
packages with runnable tests end in `ok`. When the database variable is not
configured, expected output includes
`YALLA_TEST_DATABASE_URL not set; skipping Postgres integration test`.

Live Dokploy credentials are not required for quota work. The only allowed live
smoke remains explicit and external:

```bash
YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...
```

That command must never run against production.

## Verification commands

Run focused quota checks while developing:

```bash
go test ./internal/controlplane/quota/...
go test ./internal/controlplane/store/...
go test -run TestQuotaConcurrency ./...
go test -run TestPolicyMatrix ./...
go test -run TestTenantIsolation ./...
```

Run the full required pre-commit gate before marking a quota story complete:

```bash
gofmt -w .
goimports -w .
go mod tidy
go test ./...
go test -race ./...
go vet ./...
scripts/verify.sh
```

The release gate for this document is:

```bash
go test ./internal/release/... -run TestQuotaImplementationGuideArtifact
```

If `goimports` is not installed, document that in `ralph/progress.txt` and keep
the remaining checks explicit.

Unit tests cover success, validation failure, authorization failure, and not-found behavior.
Integration tests run against isolated Postgres migrations and never require a live Dokploy server unless explicitly marked external.
Secrets, tokens, API keys, cookies, and rendered environment variable values are redacted in logs, errors, audit metadata, and test output.

## Test coverage expectations

Quota changes should include the coverage that matches their blast radius:

- Unit tests for the local decision: allowed, validation failure, hard-limit
  rejection, soft-limit warning behavior, and typed `quota.ExceededDetail`.
- Repository integration tests using `testutil.RequireMigratedDB` for
  migration-backed reads, writes, rollback, and tenant isolation.
- Concurrency tests for hard-limit rejection when multiple transactions reserve
  the same tenant and resource at once.
- HTTP contract tests for stable status, envelope, `request_id`, authorization
  failure, not-found behavior, quota failure, and redaction.
- Audit assertions for quota failures and mutating paths that reserve quota.
- Fake Dokploy worker tests only when the quota-protected path enqueues
  provisioning; quota itself must not depend on live Dokploy.

## Safety rules

- Do not expose raw Dokploy operations.
- Do not call Dokploy from quota code.
- Do not reserve quota outside the transaction that mutates desired state.
- Do not bypass auth, scoped grants, idempotency, or audit on a mutating path.
- Do not build SQL dynamically from caller-supplied quota dimensions.
- Do not print SQL bind values, DSNs, request bodies, tokens, cookies, API keys,
  rendered environment variable values, or secret metadata in errors, logs,
  audit payloads, dry-run output, or test output.
- Do not disclose whether cross-tenant IDs exist.
- Do not add a quota dimension without updating the migration, Go constant,
  membership map, OpenAPI or endpoint docs when applicable, and focused tests.

## Failure recovery

If Postgres is unavailable:

```bash
docker compose logs postgres
docker compose ps postgres
docker compose down
docker compose up -d postgres
```

Fix the local dependency first. Use `docker compose down` only for the local
dependency stack, then restart Postgres. Do not point quota tests at production,
staging, or any shared database.

If tests are returning stale results:

```bash
go clean -testcache
go test ./internal/controlplane/quota/...
go test -run TestQuotaConcurrency ./...
```

If a hard-limit concurrency test fails, inspect the `Store.Write` transaction
first. The quota decision must lock the tenant/resource usage row, sum active
reservations, insert the new reservation, and commit with the protected write.

If migration-backed quota tests fail after changing dimensions, rerun:

```bash
go test -run TestMigrations ./...
go test ./internal/controlplane/store/...
```

If a quota error, audit metadata payload, dry-run output, or test log contains
secret-shaped data, stop the run, rotate the local value if needed, add or fix
a redaction test, and remove the output before committing.

## Change log

| Date       | Change                                           | Owner              |
|------------|--------------------------------------------------|--------------------|
| 2026-05-19 | Initial quota implementation guide (BE-0546).    | Backend Operations |
