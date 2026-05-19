# Update the OpenAPI contract

Yalla's OpenAPI document is a public compatibility contract for customers,
agents, CI, and future frontend clients. Update it in the same change as the
handler, policy, validation, envelope, audit, quota, idempotency, and tenant
isolation behavior that the document describes.

The production flow stays:

```text
Yalla API -> Postgres source of truth -> worker -> private Dokploy API
```

Do not expose raw Dokploy operations. Do not hand-write an OpenAPI operation that is not backed by a registered route.

## Required workflow

1. Register or update the route in `internal/controlplane/httpapi/routes.go`
   through `newRouteTable`.
2. Keep handlers thin. Decode request bodies with `validate.DecodeJSON`,
   return typed `apierr` values, and render responses only with
   `apienvelope.WriteData` or `apienvelope.WriteError`.
3. Add or update the `policy.Action` required by the endpoint and include the
   same action in the OpenAPI operation as `x-required-action`.
4. Add or update `openapi.Endpoint` metadata under
   `internal/controlplane/openapi`, including stable operation IDs, request and
   response schemas, status codes, examples, pagination fields when present,
   and envelope references.
5. Confirm all examples use stable JSON envelopes:

```yaml
schema_version: yalla.output.v1
ok: true
request_id: req_example
data: {}
```

```yaml
schema_version: yalla.error.v1
ok: false
request_id: req_example
error:
  code: E_EXAMPLE
  message: example failure
```

6. Add contract tests for success, validation failure, authorization failure,
   and not-found behavior. Mutation endpoints also need idempotency, audit,
   quota, conflict, and dependency-failure coverage where applicable.
7. Add tenant isolation tests for every endpoint that reads or mutates
   customer-owned resources. Cross-tenant IDs must return the stable denied or
   not-found contract without revealing data from another organization.
8. If the endpoint reads or writes persisted state, run integration tests
   against isolated Postgres migrations. Integration tests run against isolated
   Postgres migrations and never require a live Dokploy server unless
   explicitly marked external.

## Required environment variables

The required environment variables for this procedure are:

Local Postgres-backed tests use redacted placeholders only:

```sh
export YALLA_TEST_DATABASE_URL=<redacted:postgres-dsn>
```

Fake Dokploy is the default for normal tests. Live Dokploy smoke tests are
external, operator controlled, and must never run against production:

```sh
export YALLA_DOKPLOY_BASE_URL=https://dokploy.internal.example
export YALLA_DOKPLOY_TOKEN=<redacted:dokploy-token>
YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...
```

Secrets, tokens, API keys, cookies, and rendered environment variable values are redacted
in logs, errors, audit metadata, and test output.

## Verification commands

Run the focused OpenAPI and route checks before the full gate:

```sh
go test ./internal/controlplane/openapi/...
go test -run TestOpenAPI ./...
go test -run TestEveryRegisteredRouteIsDocumented ./internal/controlplane/httpapi/...
go test ./internal/controlplane/httpapi/...
```

Then run the required repository checks:

```sh
gofmt -w .
go mod tidy
go test ./...
go test -race ./...
go vet ./...
scripts/verify.sh
```

The expected output is standard Go `ok` lines for changed packages, including the
OpenAPI conformance tests. The named OpenAPI suite includes
`TestOpenAPIConformance` and `TestOpenAPIExamplesAreRedacted`.

## Contract checklist

- Stable JSON envelopes use `yalla.output.v1` and `yalla.error.v1`.
- Every response includes `request_id`.
- Public status codes, error codes, field names, and operation IDs are stable.
- Unit tests cover success, validation failure, authorization failure, and not-found behavior.
- Integration tests run against isolated Postgres migrations.
- Integration tests never require a live Dokploy server unless explicitly marked external.
- Authorization metadata matches the `policy.Action` enforced by the handler.
- Tenant isolation is proven for customer-owned reads and writes.
- Mutations enforce idempotency, audit, and quota before any provisioning job.
- `dokploy_refs` remain internal mapping data and are only exposed through
  explicitly authorized support/admin endpoints.

## Failure recovery

- If OpenAPI tests fail because a route is undocumented, update the
  `openapi.Endpoint` metadata instead of deleting the route from the test.
- If examples fail redaction checks, replace the example value with a
  `<redacted:...>` placeholder and rerun `TestOpenAPIExamplesAreRedacted`.
- If Postgres integration tests skip with
  `YALLA_TEST_DATABASE_URL not set; skipping Postgres integration test`, start
  the local dependency and export the redacted test DSN placeholder:

```sh
docker compose up -d postgres
docker compose logs postgres
go clean -testcache
```

- If local dependencies are dirty after a failed run, stop them cleanly:

```sh
docker compose down
```

- If live Dokploy smoke fails, keep it outside the normal gate. Verify the
  target is non-production, rotate any exposed operator token, and rerun only
  the opt-in command.
