# Policy engine conventions

This guide is the backend contract for changing Yalla Control Plane
authorization behavior in `internal/controlplane/policy`. The policy engine is
the source of truth for Yalla authorization. Dokploy permissions are
defense-in-depth only.

The request path remains:

```text
Customer / Agent / CI
  -> Yalla Control Plane API
  -> Postgres source of truth
  -> worker
  -> private Dokploy API
```

Short form: Yalla API -> Postgres source of truth -> worker -> private Dokploy API.

Do not expose raw Dokploy operations, do not hand customers Dokploy credentials,
and do not let a handler or worker bypass policy because an upstream Dokploy
token would allow the operation.

## Add or change a policy action

1. Define the public contract first: endpoint or job, resource kind, resource
   scope, `policy.Action`, required capability, expected audit event, stable
   error code, and compatibility impact.
2. Add the action constant in the policy action file and list it in the stable
   action catalog. The authoritative action-to-capability mapping lives in
   `internal/controlplane/policy/catalog.go`.
3. Map the action to exactly one capability. Capabilities are not hierarchical;
   grant the concrete capability that matches the operation rather than relying
   on role names in handlers.
4. Build a complete `policy.Resource` before authorization. The resource scope
   must include the organization ID and any known project, environment, or
   service IDs so scoped grants can be evaluated without a database read inside
   the engine.
5. Resolve authentication to a `policy.Principal`. Disabled principals,
   unknown roles, unknown actions, and foreign-organization resources must all
   produce deterministic deny decisions.
6. Authorize through `policy.Engine.Authorize` or the existing resolver stack.
   Do not open-code role checks in HTTP handlers, store services, workers, or
   Dokploy clients.
7. Map denied decisions to typed backend errors. Missing scope is
   `apierr.ScopeRequired`; ordinary authorization denial is `apierr.Forbidden`.
   Cross-tenant IDs must still collapse to not found at the resource resolver
   layer when revealing existence would leak another organization.
8. Emit policy decision metrics through `telemetry.PolicyDecisionMetrics` and
   audit security-relevant denials through the existing audit boundary. Metrics
   labels stay low-cardinality; IDs are latest-sample incident hints only.
9. Update OpenAPI operation metadata when a public endpoint action changes and
   ensure the operation carries the correct policy action extension.
10. Add or update matrix tests, endpoint policy tests, tenant-isolation tests,
    and handler contract tests before marking the story complete.

## Engine model

`policy.Principal` is the authenticated actor. `policy.Resource` is the target
resource and its Organization -> Project -> Environment -> Service scope.
`policy.Action` is the stable dotted operation string. The engine intersects
the action catalog with the principal role and any scoped grants.

The action catalog is a compatibility contract. Adding an action without adding
it to the catalog must fail tests, and renaming an action is a public API
change. Scoped grants apply only inside their organization and only to the
resource subtree covered by their scope.

Expected deny reasons are typed and stable:

- `ReasonDeniedCrossTenant` for foreign-organization resources that are not
  covered by the support read exception.
- `ReasonDeniedNoCapability` when the principal is in the organization but
  lacks the action capability.
- `ReasonDeniedUnknownAction` when an uncatalogued action reaches the engine.
- `ReasonDeniedUnknownRole` when a role cannot be resolved.

## Stable outputs

All public responses use stable JSON envelopes:

```yaml
schema_version: yalla.output.v1
ok: true
request_id: req_example
data:
  authorized: true
```

```yaml
schema_version: yalla.error.v1
ok: false
request_id: req_example
error:
  code: E_FORBIDDEN
  message: authorization failed
  docs_url: https://docs.yalla.example/errors/E_FORBIDDEN
```

Every response includes `request_id`. Policy denials must keep stable HTTP
status codes, stable error codes, stable field names, and redacted diagnostic
metadata. A mutating request must record the same request ID in the audit event
and any provisioning job created after authorization succeeds.

## Required environment variables

This section lists the required environment variables for the focused policy
and policy-adjacent verification suites.

Pure policy tests do not require external services:

```bash
go test ./internal/controlplane/policy/...
go test -run TestPolicyMatrix ./...
```

Persistence-backed tenant-isolation or handler contract tests need an isolated
local Postgres base DSN:

```bash
docker compose up -d postgres
export YALLA_TEST_DATABASE_URL=<redacted:postgres-dsn>
go test -run TestTenantIsolation ./...
```

Only opt-in live Dokploy smoke tests use Dokploy environment values. They are
not normal policy tests and must never run against production:

```bash
export YALLA_DOKPLOY_BASE_URL=https://dokploy.internal.example
export YALLA_DOKPLOY_TOKEN=<redacted:dokploy-token>
YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...
```

Do not put real database URLs, API keys, cookies, customer identifiers, session
tokens, rendered environment variable values, or live Dokploy credentials in
docs, logs, errors, audit metadata, test output, or dry-run output.

## Verification commands

Run focused checks while developing a policy change:

```bash
go test ./internal/controlplane/policy/...
go test -run TestPolicyMatrix ./...
go test -run TestTenantIsolation ./...
go test -run TestAdminEndpoint ./...
go test ./internal/controlplane/httpapi/...
```

Run the documentation artifact gate when editing this file:

```bash
go test ./internal/release/... -run TestPolicyEngineConventionsArtifact
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
the remaining checks explicit. The expected output for passing Go checks is the
standard package summary ending in `ok` or `?` for packages with no tests.
Expected HTTP contract output uses `schema_version: yalla.output.v1` for
success and `schema_version: yalla.error.v1` for errors.

## Contract tests

Every policy-backed endpoint should add tests for the paths that apply:

- Success response for a principal with the required action.
- Validation failure for missing or malformed scope.
- Authorization failure for a principal without the required `policy.Action`.
- Not-found response for unknown IDs and cross-tenant IDs where the resolver
  must not reveal resource existence.
- tenant isolation with at least two organizations for reads and mutations.
- Audit and policy-decision metrics for security-relevant denials.

Unit tests cover success, validation failure, authorization failure, and not-found behavior.
Integration tests run against isolated Postgres migrations and never require a live Dokploy server unless explicitly marked external.
Secrets, tokens, API keys, cookies, and rendered environment variable values are redacted in logs, errors, audit metadata, and test output.

## Safety rules

- Do not open-code role checks outside `internal/controlplane/policy`.
- Do not authorize against an empty organization scope for tenant resources.
- Do not convert cross-tenant denial into a response that reveals the foreign
  resource exists.
- Do not call Dokploy before Yalla auth, policy, quota, idempotency, desired
  state, and audit have succeeded.
- Do not expose raw Dokploy operations.
- Do not log request headers, request bodies, secret-shaped metadata, or
  rendered environment variable values from policy failures.
- Do not add a policy action without matrix coverage and OpenAPI metadata for
  the public endpoint that uses it.

## Failure recovery

- If a matrix row fails, read the subtest name first; it names the role and
  action pair. Check `internal/controlplane/policy/catalog.go`, the action
  list, and the role capability mapping before changing handlers.
- If cross-tenant behavior regresses, run `go test -run TestTenantIsolation ./...`
  and inspect the scope supplied to `policy.Resource`; most failures are missing
  organization, project, environment, or service scope at the resolver boundary.
- If a handler returns the wrong envelope for a denial, run the handler contract
  test and verify it renders through `apienvelope` using typed `apierr` errors.
- If Postgres-backed tests cannot connect, run `docker compose logs postgres`,
  `docker compose down`, `docker compose up -d postgres`, then `go clean -testcache`
  before retrying the focused suite.
- If logs, test failures, dry-run output, or audit metadata contain
  secret-shaped data, stop the run, rotate the local value, add or fix a
  redaction test, and remove the output before committing.

## Change log

| Date       | Change                                           | Owner              |
|------------|--------------------------------------------------|--------------------|
| 2026-05-19 | Initial policy engine conventions doc (BE-0545). | Backend Operations |
