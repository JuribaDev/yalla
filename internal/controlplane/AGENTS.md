# internal/controlplane

Backend control-plane packages live here. The CLI remains under `internal/cli`;
do not mix customer API handlers into CLI packages.

- `cmd/yalla-api` and `cmd/yalla-worker` are separate binaries in the same Go
  module as the CLI so shared contracts can be reused without a second repo.
- Keep HTTP handlers thin. Put business logic in focused packages such as
  `auth`, `policy`, `quota`, `jobs`, `dokploy`, `store`, `audit`, and
  `telemetry`.
- Public API responses must use stable envelopes:
  `yalla.output.v1` for success and `yalla.error.v1` for errors. Render every
  response — success and error — through `apienvelope.WriteData` /
  `apienvelope.WriteError`. Handlers must never marshal JSON directly; the
  envelope structs are unexported so this boundary is enforced by the compiler.
  HTTP status follows the error `Code` via `apienvelope.StatusForCode`; only
  use `WriteErrorStatus` when a status genuinely cannot be derived from the
  code (e.g. `/readyz` returning 503).
- Construct backend errors through `apierr`, never `yerr.New` directly in
  handlers/services. `apierr` is the catalogued taxonomy: `Unauthenticated`,
  `Forbidden`, `InvalidInput`/`Invalid`, `NotFound`, `Conflict`,
  `QuotaExceeded`, the dependency constructors (`DokployUnavailable`,
  `StoreUnavailable`, `QueueUnavailable`, `NetworkFailure`, `Timeout`), and
  `Internal`. Adding a new error code is a multi-file change: define the
  `yerr.Code` constant in `internal/errors` (with its `codeDescriptions`,
  `AllCodes`, and `ExitCode` entries — the code is shared with the CLI
  manifest), add it to `apierr`'s `taxonomy` map with a constructor, and, if it
  needs a non-500 status, a case in `apienvelope.StatusForCode` (the single
  source of truth `apierr.Lookup` reads). `apienvelope_test.TestStatusForCode`
  iterates `AllCodes` and asserts every code is ≥ 400, so a new code with no
  `StatusForCode` case silently passes as 500 — add the case deliberately.
  `MessageGeneric` codes
  must keep the cause out of `Message`/`Hint` — wrap it so logs can still see
  it. `InvalidInput` carries `FieldViolation`s (field path + reason, never the
  submitted value); recover them with `apierr.ViolationsOf`. Dependency
  failures are recoverable with `apierr.DependencyOf` even when they share a
  code (store and queue both use `E_UNAVAILABLE`).
- Every customer-data path must eventually resolve organization scope before
  reading or mutating data. Cross-tenant IDs must not leak resource existence.
- Dokploy is a private provisioning backend. Customer-facing code should call
  typed control-plane services, not raw Dokploy operations.
- Normal tests should use fake dependencies. Live Dokploy tests must be
  opt-in and clearly named as external smoke tests.
- Process lifecycle lives in `runtime`: use `runtime.RunHTTPServer` for the
  API and `worker.Loop` for background jobs. Binaries derive shutdown from a
  single `signal.NotifyContext` and pass `cfg.ShutdownTimeout`; do not
  hand-roll `select`/`Shutdown` blocks in `main`.
- `/readyz` is gated by `runtime.Readiness` and must report 503 (`E_SERVER`)
  until every startup gate passes. When ready it returns a `yalla.output.v1`
  envelope whose `data.checks` map names every dependency gate and its pass
  state; when not ready the 503 error hint lists the pending check names
  (fixed, non-secret identifiers — never values). Binaries register one gate
  per real dependency (`database`, `migrations`, `queue`, and `dokploy` when a
  Dokploy base URL is configured), not a single `startup` gate. `/healthz` is
  liveness-only — it never depends on downstream checks.
- `/version` reports build identity (`version`/`commit`/`date`) plus the two
  contract fields: `api_schema_version` (the stable `runtime.APISchemaVersion`
  constant) and `migration_version` (dynamic, read from a
  `runtime.MetaReporter`). `runtime.Meta` is the concurrency-safe reporter the
  API binary populates once the persistence layer resolves the applied
  migration version; a nil reporter yields `runtime.MigrationVersionUnknown`.
- New background workers depend on the `worker.Claimer`/`worker.Lease`
  interfaces, never on a concrete job store directly, so they stay testable
  with fakes before the durable Postgres queue exists.
- Request correlation lives in `telemetry`. `telemetry.Correlate` is the
  outermost HTTP middleware (`httpapi.NewHandler` wraps the whole mux in it):
  it resolves a `request_id` (per request) and `correlation_id` (per workflow)
  onto the request context before any handler runs. Inbound `X-Request-Id` /
  `X-Correlation-Id` headers are honoured only when they pass
  `telemetry.SafeID` (`[A-Za-z0-9._-]`, 1..128 chars) — unsafe values are
  discarded and a fresh `telemetry.NewRequestID()` is generated, so a
  header-injection payload can never reach logs, response headers, or job
  rows. Read the IDs anywhere via `telemetry.RequestID(ctx)` /
  `telemetry.CorrelationID(ctx)` / `telemetry.FromContext(ctx)`; never thread
  them through signatures. New non-HTTP entry points (worker jobs) should seed
  their own context with `telemetry.WithCorrelation`.
- `telemetry.RequestLogging(logger)` is the per-request structured-log
  middleware. `httpapi.NewHandler` wraps the routed mux in it, just inside
  `Correlate`, so every served request emits exactly one JSON record with
  `method`, `route`, `target`, `status`, `latency_ms`, `bytes`, `request_id`,
  and `correlation_id` (plus `org_id` / `principal_id` once resolved). It never
  logs headers or bodies, and the request target is run through a redactor.
  Level follows the outcome: 5xx → error, 4xx → warn, else info; the logger's
  threshold (from `YALLA_LOG_LEVEL`) decides what is actually written. The
  auth/policy layers must call `telemetry.SetOrgID(ctx, …)` /
  `telemetry.SetPrincipalID(ctx, …)` once they resolve those values so they
  reach the per-request log record. Service binaries bind `service` onto the
  logger with `logger.With(slog.String("service", …))` and log JSON to stdout.
- Routes are data-driven. `httpapi/routes.go` `newRouteTable` is the single
  source of truth: each `apiRoute` pairs the served `http.HandlerFunc` with its
  `openapi.Endpoint` metadata. `NewHandler` registers every entry on the mux
  *and* generates the OpenAPI document from the same table, so a served route
  is always a documented route — `TestEveryRegisteredRouteIsDocumented` fails
  CI if they drift. When you add an endpoint, add it to `newRouteTable` (or, for
  a self-referential route like `/openapi.json`, follow the `openAPIEndpoint`
  pattern); never call `mux.HandleFunc` directly in `NewHandler`.
- Persistence tests use the shared harness in `internal/controlplane/testutil`,
  not hand-rolled database setup. `testutil.RequireDB(t)` provisions an empty,
  isolated, throwaway Postgres database per test; `testutil.RequireMigratedDB(t)`
  also applies the embedded migrations. Both skip the test (with the documented
  `testutil.SkipReason`) when `YALLA_TEST_DATABASE_URL` is unset, so
  `go test ./...` stays green without Postgres, and both drop the database on
  cleanup — safe under `t.Parallel()` because every call gets its own uniquely
  named database. `testutil.NewFactory(t)` builds deterministically-shaped,
  globally-unique fixture values for the `Organization -> Project ->
  Environment -> Service` hierarchy plus `User` and `APIKey`; two factories
  never collide, so one test can never observe another's tenant. Guard
  "must not leak a secret" assertions with `testutil.AssertRedacted` /
  `AssertRedactedValue`. The `store/migrate` package keeps its own local
  `testPool` helper instead — it cannot import `testutil` (which imports
  `migrate`) without an import cycle.
- The OpenAPI document is built by `internal/controlplane/openapi` from a
  neutral `[]openapi.Endpoint`. It is OpenAPI 3.1, references the two stable
  envelope schemas (`SchemaSuccessEnvelope` / `SchemaErrorEnvelope`), and is
  served raw (not enveloped) at `GET /openapi.json` without auth. Public
  endpoints emit `security: []`; authenticated ones require `ApiKeyAuth`. Maps
  marshal with sorted keys so the artifact is byte-stable. Any sample value
  that looks like a secret must use `output.Sentinel`, never a real credential.
- Resource identity, slug, and Dokploy-naming primitives live in
  `internal/controlplane/domain`. Generate IDs with `domain.NewID(kind)` (never
  hand-build a `<prefix>_...` string) and validate inbound ones with
  `domain.ParseID`; the kind prefixes (`org_`, `usr_`, `key_`, `proj_`, `env_`,
  `svc_`, `dep_`, `job_`) and the encoding are a stable contract. Human labels
  become slugs through `domain.NormalizeSlug` (lenient) or `domain.ParseSlug`
  (strict); slug uniqueness within a parent scope is a database constraint, not
  something this package enforces. Build the Dokploy-side name with
  `domain.DokployName(label, id)` — it embeds the full Yalla ID so the name is
  deterministic and Docker-safe. The package returns its own sentinel errors
  (`ErrInvalidID`, `ErrInvalidSlug`, …) with no HTTP semantics; the handler
  layer maps them to `apierr.InvalidInput`.
- Authorization is `internal/controlplane/policy`. It is the authoritative
  engine — Dokploy permissions are only defense-in-depth. `policy.Engine` is a
  pure, total decision function: `Decide(Principal, Action, Resource)` returns
  a `Decision{Allow, Reason}` with a stable `Reason` code; `Authorize` /
  `AuthorizeCtx` map a denial onto typed `apierr` (`Unauthenticated` for a
  missing principal, `Forbidden` otherwise). Every endpoint maps to exactly one
  `policy.Action`. Actions are named `policy.Action…` constants in
  `policy/actions.go` (never bare string literals — a typo must be a compile
  error); `allActions` enumerates them, `defaultActionCatalog` maps each to one
  `Capability`, and `policy.Catalogued(action)` is the membership check. When
  you add an endpoint, add its `Action` constant in `actions.go`, list it in
  `allActions`, map it in `defaultActionCatalog` (or pass `policy.WithAction`
  for a late addition), and set `openapi.Endpoint.RequiredAction` on the route
  (rendered as the `x-required-action` OpenAPI extension). `TestPolicyMatrix`,
  `TestCatalogAndRolesAreWellFormed`, `TestActionCatalogMatchesEnumeration`,
  and httpapi's `TestEveryAuthenticatedRouteHasMappedAction` guard the catalog —
  an authenticated route without a catalogued action fails CI. Roles confer `Capability` sets, not individual actions; the six
  built-ins are fixed and custom roles resolve through a `CustomRoleResolver`
  hook. Scoped `Grant`s narrow/widen authority within an org via `Scope`
  containment over Organization→Project→Environment→Service; cross-tenant
  resources are denied by construction except support reads/break-glass. The
  authenticated principal travels on the request context via
  `policy.WithPrincipal` / `policy.PrincipalFromContext` — never thread it
  through signatures. The `store.Authorizer` port is satisfied by this engine;
  store keeps only the narrow port and never imports `policy`.
- Request authentication is `auth.Authenticator`; the HTTP wrappers are
  `httpapi.RequireAuth` / `httpapi.RequireInternalWorker`. `RequireAuth`
  authenticates the bearer credential, attaches the principal to the context
  (`policy.WithPrincipal` + `telemetry.SetOrgID`/`SetPrincipalID`), then
  authorizes the route's action against a `ResourceResolver` (nil ⇒ the
  principal's own organization scope — pass a resolver that reads path params
  so a cross-tenant id is a 403, not a silent allow). Missing authentication
  material is `401 E_AUTHENTICATION_REQUIRED` via
  `apierr.AuthenticationRequired()`; a supplied but rejected credential is
  `401 E_AUTH_INVALID` via `apierr.AuthInvalid()` with a **fixed generic
  message** (never reveal which check failed or whether a key prefix exists).
  No-bearer, malformed-bearer, and cookie-only tests should assert
  `E_AUTHENTICATION_REQUIRED`; invalid-token tests should assert
  `E_AUTH_INVALID`. Legacy typed `apierr.Unauthenticated(...)` values still
  render `E_AUTH` for older internal call sites and should not be used for new
  invalid-credential middleware paths. An
  authenticated-but-unauthorized request is `403 E_FORBIDDEN` carrying the
  stable policy reason. A datastore failure during authentication keeps its
  typed status (a 5xx) and is never collapsed into a 401. The middleware is not
  yet wired into `newRouteTable` — the bootstrap routes are all public; the
  endpoint stories that add authenticated routes wrap them with `RequireAuth`.
- Idempotency for mutating endpoints is `httpapi.RequireIdempotency(store, ttl)`
  — middleware installed **inside** `RequireAuth` (it reads
  `policy.PrincipalFromContext` to scope the `Idempotency-Key` to a principal
  within a tenant). Safe methods and keyless unsafe requests pass straight
  through (idempotency is opt-in). The first request for a key claims it, runs
  the handler against a buffering `responseCapture`, and records the rendered
  envelope; a retry with the same key + same request hash replays the recorded
  response (`Idempotency-Replayed: true`), a different request is
  `409 E_IDEMPOTENCY_CONFLICT`, an in-flight one is `409 E_CONFLICT`. A `5xx` is
  never recorded — the claim is released so the client can retry. Persistence
  is `store.IdempotencyRepository` (`Claim` is a `WHERE`-guarded
  `ON CONFLICT DO UPDATE` upsert: fresh claim or expired-row takeover both
  RETURN the row, a live claim makes it a no-op so a follow-up `Find` reads the
  locked row). Like `RequireAuth`, it is implemented and tested but not yet
  wired into a route — wrap the first mutating endpoint with it, and document
  the `Idempotency-Key` header + the `E_IDEMPOTENCY_CONFLICT` response in that
  endpoint's OpenAPI operation.
