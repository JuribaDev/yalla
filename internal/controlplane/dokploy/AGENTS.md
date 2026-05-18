# dokploy

Wraps Dokploy as the private provisioning backend. Customer-facing code never
calls Dokploy directly — only worker/provisioner code, through the typed
client.

## Package split

- `dokploy` (this package) holds the typed Dokploy client wrapper (`Client`):
  Yalla intents (`EnsureProject`, `EnsureService`, `DeployService`,
  `ReadDeploymentLogs`, `RemoveEnvironment`, `RemoveService`, ...) mapped onto
  Dokploy operations.
  The Dokploy token is injected into the `Client` via `Config.Token` and is
  never exposed by any method; `Client.LogValue` redacts it.
- `dokployfake` is the deterministic, in-memory HTTP test double. It is the
  default Dokploy for **every** normal test — a live Dokploy server is an
  opt-in external smoke test only.

## Client conventions

- Every intent validates required fields **locally** (`requireFields` ->
  `apierr.InvalidInput` with stable field paths) so an obviously invalid intent
  never reaches Dokploy and never echoes the submitted value.
- "Ensure" intents are idempotent against Yalla's source-of-truth state: a
  populated `ExistingID` fetches+verifies the resource; an empty one creates it.
  The caller (worker) records the returned Dokploy ID in Postgres.
- `SyncVariables` is an intent, not raw proxy access: it accepts a concrete
  Dokploy service ID, service type, optional database engine, and rendered
  dotenv content, then maps to the service-kind-specific Dokploy operation.
  Keep service-kind branching in this package so worker jobs stay source-of-
  truth focused.
- Only idempotent methods (`GET`, `DELETE`) are retried — never `POST` — so a
  retry can never duplicate a provisioning side effect. Retries fire only on
  catalogued **retryable** errors (`apierr.Retryable`).
- Every failure maps onto the `apierr` taxonomy: transport/5xx/429 ->
  `DokployUnavailable` (retryable), timeouts -> `Timeout(DependencyDokploy, …)`,
  400 -> `Invalid`, 401 -> `DokployAuth`, 403 -> `DokployForbidden`, 404 ->
  `DokployNotFound`, 409 -> `DokployConflict`. Upstream
  auth/permission/missing-resource/conflict errors are non-retryable Yalla
  operator issues, not customer credential or customer resource failures. The
  redacted upstream body is wrapped as the log-only cause, never placed in a
  client-facing `Message`.
- `RemoveEnvironment` and `RemoveService` treat a Dokploy 404 as success —
  teardown is idempotent.
- The `Client` carries an `output.Redactor` seeded with the token; any error
  built from upstream response data is run through it before being wrapped.
- Correlation IDs from `telemetry.FromContext` are forwarded to Dokploy as
  `X-Request-Id` / `X-Correlation-Id` headers on every request.

## Hierarchy mapping (`mapping.go`)

- `Mapper` translates Yalla's source-of-truth hierarchy (`YallaOrganization` ->
  `YallaProject` -> `YallaEnvironment` -> `YallaService`) into the `Ensure*Input`
  intents the `Client` consumes. It is pure — no I/O, no credentials, concurrent-safe.
- Mapping is **top-down**: a child intent needs its parent's *resolved Dokploy ID*,
  so `Project`/`Environment`/`Service` take that ID as their first argument. The
  worker ensures each level, records the returned Dokploy ID, and feeds it into
  the next level.
- Dokploy resource names come **only** from `domain.DokployName(label, id)` —
  deterministic, Docker-safe, and embedding the full Yalla ID. Never hand-build
  a name.
- `WithSharedOrganization` selects the shared-internal-org fallback: `Organization`
  then returns `OrganizationTarget{Shared: true}` with no `EnsureInput`. Dedicated
  mode returns an `EnsureOrganizationInput`. A recorded `DokployID` becomes the
  intent's `ExistingID`, keeping the produced intent idempotent.
- Validation is local and collected (not short-circuited): a malformed/wrong-kind
  Yalla ID, a blank parent Dokploy ID, an unrecognised service type, or a database
  service missing its engine all become `apierr.InvalidInput` `FieldViolation`s
  with stable paths that never echo the submitted value. A `DokployName` failure
  after a validated ID is a contract bug -> `apierr.Internal`, not a user error.

## Desired-state renderer (`renderer.go`)

- `Renderer.Render(RenderInput) (RenderedSpec, error)` is the **declarative-content**
  layer; the `Mapper` is the **ID-resolution** layer. The renderer never resolves
  a parent's Dokploy ID and does no I/O — it is pure and deterministic. The worker
  combines the two: walk the `Mapper` top-down for IDs, feed `RenderedSpec` content
  into each `Ensure*` call.
- Variable precedence is ascending: `organization < project < environment < service`.
  Same-name variables at a higher level override lower ones; `RenderedVariable.Source`
  records the winning level. A duplicate name *within* one level is a violation.
- Resource limits are zero-fill: a zero `ResourceLimits` field inherits the
  deterministic tier default (`defaultResources`), so `RenderedSpec` always carries
  fully-resolved, non-zero limits. Production web (application/compose) -> 2 replicas.
- Inapplicable fields are **dropped**, mirroring how the `Mapper` drops `engine` for
  non-database services: `role` is dropped for a database, `cron_schedule` for a
  non-cron service, `domains` for a non-web service. `build` is normalised — fields
  that do not apply to the chosen builder are dropped.
- `RenderedSpec.Service.Variables` carries **verbatim** values (the worker needs
  them). Never log/audit a `RenderedSpec` directly — call `RenderedSpec.Summary()`,
  which redacts **every** variable value to `output.Sentinel` (not only `Secret`
  ones). `RenderedSpec.LogValue` redirects to the `Summary` as a backstop.
- Golden tests pin `Summary` JSON via `testutil.GoldenJSON` under
  `testdata/renderer/`; refresh with `go test -update-golden ./...`. The golden
  artifact is the redacted `Summary`, so it can never embed a real variable value.
- Validation collects every violation into one `apierr.InvalidInput` with stable,
  indexed field paths (`service.variables[2].name`, `domains[0].host`) that never
  echo the submitted value.

## dokployfake conventions

- It mimics **Dokploy's** JSON shapes, not Yalla's `yalla.output.v1` /
  `yalla.error.v1` envelopes: it stands in for the upstream provisioning API,
  not a Yalla public surface. Do not "fix" it to emit Yalla envelopes.
- IDs are deterministic per-kind counters (`org_1`, `proj_1`, ...); a fixed
  call sequence always yields the same IDs. Keep new resources deterministic.
- `QueueFault` arms a FIFO fault queue (status codes, timeout, malformed JSON);
  each request consumes one. Faults are applied before auth and routing.
- Every recorded request is scrubbed: sensitive header values become
  `output.Sentinel` and the body runs through a redactor seeded with the
  bearer token. Anything new the recorder captures must stay redaction-safe.
- Requests that carry rendered environment content must redact the `env` field
  as a whole in recorded fixtures; rendered env content contains plaintext
  effective variable values even when the source rows were secret at rest.
- The fake takes no `testing.TB`; callers `defer srv.Close()`. It depends only
  on `internal/output` + stdlib, so any package's tests can import it without
  a cycle.

## Token isolation (BE-0361)

- The bearer token MUST live in the unexported `token` field of `*Client`
  and nowhere else. A regression that renamed it `Token` (exported) is
  rejected at build time by
  `internal/release/dokploy_token_isolation_static_test.go`.
- The `.token` selector against a `*Client` receiver MUST appear in
  exactly one location across every production `.go` file in this
  package — the canonical
  `req.Header.Set("Authorization", "Bearer "+c.token)` call inside
  `client.go`'s `attempt`. The constructor's `token: token` composite-
  literal binding (a `KeyValueExpr.Key`, not a SelectorExpr) is the
  only other legitimate token-touching site. A new `fmt.Errorf("token
  %q rejected", c.token)`, `slog.String("token", c.token)`, audit-
  metadata stamp, or envelope projection that adds a second
  `.token` selector breaks the static gate by design.
- Customer-facing handlers MUST NOT name `dokploy.Client`,
  `dokploy.NewClient`, or `dokploy.Config`. The handler tree
  (`internal/controlplane/httpapi`) is allowed to consume only the
  value enum — `dokploy.ServiceType` and the
  `dokploy.Service{Application,Database,Compose}` constants — because
  those carry no token. Any new exported symbol on this package that
  reaches a handler must either be a pure-data type (no token, no
  HTTP capability) or be paired with an update to the static gate's
  `forbiddenDokployClientSelectors` allowlist after security review.
