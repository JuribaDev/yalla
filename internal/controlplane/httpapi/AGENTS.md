# httpapi — HTTP API surface

`internal/controlplane/httpapi` owns the Yalla Control Plane HTTP surface:
the route table, the OpenAPI document, the auth/idempotency middleware, and
thin per-endpoint handlers. Business logic lives in the focused control-plane
service packages — handlers only decode, delegate, and render.

## Adding an endpoint

1. Add an `apiRoute` to `newRouteTable` in `routes.go`. It pairs an
   `openapi.Endpoint` (the single source of truth for both serving and
   documentation) with an `http.HandlerFunc` and an optional `resolver`.
2. Authorization is **declarative**. On the `openapi.Endpoint`, set
   `RequiresAuth: true` and `RequiredAction: string(policy.ActionX)`.
   `NewHandler` auto-wraps the handler in `RequireAuth(authenticator, engine,
   action, resolver)` before registering it — there is no way to serve an
   authenticated route without authorization, and
   `TestEveryAuthenticatedRouteHasMappedAction` fails CI if `RequiresAuth` and
   `RequiredAction` drift apart. The action must be catalogued in `policy`.
3. `apiRoute.resolver` (a `ResourceResolver`) derives the `policy.Resource`
   from path/query params. Leave it `nil` for self / organization-root actions
   — `RequireAuth` then authorizes against the principal's own org scope. Set a
   path-param resolver whenever the endpoint targets a resource named in the
   path, so a cross-tenant id is a 403 rather than a silent allow. The resolver
   reads `r.PathValue("<name>")` — Go 1.22 ServeMux path values survive
   `RequireAuth`'s `r.WithContext` (shallow struct copy), so both the resolver
   and the handler can call `PathValue`. The resolver **is** the tenant
   boundary: scoping the `policy.Resource` to the path's org makes the engine
   deny cross-tenant reads (`ReasonDeniedCrossTenant`) for non-support
   principals before the handler runs; a support principal's cross-tenant
   `CapRead` is `ReasonAllowedBySupport` and is intended, not a leak. See
   `organizationIDResolver` + `getOrganizationHandler`.
4. Keep the handler thin: read `policy.PrincipalFromContext`, call a service,
   and render through `apienvelope.WriteData` / `WriteError`. Never marshal
   JSON directly; never hand-roll an error — return typed `apierr` errors.
5. Update OpenAPI implicitly by filling in the `openapi.Endpoint` fields
   (`Summary`, `Description`, `Tags`, `SuccessDescription`, `SuccessStatus`,
   `SuccessSchema`). The document is generated from the route table. For a
   path with a `{placeholder}`, also declare it in `openapi.Endpoint.PathParams`
   — each renders as a required `in:"path"` string parameter. A `{placeholder}`
   in the route pattern without a matching `PathParams` entry serves fine but
   publishes an undocumented parameter.

## Self endpoints (`/v1/me*`)

The `/v1/me` family (`auth.me`, `auth.orgs`, …) is built **purely from the
`policy.Principal`** that `RequireAuth` resolves — no `store`, no Dokploy. A
principal is bound to exactly one home organization and every scoped grant
narrows/widens authority within it, so e.g. "organizations visible to the
principal" is just the home org. Reuse `meGrantsOf` for the principal→wire grant
projection instead of re-inlining the `Scope` flattening loop. The
"isolated Postgres migrations" / "fake Dokploy" / "audit event" acceptance
criteria are N/A for these reads.

## Store-backed endpoints

Endpoints that read source-of-truth state (e.g. `GET /v1/organizations`) depend
on a **narrow reader port** declared in `httpapi` — an interface, not the
concrete `store` — exactly like the auth middleware depends on `Authenticator`.
`*store.OrganizationReader` (a `Store.Read`-backed adapter that composes the
tenant-scoped repository, mirroring `store.CredentialReader`) satisfies it in
production; tests pass a fake. The port is threaded through
`NewHandler` → `newRouteTable` → the handler closure. A nil reader still
registers the route; the handler reports a typed internal error rather than a
misleading empty result. Keep the handler thin: read the principal, call the
port, render. When the endpoint has no path/query parameter, the tenant
boundary is **structural** — the handler only ever passes `principal.OrganizationID`,
so there is no caller input that could point the read at another tenant.

Mutating endpoints (e.g. `POST /v1/organizations`) use the same idea with a
**narrow writer/creator port** (`OrganizationCreator`), satisfied in production
by a `store` **unit-of-work orchestrator** (`store.OrganizationService`, the
`ProjectService`/`ServiceAccountService` pattern) — not a bare repository. The
orchestrator validates input before opening a transaction, then writes the
desired state **and** appends the audit record inside one `Store.Write`. The
handler stays thin: read the principal, `validate.DecodeJSON` the body, pull
`telemetry.FromContext`, pass slug/display-name plus the principal's
id/kind/org and the correlation ids into the `store.CreateXInput`, then render
`http.StatusCreated`. Never open a `Store.Write` from a handler — that is the
orchestrator's job.

## Tests

- httpapi tests build the handler through the `newTestHandler` helper, which
  injects a canned `fakeAuthenticator` + `policy.NewEngine()`. Use
  `NewHandler` directly only when a test needs a specific authenticator
  identity (see `me_test.go`'s `meHandlerFor`).
- For every endpoint cover: success, unauthenticated (401 `E_AUTH`), invalid
  credentials (401 `E_AUTH`, identical contract), unauthorized (403
  `E_FORBIDDEN`), dependency failure stays a typed 5xx (never a disguised
  401), `request_id` propagation, and OpenAPI registration + `x-required-action`.
- For endpoints that read/mutate customer-owned resources, add tenant-isolation
  tests (a cross-tenant path id must be 403 or not-found, never a leak).
- A separate "Add contract tests for <endpoint>" story usually finds the
  implementation story's `<endpoint>_test.go` already covers most criteria —
  diff against the story's `acceptanceCriteria` and add only the gaps in a
  sibling `<endpoint>_contract_test.go`, do not duplicate. The recurring gaps
  are (a) the server writes response data **only** through the
  `http.ResponseWriter` and (b) the structured request log stays redacted on
  both the success and the error path. See `me_contract_test.go`:
  `captureProcessOutput(t, fn)` swaps `os.Stdout`/`os.Stderr` for `os.Pipe`
  write-ends and drains the read-ends in goroutines (a non-drained pipe
  deadlocks once its buffer fills) — the test that uses it must **not** be
  `t.Parallel()`. Build the test logger at `slog.LevelDebug` so a level
  threshold cannot mask the redaction assertion.

## Binary wiring

`NewHandler(build, readiness, meta, authenticator, engine, orgs, creator, logger)`.
`cmd/yalla-api` builds the real `authenticator` at startup from the pgxpool
(`store.New` → `store.NewCredentialReader` → `auth.NewAuthenticator`), the
`orgs` reader (`store.NewOrganizationReader`), the `creator`
(`store.NewOrganizationService`), and a `policy.NewEngine()`.
Registering a `RequiresAuth` route with a nil authenticator/engine panics at
startup — a wiring error, never a runtime 500.
