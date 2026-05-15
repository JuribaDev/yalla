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
   path-param resolver whenever the endpoint targets a child resource, so a
   cross-tenant id is a 403 rather than a silent allow.
4. Keep the handler thin: read `policy.PrincipalFromContext`, call a service,
   and render through `apienvelope.WriteData` / `WriteError`. Never marshal
   JSON directly; never hand-roll an error — return typed `apierr` errors.
5. Update OpenAPI implicitly by filling in the `openapi.Endpoint` fields
   (`Summary`, `Description`, `Tags`, `SuccessDescription`, `SuccessStatus`,
   `SuccessSchema`). The document is generated from the route table.

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

## Binary wiring

`NewHandler(build, readiness, meta, authenticator, engine, orgs, logger)`.
`cmd/yalla-api` builds the real `authenticator` at startup from the pgxpool
(`store.New` → `store.NewCredentialReader` → `auth.NewAuthenticator`), the
`orgs` reader (`store.NewOrganizationReader`), and a `policy.NewEngine()`.
Registering a `RequiresAuth` route with a nil authenticator/engine panics at
startup — a wiring error, never a runtime 500.
