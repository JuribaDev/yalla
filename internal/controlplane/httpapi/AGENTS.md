# httpapi — HTTP API surface

`internal/controlplane/httpapi` owns the Yalla Control Plane HTTP surface:
the route table, the OpenAPI document, the auth/idempotency middleware, and
thin per-endpoint handlers. Business logic lives in the focused control-plane
service packages — handlers only decode, delegate, and render.

## CSRF stance for browser sessions

The Yalla control-plane API authenticates exclusively through the
`Authorization: Bearer <token>` header — API keys, internal-worker
credentials, and human-session HS256 JWTs (see
`internal/controlplane/auth/authenticator.go`). It does NOT issue
session cookies, does NOT accept cookies as credentials, and does
NOT maintain any ambient browser state. Threat model: a browser
script loaded from an attacker-controlled origin attempts to forge a
credentialed cross-origin request (a `<form action="https://api.yalla">`
submit, an `<img src=...>` GET, a `fetch(url, {credentials:
"include"})`, a top-level navigation that lands on a destructive
endpoint). The defence is the absence of ambient credentials:
browsers do not auto-attach `Authorization` headers across origins,
and there is no API-issued cookie for the browser to attach. Any
such cross-origin request reaches the server with no `Authorization`
header and is rejected as 401 `E_AUTHENTICATION_REQUIRED`. The [CORS stance](#cors-stance)
below is the orthogonal browser-side defence (the script cannot read
the response); the CSRF stance is the server-side defence (even if a
browser surfaced the response, the request itself fails because no
ambient credential rides it).

The two-test backstop:

1. `csrf_static_test.go` (`TestCookieAPIIsNotUsedByProductionCode`,
   BE-0348) walks every non-test `.go` file in this package and
   rejects (a) any string literal whose case-insensitive value is one
   of the HTTP cookie header names `Cookie`, `Set-Cookie`, `Cookie2`,
   or `Set-Cookie2`, and (b) any selector expression naming a
   `net/http` cookie API symbol (`SetCookie`, `AddCookie`,
   `CookieJar`, `Cookies`, or `http.Cookie`). The companion
   `TestCSRFStaticAnalyzerDetectsRegressions` synthesizes known-bad
   and known-good snippets to prove the analyzer fires on the bad
   shapes (every cookie header literal, every cookie API selector,
   the `http.Cookie` struct constructor) and stays silent on
   innocuous occurrences (`Content-Type`, `Authorization`, an
   `Origin` read, prose comments mentioning cookies, a user-package
   field named `Cookie` that is not `http.Cookie`).
2. `csrf_test.go` proves the invariant end-to-end through
   `NewHandler`. It drives the public-surface routes (`/healthz`,
   `/version`, `/readyz`, `/healthz/backup`, `/openapi.json`) both
   with and without an attacker-style `Cookie` request header, the
   authenticated 201 happy path with a planted `Cookie`, the 400
   validation-failure path, the 401 unauthenticated path, the 404
   not-found path, and the cookie-only credential path (a request
   with no `Authorization` header but a `Cookie: session=<jwt>` /
   `Cookie: authorization=Bearer <jwt>` value is denied 401 — the
   cookie is NEVER honored as a credential). Every test asserts the
   response carries no `Set-Cookie` / `Set-Cookie2` header and the
   request cookie sentinel is never echoed in the response body
   (redaction backstop). One test additionally pins the determinism
   invariant — two GETs to `/healthz` with and without `Cookie`
   return the same response-header key set.

When adding a new handler or middleware: NEVER write a `Set-Cookie`
header, NEVER read a `Cookie` header as a credential, and NEVER add
a `http.SetCookie`/`http.Cookie`/`r.AddCookie`/`r.Cookies()` call.
If a future surface genuinely requires browser sessions, the retrofit
is NOT a per-handler cookie write: introduce a dedicated subpackage
that owns cookie issuance and verification, wire one explicit
middleware seam through `NewHandler`, adopt a double-submit-cookie or
SameSite=Strict cookie scheme with a per-request synchronizer token,
and relax the analyzer's per-package scope only after the new threat
model has been reviewed. The static analyzer will fail the build on
any per-handler cookie regression.

## CORS stance

The Yalla control-plane API serves non-browser callers (CLI, agents,
CI) authenticated by Bearer tokens or session cookies. It deliberately
does NOT enable CORS — no production code path in this package emits
any `Access-Control-*` response header, on any route, for any request
shape. Threat model: a browser script loaded from an attacker-
controlled origin attempts to read API responses or perform a
credentialed cross-origin request against the API. Without
`Access-Control-Allow-Origin` in the response, the browser's same-
origin policy refuses to surface the response body to the script; for a
credentialed request, the absence of approval makes the browser refuse
the preflight, so the unsafe request never reaches the server. A 405
or 404 with no `Access-Control-*` header is the canonical "deny"
shape for a preflight.

The two-test backstop:

1. `cors_static_test.go` (`TestCORSHeadersAreNotEmittedByProductionCode`,
   BE-0347) walks every non-test `.go` file in this package and
   rejects any string literal whose value matches (case-insensitive)
   the `Access-Control-` prefix — necessary and sufficient to catch
   every IANA-registered CORS header. The companion
   `TestCORSStaticAnalyzerDetectsRegressions` synthesizes known-bad
   and known-good snippets to prove the analyzer fires on the bad
   shapes (every CORS approval header used as a `Set`/`Add` key,
   `Header()[name]` map assignment, `const` declaration that names a
   CORS header) and stays silent on innocuous occurrences
   (`Content-Type`, `Authorization`, the request-side `Origin` read,
   prose comments mentioning CORS).
2. `cors_test.go` proves the invariant end-to-end through
   `NewHandler`. It drives the public-surface routes (`/healthz`,
   `/version`, `/readyz`, `/healthz/backup`, `/openapi.json`),
   preflight `OPTIONS` against a registered POST path with attacker-
   style `Origin` + `Access-Control-Request-Method` headers, the
   authenticated 201 happy path, the unauthenticated 401 path, and
   the 404 envelope path. Every test asserts no response header
   begins with the `Access-Control-` prefix; one test additionally
   pins the determinism invariant — two GETs with and without
   `Origin` return the same header set (modulo `Date` /
   `X-Request-Id` / `X-Correlation-Id`).

When adding a new handler or middleware: NEVER write
`Access-Control-*` from a per-handler shortcut. If a future browser
surface needs CORS, wire one explicit middleware seam — its allowlist
is the policy, the per-handler write is forbidden. The static
analyzer will fail the build on a per-handler regression.

## Request body size limits

Every handler that touches `r.Body` MUST do so through one of the
deliberately narrow size-bounded shapes. An unbounded read lets an attacker
OOM the API with a single request, monopolise a request-handling goroutine
with a slow-loris stream, or trigger a panic deep in `encoding/json`. The
allowed shapes are:

1. `validate.DecodeJSON(r.Body, &dst, 0)` — the canonical body decoder. It
   caps the read at `validate.DefaultMaxBodyBytes` (1 MiB) and surfaces an
   oversized body as a typed `apierr.Invalid` (HTTP 400, `E_VALIDATION`)
   with the fixed-string message `"request body exceeds the maximum allowed
   size"`. Every mutating handler (`POST`, `PUT`, `PATCH`, `DELETE` with a
   body) uses this exact shape.
2. `io.LimitReader(r.Body, <cap+1>)` followed by `io.ReadAll` on the
   limited reader — the explicit bounded-wrap shape used by the
   idempotency middleware in `idempotency.go` to hash the request body
   before dispatching the wrapped handler. The `<cap+1>` trick lets the
   middleware distinguish "exactly at cap" from "over cap".
3. Nil checks (`r.Body == nil`/`!= nil`), `r.Body.Close()`, and LHS
   assignments (`r.Body = io.NopCloser(...)` to restore after buffering).

`json.NewDecoder(r.Body)`, unbounded `io.ReadAll(r.Body)`,
`bufio.NewReader(r.Body)`, returning `r.Body` from a function, capturing
`r.Body` in a struct, type-asserting it, or rebinding it to a local for
later unbounded reads is forbidden. The static analyzer
`TestRequestBodyAccessIsAlwaysSizeBounded`
(`body_size_static_test.go`, BE-0345) parses every non-test file in the
package, scans `*http.Request`-named selectors (`r`/`req`/`request`), and
fails the build on the file:line of any access outside the allowed shapes;
the companion `TestRequestBodyStaticAnalyzerDetectsRegressions` synthesizes
known-bad and known-good snippets to prove the analyzer fires on the bad
shapes and stays silent on the good ones. The runtime test
`body_size_test.go` proves the cap end-to-end through `NewHandler` against
`POST /v1/organizations`.

When adding a new handler that reads a body, ALWAYS go through
`validate.DecodeJSON` — never a bespoke decoder. When adding a new
middleware that needs to inspect the body, copy the
`io.LimitReader`+`io.ReadAll`+`io.NopCloser`-restore shape from
`idempotency.readAndRestoreBody`; the static analyzer recognises that
shape and a new middleware that does not will fail the build.

## Backoffice plan entitlements

Backoffice plan-entitlement routes share `AdminPlanManager` with plan
lifecycle routes. Draft/edit/upsert/delete subscription and pricing-plan
configuration uses `policy.ActionPricingManage`; production-impacting publish,
archive, and rollback routes use `policy.ActionConfigPublish`. Upserts
configure the typed entitlement fields plus metadata (`unit`,
`warning_threshold`, `upgrade_hint`, `overage_behavior`) and render the
metadata back as stable top-level response fields. Rename and delete endpoints
must require a nonblank `impact_validation_id` before delegating, because
entitlement keys are runtime quota/billing compatibility contracts.

## Backoffice subscriptions

Backoffice subscription routes use `AdminSubscriptionManager` and
`policy.ActionPricingManage`. Keep handlers thin: validate the subscription or
override payload, redact secret-shaped metadata keys before delegation, pass
the `{org_id}` path scope through `organizationIDResolver`, and render only
through `apienvelope`.

## Backoffice metering

Backoffice metering source and metric-definition routes use
`policy.ActionMeteringManage`. Keep handlers thin: decode JSON with `validate.DecodeJSON`,
derive actor/request/correlation data from the authenticated request, delegate
to the store service, and render stable envelopes only through `apienvelope`.
Metric-definition unit changes for billing-grade metrics must expose the
explicit `allow_new_version` switch rather than silently overwriting history.
Attribution-rule routes share the same action and thin-handler shape: publish
mutations delegate to `AdminAttributionRuleService`, dry-run requests remain
side-effect free, and unsafe samples are never rendered as billable unless a
rule meets its configured confidence threshold.
Usage aggregation schedule routes share the same action and route-option
wiring: `GET/PUT/DELETE /v1/admin/metering/schedules/{schedule_key}` delegate
to `AdminUsageAggregationScheduleService`, expose interval/replay/close-delay
and late-event mode as stable top-level fields, and disable schedules instead
of deleting runtime history.

## Backoffice feature flags

Backoffice feature flag routes use `policy.ActionFeatureFlagsManage`. Keep
handlers thin: decode bodies through `validate.DecodeJSON`, derive
actor/request/correlation data from the authenticated request, delegate to
`AdminFeatureFlagService`, and render stable envelopes only through
`apienvelope`. Evaluation responses may include the configured value, but audit
metadata must not persist raw evaluated JSON values.

## Backoffice billing providers

Backoffice billing provider routes use `policy.ActionBillingManage`. Keep
credentials write-only: handlers may accept `credential_value`, but response
payloads expose only `credential_set` plus non-secret provider metadata. The
side-effect-free test route validates local provider config and fake-counter
mapping without contacting Stripe or another live provider.

## Backoffice overage policies

Backoffice overage policy routes use `policy.ActionPricingManage` and share the
admin plan audit-context shape. Keep the public route family split by scope:
global policies under `/v1/admin/overage-policies/global/{entitlement_key}`,
plan policies under `/v1/admin/plans/{plan_id}/overage-policies/{entitlement_key}`,
and organization overrides under
`/v1/admin/organizations/{org_id}/overage-policies/{entitlement_key}` with
`organizationIDResolver`.

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

   For unpathed admin routes whose tenant target is selected by request data,
   put the authorization-visible `organization_id` in the query string and have
   the resolver read that query parameter. The JSON body may repeat the same
   organization id for typed clients, but body-only cross-tenant targets must
   be rejected in the handler because `RequireAuth` cannot inspect the body
   without consuming it before validation. Store-backed admin job starters
   should also carry the request and correlation IDs into the queued job so the
   audit trail and worker logs can be joined deterministically.

   **Deep-resource resolvers** (no `{org_id}` in the path, e.g.
   `/v1/projects/{project_id}`) pull the principal's home `OrganizationID`
   from the request context with `policy.PrincipalFromContext(r.Context())`
   — `RequireAuth` attaches the principal before invoking the resolver, so
   the context already carries it even though the resolver signature is
   `func(r *http.Request) policy.Resource`. The resolver then returns
   `Scope{OrganizationID: principal.HomeOrg, ProjectID: r.PathValue(...)}`
   (do **not** look up the resource's real org from the database here —
   keep the resolver pure path+context). The policy engine sees the
   principal's own org and authorizes; a cross-tenant `project_id` reaches
   the **tenant-scoped repository query** with the principal's home org
   and surfaces as a deterministic 404 (`E_NOT_FOUND`), not a 403. That
   is the canonical containment: a project/environment/service-scoped
   grant for THAT resource authorizes the call (the engine asks whether
   the grant scope contains the resource scope), while a grant for a
   SIBLING resource does not. PATCH/DELETE on the same resource should
   adopt the same resolver. See `projectIDResolver` +
   `getProjectHandler`, and `TestGetProjectCrossTenantIDBehavesAsNotFound`
   as the regression check that this stays true.
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

## Pricing and Usage Responses

- Customer-facing limits/usage responses may expose stable source labels,
  counters, reset periods, warning thresholds, and trend summaries, but must
  not expose provider ids, plan ids, subscription ids, override ids, or
  override reasons. Keep empty collection fields as `[]` for agents; for
  example, `trend_summaries` remains a non-nil empty array until usage-event
  aggregation is implemented.
- Usage-derived soft-limit alerts belong in the top-level
  `yalla.output.v1.warnings` array via `apienvelope.WriteDataWithWarnings`, not
  inside endpoint-specific `data`. Keep warning objects structured with stable
  codes plus `entitlement_key`, `usage`, `threshold`, `limit`, optional
  `period`, and a recovery/upgrade `hint`.

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

Bare-id job reads are the exception to org-root authorization: `GET
/v1/jobs/{job_id}` must authorize against the persisted job row's owning scope.
Use the narrow `JobReader.GetJob` port in the resolver, mirror the row's
`project_id`, `environment_id`, and `service_id` into `policy.Scope`, then keep
the handler as a normal tenant-scoped `GetJob` read. That shape lets scoped
grants read covered jobs while sibling grants are denied before the response
handler runs.

Mutating endpoints (e.g. `POST /v1/organizations`, `PATCH /v1/organizations/{org_id}`)
use the same idea with a **narrow writer port** (`OrganizationCreator`,
`OrganizationUpdater`), satisfied in production by a `store` **unit-of-work
orchestrator** (`store.OrganizationService`, the
`ProjectService`/`ServiceAccountService` pattern) — not a bare repository. The
orchestrator validates input before opening a transaction, then writes the
desired state **and** appends the audit record inside one `Store.Write`. The
handler stays thin: read the principal, `validate.DecodeJSON` the body, pull
`telemetry.FromContext`, pass the resource fields plus the principal's
id/kind/org and the correlation ids into the `store.<Verb>XInput`, then render.
A partial-update (PATCH) body uses `*string` fields — a nil pointer means
"field omitted, leave unchanged"; the orchestrator rejects a patch that names
no field at all. Never open a `Store.Write` from a handler — that is the
orchestrator's job.

## Tests

- httpapi tests build the handler through the `newTestHandler` helper, which
  injects a canned `fakeAuthenticator` + `policy.NewEngine()`. Use
  `NewHandler` directly only when a test needs a specific authenticator
  identity (see `me_test.go`'s `meHandlerFor`).
- For every endpoint cover: success, unauthenticated (401
  `E_AUTHENTICATION_REQUIRED`), invalid credentials (401 `E_AUTH_INVALID`),
  unauthorized (403
  `E_FORBIDDEN`), dependency failure stays a typed 5xx (never a disguised
  401), `request_id` propagation, and OpenAPI registration + `x-required-action`.
- For endpoints that read/mutate customer-owned resources, add tenant-isolation
  tests (a cross-tenant path id must be 403 or not-found, never a leak).
- Policy matrix tests for a write endpoint that carries plaintext credential
  material in the request body (e.g. env variables PUT, project variables PUT,
  org variables PUT, api-key create/rotate) MUST pair the response-direction
  leak guard with a body-direction leak guard. Embed a globally-unique fragment
  in the credential field of the matrix request body and assert no deny path
  echoes it; structural-needle guards alone would miss a renderer that scrubs
  request keys + booleans but reflects the value column. See
  `environment_variables_put_policy_test.go`'s
  `replaceEnvironmentVariablesMatrixSecretNeedle` /
  `replaceEnvironmentVariablesRequestBodyLeak` pair.
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

## Optimistic concurrency on writes

PATCH/DELETE on a mutable resource accept the caller's expected version
through the `If-Match` request header and reject a stale write with a typed
409. Reuse the helpers in `organizations.go`:

- `parseIfMatchVersion(r) (*int64, error)` decodes the header. It accepts the
  RFC 7232 strong-ETag form `"<n>"` and a lenient unquoted integer; weak
  ETags (`W/"..."`), `*`, multi-value lists, and non-positive integers are
  rejected as 400 `E_VALIDATION` before the request reaches the store.
- `writeOrganizationETag(w, org.Version)` mirrors the row's authoritative
  version into the `ETag` response header. Call it on every success path
  (GET/POST/PATCH/DELETE/list) so the body's `version` field and the header
  always agree — agents can switch on either.
- Plumb the parsed `*int64` into the store layer through the `IfMatchVersion`
  field on the relevant `*Input`. The store-layer Update/ScheduleDeletion
  methods already accept it: `nil` disables the precondition (legacy
  next-write-wins), non-`nil` adds a `WHERE id=$1 AND version=$N` predicate,
  and a stale view returns `apierr.ConflictStale(currentVersion)`.

Render the resource's `Version` (an `int64`) on the response wire shape with
no `omitempty` so a fresh `version: 1` always appears. The error envelope
already surfaces the row's `current_version` under `error.details` for stale
writes; do not re-encode it in the message or hint.

## Binary wiring

`NewHandler(build, readiness, meta, authenticator, engine, orgs, creator,
updater, deleter, members, memberCreator, memberUpdater, memberRemover,
apiKeys, logger)`.
`cmd/yalla-api` builds the real `authenticator` at startup from the pgxpool
(`store.New` → `store.NewCredentialReader` → `auth.NewAuthenticator`), the
`orgs` reader (`store.NewOrganizationReader`), the `creator`/`updater`/`deleter`
(one `store.NewOrganizationService` value satisfies all three ports), the
`members` reader (`store.NewMembershipReader`), the
`memberCreator`/`memberUpdater`/`memberRemover` (one
`store.NewMembershipService` value satisfies all three ports), the `apiKeys`
reader (`store.NewAPIKeyReader`), plus a `policy.NewEngine()`.
Adding a port parameter to `NewHandler` breaks every test call site — `grep`
for `NewHandler(` and `newRouteTable(` across `*_test.go` and add the new fake
(`fakeOrganization{Reader,Creator,Updater,Deleter}{}`,
`fakeMembership{Reader,Creator,Updater,Remover}{}`, `fakeAPIKeyReader{}`,
`fakeProjectReader{}`, `fakeProjectCreator{}`, `fakeProjectUpdater{}`) in one
pass. The
`projects_test.go` `listProjectsHandlerFor` helper passes a named `reader`
parameter rather than a literal `fakeProjectReader{}`, so a regex pass on the
literal misses it — patch it by hand. Same gotcha for the
`createXHandlerFor` / `updateXHandlerFor` helpers (named `creator`, `updater`,
`deleter`, etc.) — grep for `fakeProjectReader{}` to find them. Two
call-site shapes coexist: single-line `..., fakeAPIKeyRotator{}, nil)`
(most files) and multi-line where the last fake is on one line and `nil)`
or `logger)` is on the next (audit_events, limits, usage, variables,
projects_create_test.go's createProjectHandlerFor) — a single-line sed
catches only the first; the second needs a multi-line pass (awk/python) or
manual edits. `Edit` with `replace_all=true` on the unique anchor
`fakeProjectCreator{}, nil)` / `fakeProjectCreator{}, logger)` covers ~25
files in one parallel batch; the named-param helpers need their own
anchor. The N-nil
`newRouteTable` test stubs in `routes_test.go`, `server_test.go`,
`variables_*_test.go`, `limits_patch_test.go`, `projects_create_test.go`
need a parallel bump (one more `nil` appended each time).
Registering a `RequiresAuth` route with a nil authenticator/engine panics at
startup — a wiring error, never a runtime 500.

## Partial-update endpoints (PATCH /v1/<resource>/{resource_id})

The handler stays thin: read principal, parse If-Match through the existing
`parseIfMatchVersion(r)`, strict-decode the body through `validate.DecodeJSON`,
call the writer port, mirror the returned version into `ETag` via
`writeOrganizationETag(w, row.Version)` (the helper's body is generic — it
just writes the int64 — despite the historical name), render through
`apienvelope.WriteData` with `http.StatusOK`. The request DTO exposes only
the partially-updatable fields as `*string` (nil = field omitted, leave
unchanged); the strict JSON decoder rejects an unknown `organization_id`
field as a stable 400 `E_VALIDATION`, so tenant isolation is structural
— the handler always builds the store input from `principal.OrganizationID`
and the path id, never from the body. The store-layer orchestrator (e.g.
`store.ProjectService.Update`) validates everything BEFORE opening the
transaction (a split-out `buildXUpdate` + `validateXDisplayName` is
unit-testable without a DB and rejects an empty patch with the canonical
"at least one of X or Y must be provided" violation), then in one
`Store.Write` tx Gets the current row, pre-checks `current.Version` against
`*IfMatchVersion` (returns `apierr.ConflictStale(current.Version)` on
mismatch — surfaces the right row even when the patch happens to not
differ), applies the non-nil fields, calls the repository `Update` with the
same `IfMatchVersion`, and appends the audit event with
`Metadata={"updated_fields": "slug,display_name"}` — stable wire names
only, never the submitted values. The repository `Update` is `*Tx`-only,
tenant scoped, and on a version-checked UPDATE matching zero rows uses a
tenant-scoped `Get` inside the same tx to disambiguate "row gone"
(NotFound) from "row stale" (ConflictStale carrying the row's current
version) — copy `classifyOrganizationConcurrencyMiss` /
`classifyProjectConcurrencyMiss` verbatim for new resources.

## Middleware chain order

`NewHandler` wraps every route with two optional layers around the
handler:

```
RequireAuth(...)        <- outer (only when endpoint.RequiresAuth)
  └── RateLimit(...)    <- inner (always, no-op when limiter is nil)
        └── handler
```

The rate-limit gate runs **inside** `RequireAuth` so the resolved
principal (`policy.PrincipalFromContext`) and credential scheme
(`AuthMethodFromContext`) are on the request context when the limiter
decides — that is what lets the gate bill the org / API key buckets for
an authenticated request, fall back to the IP bucket alone for a public
endpoint, and recognise the `auth.MethodInternalWorker` exemption. A
new middleware that needs the principal context should slot **inside**
`RequireAuth` the same way; one that needs to short-circuit before
authentication (request-size limits, host validation) should be wrapped
**around** `RequireAuth` instead.

## Auth method on the context

Both `RequireAuth` and `RequireInternalWorker` stamp the request
context with the credential scheme via `withAuthMethod(ctx, id.Method)`
(declared in `middleware.go`); downstream middleware reads it back
through `AuthMethodFromContext`. Use this when a downstream rule needs
to distinguish API-key / session / internal-worker callers without
re-running the authenticator — the rate-limit gate's internal-worker
exemption is the canonical example. **Never** re-issue an
`Authenticator.Authenticate` call from middleware just to recover the
method; that would double the credential-store load and re-introduce
the secret on a path the first authentication has already cleared.

## Adding a positional parameter to NewHandler

`NewHandler` is a single, large positional signature. When a new
backend dependency must reach every route (a rate limiter, a request-
audit sink, a feature-flag resolver), add it as a **trailing**
parameter and sweep all call sites with a depth-tracking parenthesis
walker (see the Node script noted in the BE-0035 progress entry).
Trailing-only additions are safe to sweep automatically — a regex sweep
that anchors on the previous last identifier risks corrupting
multi-line calls and tests whose closing paren is several lines below
the last argument. Pass `nil` from every call site that does not
exercise the new dependency; the constructor must treat `nil` as a
no-op so the construction path stays uniform for tests.
