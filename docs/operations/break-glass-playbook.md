# Break-Glass Playbook

This playbook describes the production operator workflow for time-bounded
break-glass support access to customer organizations through Yalla Control
Plane. It covers the versioned backend binaries `/usr/local/bin/yalla-api` and
`/usr/local/bin/yalla-worker`, the support-only break-glass endpoints, immutable
audit evidence, and the Yalla API -> Postgres source of truth -> provisioning
worker -> private Dokploy API boundary. In short:
Yalla API -> Postgres source of truth -> provisioning worker -> private Dokploy API.

Break-glass is an intentional cross-tenant exception: a support principal may
open a session against any organization, but the session is access-only
(no customer credential mint), every mutation is recorded on the immutable audit
trail with `elevated_access=true`, and the reason/user-agent are scrubbed by
the store-layer redactor before persistence.

The customer-facing break-glass routes are:
- `POST /v1/organizations/{org_id}/break-glass`
- `GET /v1/organizations/{org_id}/break-glass`
- `GET /v1/organizations/{org_id}/break-glass/{session_id}`
- `DELETE /v1/organizations/{org_id}/break-glass/{session_id}`

The admin break-glass routes are:
- `POST /v1/admin/break-glass`
- `DELETE /v1/admin/break-glass/{session_id}`

Customers must never receive Dokploy API tokens or call Dokploy directly. A
break-glass session records that a support principal reached into a tenant; it
does not grant broad Dokploy access or mint customer API keys. The mutating
endpoints are authorized through `admin.break_glass` in the current action
catalog, and the persisted audit action remains `admin.break_glass` for
compatibility with existing support tooling and audit queries.

Runtime configuration is operator-managed. The API and worker read
`/etc/yalla/control-plane.env` by default, or the path named by
`YALLA_CONTROL_PLANE_ENV_FILE`. Tickets, session notes, audit metadata, command
logs, and incident records must never contain tokens, API keys, cookies,
database URLs, Dokploy tokens, or rendered environment variable values. Use
redacted variable names such as `<redacted:YALLA_ADMIN_API_KEY>` whenever the
variable name is operationally useful.

Evidence must never contain tokens, API keys, cookies, database URLs, Dokploy tokens, or rendered environment variable values.

## Preconditions

1. Confirm the support principal holds the `CapSupport` capability. Only
   `RoleSupport` principals can authorize `admin.break_glass`.
2. Confirm the target organization exists; unknown and cross-tenant identifiers
   must collapse to the same not-found or denied shape and must not be used as
   existence probes.
3. Verify API and worker health before starting:

```bash
curl -fsS "${YALLA_API_BASE_URL:-http://127.0.0.1:8080}/healthz"
curl -fsS "${YALLA_API_BASE_URL:-http://127.0.0.1:8080}/readyz"
curl -fsS "${YALLA_API_BASE_URL:-http://127.0.0.1:8080}/version"
```

Successful probes return `yalla.output.v1`; unhealthy probes return
`yalla.error.v1`. Every response includes `request_id`, and request logs carry
the same `request_id` plus `correlation_id` where supplied.

## Required Environment

Set these values in the operator shell or load them from the approved secret
manager. Do not check them into the repository and do not paste rendered values
into tickets.

```bash
export YALLA_CONTROL_PLANE_ENV_FILE=/etc/yalla/control-plane.env
export YALLA_API_BASE_URL=https://control-plane.example.invalid
export YALLA_ADMIN_API_KEY=<redacted:YALLA_ADMIN_API_KEY>
export YALLA_BREAK_GLASS_TARGET_ORG_ID=org_target_example
```

## Start a Break-Glass Session

Create the session through the Yalla API. The API persists the session row and
an audit event before any support action is taken.

### Organization-scoped route

```bash
curl -fsS -X POST \
  "${YALLA_API_BASE_URL}/v1/organizations/${YALLA_BREAK_GLASS_TARGET_ORG_ID}/break-glass" \
  -H "Authorization: Bearer <redacted:YALLA_ADMIN_API_KEY>" \
  -H "Content-Type: application/json" \
  -H "X-Request-Id: req_breakglass_example" \
  -H "X-Correlation-Id: corr_breakglass_example" \
  --data @- <<'JSON' | jq -e '.schema_version == "yalla.output.v1" and .ok == true'
{
  "reason": "INCIDENT-42: database connectivity investigation",
  "ttl_seconds": 1800
}
JSON
```

### Admin route (cross-tenant)

```bash
curl -fsS -X POST \
  "${YALLA_API_BASE_URL}/v1/admin/break-glass?organization_id=${YALLA_BREAK_GLASS_TARGET_ORG_ID}" \
  -H "Authorization: Bearer <redacted:YALLA_ADMIN_API_KEY>" \
  -H "Content-Type: application/json" \
  -H "X-Request-Id: req_breakglass_example" \
  -H "X-Correlation-Id: corr_breakglass_example" \
  --data @- <<'JSON' | jq -e '.schema_version == "yalla.output.v1" and .ok == true'
{
  "organization_id": "org_target_example",
  "reason": "INCIDENT-42: database connectivity investigation",
  "ttl_seconds": 1800
}
JSON
```

The response is a `yalla.output.v1` envelope containing the persisted session:

```json
{"schema_version":"yalla.output.v1","ok":true,"request_id":"req_example","data":{"session":{"id":"bgs_example","organization_id":"org_target_example","actor_id":"usr_support","actor_kind":"usr","actor_organization_id":"org_yalla_support","reason":"INCIDENT-42: database connectivity investigation","status":"active","started_at":"2026-05-19T12:00:00Z","expires_at":"2026-05-19T12:30:00Z","revoked_at":null,"revoked_by_id":"","revoked_by_kind":"","active":true,"elevated_access":true,"request_id":"req_example","correlation_id":"corr_example","version":1,"created_at":"2026-05-19T12:00:00Z","updated_at":"2026-05-19T12:00:00Z"}}}
```

Validation failures return `yalla.error.v1` with stable field paths and no
secret material:

```json
{"schema_version":"yalla.error.v1","ok":false,"request_id":"req_example","error":{"code":"E_VALIDATION","message":"invalid input","hint":"One or more fields failed validation."}}
```

## List Sessions

```bash
curl -fsS -X GET \
  "${YALLA_API_BASE_URL}/v1/organizations/${YALLA_BREAK_GLASS_TARGET_ORG_ID}/break-glass?limit=50" \
  -H "Authorization: Bearer <redacted:YALLA_ADMIN_API_KEY>" \
  -H "X-Request-Id: req_list_example"
```

## Get a Session

```bash
curl -fsS -X GET \
  "${YALLA_API_BASE_URL}/v1/organizations/${YALLA_BREAK_GLASS_TARGET_ORG_ID}/break-glass/bgs_example" \
  -H "Authorization: Bearer <redacted:YALLA_ADMIN_API_KEY>" \
  -H "X-Request-Id: req_get_example"
```

## Revoke a Session

End the session early when the incident is resolved. The store-layer unit of
work marks the row revoked and appends another audit event stamped with
`elevated_access=true` inside the same transaction.

### Organization-scoped route

```bash
curl -fsS -X DELETE \
  "${YALLA_API_BASE_URL}/v1/organizations/${YALLA_BREAK_GLASS_TARGET_ORG_ID}/break-glass/bgs_example" \
  -H "Authorization: Bearer <redacted:YALLA_ADMIN_API_KEY>" \
  -H "X-Request-Id: req_revoke_example"
```

### Admin route

```bash
curl -fsS -X DELETE \
  "${YALLA_API_BASE_URL}/v1/admin/break-glass/bgs_example?organization_id=${YALLA_BREAK_GLASS_TARGET_ORG_ID}" \
  -H "Authorization: Bearer <redacted:YALLA_ADMIN_API_KEY>" \
  -H "X-Request-Id: req_revoke_example"
```

A session that is already revoked or that has elapsed returns a typed Conflict
(`E_CONFLICT`) so duplicate revocation attempts are stable.

## Expected outputs

Tests should finish with package-level `ok` lines and `PASS`:

```text
ok  github.com/juribadev/yalla/internal/controlplane/httpapi
ok  github.com/juribadev/yalla/internal/release
PASS
```

The break-glass endpoint returns a stable success envelope with a request ID and
session ID. Validation, authorization, missing organization, and conflict
failures return `yalla.error.v1` with the same request ID shape and no secret
material:

```json
{"schema_version":"yalla.error.v1","ok":false,"request_id":"req_example","error":{"code":"E_FORBIDDEN","message":"forbidden"}}
```

## Verification

Run these checks before and after changing this playbook or break-glass code:

```bash
go test -run TestBreakGlass ./...
go test ./internal/release/... -run TestBreakGlassPlaybookArtifact
go test ./...
go test -race ./...
go vet ./...
scripts/verify.sh
```

Only when a non-production Dokploy target is explicitly configured, run the
external smoke test:

```bash
YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...
```

The external smoke test must never run against production.

## Failure recovery

If the break-glass request fails validation, correct the request shape and retry
with a fresh request ID. If authorization fails, confirm the principal holds
`RoleSupport` and `CapSupport`; do not widen customer roles or scoped grants.

If a session was created but the operator needs to revoke it immediately, use
the DELETE endpoint. If the API is unavailable, stop `yalla-worker` before
investigating repeated mutation risk:

```bash
sudo systemctl stop yalla-worker
journalctl -u yalla-api -u yalla-worker -o json
```

Inspect only stable IDs: `request_id`, `correlation_id`, organization ID,
session ID, and audit event ID. Confirm the revocation is idempotent, then
resume `yalla-worker`:

```bash
sudo systemctl start yalla-worker
```

If the API is unhealthy during an active break-glass session, pause `yalla-worker` before investigating:

```bash
sudo systemctl stop yalla-worker
journalctl -u yalla-api -u yalla-worker -o json
```

Inspect only stable IDs: `request_id`, `correlation_id`, organization ID,
session ID, and audit event ID. Confirm the session is revoked or expired, then
resume `yalla-worker`:

```bash
sudo systemctl start yalla-worker
```

If break-glass access was used in error, do not run ad hoc write SQL and do not
call raw Dokploy operations. Use the audited revocation workflow that preserves
Yalla auth, policy, quota, idempotency, desired-state writes, tenant-scoped
`dokploy_refs`, and audit event ordering. If source-of-truth integrity is in
doubt, escalate to the incident response runbook and rehearse restore options
before destructive recovery.
