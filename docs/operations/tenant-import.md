# Tenant Import Playbook

This playbook describes the production operator workflow for importing an
existing Dokploy tenant hierarchy into Yalla Control Plane. It covers the
versioned backend binaries `/usr/local/bin/yalla-api` and
`/usr/local/bin/yalla-worker`, the support-only `POST /v1/admin/dokploy/import`
endpoint, the Import dry-run preview gate, durable import jobs, audit evidence,
and the Yalla API -> Postgres source of truth -> provisioning worker -> private
Dokploy API boundary. In short:
Yalla API -> Postgres source of truth -> provisioning worker -> private Dokploy API.

Customers must never receive Dokploy API tokens or call Dokploy directly. A
tenant import materializes controlled Yalla source-of-truth rows and
tenant-scoped `dokploy_refs`; it is not a generic customer-facing proxy to
Dokploy. The mutating endpoint is authorized through `support.manage` in the
current action catalog, and the persisted audit action remains `admin.import`
for compatibility with existing support tooling and audit queries.

Runtime configuration is operator-managed. The API and worker read
`/etc/yalla/control-plane.env` by default, or the path named by
`YALLA_CONTROL_PLANE_ENV_FILE`. Tickets, dry-run notes, audit metadata, command
logs, and incident records must never contain tokens, API keys, cookies,
database URLs, Dokploy tokens, or rendered environment variable values. Use
redacted variable names such as `<redacted:YALLA_ADMIN_API_KEY>` whenever the
variable name is operationally useful.

Evidence must never contain tokens, API keys, cookies, database URLs, Dokploy tokens, or rendered environment variable values.

## Preconditions

1. Confirm the target Yalla organization exists and is the intended owner for
   the import; unknown and cross-tenant identifiers must collapse to the same
   not-found or denied shape and must not be used as existence probes.
2. Confirm the Dokploy organization is the source hierarchy to import. The
   operator must have an approved ticket, an import reason, and a support
   principal with `support.manage`.
3. Run the Import dry-run gate and review every `OwnerAssignment` before
   committing the import. The dry-run must not mutate Yalla or Dokploy state.
4. Verify API and worker health before starting:

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
export YALLA_IMPORT_OWNER_ORGANIZATION_ID=org_target_example
export YALLA_IMPORT_DOKPLOY_ORGANIZATION_ID=dkp_org_source_example
export YALLA_IMPORT_IDEMPOTENCY_KEY=<redacted:YALLA_IMPORT_IDEMPOTENCY_KEY>
```

`YALLA_IMPORT_OWNER_ORGANIZATION_ID` is the Yalla organization that will own
the imported resources. `YALLA_IMPORT_DOKPLOY_ORGANIZATION_ID` is the Dokploy
organization to scan. `YALLA_IMPORT_IDEMPOTENCY_KEY` must be stable for one
approved import attempt so a retry can safely deduplicate job creation.

## Dry-Run Review

Run the canonical import dry-run suite before creating the production import
job:

```bash
go test -run TestImportDryRun ./...
```

For an environment-specific preview, call the support dry-run workflow or
admin tool that invokes `(*migrateimport.Importer).Plan(ctx, PlanInput)` with
the intended `OwnerAssignment`. Review the resulting plan for duplicate names,
missing parents, unsupported service types, already-linked resources, and any
quarantined rows. Never paste the full dry-run plan into a ticket; record only
the command, timestamp, redacted target identifiers, the plan summary counts,
and the reviewer approval.

## Commit The Import

Create the import job through the Yalla API. The API persists the job and an
audit event before `yalla-worker` performs any Dokploy read or source-of-truth
write for the import.

```bash
curl -fsS -X POST \
  "${YALLA_API_BASE_URL}/v1/admin/dokploy/import?organization_id=${YALLA_IMPORT_OWNER_ORGANIZATION_ID}" \
  -H "Authorization: Bearer <redacted:YALLA_ADMIN_API_KEY>" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: <redacted:YALLA_IMPORT_IDEMPOTENCY_KEY>" \
  -H "X-Request-Id: req_import_example" \
  -H "X-Correlation-Id: corr_import_example" \
  --data @- <<'JSON' | jq -e '.schema_version == "yalla.output.v1" and .ok == true'
{
  "organization_id": "org_target_example",
  "yalla_organization_id": "org_target_example",
  "dokploy_organization_id": "dkp_org_source_example",
  "assignment_dokploy_org_id": "dkp_org_source_example",
  "idempotency_key": "import-job-example"
}
JSON
```

The response is an accepted `yalla.output.v1` envelope containing the queued
job. Follow progress through durable job state, structured JSON logs, audit
events, and worker metrics. Do not call Dokploy directly to repair Yalla state.

## Expected outputs

Tests should finish with package-level `ok` lines and `PASS`:

```text
ok  github.com/juribadev/yalla/internal/controlplane/httpapi
ok  github.com/juribadev/yalla/internal/release
PASS
```

The import endpoint returns a stable success envelope with a request ID and job
ID:

```json
{"schema_version":"yalla.output.v1","ok":true,"request_id":"req_example","data":{"organization_id":"org_target_example","dokploy_organization_id":"dkp_org_source_example","job":{"job_id":"job_example","status":"queued"}}}
```

Validation, authorization, missing organization, conflict, dependency, and
quota failures return `yalla.error.v1` with the same request ID shape and no
secret material:

```json
{"schema_version":"yalla.error.v1","ok":false,"request_id":"req_example","error":{"code":"E_FORBIDDEN","message":"forbidden"}}
```

## Verification

Run these checks before and after changing this playbook or import code:

```bash
go test -run TestImportDryRun ./...
go test ./internal/release/... -run TestTenantImportPlaybookArtifact
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

If the import request fails validation, correct the request shape and retry with the same idempotency key.
If authorization fails, do not widen customer
roles or scoped grants; use the approved break-glass support workflow and
record the reason and expiry before retrying.

If the API accepted the job but the worker is unhealthy, pause `yalla-worker`
before investigating repeated mutation risk:

```bash
sudo systemctl stop yalla-worker
journalctl -u yalla-api -u yalla-worker -o json
```

Inspect only stable IDs: `request_id`, `correlation_id`, organization ID, job
ID, and audit event ID. Confirm the import job is idempotent and retry-safe,
then resume `yalla-worker`:

```bash
sudo systemctl start yalla-worker
```

If the import partially failed, do not run ad hoc write SQL and do not call raw
Dokploy operations. Use the audited retry or repair workflow that preserves
Yalla auth, policy, quota, idempotency, desired-state writes, tenant-scoped
`dokploy_refs`, and audit event ordering. If source-of-truth integrity is in
doubt, escalate to the incident response runbook and rehearse restore options
before destructive recovery.
