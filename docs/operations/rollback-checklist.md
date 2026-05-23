# Rollback checklist - Yalla Control Plane

This checklist is the production rollback contract for the Yalla Control Plane
API and worker. Use it when a promoted release must be backed out, when a
schema change must be held, or when operators choose to fix forward instead of
rolling back state.

## Scope

A rollback may affect these production surfaces:

- `/usr/local/bin/yalla-api`
- `/usr/local/bin/yalla-worker`
- PostgreSQL migrations owned by the control plane
- durable provisioning jobs and worker behavior
- private Dokploy API integration
- operations artifacts under `deploy/` and `docs/operations/`

The customer path remains:

```text
Customer / Agent / CI
  -> Yalla Control Plane API
  -> Postgres source of truth
  -> Provisioning worker
  -> private Dokploy API
```

Customers must never receive Dokploy API tokens, database URLs, signing keys,
secret-encryption keys, API keys, cookies, or rendered environment values.

## Decision gate

1. Confirm the failing release, target rollback release, and target migration
   version are known from `/version`, release notes, and the migration ledger.
   Public API success responses must still use
   `schema_version: yalla.output.v1`; error responses must still use
   `schema_version: yalla.error.v1`; every response carries `request_id` and
   correlated workflows carry `correlation_id`.

2. Prefer rolling back the application artifact while preserving the current
   control-plane database. If the problem is a data, dependency, or customer
   configuration issue, fix forward unless the release owner confirms rollback
   reduces risk.

3. Treat migration rollback as a separate decision. Roll back schema only when
   the migration is marked reversible, the target version is compatible with
   the older binary, and the release owner has approved the exact version.

4. Confirm runtime configuration is operator-managed in
   `/etc/yalla/control-plane.env` with least-privilege access. Do not commit,
   paste, or print rendered database URLs, Dokploy tokens, API keys, cookies,
   signing keys, secret-encryption keys, or environment variable values.

## Required environment

Rollback commands load runtime values from operator-managed configuration,
usually `/etc/yalla/control-plane.env`. Rollback notes may list variable names
and redacted placeholders only:

```bash
YALLA_DATABASE_URL=<redacted:YALLA_DATABASE_URL>
YALLA_DOKPLOY_BASE_URL=<redacted:YALLA_DOKPLOY_BASE_URL>
YALLA_DOKPLOY_TOKEN=<redacted:YALLA_DOKPLOY_TOKEN>
YALLA_BACKUP_STATUS_FILE=<redacted:YALLA_BACKUP_STATUS_FILE>
YALLA_REHEARSAL_DATABASE_URL=<redacted:YALLA_REHEARSAL_DATABASE_URL>
```

Do not paste rendered values from the env file into rollback notes, chat,
tickets, logs, screenshots, or audit metadata. If an optional external
Dokploy smoke test is approved, set `YALLA_EXTERNAL_DOKPLOY=1` only in the
non-production test environment for that command invocation.

## Pre-rollback safety

Run the dry-run safety checks first:

```bash
deploy/operations/backup-database.sh --dry-run
deploy/operations/restore-rehearsal.sh --dry-run
deploy/operations/migrate-database.sh --dry-run
```

Before any destructive or schema-changing rollback, take a fresh encrypted backup
and confirm the latest restore rehearsal is passing. Dry-run output may include
command shape and redacted `YALLA_*` variable names only. Use placeholders such
as `<redacted:YALLA_DATABASE_URL>` when a variable name is needed.

do not run ad hoc SQL snippets for rollback. Schema changes must go through the
versioned migration operation, which invokes:

```bash
/usr/local/bin/yalla-api --migrate-only
```

For schema rollback, pause `yalla-worker` first so no lease holder mutates
desired state or Dokploy while the database contract is changing.

## Application artifact rollback

For a Kubernetes target, update the image tag or release reference in the
operator-controlled deployment process, render the plan, and apply only after
review:

```bash
kubectl kustomize deploy/kubernetes
kubectl apply --dry-run=server -f deploy/kubernetes/yalla-control-plane.yaml
kubectl apply -f deploy/kubernetes/yalla-control-plane.yaml
```

For a single-node systemd target, install the previously approved binaries from
the operator-controlled release directory and restart both services:

```bash
sudo systemctl stop yalla-worker
sudo install -o root -g root -m 0755 /opt/yalla/releases/<version>/yalla-api /usr/local/bin/yalla-api
sudo install -o root -g root -m 0755 /opt/yalla/releases/<version>/yalla-worker /usr/local/bin/yalla-worker
sudo systemctl restart yalla-api
sudo systemctl start yalla-worker
```

The API and worker stay separate. `yalla-api` owns HTTP request handling,
stable JSON envelopes, readiness, and embedded migration/admin maintenance
commands. `yalla-worker` owns durable provisioning jobs and has no HTTP
listener.

## Schema rollback

Apply schema rollback only when the migration is reversible and the target
binary contract has been checked against the migration ledger. Use the
versioned migration command rather than shell SQL:

```bash
sudo deploy/operations/migrate-database.sh --apply
```

If the migration is not reversible, stop the rollback and fix forward with a
new migration. Record the blocked rollback reason without copying
secret-shaped values.

## Health, readiness, and logs

After rollback, verify process liveness and public health surfaces:

```bash
sudo systemctl is-active yalla-api
sudo systemctl is-active yalla-worker
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
curl -fsS http://127.0.0.1:8080/version
curl -fsS http://127.0.0.1:8080/metrics
```

`/healthz` is liveness-only. `/readyz` reports dependency gates for `database`,
`migrations`, `queue`, and `Dokploy` when configured. `/version` reports the
running release identity and migration version. Check durable job state,
stalled leases, and dead-letter alerts before reopening customer traffic.

Inspect structured JSON diagnostics only:

```bash
journalctl -u yalla-api -u yalla-worker -o json
kubectl logs deploy/yalla-api
kubectl logs deploy/yalla-worker
```

Expected log records include `service`, `request_id`, `correlation_id`, safe
organization/principal/resource identifiers when known, route or job metadata,
status class, and stable error codes. Logs, audit metadata, rollback notes,
dry-run output, screenshots, and incident annotations must never contain
tokens, API keys, cookies, database URLs, Dokploy tokens, authorization
headers, request bodies, response bodies, or rendered environment variable
values.

## Verification

Run the repository gates from the repository root after the rollback artifact
is updated or before promoting the rollback:

```bash
gofmt -w .
goimports -w .
go mod tidy
go test ./...
go test -race ./...
go vet ./...
scripts/verify.sh
go test ./internal/release/... -run TestRollbackChecklistArtifact
```

Normal rollback gates must never require a live Dokploy server. If a
non-production private Dokploy target is explicitly configured for rollback
confidence, run:

```bash
YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...
```

The live-Dokploy smoke test is opt-in and must never run against production.

## Expected outputs

Rollback evidence should record which command was run, the target release or
migration version, the target environment, timestamp, and pass/fail status.
Never copy the full rendered output into rollback notes because command output
can include local paths, incidental identifiers, or operator environment
details.

Go test gates should finish with package-level `ok` lines and no failing test
records:

```text
ok  github.com/juribadev/yalla/internal/controlplane/httpapi
ok  github.com/juribadev/yalla/internal/release
PASS
```

Service liveness checks should report the expected systemd state without
printing service environment values:

```text
active
active
```

Successful health and readiness probes return stable success envelopes with
request IDs:

```json
{"schema_version":"yalla.output.v1","ok":true,"request_id":"req_example","data":{"checks":{"database":true,"migrations":true,"queue":true}}}
```

Failed readiness returns the stable error envelope and must not expose database
URLs, Dokploy tokens, request bodies, response bodies, or rendered environment
values:

```json
{"schema_version":"yalla.error.v1","ok":false,"request_id":"req_example","error":{"code":"E_SERVER","message":"service unavailable"}}
```

`/version` evidence should include release identity plus compatibility
metadata:

```json
{"schema_version":"yalla.output.v1","ok":true,"request_id":"req_example","data":{"version":"v0.0.0","commit":"<redacted:git-sha>","date":"2026-05-19T00:00:00Z","api_schema_version":"yalla.api.v1","migration_version":"<redacted:migration-version>"}}
```

Structured log evidence may be summarized as key presence only. Acceptable
rollback evidence says `service=yalla-api`, `service=yalla-worker`,
`request_id`, `correlation_id`, `status_class`, and stable `error_code` were
present where applicable.

## Completion

Rollback is complete only after:

- `/healthz`, `/readyz`, `/version`, and `/metrics` return the expected
  envelope shape and version metadata.
- structured JSON logs contain no redaction canary failures.
- durable job state has no unexpected stuck leases or new dead-letter alerts.
- customer-facing endpoints preserve stable `yalla.output.v1` /
  `yalla.error.v1` envelopes and stable error codes.
- the incident or release note records whether the team rolled back or chose
  to fix forward.

## Change log

| Date       | Change                               | Owner              |
|------------|--------------------------------------|--------------------|
| 2026-05-19 | Initial rollback checklist (BE-0424). | Backend Operations |
