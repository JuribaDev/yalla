# Release checklist - Yalla Control Plane

This checklist is the production release contract for the Yalla Control Plane
API and worker. Use it before cutting or promoting a release that includes
`/usr/local/bin/yalla-api`, `/usr/local/bin/yalla-worker`, migrations,
operations artifacts, API schema changes, or worker job behavior.

## Scope

A release may change these production surfaces:

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

## Release candidate

1. Confirm the release candidate includes both backend binaries and reports the
   expected version metadata:

   ```bash
   /usr/local/bin/yalla-api --version
   /usr/local/bin/yalla-worker --version
   ```

2. Confirm the OpenAPI and response-envelope contracts are compatible with the
   PRD story being released. Public API success responses use
   `schema_version: yalla.output.v1`; error responses use
   `schema_version: yalla.error.v1`; every response carries a stable
   `request_id`.

3. Confirm runtime configuration is operator-managed. Production deployments
   read `/etc/yalla/control-plane.env`, rendered from the approved secret
   manager with least-privilege access. Do not commit, paste, or print rendered
   database URLs, Dokploy tokens, API keys, cookies, signing keys,
   secret-encryption keys, or environment variable values.

4. Confirm the target deployment substrate has a dry-run plan:

   ```bash
   kubectl kustomize deploy/kubernetes
   kubectl apply --dry-run=server -f deploy/kubernetes/yalla-control-plane.yaml
   systemd-analyze verify deploy/systemd/yalla-api.service deploy/systemd/yalla-worker.service
   deploy/operations/migrate-database.sh --dry-run
   ```

   Dry-run output may include command shape and redacted `YALLA_*` variable
   names only.

## Required gates

Run the repository gates from the repository root before tagging or promoting
the release:

```bash
gofmt -w .
goimports -w .
go mod tidy
go test ./...
go test -race ./...
go vet ./...
scripts/verify.sh
```

If `goimports` is not installed, record that in the release notes and keep
`gofmt -w .` passing. `scripts/verify.sh` runs the operations artifact static
tests, including this checklist:

```bash
go test ./internal/release/... -run TestReleaseChecklistArtifact
```

For a final local release build, run:

```bash
scripts/verify.sh --release
```

That command adds the snapshot release build gate without changing the runtime
least-privilege or redaction expectations.

## Expected outputs

Release evidence should identify which gate passed, not preserve full command
transcripts. Never copy the full rendered output into release notes, tickets, or
chat. Record the command name, target environment, release version, timestamp,
and whether the output matched these stable shapes.

Go test gates should finish with package-level `ok` lines and no failing test
records:

```text
ok  github.com/juribadev/yalla/internal/controlplane/httpapi
ok  github.com/juribadev/yalla/internal/release
PASS
```

`scripts/verify.sh` should print named gate headers, then complete without
setting a required failure. Optional tools that are not installed may be
reported by tool name only; do not paste local paths, tokens, or environment
values from a workstation.

Health and readiness probes return stable JSON envelopes. Successful probes use
`yalla.output.v1` and include a request ID:

```json
{"schema_version":"yalla.output.v1","ok":true,"request_id":"req_example","data":{"checks":{"database":true,"migrations":true,"queue":true}}}
```

Unhealthy readiness uses the stable error envelope and must not include raw
database URLs, Dokploy tokens, or rendered environment values:

```json
{"schema_version":"yalla.error.v1","ok":false,"request_id":"req_example","error":{"code":"E_SERVER","message":"service unavailable"}}
```

`/version` evidence should include release identity plus the compatibility
contract fields:

```json
{"schema_version":"yalla.output.v1","ok":true,"request_id":"req_example","data":{"version":"v0.0.0","commit":"<redacted:git-sha>","date":"2026-05-19T00:00:00Z","api_schema_version":"yalla.api.v1","migration_version":"<redacted:migration-version>"}}
```

Structured log samples may be summarized as key presence only. Acceptable
evidence says `service=yalla-api`, `service=yalla-worker`, `request_id`,
`correlation_id`, `status_class`, and stable `error_code` were present where
applicable. It must not include headers, request bodies, response bodies,
secret-shaped configuration values, or rendered environment contents.

## Database and worker safety

Before applying schema changes, take a fresh encrypted backup and confirm the
restore rehearsal artifact is current. Apply migrations only through the
versioned operation:

```bash
sudo deploy/operations/migrate-database.sh --apply
```

The migration command pauses `yalla-worker`, runs
`/usr/local/bin/yalla-api --migrate-only`, restarts services, and probes
`/healthz` plus `/readyz`. Do not run ad hoc SQL snippets for release
migrations. New worker jobs must remain idempotent, retry-safe, cancellable,
auditable, and safe to replay after a lease expires.

## Health, readiness, and logs

After staging promotion and again after production promotion, verify:

```bash
sudo systemctl is-active yalla-api
sudo systemctl is-active yalla-worker
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
curl -fsS http://127.0.0.1:8080/version
curl -fsS http://127.0.0.1:8080/metrics
```

`/healthz` is liveness-only. `/readyz` reports dependency gates for
`database`, `migrations`, `queue`, and `Dokploy` when configured. `/version`
reports release identity and migration version. The worker has no HTTP
listener; observe it through process liveness, durable job state, metrics,
dead-letter alerts, and structured JSON logs.

Inspect structured diagnostics only:

```bash
journalctl -u yalla-api -u yalla-worker -o json
kubectl logs deploy/yalla-api
kubectl logs deploy/yalla-worker
```

Expected log records include `service`, `request_id`, `correlation_id`, safe
organization/principal/resource identifiers when known, route or job metadata,
status class, and stable error codes. Logs, audit metadata, release notes,
dry-run output, screenshots, and incident annotations must never contain
tokens, API keys, cookies, database URLs, Dokploy tokens, authorization
headers, request bodies, response bodies, or rendered environment variable
values. Use redacted placeholders such as `<redacted:YALLA_DATABASE_URL>` when
the variable name matters.

## External smoke

Normal release gates must never require a live Dokploy server. If a
non-production private Dokploy target is explicitly configured for release
confidence, run:

```bash
YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...
```

The live-Dokploy smoke test is opt-in and must never run against production.

## Promotion decision

Promote only after these checks are true:

- `go test ./...`, `go test -race ./...`, and `go vet ./...` pass.
- `scripts/verify.sh` passes.
- migration dry-run output is redacted and matches the intended release.
- `/healthz`, `/readyz`, `/version`, and `/metrics` pass in staging.
- structured JSON logs show no redaction canary failures or dead-letter
  regressions.
- the deployment runbook, rollback checklist, incident response runbook,
  on-call dashboard artifact, and SLO document are compatible with the release.

If any gate fails, do not tag or promote the release. Fix forward, re-run the
full gate, and record the failed gate by name without copying secret-shaped
values.

## Change log

| Date       | Change                              | Owner              |
|------------|-------------------------------------|--------------------|
| 2026-05-19 | Initial release checklist (BE-0423). | Backend Operations |
