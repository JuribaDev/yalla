# Deployment runbook — Yalla Control Plane

This runbook is the production deployment contract for the Yalla Control
Plane API and worker. Update it with any change that affects release
artifacts, runtime configuration, health/readiness behavior, migrations,
or operator verification.

## Scope

Deployments promote a previously built release into an environment that runs:

- `/usr/local/bin/yalla-api`
- `/usr/local/bin/yalla-worker`
- PostgreSQL owned by the operator
- private Dokploy infrastructure reached only by the control plane

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
The customer-facing CLI is part of that boundary: it is configured with
`YALLA_BASE_URL=<control-plane-api>` and `YALLA_TOKEN=<yalla-bearer-token>`.
Only backend and worker processes may receive `YALLA_DOKPLOY_BASE_URL` and
`YALLA_DOKPLOY_TOKEN`.

## Preflight

1. Confirm the release artifact includes both backend binaries:

   ```bash
   /usr/local/bin/yalla-api --version
   /usr/local/bin/yalla-worker --version
   ```

2. Render the runtime environment from the operator secret manager into
   `/etc/yalla/control-plane.env` with owner `root:yalla` and mode `0640`.
   Start from `deploy/config/control-plane.env.example`; keep every rendered
   secret outside the repository, tickets, chat transcripts, and runbooks.

3. Verify the deployment target matches one supported production substrate:

   ```bash
   kubectl kustomize deploy/kubernetes
   systemd-analyze verify deploy/systemd/yalla-api.service deploy/systemd/yalla-worker.service
   ```

4. Confirm the release is compatible with the target database by running the
   dry-run migration plan:

   ```bash
   deploy/operations/migrate-database.sh --dry-run
   ```

The dry-run output must print command shape and redacted `YALLA_*` variable
names only. It must not print database URLs, Dokploy endpoints, Dokploy
tokens, API keys, cookies, signing keys, secret keys, or rendered environment
variable values.

## Deploy

For a Kubernetes target, apply the checked-in baseline after the operator has
created the `yalla-control-plane-secrets` Secret out of band:

```bash
kubectl apply --dry-run=server -f deploy/kubernetes/yalla-control-plane.yaml
kubectl apply -f deploy/kubernetes/yalla-control-plane.yaml
```

For a single-node systemd target, install the checked-in units and restart the
two services:

```bash
sudo install -o root -g root -m 0644 deploy/systemd/yalla-api.service /etc/systemd/system/yalla-api.service
sudo install -o root -g root -m 0644 deploy/systemd/yalla-worker.service /etc/systemd/system/yalla-worker.service
sudo systemctl daemon-reload
sudo systemctl restart yalla-api
sudo systemctl restart yalla-worker
```

The API and worker stay separate. `yalla-api` owns HTTP request handling,
stable JSON envelopes, readiness, and the embedded migration/admin
maintenance commands. `yalla-worker` owns durable provisioning jobs and has no
HTTP listener; observe it through process liveness, structured logs, durable
job state, metrics, and dead-letter alerts.

## Database changes

Apply schema changes only through the versioned migration command:

```bash
sudo deploy/operations/migrate-database.sh --apply
```

The command stops `yalla-worker` before applying schema changes, runs
`/usr/local/bin/yalla-api --migrate-only`, restarts services, and then probes
`/healthz` and `/readyz`. Do not run ad hoc SQL snippets for release
migrations.

## Health and readiness

After deploy, verify process liveness and public health surfaces:

```bash
sudo systemctl is-active yalla-api
sudo systemctl is-active yalla-worker
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
curl -fsS http://127.0.0.1:8080/version
```

`/healthz` is liveness-only. `/readyz` reports dependency gates for database,
migrations, queue, and Dokploy when configured. Success responses use
`schema_version: yalla.output.v1`; errors use
`schema_version: yalla.error.v1` with a stable `request_id` and stable error
code.

## Logs and redaction

Inspect structured JSON diagnostics only:

```bash
journalctl -u yalla-api -u yalla-worker -o json
kubectl logs deploy/yalla-api
kubectl logs deploy/yalla-worker
```

Expected log records include `service`, `request_id`, `correlation_id`, safe
organization/principal/resource identifiers when known, route or job metadata,
status class, and stable error codes. Logs must never contain database URLs,
tokens, API keys, cookies, signing keys, secret keys, Dokploy credentials,
backup credentials, request bodies, response bodies, or rendered environment
variable values.

## Post-deploy checks

Run the focused release gate for this runbook:

```bash
go test ./internal/release/... -run TestDeploymentRunbookArtifact
```

Then run the repository verification gate before promoting the release:

```bash
scripts/verify.sh
```

When optional external smoke testing is explicitly configured for a
non-production Dokploy target, run:

```bash
YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...
```

External Dokploy smoke tests are opt-in and must never run against production
by accident.

## Rollback

Prefer rolling back the application artifact first while preserving the
control-plane database. If the release included schema changes, use the
versioned migration rollback procedure only after confirming the target
migration is reversible and after taking a fresh encrypted database backup.

After rollback, repeat the health/readiness probes, inspect structured JSON
logs, and check durable job state for stuck leases or dead-letter alerts.

## Change log

| Date       | Change                             | Owner              |
|------------|------------------------------------|--------------------|
| 2026-05-19 | Initial deployment runbook (BE-0419). | Backend Operations |
