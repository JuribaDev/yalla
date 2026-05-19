# On-Call Dashboard

This artifact is the production on-call dashboard contract for the Yalla
Control Plane API and worker. It covers the versioned backend binaries
`/usr/local/bin/yalla-api` and `/usr/local/bin/yalla-worker`, Customer / Agent / CI
traffic, Postgres source of truth, durable provisioning jobs, and the
private Dokploy API dependency. Customer traffic must flow through Yalla;
Customers must never receive Dokploy API tokens or call Dokploy directly.

The checked-in dashboard source is intentionally tool-neutral. Operators may
render it into Grafana, Datadog, a custom incident console, or an on-call bot,
but the source of truth is:

```text
GET /dashboards/control-plane.json
GET /metrics
```

`GET /dashboards/control-plane.json` returns a `yalla.output.v1` response
envelope whose data payload is a `yalla.dashboard.v1` dashboard definition.
Failed dashboard reads use the stable `yalla.error.v1` envelope. Every response
must carry `request_id`; panels that expose the latest safe incident hint may
also carry `correlation_id`, organization, principal, resource, service, or job
identifiers for log joins. These identifiers are join hints only, not dashboard
grouping labels.

Runtime configuration is operator-managed. The deployed API and worker read
`/etc/yalla/control-plane.env`; keep that file outside the repository and
populate it from the approved secret manager. Dashboard config, screenshots,
incident notes, tickets, audit metadata, dry-run output, and log excerpts must not print database URLs. Evidence must never contain tokens, API keys, cookies, database URLs, Dokploy tokens, or rendered environment variable values. Use
redacted placeholders such as `<redacted:YALLA_DATABASE_URL>` when the variable
name matters.

## Least-Privilege Access

Dashboard readers should use a least-privilege read-only credential that can
read `/dashboards/control-plane.json`, `/metrics`, `/healthz`, `/readyz`, and
`/version`. It must not be able to mutate tenants, projects, environments,
services, jobs, quota, billing config, feature flags, or Dokploy state.

Support-only inspection during an incident still goes through the approved
break-glass workflow with `support.manage`, a reason, an expiry, and audit
metadata. The dashboard must show only stable IDs and closed-set status fields
until the operator explicitly joins those IDs to structured logs, audit rows,
or source-of-truth records under the incident process.

## Core Panels

The dashboard should group only by low-cardinality fields documented by the
`yalla.dashboard.v1` export. Do not group by tenant, principal, resource, or
job IDs.

| Panel | Primary source | Use |
| --- | --- | --- |
| API availability | `/healthz`, HTTP request metrics | Confirm whether the API process is serving stable probes. |
| Readiness degradation | `/readyz`, readiness degradation metrics | Identify dependency gates such as database, migrations, queue, and Dokploy. |
| HTTP error budget | HTTP request metrics and SLO burn-rate metrics | Detect customer-visible error spikes by method, route, status class, and error code. |
| Provisioning worker | Durable job metrics and worker process liveness | Detect lease stalls, retries, cancellations, and queue backlog. |
| Dead-letter alerts | Dead-letter alert metrics | Page when retry-safe provisioning can no longer progress automatically. |
| Reconciliation drift | Reconciliation drift alert metrics | See desired-state vs private Dokploy state divergence. |
| Dokploy dependency | Dokploy dependency metrics | Separate retryable private dependency errors from deterministic failures. |
| Policy decisions | Policy decision metrics | Detect authorization-denied spikes without leaking tenant-owned values. |
| Audit events | Audit event metrics | Confirm mutation, denial, break-glass, quota, and key-change audit trails. |
| Secret-redaction canaries | Secret-redaction canary metrics | Page on any failed redaction canary outcome. |
| SLO burn-rate | SLO burn-rate metrics | Classify paging severity from the current burn window. |
| Slow queries | Slow-query metrics | Identify store-bound latency without logging SQL text or bind values. |
| Trace spans | Trace-span metrics | Join request and dependency latency by route, component, outcome, and status class. |

## Health, Readiness, And Logs

Probe the API process before relying on dashboard panels:

```bash
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
curl -fsS http://127.0.0.1:8080/version
curl -fsS http://127.0.0.1:8080/dashboards/control-plane.json
curl -fsS http://127.0.0.1:8080/metrics
```

`/healthz` is liveness-only. `/readyz` reports dependency gates including
`database`, `migrations`, `queue`, and `Dokploy` when configured. `/version`
reports release identity and migration version. The worker has no HTTP
listener; observe `yalla-worker` through process liveness, durable job rows,
metrics, dead-letter alerts, and structured JSON logs.

Use structured JSON logs as evidence joins, not as secret stores:

```bash
journalctl -u yalla-api -u yalla-worker -o json
kubectl logs deploy/yalla-api
kubectl logs deploy/yalla-worker
```

Log records, dashboard annotations, and alert payloads must never include raw
authorization headers, request bodies, response bodies, database URLs, Dokploy
tokens, API keys, cookies, or rendered environment values.

## Incident Flows

### Customer-impacting API incident

Start with API availability, Readiness degradation, HTTP error budget, SLO
burn-rate, and Trace spans. Compare `/healthz` with `/readyz`; a live process
with failing readiness usually points to database, migrations, queue, or
Dokploy dependency gates. Join the latest safe `request_id` or `correlation_id`
to structured logs before reading customer-owned records.

### Provisioning worker incident

Start with Provisioning worker, Dead-letter alerts, Reconciliation drift,
Dokploy dependency, Policy decisions, and Audit events. Join by `job_id` and
organization ID before retrying or cancelling work. Dokploy mutations must
happen only after Yalla auth, policy, quota, desired-state write, idempotency,
and audit requirements are satisfied.

### Secret exposure incident

Start with Secret-redaction canaries, Audit events, Trace spans, and structured
log joins. Treat any unredacted token-shaped, key-shaped, URL-shaped, or
rendered environment value in dashboard data, logs, tickets, audit metadata, or
dry-run output as a high-severity incident until contained. Preserve evidence
with redacted markers only.

## Verification

Run these checks when changing this artifact and before relying on a freshly
deployed dashboard:

```bash
go test ./...
go test -race ./...
go vet ./...
go test ./internal/release/... -run TestOnCallDashboardArtifact
scripts/verify.sh
```

For live operational confidence against a non-production private Dokploy target
only, run:

```bash
YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...
```

The live-Dokploy smoke test must never run against production.
