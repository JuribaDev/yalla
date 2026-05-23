# SLO Document

This artifact is the production SLO contract for the Yalla Control Plane API
and worker. It covers the versioned backend binaries
`/usr/local/bin/yalla-api` and `/usr/local/bin/yalla-worker`, Customer / Agent / CI
traffic, Postgres source of truth, durable provisioning jobs, and the private
Dokploy API dependency. The dependency boundary is the private Dokploy API.
Customer traffic must flow through Yalla; Customers must never receive Dokploy
API tokens or call Dokploy directly. Customers must never receive Dokploy API tokens.

The SLO evidence surface is intentionally narrow and deterministic:

```text
GET /metrics
GET /healthz
GET /readyz
GET /version
```

Successful API responses use stable `yalla.output.v1` envelopes. Failed API
responses use stable `yalla.error.v1` envelopes. Every response carries
`request_id`; incident evidence may also include `correlation_id`, organization
ID, principal ID, resource ID, service ID, or job ID as safe join hints. These
identifiers are not metrics labels and must not be used for high-cardinality
dashboard grouping.

Runtime configuration is operator-managed. The deployed API and worker read
`/etc/yalla/control-plane.env`; keep that file outside the repository and
populate it from the approved secret manager. SLO reports, alert payloads,
incident notes, tickets, audit metadata, dry-run output, and log excerpts must
not print database URLs. They must not print database URLs even when an
operator command fails before a probe can complete. Evidence must never contain
tokens, API keys, cookies, database URLs, Dokploy tokens, or rendered
environment variable values. Use redacted placeholders such as
`<redacted:YALLA_DATABASE_URL>` when the variable name matters.
SLO evidence must never contain tokens, API keys, cookies, database URLs, Dokploy tokens, or rendered environment variable values.

## Objectives

The following objectives are the production default. Tightening or loosening
one requires a PRD story, an updated SLO document, and updated release gates.

| Objective | Target | Primary signal | Notes |
| --- | ---: | --- | --- |
| API availability | 99.9% monthly | `/healthz`, HTTP request metrics | Counts customer-facing API availability, not private dependency health. |
| API latency | 95% under 500 ms monthly | HTTP request metrics and trace spans | Excludes unauthenticated health probes and operator maintenance commands. |
| Provisioning job completion | 99.5% within 15 minutes monthly | Durable job metrics and dead-letter alerts | Measures accepted Yalla jobs after auth, policy, quota, desired-state write, and audit. |
| Backup freshness | 99.9% monthly | `/healthz/backup` and backup freshness checks | Uses the Postgres source-of-truth backup contract; stale backup status pages immediately. |
| Audit durability | 99.99% monthly | audit event metrics | Mutations, denied decisions, key changes, quota failures, and break-glass access must be auditable. |

`data.slo_burn_rates` in `GET /metrics` is the paging source for these
objectives. Series are grouped by low-cardinality `objective`, `window`,
`severity`, `status`, and `signal` fields only. Safe latest-sample hints such
as `request_id`, `correlation_id`, organization ID, principal ID, resource ID,
and job ID may be copied into structured log searches after the alert fires.

## Error Budget Policy

Error budget policy is production release policy.

SLO burn-rate alerts use the same windows exposed by telemetry: `1h`, `6h`,
and `24h` are the operator-facing windows for release decisions, while shorter
windows remain useful for fast incident detection. Alert severities are:

| Severity | Meaning | Required action |
| --- | --- | --- |
| page | Customer-impacting burn is high enough to require immediate response. | Page the backend on-call, open an incident, and freeze non-urgent releases for the affected surface. |
| ticket | Budget burn is visible but not yet urgent. | Create a tracked remediation ticket before the next release train. |
| info | Budget is recovering or below action threshold. | Keep observing; no release freeze is required. |

When a `page` alert fires, operators freeze non-urgent releases that touch the
affected route, worker path, quota path, policy path, or Dokploy integration
until the incident commander explicitly clears the freeze. Emergency fixes are
allowed when they reduce the active burn and preserve the API contract.

## Least-Privilege Access

SLO readers should use a least-privilege read-only credential that can read
`/metrics`, `/healthz`, `/readyz`, `/healthz/backup`, and `/version`. It must
not be able to mutate tenants, projects, environments, services, jobs, quota,
billing config, feature flags, audit rows, support sessions, or Dokploy state.

Support-only inspection during an incident still goes through the approved
break-glass workflow with `support.manage`, a reason, an expiry, and audit
metadata. The SLO process must show only stable IDs and closed-set status
fields until the operator explicitly joins those IDs to structured logs, audit
rows, or source-of-truth records under the incident process.

## Health, Readiness, And Logs

Probe the API process before relying on SLO evidence:

```bash
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
curl -fsS http://127.0.0.1:8080/version
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

SLO triage should start with readiness degradation, policy decision metrics,
audit event metrics, secret-redaction canaries, SLO burn-rate metrics,
dead-letter alerts, slow-query metrics, and trace spans. Log records, SLO
reports, alert payloads, and incident annotations must never include raw
authorization headers, request bodies, response bodies, database URLs, Dokploy
tokens, API keys, cookies, or rendered environment values.

## Verification

Run these checks when changing this artifact and before relying on a freshly
deployed SLO policy:

```bash
go test ./...
go test -race ./...
go vet ./...
go test ./internal/release/... -run TestSLODocumentArtifact
scripts/verify.sh
```

For live operational confidence against a non-production private Dokploy target
only, run:

```bash
YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...
```

The live-Dokploy smoke test must never run against production.
