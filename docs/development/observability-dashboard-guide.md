# Observability Dashboard Guide

This guide documents how to build, validate, and maintain the observability
 dashboard for the Yalla Control Plane API and worker. It covers the versioned
 backend binaries `/usr/local/bin/yalla-api` and `/usr/local/bin/yalla-worker`,
 Customer / Agent / CI traffic, Postgres source of truth, Provisioning worker,
 durable provisioning jobs, PostgreSQL, and the private Dokploy API dependency. Customer traffic must flow through
 Yalla; Customers must never receive Dokploy API tokens or call Dokploy directly.

The dashboard aggregates telemetry from HTTP request metrics, trace spans, quota
 decisions, policy decisions, audit events, Dokploy dependency metrics, worker
 queue metrics, reconciliation drift alerts, dead-letter alerts, SLO burn-rate
 metrics, secret-redaction canaries, readiness degradation metrics, and slow-query
 metrics. All metrics are emitted as structured JSON logs or Prometheus-compatible
 time-series snapshots exposed through `GET /metrics`.

Runtime configuration is operator-managed. The deployed API and worker read
 `/etc/yalla/control-plane.env`; keep that file outside the repository and
 populate it from the approved secret manager. Dashboard config, screenshots, incident notes, tickets, audit metadata, dry-run output, and log excerpts must not print database URLs. Dashboard evidence must never contain tokens, API keys, cookies, database URLs, Dokploy tokens, or rendered environment variable values. Use redacted placeholders such as `<redacted:YALLA_DATABASE_URL>` when the variable name matters.

## Dashboard Sources

The observability dashboard is composed from the following low-cardinality metric
 series. Do not group by tenant, principal, resource, service, or job IDs.

| Source | Endpoint / Collector | Use |
| --- | --- | --- |
| HTTP request metrics | `telemetry.HTTPRequestMetrics` in `internal/controlplane/telemetry` | Group by method, normalized route, status code, and status class. |
| Trace spans | `telemetry.TraceSpanMetrics` | Group by name, kind, route, component, outcome, status class, and error code. |
| Dokploy dependencies | `telemetry.DokployDependencyMetrics` | Group by method, normalized endpoint, outcome, status class, error code, and retryable. |
| Quota usage | `telemetry.QuotaUsageMetrics` | Group by resource, enforcement mode, outcome, and reason. |
| Policy decisions | `telemetry.PolicyDecisionMetrics` | Group by action, resource kind, decision, and reason. |
| Audit events | `telemetry.AuditEventMetrics` | Group by action, resource kind, decision, outcome, reason, and error code. |
| Worker queue | Worker queue metrics | Group by event, job type, status, and status class. |
| Reconciliation drift | `telemetry.ReconciliationDriftAlertMetrics` | Group by drift kind, action type, reason, severity, and status. |
| Dead-letter alerts | `telemetry.DeadLetterAlertMetrics` | Group by job type, reason, severity, and status. |
| SLO burn-rate | `telemetry.SLOBurnRateMetrics` | Group by objective, window, severity, status, and signal. |
| Secret-redaction canaries | `telemetry.SecretRedactionCanaryMetrics` | Group by surface, vector, outcome, and reason. |
| Readiness degradation | `telemetry.ReadinessDegradationMetrics` | Group by check, status, and reason. |
| Slow queries | `telemetry.SlowQueryMetrics` | Group by operation, query kind, and outcome. |

Request, correlation, organization, principal, resource, service, and job IDs are
 join hints only. They are stored as latest-sample incident hints and must never
 be used as dashboard grouping labels.

## Required Environment Variables

The observability stack is configured through the same environment file used by
 the API and worker:

```bash
# Operator-managed secrets (never commit real values)
YALLA_DATABASE_URL=<redacted:YALLA_DATABASE_URL>
YALLA_DOKPLOY_BASE_URL=<redacted:YALLA_DOKPLOY_BASE_URL>
YALLA_DOKPLOY_TOKEN=<redacted:YALLA_DOKPLOY_TOKEN>

# Observability tuning
YALLA_LOG_LEVEL=info
YALLA_FEATURE_FLAGS=
```

All secret-shaped values must be redacted. The document must never contain
 rendered tokens, cookies, API keys, database URLs, Dokploy tokens, or rendered
 environment variable values.

## Expected Output Shapes

`GET /metrics` exposes a Prometheus-compatible snapshot. `GET /dashboards/control-plane.json`
 returns a `yalla.output.v1` envelope whose `data` block is a `yalla.dashboard.v1`
 document.

Success envelopes use `schema_version: yalla.output.v1`:


```json
{
  "schema_version": "yalla.output.v1",
  "ok": true,
  "request_id": "req_...",
  "data": {
    "schema_version": "yalla.dashboard.v1",
    "panels": [...]
  }
}
```

Failed dashboard reads use the stable `yalla.error.v1` envelope with `schema_version: yalla.error.v1`:

```json
{
  "schema_version": "yalla.error.v1",
  "ok": false,
  "request_id": "req_...",
  "error": {
    "code": "E_NOT_FOUND",
    "message": "Human readable message.",
    "hint": "Optional recovery hint."
  }
}
```

Every response must carry `request_id`. Panels that expose the latest safe
 incident hint may also carry `correlation_id`, organization, principal, resource,
 service, or job identifiers for log joins.

## Verification

Run these checks when changing this artifact and before relying on a freshly
 deployed dashboard:

```bash
gofmt -w .
goimports -w .
go mod tidy
go test ./...
go test -race ./...
go vet ./...
go test ./internal/controlplane/telemetry/...
go test ./internal/release/... -run TestObservabilityDashboardGuideArtifact
scripts/verify.sh
```

For live operational confidence against a non-production private Dokploy target
 only, run:

```bash
YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...
```

The live-Dokploy smoke test must never run against production.

## Failure Recovery

- If `/metrics` is missing expected sections, verify the `telemetry` package is
 wired in `httpapi.NewHandler` and that the request logging middleware is active.
- If dashboard panels show high-cardinality labels, review the metric collector
 to ensure IDs are stored only as latest-sample incident hints, not as label
 dimensions.
- If secret-redaction canaries fire, treat it as a high-severity incident until
 contained. Preserve evidence with redacted markers only.
- If slow-query metrics appear, investigate store-bound latency through
 structured logs. Do not log SQL text, bind args, table names, DSNs, or driver
 error strings.
- Normal verification gates must never require a live Dokploy server.
- For additional failure recovery guidance, consult the on-call dashboard runbook.
