# HTTP Request Metrics

Yalla exposes in-process operational metrics at `GET /metrics`. The endpoint
uses the standard `yalla.output.v1` envelope and includes HTTP request metrics,
distributed trace-span metrics, private Dokploy dependency metrics, quota usage
metrics, audit event metrics, policy decision metrics, datastore slow-query
metrics, readiness degradation metrics, and SLO burn-rate alert metrics. It is
intended for operators, agents, and incident tooling that need a quick view of
API behavior without reading application logs first.

The metric series are intentionally low cardinality:

- `method`
- `route`
- `status_code`
- `status_class`

Each series also carries the latest `request_id`, `correlation_id`,
`organization_id`, `principal_id`, and redacted request `target` observed for
that series. Treat those fields as log-join hints, not dashboard group-by
labels. Dashboards should group by the low-cardinality fields above.

Incident workflow:

1. Check `total_requests` and the `5xx`/`4xx` series for the affected route.
2. Copy the latest `request_id` or `correlation_id` from the matching series.
3. Search structured request logs for that identifier.
4. Use `organization_id` and `principal_id` only when present; public,
   unauthenticated, and unmatched requests omit them.

The metrics middleware does not log headers or bodies. Request targets pass
through the same structural redactor as request logs, so token-like query
parameters are replaced with `[REDACTED]`.

## Datastore Slow Queries

Slow-query metrics live under `data.slow_queries`. Series are grouped only by:

- `operation` (`read` or `write`)
- `query_kind` (`select`, `insert`, `update`, `delete`, `with`, etc.)
- `outcome` (`success` or `error`)

Each series includes the latest `request_id`, `correlation_id`, safe tenant and
resource hints, `last_duration_ms`, and `threshold_ms`. SQL text, bind values,
table names, driver errors, DSNs, tokens, and secret values are never stored in
the metric snapshot.

Incident workflow:

1. Check `data.slow_queries.series` for the affected operation and statement
   kind.
2. Copy the latest `request_id` or `correlation_id`.
3. Search structured logs for `msg="store slow query observed"` and the copied
   identifier.
4. Use the safe organization/resource hints only after confirming the request
   scope in the matching API or worker log.

## Readiness Degradation

Readiness degradation metrics live under `data.readiness_degradation`. The
`/readyz` handler records one observation per configured dependency gate on
each probe. Series are grouped only by:

- `check` (`database`, `migrations`, `queue`, `dokploy`, or another fixed
  process gate)
- `status` (`passing` or `failing`)
- `reason` (`ready` or `pending`)

Each series carries the latest `request_id`, `correlation_id`, and safe
organization/principal/job hints when present. Normal load-balancer probes are
public and usually have no tenant identifiers; keep those fields as join hints,
not labels.

Incident workflow:

1. Check `data.readiness_degradation.series` for `status="failing"` and
   `reason="pending"`.
2. Use `check` to identify the blocking dependency gate.
3. Copy the latest `request_id` or `correlation_id` into structured log
   search to inspect the matching `/readyz` probe and adjacent startup logs.
4. Treat absent tenant identifiers as expected for unauthenticated probes.

## SLO Burn-Rate Alerts

SLO burn-rate alert metrics live under `data.slo_burn_rates`. Series are
grouped only by:

- `objective` such as `api_availability`
- `window` (`1m`, `5m`, `15m`, `30m`, `1h`, `6h`, or `24h`)
- `severity` (`page`, `ticket`, or `info`)
- `status` (`firing`, `resolved`, or `suppressed`)
- `signal` such as `http_5xx_ratio`

Each series includes `last_burn_rate`, `last_error_budget_pct`, and the latest
safe request, correlation, organization, principal, resource, and job hints.
Those identifiers are for log joins during incidents; do not use them as
dashboard labels. Unknown or unsafe label values collapse to `unknown` or
`other`, and unsafe identifiers are omitted.

Incident workflow:

1. Alert on `data.slo_burn_rates.series` where `status="firing"` and the
   `last_burn_rate` exceeds the objective's configured paging threshold.
2. Use `objective`, `window`, `severity`, and `signal` to identify the affected
   SLO and source signal without grouping by tenant identifiers.
3. Copy the latest `request_id`, `correlation_id`, or `job_id` into structured
   log search to find the concrete request or worker execution.
4. Use organization/resource hints only after confirming the matching log or
   job row; absent hints are expected for global process objectives.
