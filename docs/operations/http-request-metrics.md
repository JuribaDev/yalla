# HTTP Request Metrics

Yalla exposes in-process operational metrics at `GET /metrics`. The endpoint
uses the standard `yalla.output.v1` envelope and includes HTTP request metrics,
distributed trace-span metrics, private Dokploy dependency metrics, quota usage
metrics, audit event metrics, policy decision metrics, and datastore slow-query
metrics. It is intended for operators, agents, and incident tooling that need a
quick view of API behavior without reading application logs first.

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
