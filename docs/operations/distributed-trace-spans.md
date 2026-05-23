# Distributed Trace Spans

Yalla exposes completed span aggregates at `GET /metrics` under
`data.trace_spans`. The endpoint uses the standard `yalla.output.v1` envelope
and is designed for incident triage before a full external OpenTelemetry
pipeline is wired.

Span series are intentionally low cardinality:

- `name`
- `kind`
- `route`
- `component`
- `outcome`
- `status_class`
- `error_code`

Each series also carries the latest `request_id`, `correlation_id`,
`organization_id`, `principal_id`, `resource_kind`, `resource_id`, `job_id`, and
redacted request `target` observed for that series. Treat those fields as
incident join hints, not dashboard labels. Dashboards should group by the
low-cardinality fields above.

Incident workflow:

1. Find the `trace_spans` series with the affected `route`, `component`, and
   `outcome`.
2. Check `count`, `total_duration_ms`, and `last_duration_ms` to identify slow
   or failing paths.
3. Copy the latest `request_id` or `correlation_id` from that series.
4. Search structured request logs, audit rows, job rows, and Dokploy dependency
   metrics for the same identifier.
5. Use organization, principal, resource, and job identifiers only when present;
   public, unauthenticated, and unmatched requests omit unresolved identifiers.

The trace-span collector records route templates rather than raw URLs whenever
the router matched a route. For unmatched requests, the route is `unmatched`.
Request targets pass through the same structural redactor as request logs, so
token-like query parameters are replaced with `[REDACTED]`.
