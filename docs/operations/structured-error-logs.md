# Structured Error Logs

Every API request emits one structured request log after the handler returns.
The request log is the operator join point between public API envelopes,
metrics, audit rows, and provisioning jobs.

Low-cardinality fields:

- `method`
- `route`
- `status`
- `status_class`
- `outcome`
- `error_code`

Correlation and incident hints:

- `request_id`
- `correlation_id`
- `org_id`
- `principal_id`
- `resource_kind`
- `resource_id`
- `job_id`

Use `method`, `route`, `status_class`, `outcome`, and `error_code` for
dashboards and alert filters. Treat organization, principal, resource, and job
IDs as log-join hints for a specific incident, not as high-cardinality metric
labels.

Incident workflow:

1. Start from a failing response envelope, `/metrics` series, audit event, or
   worker log and copy `request_id`, `correlation_id`, or `job_id`.
2. Search request logs for the copied identifier.
3. Filter by `error_code` to separate customer input failures from dependency
   or internal failures.
4. Use `resource_kind` plus `resource_id` only after the request has resolved a
   safe tenant-scoped resource. Public and unauthenticated requests omit those
   fields.

The logging middleware does not record request headers, response headers,
request bodies, or response bodies. The request target is redacted before it is
logged, so token-like query parameters are replaced with `[REDACTED]`.
