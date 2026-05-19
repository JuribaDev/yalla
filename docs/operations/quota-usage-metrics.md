# Quota Usage Metrics

Yalla emits in-process quota decision metrics through
`telemetry.QuotaUsageMetrics`. The API process wires the quota checker to
`telemetry.DefaultQuotaUsageMetrics`, and `GET /metrics` returns the snapshot in
the standard `yalla.output.v1` envelope under `data.quota_usage`.

The metric series are intentionally low cardinality:

- `resource`: the closed quota dimension, for example `projects`, `services`,
  `domains`, or `memory_mb`
- `enforcement_mode`: `hard`, `soft`, `metered`, `disabled`, `unknown`, or
  `other`
- `outcome`: `allowed`, `rejected`, or `error`
- `reason`: a bounded reason such as `reserved`, `limit_exceeded`,
  `unconstrained`, `disabled`, `invalid_resource`, or `reservation_insert_failed`

Each series also carries the latest `current`, `reserved`, `requested`, and
`limit` counts plus the latest `request_id`, `correlation_id`,
`organization_id`, `principal_id`, and `job_id` observed for that series. Treat
those identifiers as log-join and source-row hints, not dashboard group-by
labels. Dashboards should group only by the low-cardinality fields above.

Incident workflow:

1. Look for `outcome=rejected` with `reason=limit_exceeded` to distinguish real
   customer limit pressure from infrastructure failures.
2. Compare `current + reserved + requested` against `limit` on the latest
   sample to understand why a hard limit rejected the request.
3. Look for `outcome=error` series to detect quota infrastructure failures such
   as lookup, usage-lock, reservation-sum, or reservation-insert failures.
4. Copy the latest `request_id`, `correlation_id`, or `job_id` from the series
   and search structured API or worker logs for the same identifier.
5. Use `organization_id` only to navigate tenant-scoped source rows during an
   incident. It is an operational hint, not a metric label.

Quota metrics do not record request bodies, API keys, cookies, rendered
environment variables, database URLs, Dokploy tokens, entitlement override
reasons, or error strings. Unknown resource names and free-form reasons are
collapsed to bounded values before storage.
