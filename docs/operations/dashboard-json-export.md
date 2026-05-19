# Dashboard JSON Export

Yalla exposes a deterministic operations dashboard definition at:

```text
GET /dashboards/control-plane.json
```

The response is a `yalla.output.v1` envelope. Its `data` block is a
`yalla.dashboard.v1` document that points panels at `GET /metrics`.

Operators can import or mirror this JSON into Grafana, Datadog, a custom
dashboard renderer, or an incident bot. The export is intentionally
tool-neutral: it names panels, data sections, group-by fields, join hints, and
incident flows without depending on a vendor schema.

## Cardinality

Dashboard panels group only by stable low-cardinality fields:

- HTTP: `method`, `route`, `status_code`, `status_class`
- Trace spans: `name`, `kind`, `route`, `component`, `outcome`,
  `status_class`, `error_code`
- Dokploy dependency calls: `method`, `endpoint`, `outcome`, `status_class`,
  `error_code`, `retryable`
- Quota, policy, audit, readiness, SLO, dead-letter, drift, and redaction
  series: their bounded reason/status/action fields

Request, correlation, organization, principal, resource, service, and job ids
are join hints only. Do not use them as dashboard labels. During an incident,
copy the latest safe `request_id`, `correlation_id`, or `job_id` from a panel
and join it to structured logs, audit rows, drift findings, or provisioning job
rows.

## Incident Use

For API error spikes, start with the HTTP request panel by `route` and
`status_class`, then open trace-span rows for the same route and outcome. Join
the latest `request_id` or `correlation_id` to structured logs.

For provisioning stalls, start with dead-letter and reconciliation drift
panels, then inspect Dokploy dependency retryability and quota decisions. Join
the latest `job_id` to the durable job row before retrying.

For secret-redaction regressions, page on any failed canary series and join
only by request, correlation, resource, or job identifiers. The canary emitter
and dashboard export never store raw canary values.
