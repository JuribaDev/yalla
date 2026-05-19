# Audit Event Metrics

Yalla emits in-process audit-log append metrics through
`telemetry.AuditEventMetrics`. The audit repository records every append
attempt to `telemetry.DefaultAuditEventMetrics`, and `GET /metrics` returns the
snapshot in the standard `yalla.output.v1` envelope under `data.audit_events`.

The metric series are intentionally low cardinality:

- `action`: the bounded control-plane action, for example `project.create`
- `resource_kind`: the audited resource kind, for example `project`
- `decision`: `allowed`, `denied`, `unknown`, or `other`
- `outcome`: `recorded` or `failed`
- `reason`: a bounded decision or append reason
- `error_code`: a stable Yalla error code for failed appends

Each series also carries the latest `request_id`, `correlation_id`,
`organization_id`, `resource_id`, `actor_id`, and `job_id` observed for that
series. Treat those identifiers as log-join and source-row hints, not dashboard
group-by labels. Dashboards should group only by the low-cardinality fields
above.

Incident workflow:

1. Alert on any sustained `outcome=failed` series. A failed audit append means a
   mutation or denial path may not have a durable audit row.
2. Break failures down by `error_code` and `reason` to distinguish programming
   errors such as `invalid_decision` from store failures such as `write_failed`.
3. Watch for sudden increases in `decision=denied` by `action` to identify
   policy regressions, credential-scope changes, or customer automation using
   stale grants.
4. Copy the latest `request_id`, `correlation_id`, or `job_id` from the series
   and search structured API or worker logs for the same identifier.
5. Use `organization_id` and `resource_id` only to navigate tenant-scoped source
   rows during an incident. They are operational hints, not metric labels.

Audit metrics do not record request bodies, API keys, cookies, database URLs,
Dokploy tokens, rendered environment variables, plaintext secret values, user
agents, IP addresses, metadata values, or error strings. Free-form or unsafe
dimension values collapse to `other`, and unsafe identifiers are omitted.
