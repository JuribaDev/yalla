# Job Queue Metrics

Yalla workers emit in-process durable-job queue metrics through
`telemetry.JobQueueMetrics`. The real Postgres-backed worker uses
`telemetry.DefaultJobQueueMetrics` unless a test or embedding process injects a
collector.

The metric series are intentionally low cardinality:

- `event`: `claimed` or `completed`
- `job_type`
- `status`
- `status_class`: `active`, `retry`, `success`, `failure`, or `other`

Each series also carries the latest `job_id`, `request_id`, `correlation_id`,
`organization_id`, `project_id`, `environment_id`, `service_id`, `attempt`,
`max_attempts`, and `next_run_delay_ms` observed for that series. Treat those
fields as log-join and source-row hints, not dashboard group-by labels.
Dashboards should group by the low-cardinality fields above.

Incident workflow:

1. Look for growth in `completed` series with `status_class=failure` or
   `status_class=retry`.
2. Check `attempt` / `max_attempts` and `next_run_delay_ms` to decide whether a
   dependency is recovering or jobs are approaching dead-letter.
3. Copy the latest `job_id`, `request_id`, or `correlation_id` from the
   matching series.
4. Search structured worker logs for that identifier. Worker claim and outcome
   logs include the same correlation fields.
5. Use organization/resource identifiers only to navigate tenant-scoped source
   rows. They are operational hints, not metric labels.

The queue metrics do not record job payloads, headers, rendered environment
variables, API keys, Dokploy tokens, cookies, database URLs, or error strings.
Persisted job error summaries continue to be redacted by the store boundary.
