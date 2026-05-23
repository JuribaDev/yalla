# Secret Redaction Canaries

Yalla exposes redaction canary observations at `GET /metrics` under
`data.secret_redaction_canaries`. The signal is for tests, deployment smoke
checks, and incident verification that deliberately plant a known canary value
through a log, error, audit, or metrics path and then assert the raw value never
appears in operator-visible output.

Series are grouped only by:

- `surface`: bounded redaction surface, for example `request_logs`,
  `error_envelope`, `audit_metadata`, or `metrics_snapshot`.
- `vector`: bounded probe vector, for example `authorization_header`,
  `cookie_header`, `database_url`, or `operator_reason`.
- `outcome`: `passed`, `failed`, or `unknown`.
- `reason`: bounded classifier such as `sentinel_absent` or `sentinel_found`.

`request_id`, `correlation_id`, `organization_id`, `principal_id`,
`resource_kind`, `resource_id`, and `job_id` are latest-sample incident hints.
Use them to join a failing canary metric to structured logs, audit rows, or job
rows. Do not use them as dashboard labels.

During an incident:

1. Alert on any series with `outcome="failed"`.
2. Join the latest `request_id` / `correlation_id` to structured logs.
3. Identify the affected `surface` and `vector`.
4. Treat the planted canary value as compromised until downstream log, audit,
   and metrics sinks have been checked or scrubbed.
5. Keep the raw canary secret out of tickets and postmortems; record only the
   bounded dimensions and identifiers above.

Canary emitters should call `telemetry.ObserveSecretRedactionCanary`. That
helper records the metric and emits a structured log line named
`secret_redaction_canary` without accepting the raw probe value as an argument.
