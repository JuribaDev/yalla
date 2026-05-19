# Incident Response Runbook

This runbook is the production response guide for Yalla Control Plane API and
worker incidents. It covers the versioned backend binaries
`/usr/local/bin/yalla-api` and `/usr/local/bin/yalla-worker`, the API and
worker release artifacts, Postgres source of truth, durable provisioning jobs,
and the private Dokploy API dependency. Customer / Agent / CI traffic must flow
through the Yalla API; Customers must never receive Dokploy API tokens or call
Dokploy directly.

Runtime configuration is operator-managed. The deployed API and worker read
`/etc/yalla/control-plane.env`; keep that file outside the repository, owned by
the production operator account, and populated from the approved secret manager.
Incident notes, tickets, pages, dry-run output, audit metadata, and log excerpts
must not print database URLs. Evidence must never contain tokens, API keys, cookies, database URLs, Dokploy tokens, or rendered environment variable values.
Use redacted values such as `<redacted:YALLA_DATABASE_URL>` when a variable name
is operationally important.

## Incident Severity

Incident severity uses these levels consistently so pages, customer updates, and
post-incident review records line up.

| Severity | Trigger | Initial response target |
| --- | --- | --- |
| SEV1 | Widespread API outage, data integrity risk, active secret exposure, or provisioning mutations that may cross tenant boundaries | Page primary and secondary immediately |
| SEV2 | Customer-visible degradation, sustained `/readyz` failure, worker queue stalling, Dokploy dependency outage, or billing/quota enforcement risk | Page primary immediately |
| SEV3 | Single-tenant impact, delayed jobs with no data-risk signal, degraded metrics, or non-urgent operator workflow failure | Ticket plus on-call acknowledgement |

## Initial Containment

Initial containment starts before root-cause analysis.

1. Acknowledge the page and create an incident channel.
2. Record the incident commander, communications owner, and current severity.
3. Capture the first safe identifiers: `request_id`, `correlation_id`,
   affected organization IDs, resource IDs, job IDs, and deployment version.
4. Stop risky mutation paths before investigating deeply. Prefer disabling the
   affected route, pausing `yalla-worker`, or applying a backoffice feature flag
   over direct database edits.
5. If support-only data access is needed, use the approved break-glass workflow
   with `support.manage`; record the reason and expected expiry before reading
   tenant data.

Do not paste `/etc/yalla/control-plane.env`, request bodies, response bodies,
database dumps, raw headers, rendered variables, or Dokploy credentials into the
incident channel. Logs are structured diagnostics only.

## Health And Readiness

Probe the API process first:

```bash
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
curl -fsS http://127.0.0.1:8080/version
```

`/healthz` is liveness-only. `/readyz` reports dependency gates including
`database`, `migrations`, `queue`, and `Dokploy` when configured. `/version`
reports release identity and migration version. Successful HTTP responses use
`schema_version: yalla.output.v1`; failed responses use
`schema_version: yalla.error.v1`; every response must include a stable
`request_id`. The worker has no HTTP listener; observe it through process
liveness, durable job rows, metrics, dead-letter alerts, and structured JSON
logs.

## Logs And Metrics

Use structured JSON logs and low-cardinality metrics as join surfaces, not as
secret stores:

```bash
journalctl -u yalla-api -u yalla-worker -o json
kubectl logs deploy/yalla-api
kubectl logs deploy/yalla-worker
```

Filter by `request_id`, `correlation_id`, organization ID, principal ID,
resource ID, or job ID. Check readiness degradation, policy decision, quota
usage, audit event, slow-query, trace-span, SLO burn-rate, secret-redaction
canary, reconciliation drift, and dead-letter alerts in `/metrics` or the
configured dashboard export. Log records must never include raw authorization
headers, cookies, request bodies, response bodies, database URLs, Dokploy
tokens, API keys, or rendered environment values.

## Customer-Impacting API Incident

A Customer-impacting API incident starts when customers, agents, or CI cannot
use a stable public API workflow.

1. Confirm whether `/healthz` and `/readyz` disagree. A live process with
   failing readiness usually points at database, migrations, queue, or Dokploy
   dependency gates.
2. Compare failing route, method, status class, and error code in HTTP request
   metrics. Stable `yalla.error.v1` codes are the public contract; do not infer
   behavior from handler internals during customer communication.
3. Verify recent releases with `/version` and deployment metadata.
4. If the API is returning unstable responses, roll back the release using the
   deployment runbook after confirming the target migration version is safe.
5. If only one tenant is affected, prove tenant scope before reading any
   customer-owned resource. Cross-tenant IDs must not be used as existence
   probes.

## Provisioning Worker Incident

A Provisioning worker incident starts when durable jobs stop progressing or
worker retries risk repeated external mutation.

1. Check `yalla-worker` process liveness and queue depth.
2. Inspect durable provisioning job state by job ID and organization ID. Focus
   on lease age, retry count, cancellation state, and dead-letter alerts.
3. Pause `yalla-worker` before schema-changing operations or before stopping a
   repeated external mutation.
4. Confirm that failed jobs are retry-safe and idempotent before restarting the
   worker. Dokploy mutations must happen only after Yalla auth, policy, quota,
   desired-state write, idempotency, and audit requirements are satisfied.
5. Resume the worker only after the queue, database, and Dokploy dependency
   gates are healthy.

## Postgres Incident

A Postgres incident starts when source-of-truth reads, writes, migrations, or
backup recovery paths are degraded.

1. Treat Postgres as the source of truth for tenants, ownership, policy, limits,
   desired state, audit events, and job state.
2. Do not run ad hoc write SQL in production. Use the versioned API maintenance
   commands or a reviewed repair playbook that preserves validation,
   transactionality, and audit.
3. If restore is considered, use the backup and restore runbook. A restore
   rehearsal must have passed for the selected snapshot class before production
   recovery starts.
4. After recovery, run readiness, migration, contract, policy, quota, worker,
   and redaction checks before declaring the incident resolved.

## Dokploy Dependency Incident

A Dokploy dependency incident starts when the private provisioning backend is
unavailable or returns unsafe dependency failures.

1. Confirm whether the impact is read-only monitoring, provisioning, deploy,
   rollback, or network reachability.
2. Keep customer communication focused on Yalla resource state and stable job
   status. Do not expose raw Dokploy operation names or broad Dokploy access.
3. Hold or cancel retrying jobs when Dokploy is returning deterministic failure
   responses that would burn retry budgets without recovery.
4. Run the external live-Dokploy smoke test only against an explicitly
   configured non-production target:

```bash
YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...
```

This smoke test must never run against production.

## Secret Exposure Incident

A Secret exposure incident starts when secret-shaped material appears outside
approved operator-managed storage.

1. Treat any unredacted token, API key, cookie, database URL, Dokploy token, or
   rendered environment value in logs, tickets, audit metadata, dry-run output,
   or customer-visible errors as SEV1 until proven otherwise.
2. Revoke or rotate the exposed credential through the owning secret manager.
3. Search only redacted log surfaces for the marker and record affected
   `request_id` / `correlation_id` values.
4. Verify secret-redaction canary metrics and tests before closing containment.
5. Preserve evidence without copying the raw secret into the incident record.

## Verification

Use these checks during containment and before resolution:

```bash
go test ./...
go test -race ./...
go vet ./...
go test ./internal/release/... -run TestIncidentResponseRunbookArtifact
scripts/verify.sh
```

When persistence, policy, quota, job, or worker behavior was involved, also run
the focused backend suites named in the PRD for migrations, policy matrix,
quota concurrency, fake Dokploy, and worker leases. Document any unavailable
optional tool explicitly in the incident record and in `ralph/progress.txt`
when the story runner is being used.

## Expected outputs

Incident evidence should identify the command, target environment, timestamp,
incident ID, and whether the output matched the expected shape.
Never copy full rendered command output into the incident record. Command
output can carry local paths, operator environment details, customer
identifiers, or secret-shaped values.

Go test gates should finish with package-level `ok` lines and no failing test
records:

```text
ok  github.com/juribadev/yalla/internal/controlplane/httpapi
ok  github.com/juribadev/yalla/internal/release
PASS
```

Health and readiness probes return stable JSON envelopes. Successful probes use
`yalla.output.v1` and include a request ID:

```json
{"schema_version":"yalla.output.v1","ok":true,"request_id":"req_example","data":{"checks":{"database":true,"migrations":true,"queue":true}}}
```

Unhealthy readiness uses the stable error envelope and must not include raw
database URLs, Dokploy tokens, cookies, request bodies, response bodies, or
rendered environment values:

```json
{"schema_version":"yalla.error.v1","ok":false,"request_id":"req_example","error":{"code":"E_SERVER","message":"service unavailable"}}
```

`/version` evidence should include release identity plus compatibility metadata:

```json
{"schema_version":"yalla.output.v1","ok":true,"request_id":"req_example","data":{"version":"v0.0.0","commit":"<redacted:git-sha>","date":"2026-05-19T00:00:00Z","api_schema_version":"yalla.api.v1","migration_version":"<redacted:migration-version>"}}
```

Structured log evidence may be summarized as key presence only. Acceptable
incident evidence says `service=yalla-api`, `service=yalla-worker`,
`request_id`, `correlation_id`, `status_class`, route or job metadata, and
stable `error_code` were present where applicable. Worker alert evidence should
name the metric section, such as `dead_letter_alerts`, without pasting job
payloads or secret-shaped metadata.

## Post-Incident Review

The post-incident review is the durable learning and accountability record.

Complete the post-incident review within two business days. Include timeline,
customer impact, stable error codes, affected request IDs, audit event IDs,
job IDs, containment actions, recovery actions, verification results, and
follow-up owners. Keep raw secrets, rendered environment values, request
bodies, and response bodies out of the review. Link to the deployment,
rollback, backup, restore rehearsal, and dashboard artifacts used during the
response.
