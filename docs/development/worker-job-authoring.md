# Worker job authoring - Yalla Control Plane

This document is the backend contract for adding or changing durable worker
jobs in the Yalla Control Plane. Worker jobs are the only path that mutates
private Dokploy resources after customer-facing API requests have already
completed Yalla auth, policy, quota, idempotency, audit, and desired-state
writes.

## Architecture boundary

Worker job execution lives behind the source-of-truth queue:

```text
Customer / Agent / CI -> Yalla API -> Postgres source of truth -> provisioning worker -> private Dokploy API
```

HTTP responses above the queue continue to use stable JSON envelopes:
success responses carry `schema_version yalla.output.v1`, error responses
carry `schema_version yalla.error.v1`, and every response includes
`request_id`. Jobs created from HTTP requests must persist that `request_id`
on the `provisioning_jobs` row so logs, audit events, and worker outcomes can
be correlated without printing request bodies or secrets.

Do not expose raw Dokploy operations to customer-facing endpoints. Do not call Dokploy from handlers. Do not enqueue a job before auth, policy, quota, idempotency, audit, and desired-state writes have succeeded in Yalla source of truth.

## Author a worker job

Worker implementation belongs under:

```text
internal/controlplane/worker
```

Durable source-of-truth persistence belongs under:

```text
internal/controlplane/store
```

Use this workflow for a new job type:

1. Define the intent as a typed durable payload with only scoped identifiers
   and stable schema fields. Include `organization_id` and the needed
   hierarchy IDs, such as `project_id`, `environment_id`, and `service_id`.
2. Add or reuse repository methods in `internal/controlplane/store` that write
   desired state and the `provisioning_jobs` row in one `Store.Write`
   transaction. Any mutation should also write audit metadata in that
   transaction.
3. Add a parser near the existing `Parse...Payload` functions in
   `Provisioner`. Malformed JSON, missing IDs, stale desired versions, or
   cross-tenant source-of-truth mismatches should return `Terminal` so the job
   does not retry an invalid request forever.
4. Add the dispatch branch in `Provisioner.Run` and keep business logic inside
   a focused `run...` method. The runner must reload source-of-truth rows
   tenant-scoped before any Dokploy call.
5. Resolve parent Dokploy IDs from `dokploy_refs` before creating child
   resources. Replays should read an existing ref, pass the existing upstream
   ID into the typed Dokploy intent when supported, and avoid duplicate
   mapping rows.
6. Call Dokploy only through the typed internal client from worker/provisioner
   code. Use `dokploy/dokployfake.New` through a `RunnerFunc` or fake typed
   client in normal tests.
7. Persist resulting Dokploy IDs only through tenant-scoped `dokploy_refs`
   rows. Do not store raw tokens, rendered environment variables, request
   bodies, response bodies, or upstream credentials in job payloads, logs,
   errors, or audit metadata.
8. Add unit tests for success, validation failure, authorization failure, and
   not-found behavior at the endpoint/service layer that creates the job. Add
   worker tests for malformed payloads, stale desired state, replay, dependency
   failure, and idempotent upstream not-found behavior where applicable.
9. Add integration tests against isolated Postgres migrations when the job
   touches persistence, `provisioning_jobs`, `dokploy_refs`, quota, policy, or
   audit. Tests must prove tenant isolation for every customer-owned row.
10. Update OpenAPI metadata for any public API endpoint that creates, cancels,
    retries, or reads the job.

## Queue and lease rules

The worker queue is Postgres-backed. `StoreClaimer` is the bridge between the
pure worker loop and `store.JobRepository`; it is the only worker component
that owns durable queue writes. `JobRunner` executes one claimed job.

Required queue behavior:

- Claiming goes through `store.JobRepository.ClaimNext` with
  `SELECT ... FOR UPDATE SKIP LOCKED` inside one `Store.Write` transaction.
  Do not add a second queue system or advisory-lock layer.
- Outcome writes must set `ExpectedLeaseOwner`. If an expired lease was
  reclaimed, the stale worker receives `apierr.JobNotClaimed` and the public
  error code is `E_JOB_NOT_CLAIMED`.
- If an API/operator cancellation wins before the worker records its outcome,
  the outcome path receives `apierr.JobCancelled` and the public error code is
  `E_JOB_CANCELLED`.
- A `Lease.Run` returns `nil` only after the terminal or retry outcome was
  committed. It returns a non-nil error when shutdown interrupted execution
  before commit so the loop can release the lease.
- Transient errors move to `retrying` with backoff until the retry budget is
  exhausted, then to `dead_letter`. Permanent validation or source-of-truth
  conflicts should be wrapped with `Terminal`.
- Dead-letter alerts are emitted only after the database transition to
  `dead_letter` succeeds. Logs should include stable IDs and never include the
  raw runner error summary when it may contain request or upstream detail.

## Required environment variables

This section lists the required environment variables for local worker job
verification.

Start the local Postgres dependency when running integration tests:

```bash
export YALLA_POSTGRES_PASSWORD=<redacted:postgres-password>
docker compose up -d postgres
docker compose ps postgres
```

expected output: the `postgres` service appears with `STATUS` containing
`healthy`.

Point migration-backed tests at the local admin database without printing the
rendered value:

```bash
export YALLA_TEST_DATABASE_URL=<redacted:postgres-dsn>
```

When the variable is not configured, expected output includes
`YALLA_TEST_DATABASE_URL not set; skipping Postgres integration test`.

Only opt-in external smoke tests need Dokploy-shaped runtime variables:

```bash
export YALLA_DOKPLOY_BASE_URL=https://dokploy.internal.example
export YALLA_DOKPLOY_TOKEN=<redacted:dokploy-token>
```

Normal unit and integration tests must use fake Dokploy and must never require
a live Dokploy server unless explicitly marked external. The opt-in smoke
command is:

```bash
YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...
```

This command must never run against production. Use a disposable Dokploy
instance with throwaway resources and credentials.

## Verification commands

Run focused worker checks while developing:

```bash
go test ./internal/controlplane/worker/...
go test -run TestJobWorkerLease ./...
go test -run TestFakeDokploy ./...
go test ./internal/controlplane/store/...
```

expected output: each command prints `ok` for the relevant package, or skips
Postgres integration cases with the documented
`YALLA_TEST_DATABASE_URL not set; skipping Postgres integration test` message
when the local database is not configured.

Run the commit gate before marking the story complete:

```bash
gofmt -w .
goimports -w .
go mod tidy
go test ./...
go test -race ./...
go vet ./...
scripts/verify.sh
```

If `goimports` is not installed, document that in `ralph/progress.txt` and
still run the rest of the required checks.

## Contracts and safety checklist

Every new worker job must preserve these contracts:

- Stable JSON envelopes remain `schema_version yalla.output.v1` and
  `schema_version yalla.error.v1` at HTTP boundaries.
- Unit tests cover success, validation failure, authorization failure, and not-found behavior for the API or service path that creates the job.
- Integration tests run against isolated Postgres migrations and never require a live Dokploy server unless explicitly marked external.
- Secrets, tokens, API keys, cookies, and rendered environment variable values are redacted from logs, errors, audit metadata, dry-run output, docs, and test output.
- Tenant isolation is proved before reads, writes, Dokploy calls, and
  `dokploy_refs` persistence. Cross-tenant IDs collapse to not found.
- Idempotency keys must guard customer-initiated mutations. Replays return the
  original durable job or converge through existing source-of-truth rows.
- Quota is reserved before enqueueing a provisioning mutation when the job
  creates or expands billable resources.
- Audit events are appended in the same transaction as desired-state writes
  and job creation for mutating customer or admin actions.

## Failure recovery

Use these recovery steps before changing code:

1. Clear stale test results:

   ```bash
   go clean -testcache
   ```

2. Restart the local database if integration tests cannot connect:

   ```bash
   docker compose up -d postgres
   docker compose logs postgres
   ```

3. If a test database is wedged, stop the local stack and recreate the
   Postgres volume only after confirming it is not a shared developer
   database:

   ```bash
   docker compose down
   ```

4. For `retrying` jobs, inspect the redacted job event timeline, the stable
   `request_id`, and dependency metrics. Fix transient dependency or config
   issues, then let the lease/backoff path retry.
5. For `dead_letter` jobs, preserve the source row and audit timeline. Use the
   typed retry endpoint or operator workflow so a fresh queued job records the
   retry lineage instead of editing SQL by hand.
6. For `E_JOB_NOT_CLAIMED`, inspect lease expiry and worker overlap. This is a
   stale worker protection path; do not force the stale outcome into the row.
7. For `E_JOB_CANCELLED`, confirm whether the API/operator cancellation was
   intended. A cancelled job should not be resurrected by replaying the stale
   worker outcome.

Never recover by calling private Dokploy APIs manually for a customer-facing
intent. Yalla Postgres source of truth remains authoritative, and worker jobs
converge Dokploy through typed, auditable, idempotent intents.
