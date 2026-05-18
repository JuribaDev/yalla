# worker

Background provisioning/metering workers for the control plane.

## Package split

- `loop.go` stays **pure**: the run loop depends only on the `Claimer` and
  `Lease` interfaces, so it is testable with fakes and never imports `store`.
  Do not add a `store` import to `loop.go`.
- `queue.go` is the **Postgres-backed** implementation of those interfaces
  (`StoreClaimer`, `storeLease`). It is the only worker file that imports
  `store`. New durable-queue behaviour belongs here.

## Conventions

- Claiming goes through `store.JobRepository.ClaimNext` — `SELECT ... FOR UPDATE
  SKIP LOCKED` inside one `Store.Write`. That row lock is the entire
  concurrency story; never add a separate queue library or advisory-lock layer.
- A `Lease.Run` returns `nil` once an outcome (succeeded / retrying / failed /
  dead_letter) is **committed** — the loop must not release it. It returns
  non-nil **only** when shutdown interrupted the job before it finished, so the
  loop releases the lease for another worker.
- Recording an outcome (`StoreClaimer.complete`) runs on a context detached
  from cancellation (`context.WithoutCancel` + timeout): once the runner ran,
  the result must reach the database even mid-shutdown.
- Failure classification: `Terminal(err)` marks a permanent failure (→ failed,
  never retried); a plain error is transient (→ retrying with `Backoff`, or →
  dead_letter once `Attempts >= MaxAttempts`).
- The real provisioning runner (typed Dokploy client) is injected via
  `JobRunner`; normal tests use a `RunnerFunc` fake, never a live Dokploy.
  When a worker test needs Dokploy to actually answer (provisioning chains,
  fault/retry paths), point the `RunnerFunc` at
  `dokploy/dokployfake.New()` — the deterministic in-memory Dokploy double —
  and assert on `Server.Requests()`; it records every call with credentials
  already redacted.
- Typed provisioning jobs live behind `Provisioner` and should follow the
  `ensure_dokploy_organization` pattern: validate `provisioning_jobs.payload`
  into a small typed schema first, return `worker.Terminal` for malformed,
  stale, or cross-tenant desired state, load source-of-truth rows from
  Postgres before calling Dokploy, and persist resulting Dokploy IDs only
  through tenant-scoped `dokploy_refs` rows. Replays should read an existing
  ref and verify the upstream resource instead of inserting a second mapping.
- Child ensure jobs (for example `ensure_project`) must resolve their parent
  Dokploy ID from `dokploy_refs` before mapping the child intent. A missing
  parent mapping is a terminal source-of-truth conflict for that job; a replay
  with the child ref already present should call Dokploy with `ExistingID` and
  leave the mapping table unchanged.
- Service-kind ensure jobs must verify the source-of-truth `services.kind`
  matches the job type before calling Dokploy, then persist the matching
  `dokploy_refs.dokploy_resource` (`application`, `compose`, or `database`).
  `ensure_application_service` is the reference implementation for the
  application path.
- `ensure_database_service` additionally validates a closed-set `engine` in
  the durable job payload (`postgres`, `mysql`, `mariadb`, `mongo`, `redis`).
  The current `services` row stores only the broad `database` kind, so the
  worker loads and verifies the service row for tenant/kind/version while using
  the persisted job payload as the concrete database-engine intent.
- Runtime-control jobs such as `service.restart`/`restart_service`,
  `service.stop`/`stop_service`, and `service.start`/`start_service` should
  parse the same scoped payload `(organization_id, project_id, environment_id,
  service_id)`, reload the
  service through the tenant-scoped repository, reject stale desired versions
  and deletion-scheduled services before any Dokploy call, resolve the
  service-kind-specific `dokploy_refs` row, then call the matching typed
  Dokploy intent. A job already marked `succeeded` is a replay no-op and must
  not issue another upstream POST.
- Integration tests are `package worker_test`, use `testutil.RequireMigratedDB`,
  and `t.Skip` when `YALLA_TEST_DATABASE_URL` is unset. A concurrent-claim test
  must retry-until-drained with a deadline guard — a job locked by a peer's
  open transaction reads as empty through `SKIP LOCKED`.
