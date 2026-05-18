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
- Teardown jobs such as `service.delete`/`delete_service` should reuse the
  same scoped payload and service-kind-specific `dokploy_refs` resolution, but
  should not reject `deletion_scheduled_at` because scheduled deletion is the
  expected lifecycle path. Call the typed Dokploy `RemoveService` intent; it is
  already idempotent for upstream 404s, so do not add raw Dokploy DELETE calls
  or handler-side Dokploy access.
- Environment teardown jobs (`environment.delete`/`delete_environment`) use the
  scoped payload `(organization_id, project_id, environment_id)`, reload the
  environment through `EnvironmentRepository.GetByID`, verify job/payload scope
  and `DesiredVersion`, resolve the `environment` `dokploy_refs` row, and call
  the typed Dokploy `RemoveEnvironment` intent. A job already marked
  `succeeded` is a replay no-op, and an upstream 404 is idempotent success in
  the typed client.
- Preview create jobs (`create_preview_environment`) use the scoped payload
  `(organization_id, project_id, environment_id, preview_id)`, reload the
  project-scoped `preview_environments` row plus the wrapped
  `environments.kind='preview'` clone, verify payload scope and the preview row
  `DesiredVersion`, reject deletion-scheduled previews before any Dokploy call,
  resolve the parent project mapping, and persist one `environment`
  `dokploy_refs` row for the wrapped clone. A job already marked `succeeded` is
  a no-op replay; a replay after a crash should fetch the existing Dokploy
  environment through `EnsureEnvironment` and leave the mapping table unchanged.
- Preview teardown jobs (`delete_preview_environment`) use the scoped payload
  `(organization_id, project_id, environment_id, preview_id)`, reload the
  project-scoped `preview_environments` row plus the wrapped
  `environments.kind='preview'` clone, verify payload scope and the preview row
  `DesiredVersion`, resolve the clone's `environment` `dokploy_refs` row, call
  the typed Dokploy `RemoveEnvironment` intent when a mapping exists, then
  delete the mapping and hard-delete the preview wrapper in the same
  transaction. A job already marked `succeeded` is a no-op replay, and a replay
  after cleanup should treat a missing preview wrapper as success without
  issuing another Dokploy call.
- Project teardown jobs (`project.delete`/`delete_project`) use the scoped
  payload `(organization_id, project_id)`, reload the project through
  `ProjectRepository.Get`, verify job/payload scope and `DesiredVersion`,
  resolve the `project` `dokploy_refs` row, and call the typed Dokploy
  `RemoveProject` intent. A job already marked `succeeded` is a replay no-op,
  and an upstream 404 is idempotent success in the typed client.
- Domain sync jobs (`sync_domains`) use the scoped payload
  `(organization_id, project_id, environment_id, service_id)`, reload the
  service through `ServiceRepository.GetByID`, verify payload scope and
  `DesiredVersion`, resolve the service-kind-specific Dokploy service ref,
  list desired `service_domains`, then create or verify one `domain`
  `dokploy_refs` row per `service_domain` row using
  `YallaKindServiceDomain`. Replays should call `EnsureDomain` with
  `ExistingID` and must not insert duplicate mapping rows.
- Variable sync jobs (`sync_variables`) use the scoped payload
  `(organization_id, project_id, environment_id, service_id[, engine])`, reload
  the service through `ServiceRepository.GetByID`, verify payload scope and
  `DesiredVersion`, resolve the service-kind-specific Dokploy service ref, fetch
  organization/project/environment/service variables in one read transaction,
  merge through `variables.Resolver` with the configured secrets provider, and
  call the typed Dokploy `SyncVariables` intent. Fake Dokploy request recording
  must redact the rendered `env` field because it contains plaintext effective
  values.
- Service reconciliation jobs (`reconcile_service`) use the same scoped payload
  as `sync_variables`, but converge the full service surface in one durable
  pass: reload the service, reject stale/deletion-scheduled state, resolve the
  parent environment ref, call typed Dokploy `EnsureService`, persist the
  service ref idempotently, sync effective variables, then ensure each desired
  service domain with per-domain `dokploy_refs`. Persist the service ref before
  variable/domain calls so retries after a partial upstream success fetch the
  existing service instead of creating a duplicate.
- Backup run jobs (`run_backup`) use the scoped payload
  `(organization_id, project_id, environment_id, service_id, backup_id)`, reload
  both the service and `service_backups` row through tenant-scoped repositories,
  reject stale backup versions plus disabled/running/deletion-scheduled state
  before any Dokploy call, resolve the service-kind-specific Dokploy service
  ref, mark the backup `running`, call the typed Dokploy `RunBackup` intent,
  then project the row to `succeeded` or `failed`. A succeeded backup row is a
  replay no-op and must not issue another upstream POST.
- Backup restore jobs (`restore_backup`) use the same scoped payload and
  tenant-scoped service/backup reload shape, but require the selected
  `service_backups` row to be enabled and already `succeeded` before any
  Dokploy call. Resolve the service-kind-specific Dokploy service ref and call
  the typed Dokploy `RestoreBackup` intent; replay of a job row already marked
  `succeeded` must be a no-op.
- Integration tests are `package worker_test`, use `testutil.RequireMigratedDB`,
  and `t.Skip` when `YALLA_TEST_DATABASE_URL` is unset. A concurrent-claim test
  must retry-until-drained with a deadline guard — a job locked by a peer's
  open transaction reads as empty through `SKIP LOCKED`.
