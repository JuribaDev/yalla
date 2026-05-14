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
- Integration tests are `package worker_test`, use `testutil.RequireMigratedDB`,
  and `t.Skip` when `YALLA_TEST_DATABASE_URL` is unset. A concurrent-claim test
  must retry-until-drained with a deadline guard — a job locked by a peer's
  open transaction reads as empty through `SKIP LOCKED`.
