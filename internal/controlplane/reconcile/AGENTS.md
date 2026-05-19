# reconcile — drift detection and repair engine

`internal/controlplane/reconcile` is the pure reconciliation engine that
compares Yalla's source-of-truth hierarchy against Dokploy's actual state and
produces a deterministic Plan of actions classified as `DriftSafe`,
`DriftDangerous`, or `DriftUnmanaged`.

## Conventions

- **Pure planner**. `Diff(desired, actual) Plan` is a pure function over
  in-memory data. The package has no Postgres, Dokploy, or HTTP dependency;
  every external resource is reached through a port interface
  (`DesiredStateReader`, `ActualStateReader`, `Repairer`, `ReviewRecorder`,
  `UnmanagedRecorder`). Adapters land in the store/worker/dokploy layers and
  never reach back into this package.
- **Value-free classification**. `Reason`, `DriftKind`, and every other
  classification field carries only stable codes. An env var's *value* never
  reaches a Reason, log attribute, audit metadata, or review event. The value
  travels through `Action.DesiredValue` to the Repairer and nowhere else. Add
  a "never leaks the value" test for any new classification rule that touches
  a sensitive field.
- **Safe vs dangerous classification.** Auto-repair is reserved for changes
  that are reversible and cannot cause data loss: env var ensures/updates,
  rebinding a missing managed domain, removing an extra env var the desired
  state doesn't claim. Anything that could destroy data, mask compromise, or
  resurrect a customer-removed resource is `DriftDangerous` and goes through
  the `ReviewRecorder` for human triage — missing managed services, missing
  managed databases, host renames, and service-type changes all live here.
  Once desired and actual service types differ, stop after the dangerous
  `review_service_type_change` action; do not also emit build, env-var, or
  domain safe repairs against an upstream resource whose shape is no longer
  trusted.
- **Database engine drift is subtype drift.** For `dokploy.ServiceDatabase`,
  the `Engine` value is the database subtype boundary. If desired and actual
  engines differ after normalization, emit one dangerous
  `ActionReviewServiceTypeChange` / `ReasonServiceTypeChanged` action and
  stop before env/domain safe repairs.
- **Runtime role drift is subtype drift.** For application and compose
  services, a non-empty desired `Role` (`web`, `worker`, `cron`) is the
  runtime subtype boundary. If actual reports a different role after
  normalization, emit one dangerous `ActionReviewServiceRoleChange` /
  `ReasonServiceRoleChanged` action and stop before build/env/domain safe
  repairs. Desired domains are web-only; for non-web desired roles, ignore
  desired domains so a bad adapter cannot auto-bind inbound HTTP to a worker
  or cron process.
- **Cron schedule drift is safe only after role matches.** For desired
  `RoleCron` services, compare trimmed cron schedules after service type and
  role subtype checks. A mismatch emits `ActionUpdateCronSchedule` /
  `ReasonCronScheduleChanged`; the schedule value travels only through
  `Action.DesiredCronSchedule` to the Repairer and never through
  classification fields, review events, logs, or unmanaged records.
- **Unmanaged means quarantine, never delete.** A Dokploy resource without a
  Yalla counterpart is recorded via `UnmanagedRecorder` only. The engine
  never auto-deletes unmanaged resources and adapters never expose them on a
  customer-facing endpoint by default.
- **Deterministic order.** `Diff` sorts the returned `Plan.Actions` by
  (Dokploy service ID, drift kind, reason, secondary key). Tests can compare
  plans directly without set semantics; reviewers see a stable triage order.
- **Best-effort Apply.** `Reconciler.Apply` continues past per-action
  failures; each failure is collected in `Result.Failures` with its error
  string scrubbed through the configured `output.Redactor` so a Dokploy
  Authorization header or token query parameter that bleeds into an upstream
  error message stays redacted.
- **Validation surface.** The only request input the engine validates is the
  organization id passed to `Plan` / `Reconcile` — `domain.ParseID` plus a
  kind check, returning a typed `apierr.InvalidInput`. Anything else is the
  adapter's contract; an adapter that returns a typed `apierr.*` keeps the
  code; an untyped error is upgraded to `apierr.StoreUnavailable` (desired
  reader) or `apierr.DokployUnavailable` (actual reader).
- **No process-level I/O.** Concrete adapters (store-backed desired reader,
  Dokploy-backed actual reader, worker-backed repairer, store-backed review
  and unmanaged recorders) land in their own packages once the
  service/application/domain persistence schema ships. The reconcile
  package's stable surface — `Plan`, `Action`, `ReviewEvent`,
  `UnmanagedResource`, `DriftKind`, `DriftReason`, `ActionType` — is the
  contract those adapters sit behind.
