# internal/controlplane

Backend control-plane packages live here. The CLI remains under `internal/cli`;
do not mix customer API handlers into CLI packages.

- `cmd/yalla-api` and `cmd/yalla-worker` are separate binaries in the same Go
  module as the CLI so shared contracts can be reused without a second repo.
- Keep HTTP handlers thin. Put business logic in focused packages such as
  `auth`, `policy`, `quota`, `jobs`, `dokploy`, `store`, `audit`, and
  `telemetry`.
- Public API responses must use stable envelopes:
  `yalla.output.v1` for success and `yalla.error.v1` for errors. Render every
  response — success and error — through `apienvelope.WriteData` /
  `apienvelope.WriteError`. Handlers must never marshal JSON directly; the
  envelope structs are unexported so this boundary is enforced by the compiler.
  HTTP status follows the error `Code` via `apienvelope.StatusForCode`; only
  use `WriteErrorStatus` when a status genuinely cannot be derived from the
  code (e.g. `/readyz` returning 503).
- Construct backend errors through `apierr`, never `yerr.New` directly in
  handlers/services. `apierr` is the catalogued taxonomy: `Unauthenticated`,
  `Forbidden`, `InvalidInput`/`Invalid`, `NotFound`, `Conflict`,
  `QuotaExceeded`, the dependency constructors (`DokployUnavailable`,
  `StoreUnavailable`, `QueueUnavailable`, `NetworkFailure`, `Timeout`), and
  `Internal`. Adding a new error code means adding it to `apierr`'s `taxonomy`
  map and, if it needs a non-500 status, a case in `apienvelope.StatusForCode`
  (the single source of truth `apierr.Lookup` reads). `MessageGeneric` codes
  must keep the cause out of `Message`/`Hint` — wrap it so logs can still see
  it. `InvalidInput` carries `FieldViolation`s (field path + reason, never the
  submitted value); recover them with `apierr.ViolationsOf`. Dependency
  failures are recoverable with `apierr.DependencyOf` even when they share a
  code (store and queue both use `E_UNAVAILABLE`).
- Every customer-data path must eventually resolve organization scope before
  reading or mutating data. Cross-tenant IDs must not leak resource existence.
- Dokploy is a private provisioning backend. Customer-facing code should call
  typed control-plane services, not raw Dokploy operations.
- Normal tests should use fake dependencies. Live Dokploy tests must be
  opt-in and clearly named as external smoke tests.
- Process lifecycle lives in `runtime`: use `runtime.RunHTTPServer` for the
  API and `worker.Loop` for background jobs. Binaries derive shutdown from a
  single `signal.NotifyContext` and pass `cfg.ShutdownTimeout`; do not
  hand-roll `select`/`Shutdown` blocks in `main`.
- `/readyz` is gated by `runtime.Readiness` and must report 503 (`E_SERVER`)
  until every startup gate passes. `/healthz` is liveness-only — it never
  depends on downstream checks.
- New background workers depend on the `worker.Claimer`/`worker.Lease`
  interfaces, never on a concrete job store directly, so they stay testable
  with fakes before the durable Postgres queue exists.
- Request correlation lives in `telemetry`. `telemetry.Correlate` is the
  outermost HTTP middleware (`httpapi.NewHandler` wraps the whole mux in it):
  it resolves a `request_id` (per request) and `correlation_id` (per workflow)
  onto the request context before any handler runs. Inbound `X-Request-Id` /
  `X-Correlation-Id` headers are honoured only when they pass
  `telemetry.SafeID` (`[A-Za-z0-9._-]`, 1..128 chars) — unsafe values are
  discarded and a fresh `telemetry.NewRequestID()` is generated, so a
  header-injection payload can never reach logs, response headers, or job
  rows. Read the IDs anywhere via `telemetry.RequestID(ctx)` /
  `telemetry.CorrelationID(ctx)` / `telemetry.FromContext(ctx)`; never thread
  them through signatures. New non-HTTP entry points (worker jobs) should seed
  their own context with `telemetry.WithCorrelation`.
