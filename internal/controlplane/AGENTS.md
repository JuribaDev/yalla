# internal/controlplane

Backend control-plane packages live here. The CLI remains under `internal/cli`;
do not mix customer API handlers into CLI packages.

- `cmd/yalla-api` and `cmd/yalla-worker` are separate binaries in the same Go
  module as the CLI so shared contracts can be reused without a second repo.
- Keep HTTP handlers thin. Put business logic in focused packages such as
  `auth`, `policy`, `quota`, `jobs`, `dokploy`, `store`, `audit`, and
  `telemetry`.
- Public API responses must use stable envelopes:
  `yalla.output.v1` for success and `yalla.error.v1` for errors.
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
