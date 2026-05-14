# dokploy

Wraps Dokploy as the private provisioning backend. Customer-facing code never
calls Dokploy directly — only worker/provisioner code, through the typed
client.

## Package split

- `dokploy` (this package) holds the typed Dokploy client wrapper (`Client`):
  Yalla intents (`EnsureProject`, `EnsureService`, `DeployService`,
  `ReadDeploymentLogs`, `RemoveService`, ...) mapped onto Dokploy operations.
  The Dokploy token is injected into the `Client` via `Config.Token` and is
  never exposed by any method; `Client.LogValue` redacts it.
- `dokployfake` is the deterministic, in-memory HTTP test double. It is the
  default Dokploy for **every** normal test — a live Dokploy server is an
  opt-in external smoke test only.

## Client conventions

- Every intent validates required fields **locally** (`requireFields` ->
  `apierr.InvalidInput` with stable field paths) so an obviously invalid intent
  never reaches Dokploy and never echoes the submitted value.
- "Ensure" intents are idempotent against Yalla's source-of-truth state: a
  populated `ExistingID` fetches+verifies the resource; an empty one creates it.
  The caller (worker) records the returned Dokploy ID in Postgres.
- Only idempotent methods (`GET`, `DELETE`) are retried — never `POST` — so a
  retry can never duplicate a provisioning side effect. Retries fire only on
  catalogued **retryable** errors (`apierr.Retryable`).
- Every failure maps onto the `apierr` taxonomy: transport/5xx/429 ->
  `DokployUnavailable` (retryable), timeouts -> `Timeout(DependencyDokploy, …)`,
  400 -> `Invalid`, 401/403 -> `Internal` (a Yalla misconfig, non-retryable),
  404 -> `NotFound`, 409 -> `Conflict`. The redacted upstream body is wrapped as
  the log-only cause, never placed in a client-facing `Message`.
- `RemoveService` treats a Dokploy 404 as success — teardown is idempotent.
- The `Client` carries an `output.Redactor` seeded with the token; any error
  built from upstream response data is run through it before being wrapped.
- Correlation IDs from `telemetry.FromContext` are forwarded to Dokploy as
  `X-Request-Id` / `X-Correlation-Id` headers on every request.

## dokployfake conventions

- It mimics **Dokploy's** JSON shapes, not Yalla's `yalla.output.v1` /
  `yalla.error.v1` envelopes: it stands in for the upstream provisioning API,
  not a Yalla public surface. Do not "fix" it to emit Yalla envelopes.
- IDs are deterministic per-kind counters (`org_1`, `proj_1`, ...); a fixed
  call sequence always yields the same IDs. Keep new resources deterministic.
- `QueueFault` arms a FIFO fault queue (status codes, timeout, malformed JSON);
  each request consumes one. Faults are applied before auth and routing.
- Every recorded request is scrubbed: sensitive header values become
  `output.Sentinel` and the body runs through a redactor seeded with the
  bearer token. Anything new the recorder captures must stay redaction-safe.
- The fake takes no `testing.TB`; callers `defer srv.Close()`. It depends only
  on `internal/output` + stdlib, so any package's tests can import it without
  a cycle.
