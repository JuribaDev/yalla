# Yalla Control Plane Production Config Reference

This document is the operator-facing reference for every environment variable
consumed by the production backend binaries that serve Customer / Agent / CI
traffic through the Yalla Control Plane API. Postgres source of truth owns all
tenant data; the Provisioning worker talks to Dokploy, which is the private
provisioning engine:

- `/usr/local/bin/yalla-api`
- `/usr/local/bin/yalla-worker`

Configuration is resolved once at process startup from environment variables
layered over per-profile defaults. The precedence chain is environment variable
> profile default. Environment variables are the production default for backend
processes.

The checked-in example at `deploy/config/control-plane.env.example` is the
canonical starting point. Operators install it as `/etc/yalla/control-plane.env`
with owner `root:yalla` and mode `0640`, then replace every `<redacted:...>`
placeholder from their secret manager.

## Profiles

`YALLA_PROFILE` selects the deployment environment:

| Profile | Strict | Typical use |
| --- | --- | --- |
| `local` | No | Developer machine |
| `test` | No | Unit and integration tests |
| `staging` | Yes | Pre-production validation |
| `production` | Yes | Live traffic |

Strict profiles (`staging`, `production`) fail fast when an operational field
is missing. Local and test profiles supply permissive defaults so the backend
starts without real credentials.

## Required environment variables

### `YALLA_PROFILE`
- **Default:** `local`
- **Allowed values:** `local`, `test`, `staging`, `production`
- **Description:** Selects the configuration profile. An unrecognised value
  causes the process to exit immediately with a stable `E_CONFIG` error.

### `YALLA_API_ADDR`
- **Default:** `:8080` (local/staging/production), `127.0.0.1:0` (test)
- **Format:** `host:port`
- **Description:** The address the HTTP API listens on. The API binary does not
  terminate TLS itself; TLS is terminated at the operator's reverse proxy.

### `YALLA_PUBLIC_URL`
- **Default:** `http://localhost:8080` (local), `http://127.0.0.1` (test)
- **Required for:** `staging`, `production`
- **Format:** Absolute `http` or `https` URL with a host
- **Description:** The externally reachable base URL of the API. Used to build
  absolute links in responses and notifications.

### `YALLA_DATABASE_URL`
- **Required for:** `staging`, `production`
- **Format:** DSN using the `postgres` or `postgresql` URL scheme
- **Description:** The PostgreSQL DSN for the source-of-truth database. Use a
  least-privilege role for the deployed API and worker processes.
- **Security:** Treated as a secret. Never logged, never rendered in errors,
  never exposed to customer-facing endpoints. Example placeholder:
  `YALLA_DATABASE_URL=<redacted:postgres-dsn>`

### `YALLA_SIGNING_KEYS`
- **Required for:** `staging`, `production`
- **Format:** Comma-separated list of signing keys. The first entry is the
  active key; the rest are accepted during rotation.
- **Validation:** Each key must be at least 16 characters long.
- **Security:** Treated as a secret. Never logged.

### `YALLA_SECRET_KEYS`
- **Required for:** `staging`, `production`
- **Format:** Comma-separated list of hex-encoded 32-byte AES-256 master keys.
  Each entry must be exactly 64 hex characters.
- **Description:** Consumed by `internal/controlplane/secrets.AESGCM` to seal
  organization variable values at rest. The first entry is the active key; the
  rest are accepted during rotation.
- **Security:** Treated as a secret. Never logged.

### `YALLA_DOKPLOY_BASE_URL`
- **Required for:** `staging`, `production`
- **Format:** Absolute `http` or `https` URL with a host
- **Description:** The base URL of the private Dokploy API. Customers must never
  receive this URL directly and must never call Dokploy directly. Example
  placeholder: `YALLA_DOKPLOY_BASE_URL=<redacted:YALLA_DOKPLOY_BASE_URL>`

### `YALLA_DOKPLOY_TOKEN`
- **Required for:** `staging`, `production`
- **Description:** The privileged Dokploy service token used by the worker for
  provisioning.
- **Security:** Treated as a secret. Never logged and never exposed to
  customer-facing endpoints. Example placeholder:
  `YALLA_DOKPLOY_TOKEN=<redacted:YALLA_DOKPLOY_TOKEN>`

### `YALLA_INTERNAL_WORKER_TOKEN`
- **Required for:** `staging`, `production`
- **Validation:** At least 32 characters.
- **Description:** Shared secret accepted by `yalla-api` for private internal
  worker callbacks. Configure the same value for `yalla-api` and
  `yalla-worker`.
- **Security:** Treated as a secret. Never logged and never exposed to
  customer-facing endpoints. Example placeholder:
  `YALLA_INTERNAL_WORKER_TOKEN=<redacted:YALLA_INTERNAL_WORKER_TOKEN>`

## Optional environment variables

### `YALLA_SHUTDOWN_TIMEOUT`
- **Default:** `15s` (local), `2s` (test), `25s` (staging/production)
- **Format:** Go duration string (e.g. `15s`, `1m`)
- **Range:** Between `1s` and `5m`
- **Description:** Bounds how long a backend process waits to drain in-flight
  HTTP requests and release in-flight job leases during graceful shutdown.

### `YALLA_BACKUP_STATUS_FILE`
- **Default:** Empty (probe reports "unconfigured")
- **Format:** Absolute filesystem path
- **Description:** The file the operator's backup pipeline writes its
  last-success RFC3339 timestamp to. When set, the unauthenticated
  `GET /healthz/backup` probe reports the timestamp. The file content is never
  logged.

### `YALLA_BACKUP_MAX_AGE`
- **Default:** Empty (freshness predicate disabled)
- **Format:** Go duration string (e.g. `26h`)
- **Description:** The freshness threshold the `GET /healthz/backup` probe
  reports as `max_age_seconds`. A backup older than this is rendered as
  `fresh=false`. Zero or unset disables the freshness predicate.

### `YALLA_LOG_LEVEL`
- **Default:** `debug` (local), `warn` (test), `info` (staging/production)
- **Allowed values:** `debug`, `info`, `warn`, `error`
- **Description:** Sets the structured log level. Both binaries write structured
  JSON diagnostics only.

### `YALLA_FEATURE_FLAGS`
- **Default:** Empty
- **Format:** Comma-separated list of feature flags. Each entry is either
  `name` (enabled) or `name=true` / `name=false`.
- **Description:** Runtime feature toggles. Unknown flags are reported as
  disabled.

## Rate-limit variables

The inbound HTTP rate limiter is enabled by default in `local`, `staging`, and
`production`. The `test` profile disables it so contract tests never
accidentally trip it.

### `YALLA_RATE_LIMIT_DISABLED`
- **Default:** `false`
- **Allowed values:** `1`, `true`, `yes`, `on`, `0`, `false`, `no`, `off`
- **Description:** Master switch that turns the limiter off for every
  dimension. Exists for staging soak tests and local development.

### `YALLA_RATE_LIMIT_ORG_READ_RPS` / `YALLA_RATE_LIMIT_ORG_READ_BURST`
- **Default:** `50` / `100` (local), `100` / `200` (staging/production)
- **Description:** Per-organization read bucket.

### `YALLA_RATE_LIMIT_ORG_WRITE_RPS` / `YALLA_RATE_LIMIT_ORG_WRITE_BURST`
- **Default:** `20` / `40` (local), `30` / `60` (staging/production)
- **Description:** Per-organization write bucket (POST/PUT/PATCH/DELETE).

### `YALLA_RATE_LIMIT_KEY_READ_RPS` / `YALLA_RATE_LIMIT_KEY_READ_BURST`
- **Default:** `25` / `50` (local), `50` / `100` (staging/production)
- **Description:** Per-API-key (or per-session-principal) read bucket.

### `YALLA_RATE_LIMIT_KEY_WRITE_RPS` / `YALLA_RATE_LIMIT_KEY_WRITE_BURST`
- **Default:** `10` / `20` (local), `15` / `30` (staging/production)
- **Description:** Per-API-key write bucket.

### `YALLA_RATE_LIMIT_IP_READ_RPS` / `YALLA_RATE_LIMIT_IP_READ_BURST`
- **Default:** `50` / `100` (local), `60` / `120` (staging/production)
- **Description:** Per-client-IP read bucket. The IP bucket is the only one a
  public (unauthenticated) endpoint can fall back to.

### `YALLA_RATE_LIMIT_IP_WRITE_RPS` / `YALLA_RATE_LIMIT_IP_WRITE_BURST`
- **Default:** `20` / `40` (local), `20` / `40` (staging/production)
- **Description:** Per-client-IP write bucket.

### `YALLA_RATE_LIMIT_IDLE_TTL`
- **Default:** `5m`
- **Format:** Go duration string
- **Range:** Between `10s` and `1h`
- **Description:** How long an unused bucket is retained before lazy eviction.

## Validation and failure recovery

If a required variable is missing or malformed, the binary exits immediately
with a typed `E_CONFIG` error and a deterministic message that names the field
without echoing its value. Examples:

```
profile "production" requires YALLA_DATABASE_URL, YALLA_DOKPLOY_BASE_URL, YALLA_DOKPLOY_TOKEN, YALLA_INTERNAL_WORKER_TOKEN, YALLA_PUBLIC_URL, YALLA_SECRET_KEYS, YALLA_SIGNING_KEYS
invalid YALLA_API_ADDR "bad-address": missing port in address
invalid YALLA_SHUTDOWN_TIMEOUT 500ms is out of range (want between 1s and 5m)
```

Recovery steps:
1. Verify `/etc/yalla/control-plane.env` exists and is readable by the `yalla`
   service account.
2. Check that every secret-shaped variable uses a `<redacted:...>` placeholder
   in the checked-in example and a real value in the rendered file.
3. Confirm `YALLA_PROFILE` is one of the four recognised profiles.
4. Restart the service and inspect `journalctl -u yalla-api -u yalla-worker -o json`.

## Health and readiness

`yalla-api` exposes:
- `GET /healthz` — process liveness
- `GET /readyz` — dependency readiness (Postgres migrations and checks)

Both render stable `yalla.output.v1` or `yalla.error.v1` envelopes. Every
response carries a `request_id`.

`yalla-worker` has no HTTP listener; observe it through process liveness,
durable job state, worker metrics, dead-letter alerts, and structured JSON logs.

## Redaction rules

Logs, errors, audit metadata, and dry-run output must redact tokens, cookies, API keys, database URLs, Dokploy tokens, internal worker tokens, signing keys, secret-encryption keys, rendered environment variable values, request bodies, and response bodies. The rule is explicit: tokens, cookies, API keys, database URLs, Dokploy tokens, and internal worker tokens must never appear in any diagnostic output. Signing keys, secret-encryption keys, and Rendered environment variable values are equally restricted.

The `Config` type implements `slog.LogValuer` and `fmt.Stringer` with redacted
views so an accidental structured-log or `%v` print never leaks a credential.

## Verification commands

Static verification does not require production secrets:

```bash
gofmt -w .
goimports -w .
go mod tidy
go test ./...
go test -race ./...
go vet ./...
go test ./internal/controlplane/...
go test -race ./internal/controlplane/...
go test -run TestMigrations ./...
go test -run TestPolicyMatrix ./...
go test -run TestQuotaConcurrency ./...
go test -run TestFakeDokploy ./...
go test ./internal/release/... -run TestProductionConfigReferenceArtifact
scripts/verify.sh
```

Expected outputs:
- `PASS`
- `ok  `
- `no changes`
- `HTTP/1.1 200 OK`
- `"schema_version":"yalla.output.v1"`
- `"schema_version":"yalla.error.v1"`

## Opt-in external Dokploy smoke test

Normal verification gates must never require a live Dokploy server.
An optional external smoke test exists for operators who have set:

```
YALLA_EXTERNAL_DOKPLOY=1
YALLA_EXTERNAL_DOKPLOY_BASE_URL=<redacted:YALLA_EXTERNAL_DOKPLOY_BASE_URL>
YALLA_EXTERNAL_DOKPLOY_TOKEN=<redacted:YALLA_EXTERNAL_DOKPLOY_TOKEN>
```

Run it with:

```bash
YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...
```

This test must never run against production.
