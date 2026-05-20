# Environment Variable Reference — Yalla Control Plane Backend

This document is the developer-facing reference for every environment variable
consumed by the Yalla Control Plane backend binaries. It covers the config
resolution contract, per-profile defaults, and local-development recipes.

The backend binaries are:

- `cmd/yalla-api` — the HTTP API server
- `cmd/yalla-worker` — the provisioning worker

Configuration is resolved once at process startup from environment variables
layered over per-profile defaults. The precedence chain is:

```text
environment variable > profile default
```

Environment variables are the production default for backend processes; CLI flags
belong to the customer-facing CLI, not these long-running services.

Keep real secrets, customer identifiers, live Dokploy credentials, database URLs,
API keys, cookies, and rendered environment values out of this file.

## Architecture boundary

Backend configuration must preserve the production boundary:

```text
Customer / Agent / CI
  -> Yalla Control Plane API
  -> Postgres source of truth
  -> Provisioning worker
  -> private Dokploy API
```

Customers must never receive Dokploy API tokens. Secrets — the Postgres DSN,
signing keys, secret-encryption keys, the Dokploy service token, and the
internal worker token — must never reach logs, errors, audit metadata, or test
output.

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
- **Description:** The address the HTTP API listens on.

### `YALLA_PUBLIC_URL`
- **Default:** `http://localhost:8080` (local), `http://127.0.0.1` (test)
- **Required for:** `staging`, `production`
- **Format:** Absolute `http` or `https` URL with a host
- **Description:** The externally reachable base URL of the API. Used to build
absolute links in responses and notifications.

### `YALLA_DATABASE_URL`
- **Required for:** `staging`, `production`
- **Format:** DSN using the `postgres` or `postgresql` URL scheme
- **Description:** The PostgreSQL DSN for the source-of-truth database.
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
worker callbacks. Configure the same value for `yalla-api` and `yalla-worker`.
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
`production`. Local uses the in-process backend by default; staging and
production use Redis so every API replica shares the same bucket state. The
`test` profile disables it so contract tests never accidentally trip it.

### `YALLA_RATE_LIMIT_DISABLED`
- **Default:** `false`
- **Allowed values:** `1`, `true`, `yes`, `on`, `0`, `false`, `no`, `off`
- **Description:** Master switch that turns the limiter off for every
dimension. Exists for staging soak tests and local development.

### `YALLA_RATE_LIMIT_BACKEND`
- **Default:** `memory` (local/test), `redis` (staging/production)
- **Allowed values:** `memory`, `redis`
- **Description:** Selects where bucket state is stored. Use Redis for any
multi-replica API deployment.

### `YALLA_RATE_LIMIT_REDIS_URL`
- **Default:** Empty
- **Format:** `redis://` or `rediss://` URL
- **Description:** Redis DSN for the distributed limiter. Required when the
limiter is enabled and `YALLA_RATE_LIMIT_BACKEND=redis`. The value may contain
credentials and is redacted from logs.

### `YALLA_RATE_LIMIT_REDIS_KEY_PREFIX`
- **Default:** `yalla:ratelimit`
- **Description:** Prefix applied to every Redis limiter key. Use a distinct
prefix per environment or cluster.

### `YALLA_RATE_LIMIT_REDIS_TIMEOUT`
- **Default:** `250ms`
- **Format:** Go duration string
- **Range:** Between `1ms` and `5s`
- **Description:** Dial/read/write timeout applied to Redis limiter calls.

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

```text
profile "production" requires YALLA_DATABASE_URL, YALLA_DOKPLOY_BASE_URL, YALLA_DOKPLOY_TOKEN, YALLA_INTERNAL_WORKER_TOKEN, YALLA_PUBLIC_URL, YALLA_SECRET_KEYS, YALLA_SIGNING_KEYS
invalid YALLA_API_ADDR "bad-address": missing port in address
invalid YALLA_SHUTDOWN_TIMEOUT 500ms is out of range (want between 1s and 5m)
```

Recovery steps:
1. Verify the environment file exists and is readable by the process.
2. Check that every secret-shaped variable uses a `<redacted:...>` placeholder
in checked-in examples and a real value in the rendered runtime file.
3. Confirm `YALLA_PROFILE` is one of the four recognised profiles.
4. Restart the process and inspect structured JSON logs.

## Local development quick start

Set the minimum variables for local development:

```bash
export YALLA_PROFILE=local
export YALLA_DATABASE_URL=<redacted:postgres-dsn>
export YALLA_SIGNING_KEYS=<redacted:signing-keys>
export YALLA_SECRET_KEYS=<redacted:secret-keys>
export YALLA_DOKPLOY_BASE_URL=https://dokploy.internal.example
export YALLA_DOKPLOY_TOKEN=<redacted:dokploy-token>
export YALLA_INTERNAL_WORKER_TOKEN=<redacted:internal-worker-token>
```

Run the API:

```bash
go run ./cmd/yalla-api
```

Run the worker:

```bash
go run ./cmd/yalla-worker
```

Probe health:

```bash
curl -fsS http://localhost:8080/healthz
curl -fsS http://localhost:8080/readyz
curl -fsS http://localhost:8080/version
```

expected output: successful probes return stable JSON envelopes with
`schema_version: yalla.output.v1` and a `request_id`; failed probes use
`schema_version: yalla.error.v1`. `/readyz` reports dependency gates such as
`database`, `migrations`, `queue`, and `Dokploy` when configured.

## Verification commands

Documentation artifacts are pinned by focused release tests. This document is
covered by:

```bash
go test ./internal/release/... -run TestEnvironmentVariableReferenceArtifact
```

Before committing backend changes, run the full verification gate:

```bash
gofmt -w .
goimports -w .
go mod tidy
go test ./...
go test ./internal/controlplane/...
go test -race ./...
go test -race ./internal/controlplane/...
go test -run TestMigrations ./...
go test -run TestPolicyMatrix ./...
go test -run TestQuotaConcurrency ./...
go test -run TestFakeDokploy ./...
go vet ./...
scripts/verify.sh
```

Normal verification gates must never require a live Dokploy server. The opt-in
external Dokploy smoke test is:

```bash
YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...
```

This must never run against production.

## Redaction contract

The backend must redact tokens, cookies, API keys, database URLs, Dokploy tokens, internal worker tokens, signing keys, secret-encryption keys, and rendered environment variable values in logs, errors, audit metadata, and test output. Signing keys, secret-encryption keys, and Rendered environment variable values must never reach stdout. Secret-shaped values that are configured collapse to a presence indicator; unset values stay empty.
