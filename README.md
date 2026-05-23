# yalla

`yalla` is a production-grade, agent-first CLI for the Yalla Control Plane.
It talks to the Yalla backend API with bearer credentials. The backend and
worker own Dokploy infrastructure access; normal CLI users never send Dokploy
URLs or Dokploy tokens.

## Highlights

- **Native binary, no Go required** — distributed as static binaries for macOS,
  Linux, and Windows (`amd64` and `arm64`).
- **Agent contract** — `--json`, `--no-input`, stable exit codes, machine
  readable error envelopes, deterministic stdout/stderr separation.
- **Backend contract discovery** — `yalla api operations` and `yalla schema`
  read the backend `/openapi.json` contract shared by the frontend, CLI, and
  CI agents.

## Install

| Channel  | Command                                                      |
|----------|--------------------------------------------------------------|
| Homebrew | `brew install JuribaDev/yalla/yalla`                         |
| Scoop    | `scoop bucket add yalla https://github.com/JuribaDev/scoop-yalla && scoop install yalla` |
| WinGet   | `winget install --id JuribaDev.yalla`                        |
| npm      | `npm install -g @juriba/yalla-cli`                           |
| npx      | `npx @juriba/yalla-cli --version`                            |
| Manual   | Download from [Releases](https://github.com/JuribaDev/yalla/releases) |
| Go       | `go install github.com/JuribaDev/yalla/cmd/yalla@latest` (contributor fallback) |

## Run the project

Prerequisites for local development:

- Go matching `go.mod`
- Docker with the Compose plugin
- A shell that can export environment variables

Run the CLI from source:

```sh
go run ./cmd/yalla --help
go run ./cmd/yalla --version
go run ./cmd/yalla --json manifest
```

Start only the local Postgres dependency for integration tests:

```sh
export YALLA_POSTGRES_PASSWORD="$(openssl rand -base64 24)"
docker compose up -d postgres
export YALLA_TEST_DATABASE_URL="postgres://yalla:${YALLA_POSTGRES_PASSWORD}@127.0.0.1:5432/yalla?sslmode=disable"
go test ./...
```

Start the full local control-plane stack:

```sh
export YALLA_POSTGRES_PASSWORD="$(openssl rand -base64 24)"
export YALLA_SIGNING_KEYS="$(openssl rand -base64 32)"
export YALLA_SECRET_KEYS="$(openssl rand -hex 32)"
export YALLA_DOKPLOY_BASE_URL="https://dokploy.internal.example"
export YALLA_DOKPLOY_TOKEN="$(openssl rand -base64 32)"
export YALLA_INTERNAL_WORKER_TOKEN="$(openssl rand -base64 48)"

docker compose --profile control-plane up --build
```

In another shell, probe the API:

```sh
curl -fsS http://localhost:8080/healthz
curl -fsS http://localhost:8080/readyz
curl -fsS http://localhost:8080/version
```

Follow local service logs with:

```sh
docker compose logs -f yalla-api yalla-worker
```

For the full local verification gate, run:

```sh
scripts/verify.sh
```

See [`docs/development/local-development.md`](./docs/development/local-development.md)
for Postgres-backed tests, optional tools, failure recovery, and external smoke
test rules.

## Usage

```sh
yalla --version
yalla auth login
yalla auth status
yalla auth whoami
yalla manifest --json
yalla api operations --json
yalla project create --project-id proj_acme_web --name acme-web --json
yalla environment create --environment-id env_acme_web_prod --project-id proj_acme_web --name production --json
yalla service create --service-id svc_acme_web --environment-id env_acme_web_prod --name web --kind application --build-type dockerfile --repo https://github.com/acme/web --branch main --context . --dockerfile Dockerfile --port 3000 --deploy --wait --json
yalla service build set --service-id svc_acme_web --build-type static --repo https://github.com/acme/web --branch main --build-command "npm run build" --output-dir dist --json
yalla service create --service-id svc_acme_stack --environment-id env_acme_web_prod --name stack --kind compose --build-type compose --compose-file docker-compose.yml --repo https://github.com/acme/stack --branch main --json
yalla service create --service-id svc_acme_worker --environment-id env_acme_web_prod --name worker --kind application --build-type image --image ghcr.io/acme/worker:latest --port 8080 --json
yalla service deploy --service-id svc_acme_web --source git --source-ref main --idempotency-key deploy-001 --wait --json
yalla database backup run --service-id svc_db --backup-id sbkp_123 --wait --json
yalla wait job --job-id job_123 --status succeeded --json
yalla teardown project --project-id proj_123 --json
yalla wait url --url https://example.com --status-class 2xx --timeout 10s --json
```

`yalla api call <operationId>` is no longer a normal-user escape hatch.
Every mutating operation must be represented as a Yalla backend product route
that persists desired state and durable jobs before the worker reconciles
Dokploy.

Backend-only command behavior:

- `yalla auth login` verifies credentials with `GET /v1/me`.
- `yalla project ...`, `yalla environment ...`, and `yalla service ...`
  provide first-class project, environment, service, build-config, and deploy
  workflows through backend product routes.
- `yalla deploy compose` creates a backend deployment via
  `POST /v1/services/{service_id}/deployments`.
- `yalla teardown project` deletes through `DELETE /v1/projects/{project_id}`.
- `yalla wait job|deployment` polls backend state.
- `yalla database ...` manages database services and backup policies through
  backend service/backup routes, including manual run and restore requests.
- Direct rescue commands are disabled until backend admin routes cover them.
- `yalla audit tail` reads the local JSONL mutation audit log.

For automation, avoid putting tokens in shell history:

```sh
printf '%s' "$YALLA_TOKEN" | yalla auth login --url https://api.yalla.example --token-stdin --json
```

## Documentation

- [`docs/development/cli-backend-command-parity.md`](./docs/development/cli-backend-command-parity.md)
  tracks the active CLI-to-backend route contract.
- [`docs/development/environment-variable-reference.md`](./docs/development/environment-variable-reference.md)
  documents backend process configuration for developers.
- [`docs/operations/production-config-reference.md`](./docs/operations/production-config-reference.md)
  is the operator-facing production configuration reference.
- [`docs/development/frontend-handoff-api-guide.md`](./docs/development/frontend-handoff-api-guide.md)
  describes the public `/v1` API contract for frontend and external clients.
- [`skills/README.md`](./skills/README.md) explains the agent skill trees that
  guide natural-language deployment work through first-class `yalla` commands.

Historical implementation plans under `docs/superpowers/plans/` are retained
for rationale only. Use this README, the current docs above, and
`yalla --json manifest` as the authoritative command surface.

## Releases

Releases are produced by [GoReleaser](https://goreleaser.com) on tag push. See
[`RELEASING.md`](./RELEASING.md) for the release process and verification
gates.

## Security

Yalla handles production deployment credentials. See
[`SECURITY.md`](./SECURITY.md) for the full threat model, redaction policy,
required verification gates, and vulnerability disclosure process.

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for the minimum required checks
before commit and before release, the dependency-review checklist, and the
local verification harness (`scripts/verify.sh`).

## License

MIT — see [`LICENSE`](./LICENSE).
