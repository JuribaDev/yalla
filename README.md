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

## Usage

```sh
yalla --version
yalla auth login
yalla auth status
yalla auth whoami
yalla manifest --json
yalla api operations --json
yalla deploy compose --service-id svc_123 --source git --source-ref main --idempotency-key deploy-001 --json
yalla wait job --job-id job_123 --status succeeded --json
yalla teardown project --project-id proj_123 --json
yalla wait url --url https://example.com --status-class 2xx --timeout 10s --json
```

`yalla api call <dokployOperation>` is no longer a normal-user escape hatch.
Every mutating operation must be represented as a Yalla backend product route
that persists desired state and durable jobs before the worker reconciles
Dokploy.

Backend-only command behavior:

- `yalla auth login` verifies credentials with `GET /v1/me`.
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
