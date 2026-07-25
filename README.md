# yalla

`yalla` is a production-grade, agent-first CLI for [Dokploy](https://dokploy.com).
It exposes the full Dokploy public API as deterministic, machine-readable
commands so AI agents and humans can drive Dokploy with the same tooling.

## Highlights

- **Native binary, no Go required** — distributed as static binaries for macOS,
  Linux, and Windows (`amd64` and `arm64`).
- **Agent contract** — `--json`, `--no-input`, stable exit codes, machine
  readable error envelopes, deterministic stdout/stderr separation.
- **Full API coverage** — every Dokploy OpenAPI operation is reachable through
  `yalla api call <operationId>`, with `yalla schema get` and `yalla manifest`
  describing the surface programmatically.

## Install

| Channel  | Command                                                      |
|----------|--------------------------------------------------------------|
| npm      | `npm install -g @juriba/yalla-cli`                           |
| Manual   | Download from [Releases](https://github.com/JuribaDev/yalla/releases) |


## Usage

```sh
yalla --version
yalla auth login
yalla auth status
yalla auth whoami
yalla manifest --json
yalla api operations --json
yalla api call project-create --data '{"name":"smoke"}' --dry-run --json
yalla deploy compose --project smoke --env staging --compose-file docker-compose.yml --dry-run --json
yalla teardown project --project smoke --json
yalla wait url --url https://example.com --status-class 2xx --timeout 10s --json
```

`yalla api call` accepts either `--input request.json` for the full envelope
(`path_params`, `query`, `headers`, `body`, `files`) or `--data '<json>'` for
single-line JSON. With `--data`, a bare object is treated as the request body,
so agents can call create/update operations without boilerplate wrappers.

Composite commands layer safe orchestration on top of the raw executor:

- `yalla deploy compose` creates or updates project/env/compose/domain state,
  deploys, and waits for completion.
- `yalla teardown project` cascades cleanup before removing a project and
  returns `E_ORPHAN` when Docker resources remain.
- `yalla rescue orphans` runs the API cleanup path or prints an explicit SSH
  fallback.
- `yalla wait compose|url|orphans` provides deterministic polling primitives.
- `yalla audit tail` reads the local JSONL mutation audit log.

For automation, avoid putting tokens in shell history:

```sh
printf '%s' "$YALLA_TOKEN" | yalla auth login --url https://deploy.example.com --token-stdin --json
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
