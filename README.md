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
| Homebrew | `brew install JuribaDev/yalla/yalla`                         |
| Scoop    | `scoop bucket add yalla https://github.com/JuribaDev/scoop-yalla && scoop install yalla` |
| WinGet   | `winget install --id JuribaDev.yalla`                        |
| npm      | `npm install -g yalla-cli`                                   |
| npx      | `npx yalla-cli --version`                                    |
| Manual   | Download from [Releases](https://github.com/JuribaDev/yalla/releases) |
| Go       | `go install github.com/JuribaDev/yalla/cmd/yalla@latest` (contributor fallback) |

## Usage

```sh
yalla --version
yalla manifest --json
yalla api operations --json
yalla api call project-create --input request.json --json
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
