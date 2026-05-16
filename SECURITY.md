# Yalla Security Policy

Yalla is the CLI agents and humans use to drive production Dokploy
deployments. A leaked token, a tampered release archive, or a
vulnerable dependency can compromise every server connected to a
Dokploy instance. We treat security regressions as release blockers.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security problems.

- Email: <security@juriba.dev>
- Subject prefix: `[yalla][security]`
- Optional: encrypt with the maintainer's public key (linked from
  <https://github.com/JuribaDev>)

What to include:

1. The yalla version (`yalla version --json`).
2. Reproduction steps, including the exact command line and any
   redacted log excerpts.
3. The impact you observed (token leak, RCE, denial-of-service,
   privilege escalation, etc.).

You will receive an acknowledgement within **3 business days**. We aim
to ship a fix or mitigation within **30 days** for high-severity
issues; lower-severity issues are folded into the next scheduled
release.

## Supported Versions

Pre-1.0 yalla supports only the latest minor release line on
[GitHub Releases](https://github.com/JuribaDev/yalla/releases). Once
yalla reaches 1.0 the matrix will be published here.

## Threat Model and Hard Rules

Yalla is invoked by AI agents in unattended pipelines. The following
properties are part of the public contract and are enforced by the
test suite:

- **Secrets never reach stdout.** `--json` data on stdout, all
  diagnostics on stderr. The `--token` value, well-known transport
  patterns (`Authorization`, `X-Api-Key`, `X-Auth-Token`), and
  `?token=`/`?api_key=` query strings are scrubbed by
  `internal/output.Redactor` before any byte is written.
- **Errors are typed.** Every user-visible failure is an
  `internal/errors.Error` with a stable `Code` and exit code. Plain
  `fmt.Errorf` reaching stderr is a contract violation.
- **`--no-input` never hangs.** When the flag is set, any prompt path
  exits with `E_NO_INPUT_REQUIRED` (exit code 9) instead of blocking.
- **Releases are reproducible.** Archives are built by GoReleaser in
  GitHub Actions; checksums are published alongside every release.
  The npm wrapper, Homebrew formula, Scoop manifest, and WinGet
  manifest all resolve to the same archives.

## Required Verification Gates

Before any commit lands in `main`, the CI pipeline runs the gate
defined in `.github/workflows/ci.yml`:

| Check | Tool | Where | When |
| --- | --- | --- | --- |
| Formatting | `gofmt -l .` | `scripts/verify.sh`, CI | Every push and PR |
| Module hygiene | `go mod tidy` | `scripts/verify.sh`, CI | Every push and PR |
| Static analysis | `go vet ./...` | `scripts/verify.sh`, CI | Every push and PR |
| Tests | `go test ./...` | `scripts/verify.sh`, CI | Every push and PR |
| Race detector | `go test -race ./...` | `scripts/verify.sh`, CI | Every push and PR |
| Vulnerability scan | `govulncheck ./...` | CI `security` job | Every push and PR |
| Lint suite | `staticcheck ./...` and `golangci-lint run ./...` | CI `security` job | Every push and PR |
| Dependency review | `actions/dependency-review-action` | CI on PRs | Every PR |
| Container image hardening | `go test ./internal/release/... -run TestDockerfile` | CI `test` job, `scripts/verify.sh` | Every push and PR |
| Release config | `goreleaser check` and `goreleaser release --snapshot` | CI `goreleaser-check` job | Every push and PR |

Before cutting a tag the maintainer additionally runs:

- `scripts/verify.sh --release` locally — runs every check above plus
  `goreleaser release --snapshot --clean`.
- A manual review of the dependency diff since the last tag
  (`go list -m -json all` baseline).
- A spot-check of `yalla manifest --json` to confirm no schema
  removals or exit-code remappings have slipped in unintentionally.

If a verification tool is missing locally, `scripts/verify.sh` reports
it explicitly. The repository's policy is **never silently skip a
check** — an absent tool must either be installed or noted in
`ralph/progress.txt` so the gap is visible.

## Dependency Review Expectations

Yalla pulls only what it needs. When you add or update a third-party
Go module, follow the checklist in
[`CONTRIBUTING.md`](./CONTRIBUTING.md#dependency-review-checklist) and
expect the dependency-review CI job to gate the PR. New modules with
unknown licenses or known high-severity advisories will be rejected
automatically.

## Container Image Hardening

The production `Dockerfile` ships the `yalla-api` binary inside a
`gcr.io/distroless/static-debian12:nonroot` runtime so a leaked or
compromised image carries no shell, no package manager, no busybox,
and no setuid binaries — only the API binary and the system CA
bundle. The hardening posture is part of the public contract and is
pinned by `internal/release/container_hardening_static_test.go`; a
regression in any one of the following is caught at build time:

- **Multi-stage build.** The Go toolchain, module cache, and source
  tree never reach the runtime layer. A single-stage Dockerfile is
  rejected.
- **Distroless `nonroot` runtime.** The runtime stage's base image
  is pinned to `gcr.io/distroless/static-debian12:nonroot` (UID/GID
  65532). Debian/Ubuntu/Alpine slim runtimes are rejected because
  they reintroduce a shell and a package manager.
- **`USER nonroot:nonroot`.** The runtime stage MUST run as the
  non-root user. A missing or partial (`USER nonroot`) directive is
  rejected.
- **Hardened build flags.** The builder stage MUST invoke
  `go build` with `CGO_ENABLED=0` (static binary compatible with
  the distroless static image), `-trimpath` (strip local filesystem
  paths from the binary), and `-ldflags="-s -w"` (drop the symbol
  and DWARF tables). Each missing flag is a separate regression.
- **No `ADD <url>`.** Fetching arbitrary content at build time
  without checksum verification is forbidden. Use `COPY` or a
  `RUN curl ... | sha256sum -c` pattern.
- **No baked secrets.** The Dockerfile MUST NOT declare ENV values
  whose key names contain `TOKEN`, `PASSWORD`, `SECRET`, `API_KEY`,
  `PRIVATE_KEY`, `SIGNING_KEY`, or `DSN`. Secrets are supplied by
  the operator at runtime through environment variables, never
  baked into the image.
- **No package install in the runtime stage.** `apt-get`,
  `apt install`, `yum install`, `dnf install`, `microdnf install`,
  and `apk add` are rejected in the final layer. The builder stage
  is free to install build dependencies; the runtime stage is not.
- **`COPY --from=builder --chown=nonroot:nonroot`.** Every
  cross-stage COPY into the runtime layer MUST chown to the
  non-root user so the copied artefact is not owned by root.
- **Explicit `ENTRYPOINT`.** The runtime stage MUST declare an
  `ENTRYPOINT` (not just `CMD`) so `docker run -- <args>` cannot
  replace the binary at launch.

Operators are expected to run the image with `--read-only`,
`--cap-drop=ALL`, and a non-host network. The Dockerfile's header
comment documents the canonical `docker run` invocation.

The local integration-test stack (`docker-compose.yml`) MUST pin
the Postgres image to a major version tag (`postgres:16`, not
`postgres` and not `postgres:latest`) and declare a `healthcheck`
so the integration-test harness has a deterministic readiness gate.

## Disclosure Timeline (Best Effort)

1. **Day 0** — report received, acknowledgement sent.
2. **Day 1–7** — triage, severity assessment, reproduction.
3. **Day 7–30** — fix authored, embargoed PR prepared, advisory
   drafted on GitHub Security Advisories.
4. **Release day** — patched binary released, advisory published,
   reporter credited (unless they ask otherwise).
