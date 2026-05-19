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
| Repository integration tests | `go test ./internal/controlplane/store/...` | `scripts/verify.sh`, CI | Every push and PR |
| HTTP handler contract tests | `go test ./internal/controlplane/httpapi/...` | `scripts/verify.sh`, CI | Every push and PR |
| OpenAPI schema conformance tests | `go test ./internal/controlplane/openapi/...` | `scripts/verify.sh`, CI | Every push and PR |
| Policy matrix tests | `go test -run TestPolicyMatrix ./...` | `scripts/verify.sh`, CI | Every push and PR |
| Quota concurrency tests | `go test -run TestQuotaConcurrency ./...` | `scripts/verify.sh`, CI | Every push and PR |
| Job worker lease tests | `go test -run TestJobWorkerLease ./...` | `scripts/verify.sh`, CI | Every push and PR |
| Fake Dokploy contract tests | `go test -run TestFakeDokploy ./...` | `scripts/verify.sh`, CI | Every push and PR |
| Redaction tests | `go test -run TestRedaction ./...` | `scripts/verify.sh`, CI | Every push and PR |
| Fuzz validator tests | `go test -run TestFuzzValidator ./...` | `scripts/verify.sh`, CI | Every push and PR |
| Migration tests from empty DB | `go test -run TestMigrationsEmptyDB ./...` | `scripts/verify.sh`, CI | Every push and PR |
| Migration downgrade safety tests | `go test -run TestMigrationsDowngradeSafety ./...` | `scripts/verify.sh`, CI | Every push and PR |
| Load smoke tests | `go test -run TestLoadSmoke ./...` | `scripts/verify.sh`, CI | Every push and PR |
| Chaos tests for Dokploy timeouts | `go test -run TestChaosDokployTimeouts ./...` | `scripts/verify.sh`, CI | Every push and PR |
| Chaos tests for Postgres disconnects | `go test -run TestChaosPostgresDisconnects ./...` | `scripts/verify.sh`, CI | Every push and PR |
| Idempotency replay tests | `go test -run TestIdempotencyReplay ./...` | `scripts/verify.sh`, CI | Every push and PR |
| Audit completeness tests | `go test -run TestAuditCompleteness ./...` | `scripts/verify.sh`, CI | Every push and PR |
| Pagination stability tests | `go test -run TestPaginationStability ./...` | `scripts/verify.sh`, CI | Every push and PR |
| Tenant isolation tests | `go test -run TestTenantIsolation ./...` | `scripts/verify.sh`, CI | Every push and PR |
| Backup restore rehearsal tests | `go test -run TestBackupRestoreRehearsal ./...` | `scripts/verify.sh`, CI | Every push and PR |
| Release build tests | `go test -run TestReleaseBuild ./...` | `scripts/verify.sh`, CI | Every push and PR |
| Config validation tests | `go test -run TestConfigValidation ./...` | `scripts/verify.sh`, CI | Every push and PR |
| Admin endpoint tests | `go test -run TestAdminEndpoint ./...` | `scripts/verify.sh`, CI | Every push and PR |
| Break-glass tests | `go test -run TestBreakGlass ./...` | `scripts/verify.sh`, CI | Every push and PR |
| Reconciliation tests | `go test -run TestReconciliation ./...` | `scripts/verify.sh`, CI | Every push and PR |
| Import dry-run tests | `go test -run TestImportDryRun ./...` | `scripts/verify.sh`, CI | Every push and PR |
| Service desired-state golden tests | `go test -run TestServiceDesiredState ./...` | `scripts/verify.sh`, CI | Every push and PR |
| Deployment lifecycle end-to-end tests | `go test -run TestDeploymentLifecycleE2E ./...` | `scripts/verify.sh`, CI | Every push and PR |
| External live-Dokploy smoke tests | `YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...` | `.github/workflows/external-smoke.yml`, `scripts/verify.sh` (opt-in) | Opt-in (`YALLA_EXTERNAL_DOKPLOY=1`), nightly + manual |
| Race detector | `go test -race ./...` | `scripts/verify.sh`, CI | Every push and PR |
| Vulnerability scan | `govulncheck ./...` | CI `security` job | Every push and PR |
| Lint suite | `staticcheck ./...` and `golangci-lint run ./...` | CI `security` job | Every push and PR |
| Dependency review | `actions/dependency-review-action` | CI on PRs | Every PR |
| Container image hardening | `go test ./internal/release/... -run TestDockerfile` | CI `test` job, `scripts/verify.sh` | Every push and PR |
| TLS and proxy header trust | `go test ./internal/release/... -run TestHTTPServerHardening` | CI `test` job, `scripts/verify.sh` | Every push and PR |
| Admin endpoint isolation | `go test ./internal/release/... -run TestAdminEndpointIsolation` | CI `test` job, `scripts/verify.sh` | Every push and PR |
| Support access review | `go test ./internal/release/... -run TestSupportAccessReview` | CI `test` job, `scripts/verify.sh` | Every push and PR |
| Environment variable redaction | `go test ./internal/controlplane/variables/... -run TestRedaction` | CI `test` job, `scripts/verify.sh` | Every push and PR |
| Dokploy token isolation | `go test ./internal/release/... -run TestDokployTokenIsolation` and `go test ./internal/controlplane/config/... -run TestRuntimeConfigDokployToken` | CI `test` job, `scripts/verify.sh` | Every push and PR |
| Backup encryption | `go test ./internal/release/... -run TestBackupEncryption` and `go test ./internal/controlplane/backup/... -run TestFileReporterEncryptionMarker` | CI `test` job, `scripts/verify.sh` | Every push and PR |
| Rate limit bypass resistance | `go test ./internal/release/... -run TestRateLimitBypassResistance` and `go test ./internal/controlplane/httpapi/... -run TestRateLimitBypassResistance` | CI `test` job, `scripts/verify.sh` | Every push and PR |
| Kubernetes operations artifact | `go test ./internal/release/... -run TestKubernetesArtifact` | CI `test` job, `scripts/verify.sh` | Every push and PR |
| systemd operations artifact | `go test ./internal/release/... -run TestSystemdArtifact` | CI `test` job, `scripts/verify.sh` | Every push and PR |
| Database migration command artifact | `go test ./internal/release/... -run TestDatabaseMigrationCommand` | CI `test` job, `scripts/verify.sh` | Every push and PR |
| Database migration authoring artifact | `go test ./internal/release/... -run TestDatabaseMigrationAuthoringArtifact` | CI `test` job, `scripts/verify.sh` | Every push and PR |
| Worker job authoring artifact | `go test ./internal/release/... -run TestWorkerJobAuthoringArtifact` | CI `test` job, `scripts/verify.sh` | Every push and PR |
| Fake Dokploy usage artifact | `go test ./internal/release/... -run TestFakeDokployUsageArtifact` | CI `test` job, `scripts/verify.sh` | Every push and PR |
| OpenAPI update procedure artifact | `go test ./internal/release/... -run TestOpenAPIUpdateProcedureArtifact` | CI `test` job, `scripts/verify.sh` | Every push and PR |
| Security review checklist artifact | `go test ./internal/release/... -run TestSecurityReviewChecklistArtifact` | CI `test` job, `scripts/verify.sh` | Every push and PR |
| Seed admin command artifact | `go test ./internal/release/... -run TestSeedAdminCommand` | CI `test` job, `scripts/verify.sh` | Every push and PR |
| Backup command artifact | `go test ./internal/release/... -run TestBackupCommand` | CI `test` job, `scripts/verify.sh` | Every push and PR |
| Restore rehearsal command artifact | `go test ./internal/release/... -run TestRestoreRehearsalCommand` | CI `test` job, `scripts/verify.sh` | Every push and PR |
| Config example files artifact | `go test ./internal/release/... -run TestConfigExamplesArtifact` | CI `test` job, `scripts/verify.sh` | Every push and PR |
| Deployment runbook artifact | `go test ./internal/release/... -run TestDeploymentRunbookArtifact` | CI `test` job, `scripts/verify.sh` | Every push and PR |
| Local development setup artifact | `go test ./internal/release/... -run TestLocalDevelopmentSetupArtifact` | CI `test` job, `scripts/verify.sh` | Every push and PR |
| API handler conventions artifact | `go test ./internal/release/... -run TestAPIHandlerConventionsArtifact` | CI `test` job, `scripts/verify.sh` | Every push and PR |
| Policy engine conventions artifact | `go test ./internal/release/... -run TestPolicyEngineConventionsArtifact` | CI `test` job, `scripts/verify.sh` | Every push and PR |
| Quota implementation guide artifact | `go test ./internal/release/... -run TestQuotaImplementationGuideArtifact` | CI `test` job, `scripts/verify.sh` | Every push and PR |
| Repository conventions artifact | `go test ./internal/release/... -run TestRepositoryConventionsArtifact` | CI `test` job, `scripts/verify.sh` | Every push and PR |
| Incident response runbook artifact | `go test ./internal/release/... -run TestIncidentResponseRunbookArtifact` | CI `test` job, `scripts/verify.sh` | Every push and PR |
| On-call dashboard artifact | `go test ./internal/release/... -run TestOnCallDashboardArtifact` | CI `test` job, `scripts/verify.sh` | Every push and PR |
| SLO document artifact | `go test ./internal/release/... -run TestSLODocumentArtifact` | CI `test` job, `scripts/verify.sh` | Every push and PR |
| Release checklist artifact | `go test ./internal/release/... -run TestReleaseChecklistArtifact` | CI `test` job, `scripts/verify.sh` | Every push and PR |
| Rollback checklist artifact | `go test ./internal/release/... -run TestRollbackChecklistArtifact` | CI `test` job, `scripts/verify.sh` | Every push and PR |
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

The production `Dockerfile` ships the `yalla-api` binary and
`Dockerfile.worker` ships the `yalla-worker` binary inside a
`gcr.io/distroless/static-debian12:nonroot` runtime so a leaked or
compromised image carries no shell, no package manager, no busybox,
and no setuid binaries — only the service binary and the system CA
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
- **Worker image contract.** `Dockerfile.worker` MUST build
  `./cmd/yalla-worker`, copy `/out/yalla-worker` to
  `/usr/local/bin/yalla-worker`, and use that binary as the
  entrypoint. The worker has no HTTP listener, so orchestrators
  should use process liveness, non-zero exit restarts, durable
  provisioning job state, dead-letter alerts, worker queue metrics,
  and structured `service=yalla-worker` logs instead of an in-image
  HTTP health probe.

Operators are expected to run the image with `--read-only`,
`--cap-drop=ALL`, and a non-host network. The Dockerfile's header
comment documents the canonical `docker run` invocation; the worker
Dockerfile documents the corresponding no-port runtime contract.

The local operations stack (`docker-compose.yml`) MUST keep the
Postgres-only integration-test workflow available while also
versioning an opt-in `control-plane` profile for `yalla-api` and
`yalla-worker`. The Postgres image is pinned to a major version tag
(`postgres:16`, not `postgres` and not `postgres:latest`) and
declares a `healthcheck` so the integration-test harness has a
deterministic readiness gate. The API and worker services build from
the production `Dockerfile` / `Dockerfile.worker`, wait for
`postgres.condition=service_healthy`, run with a read-only root
filesystem, `cap_drop: [ALL]`, `no-new-privileges:true`, and a `/tmp`
tmpfs, and use required environment-variable interpolation for every
secret-shaped value. `yalla-api` publishes `8080:8080` so operators
can probe `GET /healthz` and `GET /readyz`; `yalla-worker` still has
no HTTP listener and is observed through structured stdout logs plus
durable job state.

## Kubernetes Operations Artifact

The production Kubernetes baseline lives at
`deploy/kubernetes/yalla-control-plane.yaml` with the operator runbook in
`deploy/kubernetes/README.md`. The artifact references the hardened
`ghcr.io/juribadev/yalla-api` and `ghcr.io/juribadev/yalla-worker`
images, runs both pods as non-root with a read-only root filesystem,
drops all Linux capabilities, disables service-account token mounting,
and uses `RuntimeDefault` seccomp.

The checked-in manifest intentionally does **not** include a Kubernetes
`Secret`. Runtime credentials are bound by `secretKeyRef` from the
operator-created `yalla-control-plane-secrets` object so database URLs,
signing keys, Dokploy endpoints, and Dokploy tokens are never baked into
images or repository files.

`yalla-api` exposes `/healthz` and `/readyz` on port 8080 for Kubernetes
liveness and readiness probes. `yalla-worker` has no HTTP listener; its
health model is process liveness, durable job state, worker metrics, and
structured JSON logs. Operators can render the artifact offline with
`kubectl kustomize deploy/kubernetes` or validate it against a cluster with
`kubectl apply --dry-run=server -f deploy/kubernetes/yalla-control-plane.yaml`.
CI pins the contract with
`go test ./internal/release/... -run TestKubernetesArtifact`.

## systemd Operations Artifact

The single-node systemd baseline lives under `deploy/systemd/` with separate
units for `deploy/systemd/yalla-api.service` and
`deploy/systemd/yalla-worker.service`. The API unit executes
`/usr/local/bin/yalla-api`; the worker unit executes
`/usr/local/bin/yalla-worker`. Both run as the dedicated non-root `yalla`
service account, load runtime configuration from
`/etc/yalla/control-plane.env`, and write structured JSON diagnostics to
journald.

The checked-in units intentionally do **not** include database URLs, signing
keys, secret-encryption keys, Dokploy endpoints, or Dokploy tokens. Operators
copy `deploy/systemd/control-plane.env.example` to
`/etc/yalla/control-plane.env`, replace the `<redacted:...>` placeholders from
their secret manager, and keep the rendered file outside the repository with
mode `0640` and group `yalla`.

Both units preserve a least-privilege sandbox: `NoNewPrivileges=true`,
`ProtectSystem=strict`, `ProtectHome=true`, private temporary and device
namespaces, empty capability sets, native syscall architecture, and address
families limited to `AF_UNIX`, `AF_INET`, and `AF_INET6`. `yalla-api` binds
`127.0.0.1:8080` by default for a local TLS-terminating reverse proxy and
exposes `GET /healthz` plus `GET /readyz`; `yalla-worker` has no HTTP listener
and is observed through process liveness, durable job state, worker metrics,
dead-letter alerts, and structured logs.

Operators can dry-run the unit syntax with
`systemd-analyze verify deploy/systemd/yalla-api.service deploy/systemd/yalla-worker.service`.
CI pins the artifact with
`go test ./internal/release/... -run TestSystemdArtifact`.

## Database Migration Command Artifact

The production database migration command lives at
`deploy/operations/migrate-database.sh` with the runbook in
`deploy/operations/README.md`. It runs the API binary's embedded migration
runner through `/usr/local/bin/yalla-api --migrate-only`, so the SQL ladder
applied in production is exactly the version compiled into the backend
release. The worker binary remains separate: the script stops `yalla-worker`
before applying schema changes and restarts both `yalla-api` and
`yalla-worker` after a successful migration.

The command loads runtime configuration from `/etc/yalla/control-plane.env`
or `YALLA_CONTROL_PLANE_ENV_FILE`. It never checks in or prints database URLs,
signing keys, secret-encryption keys, Dokploy endpoints, Dokploy tokens, API
keys, cookies, or rendered environment values; `--dry-run` prints only command
shape plus redacted `YALLA_*` variable names. After `--apply`, operators verify
the API through `/healthz` and `/readyz` and inspect structured JSON logs with
`journalctl -u yalla-api -u yalla-worker -o json`.

CI pins the command, runbook, binary flag, and release gate with
`go test ./internal/release/... -run TestDatabaseMigrationCommand`.

## Database Migration Authoring Artifact

The database migration authoring guide lives at
`docs/development/database-migration-authoring.md`. It documents how to create
paired `NNNN_description.up.sql` and `NNNN_description.down.sql` files under
`internal/controlplane/store/migrate/migrations`, how the embedded runner
records versions in `schema_migrations`, and how developers verify migrations
against isolated Postgres databases before merge.

The guide keeps runtime secrets operator-managed and uses only
`<redacted:...>` placeholders for local environment values. It documents the
canonical checks: `go test -run TestMigrations ./...`,
`go test -run TestMigrationsEmptyDB ./...`,
`go test -run TestMigrationsDowngradeSafety ./...`, `go test ./...`,
`go test -race ./...`, `go vet ./...`, and `scripts/verify.sh`. It also
documents failure recovery for unhealthy local Postgres, dirty migration
states, downgrade failures, and production rollback through backup or forward
fixes rather than ad hoc SQL.

CI pins the guide and release gate with
`go test ./internal/release/... -run TestDatabaseMigrationAuthoringArtifact`.

## Worker Job Authoring Artifact

The worker job authoring guide lives at
`docs/development/worker-job-authoring.md`. It documents how durable
provisioning work flows from the Yalla API to Postgres source of truth, then
through `yalla-worker` to the private Dokploy API. The guide covers
`provisioning_jobs`, `StoreClaimer`, `Provisioner`, `JobRunner`,
`store.JobRepository.ClaimNext`, `SELECT ... FOR UPDATE SKIP LOCKED`,
lease-owner outcome checks, terminal failure classification, fake Dokploy
fixtures, tenant-scoped `dokploy_refs`, and redacted job/audit metadata.

The guide keeps runtime secrets operator-managed and uses only
`<redacted:...>` placeholders for local environment values. It documents the
canonical checks: `go test ./internal/controlplane/worker/...`,
`go test -run TestJobWorkerLease ./...`,
`go test -run TestFakeDokploy ./...`,
`go test ./internal/controlplane/store/...`, `go test ./...`,
`go test -race ./...`, `go vet ./...`, and `scripts/verify.sh`. It also
documents stable `yalla.output.v1` and `yalla.error.v1` envelopes, request IDs,
isolated Postgres integration tests, fake-Dokploy-by-default behavior,
dead-letter recovery, `E_JOB_NOT_CLAIMED`, `E_JOB_CANCELLED`, and the opt-in
external live-Dokploy smoke test that must never run against production.

CI pins the guide and release gate with
`go test ./internal/release/... -run TestWorkerJobAuthoringArtifact`.

## Fake Dokploy Usage Artifact

The fake Dokploy usage guide lives at
`docs/development/fake-dokploy-usage.md`. It documents how backend tests use
`internal/controlplane/dokploy/dokployfake` and `dokployfake.New` for
Dokploy-shaped behavior without reaching a live Dokploy server. The guide
covers the Yalla API -> Postgres source of truth -> provisioning worker ->
private Dokploy API boundary, typed client usage in
`internal/controlplane/dokploy`, worker provisioning paths in
`internal/controlplane/worker`, HTTP contract tests in
`internal/controlplane/httpapi`, tenant-scoped `dokploy_refs`, and recorder
redaction through `output.Sentinel`.

The guide keeps runtime secrets operator-managed and uses only
`<redacted:...>` placeholders for local environment values. It documents the
canonical checks: `go test -run TestFakeDokploy ./...`,
`go test ./internal/controlplane/dokploy/...`,
`go test ./internal/controlplane/worker/...`,
`go test ./internal/controlplane/httpapi/...`, `go test ./...`,
`go test -race ./...`, `go vet ./...`, and `scripts/verify.sh`. It also
documents stable `yalla.output.v1` and `yalla.error.v1` envelopes, request IDs,
isolated Postgres integration tests, fake-Dokploy-by-default behavior,
failure recovery, and the opt-in external live-Dokploy smoke test that must
never run against production.

CI pins the guide and release gate with
`go test ./internal/release/... -run TestFakeDokployUsageArtifact`.

## Seed Admin Command Artifact

The production seed-admin command lives at
`deploy/operations/seed-admin.sh` with the runbook in
`deploy/operations/README.md`. It runs the API binary's embedded maintenance
path through `/usr/local/bin/yalla-api --seed-admin`, so the bootstrap write
uses the same database contract as the deployed backend release. The worker
binary remains separate: the script verifies both `yalla-api` and
`yalla-worker` are active before seeding, but it never gives the worker broad
database or Dokploy credentials.

The command loads runtime configuration from `/etc/yalla/control-plane.env`
or `YALLA_CONTROL_PLANE_ENV_FILE`. It never checks in or prints database URLs,
signing keys, secret-encryption keys, Dokploy endpoints, Dokploy tokens, API
keys, cookies, seed identity values, or rendered environment values;
`--dry-run` prints only command shape plus redacted `YALLA_*` variable names.
After `--apply`, operators verify the API through `/healthz` and `/readyz`
and inspect structured JSON logs with
`journalctl -u yalla-api -u yalla-worker -o json`.

CI pins the command, runbook, binary flag, and release gate with
`go test ./internal/release/... -run TestSeedAdminCommand`.

## Backup Command Artifact

The production backup command lives at
`deploy/operations/backup-database.sh` with the runbook in
`deploy/operations/README.md`. It references the deployed
`/usr/local/bin/yalla-api` and `/usr/local/bin/yalla-worker` binaries for
version coupling and service checks, but it keeps backup production outside
the Yalla Go processes. The operator command invokes
`pg_dump --format=custom --no-acl --no-owner --compress=9` against the
least-privilege Postgres role supplied in `/etc/yalla/control-plane.env`.

The command loads runtime configuration from `/etc/yalla/control-plane.env`
or `YALLA_CONTROL_PLANE_ENV_FILE`. It never checks in or prints database URLs,
signing keys, secret-encryption keys, Dokploy endpoints, Dokploy tokens, API
keys, cookies, backup bucket credentials, or rendered environment values;
`--dry-run` prints only command shape plus redacted `YALLA_*` variable names.
The backup directory is operator-managed encrypted storage. The status file
named by `YALLA_BACKUP_STATUS_FILE` is updated atomically with `mktemp` and
`mv` only after `pg_dump` succeeds, so `/healthz/backup` never observes a
partial timestamp.

Before and after a backup, operators verify `/healthz`, `/readyz`, and
`/healthz/backup`; the API renders stable `yalla.output.v1` or
`yalla.error.v1` envelopes for those probes. Structured JSON logs from
`yalla-api` and `yalla-worker` remain diagnostics only and must not contain
backup credentials or rendered environment values.

CI pins the command, runbook, and release gate with
`go test ./internal/release/... -run TestBackupCommand`.

## Restore Rehearsal Command Artifact

The production restore rehearsal command lives at
`deploy/operations/restore-rehearsal.sh` with the runbook in
`deploy/operations/README.md`. It references the deployed
`/usr/local/bin/yalla-api` and `/usr/local/bin/yalla-worker` binaries for
version coupling and service checks, but it restores only into the
operator-provided throwaway `YALLA_REHEARSAL_DATABASE_URL`. The script rejects
a rehearsal DSN that matches the primary control-plane DSN, runs
`pg_restore --clean --if-exists --no-owner --no-acl --jobs`, applies the
release's embedded migration ladder with `/usr/local/bin/yalla-api
--migrate-only`, and runs the configured canary suite before publishing a
report.

The command loads runtime configuration from `/etc/yalla/control-plane.env`
or `YALLA_CONTROL_PLANE_ENV_FILE`. It never checks in or prints database URLs,
snapshot object locations, signing keys, secret-encryption keys, Dokploy
endpoints, Dokploy tokens, API keys, cookies, backup bucket credentials, or
rendered environment values; `--dry-run` prints only command shape plus
redacted `YALLA_*` variable names. The rehearsal report is written under
`YALLA_RESTORE_REHEARSAL_REPORT_DIR` through `mktemp` and `mv`, carries only
redacted snapshot and DSN fields, and is created only after restore,
migrations, and canary pass.

Operators verify `/healthz`, `/readyz`, and `/healthz/backup`; the API renders
stable `yalla.output.v1` or `yalla.error.v1` envelopes for those probes.
Structured JSON logs from `yalla-api` and `yalla-worker` remain diagnostics
only and must not contain backup credentials, restore DSNs, snapshot locations,
or rendered environment values.

CI pins the command, runbook, and release gate with
`go test ./internal/release/... -run TestRestoreRehearsalCommand`.

## Config Example Files Artifact

The production configuration example lives at
`deploy/config/control-plane.env.example` with its operator notes in
`deploy/config/README.md`. The file is consumed by the deployed
`/usr/local/bin/yalla-api` and `/usr/local/bin/yalla-worker` binaries through
the rendered `/etc/yalla/control-plane.env` copy. Operators install the
rendered copy as `root:yalla` with mode `0640`, replace every
`<redacted:...>` placeholder from their secret manager, and keep the rendered
file outside the repository.

The checked-in example intentionally contains no rendered database URLs,
signing keys, secret-encryption keys, Dokploy tokens, API keys, cookies, or
passwords. It documents API `/healthz` and `/readyz` probes, stable
`yalla.output.v1` and `yalla.error.v1` envelopes, worker no-HTTP-listener
health expectations, structured JSON logs, and the rule that logs, errors,
audit metadata, and dry-run output must redact rendered environment values.

CI pins the config example files with
`go test ./internal/release/... -run TestConfigExamplesArtifact`.

## Deployment Runbook Artifact

The production deployment runbook lives at `docs/operations/deployment.md`.
It ties the versioned backend release to both deployed binaries
(`/usr/local/bin/yalla-api` and `/usr/local/bin/yalla-worker`), the
operator-managed runtime environment file, the Kubernetes and systemd
artifacts, and the versioned migration command. The runbook documents that
customers never receive Dokploy credentials and that rendered database URLs,
tokens, API keys, cookies, signing keys, secret keys, Dokploy credentials, and
environment values stay out of repository files, tickets, runbooks, logs,
errors, audit metadata, and dry-run output.

The runbook is also the operator-facing health contract: `/healthz` is
liveness-only, `/readyz` reports dependency gates, `/version` exposes the
release identity, successful probes use `yalla.output.v1`, failed probes use
`yalla.error.v1`, and every response carries a stable `request_id`.
`yalla-worker` has no HTTP listener and is observed through process liveness,
durable job state, metrics, dead-letter alerts, and structured JSON logs.

CI pins the deployment runbook with
`go test ./internal/release/... -run TestDeploymentRunbookArtifact`.

## Local Development Setup Artifact

The backend local development setup lives at
`docs/development/local-development.md`. It documents the local Postgres
dependency, isolated migration-backed integration tests, the optional full
Docker Compose control-plane stack, expected health/readiness outputs, and
failure recovery commands. The document preserves the production boundary:
Customer / Agent / CI traffic reaches the Yalla API, Postgres remains the
source of truth, the worker performs provisioning, and Dokploy stays private.

The checked-in setup guide intentionally uses only `<redacted:...>`
placeholders for secret-shaped values. It documents that customers never
receive Dokploy API tokens and that database URLs, rendered environment
values, API keys, cookies, request bodies, response bodies, and Dokploy
credentials stay out of logs, errors, audit metadata, tests, and docs.
External Dokploy smoke tests remain opt-in and must never run against
production.

CI pins the local development setup with
`go test ./internal/release/... -run TestLocalDevelopmentSetupArtifact`.

## API Handler Conventions Artifact

The backend API handler convention guide lives at
`docs/development/api-handler-conventions.md`. It documents how new and changed
handlers are registered through `internal/controlplane/httpapi/routes.go`,
documented with OpenAPI metadata, decoded through bounded validators,
authorized with scoped policy actions, and rendered only through stable
`yalla.output.v1` / `yalla.error.v1` envelopes with request IDs.

The guide preserves the production boundary: the Yalla API owns customer-facing
intent, Postgres remains the source of truth, workers call the private Dokploy
API through typed clients, and handlers never expose raw Dokploy operations or
live credentials. It also pins required local environment variables with
redacted placeholders, expected verification output, tenant-isolation testing,
idempotency, quota, audit, and failure recovery guidance.

CI pins the API handler conventions with
`go test ./internal/release/... -run TestAPIHandlerConventionsArtifact`.

## OpenAPI Update Procedure Artifact

The backend OpenAPI update procedure lives at
`docs/development/openapi-update-procedure.md`. It documents how new and
changed public operations are tied to registered routes in
`internal/controlplane/httpapi/routes.go`, `openapi.Endpoint` metadata under
`internal/controlplane/openapi`, `x-required-action`, bounded
`validate.DecodeJSON` request handling, typed `apierr` failures, and stable
`yalla.output.v1` / `yalla.error.v1` envelopes with request IDs.

The guide preserves the production boundary: Yalla API owns customer intent,
Postgres is the source of truth, workers call the private Dokploy API, and
OpenAPI must never document customer-facing raw Dokploy access. It pins exact
OpenAPI, handler, full-suite, race, and vet commands; required environment
variables with redacted placeholders; expected output; tenant-isolation,
idempotency, quota, and audit expectations; isolated Postgres integration
tests; opt-in live Dokploy smoke safety; and failure recovery.

CI pins the OpenAPI update procedure with
`go test ./internal/release/... -run TestOpenAPIUpdateProcedureArtifact`.

## Quota Implementation Guide Artifact

The backend quota implementation guide lives at
`docs/development/quota-implementation-guide.md`. It documents how quota
enforcement is added through `internal/controlplane/quota`,
`store.QuotaReserver`, `store.QuotaRepository`, `Store.Write`, and
tenant-scoped Postgres rows without exposing raw Dokploy operations. The guide
pins hard-limit rejection, soft-limit warnings, metered/disabled behavior,
`quota_reservations`, `usage_counters`, `apierr.QuotaExceeded`, stable
`yalla.output.v1` / `yalla.error.v1` envelopes with request IDs,
concurrency tests, tenant-isolation tests, fake-Dokploy-by-default behavior,
and redaction of secrets, tokens, API keys, cookies, and rendered environment
variable values.

The guide preserves the production boundary: quota protects Yalla source of
truth before desired-state writes and job enqueueing; workers call the private
Dokploy API only after auth, policy, quota, idempotency, and audit succeed.
Required local environment variables use redacted placeholders, expected
outputs are pinned, and failure recovery keeps quota tests on isolated
Postgres databases.

CI pins the quota implementation guide with
`go test ./internal/release/... -run TestQuotaImplementationGuideArtifact`.

## Repository Conventions Artifact

The backend repository convention guide lives at
`docs/development/repository-conventions.md`. It documents how source-of-truth
repository methods under `internal/controlplane/store` are added, verified, and
kept tenant-scoped by `organization_id` or verified parent joins. The guide
ties repository work to migrations, `Store.Read` / `Store.Write` transaction
boundaries, `apierr` typed errors, deterministic list ordering, optimistic
concurrency, rollback tests, tenant-isolation tests, and the stable
`yalla.output.v1` / `yalla.error.v1` response envelope contract above the
persistence layer.

The guide preserves the production boundary: repositories persist Yalla state,
workers call the private Dokploy API through typed clients, and customer-facing
code never exposes raw Dokploy operations or live credentials. Required local
environment variables use redacted placeholders, expected outputs are pinned,
and failure recovery keeps tests on isolated Postgres databases with fake
Dokploy by default.

CI pins the repository conventions with
`go test ./internal/release/... -run TestRepositoryConventionsArtifact`.

## Incident Response Runbook Artifact

The production incident response runbook lives at
`docs/operations/incident-response.md`. It ties emergency operations to the
versioned backend binaries (`/usr/local/bin/yalla-api` and
`/usr/local/bin/yalla-worker`), the Postgres source-of-truth boundary, durable
job state, the private Dokploy API dependency, and the public response envelope
contract. Operators use the runbook to classify incident severity, contain
customer-impacting API incidents, worker incidents, Postgres incidents, Dokploy
dependency incidents, and secret exposure incidents without bypassing Yalla
authorization, policy, quota, idempotency, audit, or redaction controls.

The runbook requires runtime secrets to stay in operator-managed configuration
such as `/etc/yalla/control-plane.env`, keeps customer-facing incident evidence
limited to stable IDs (`request_id`, `correlation_id`, resource IDs, and job
IDs), and documents `/healthz`, `/readyz`, `/version`, stable
`yalla.output.v1` / `yalla.error.v1` envelopes, structured JSON logs,
readiness degradation metrics, policy decision metrics, audit event metrics,
dead-letter alerts, and opt-in external live-Dokploy smoke tests that must
never target production.

CI pins the incident response runbook with
`go test ./internal/release/... -run TestIncidentResponseRunbookArtifact`.

## On-Call Dashboard Artifact

The production on-call dashboard artifact lives at
`docs/operations/on-call-dashboard.md`. It ties dashboard rendering to the
versioned backend binaries (`/usr/local/bin/yalla-api` and
`/usr/local/bin/yalla-worker`), the `GET /dashboards/control-plane.json`
`yalla.dashboard.v1` export, the `GET /metrics` snapshot, the Postgres
source-of-truth boundary, durable job state, and the private Dokploy API
dependency. The dashboard is a read-only operator surface: customer and agent
traffic still flows through Yalla, and customers never receive Dokploy
credentials or raw private dependency access.

The artifact requires runtime secrets to stay in operator-managed
configuration such as `/etc/yalla/control-plane.env`, keeps panels grouped by
low-cardinality fields only, and treats `request_id`, `correlation_id`,
organization, principal, resource, service, and job IDs as incident join hints
rather than labels. It documents `/healthz`, `/readyz`, `/version`, stable
`yalla.output.v1` / `yalla.error.v1` envelopes, structured JSON logs, readiness
degradation metrics, SLO burn-rate metrics, policy decision metrics, audit
event metrics, dead-letter alerts, reconciliation drift alerts,
secret-redaction canaries, slow-query metrics, trace spans, support
break-glass with `support.manage`, and opt-in external live-Dokploy smoke tests
that must never target production.

CI pins the on-call dashboard artifact with
`go test ./internal/release/... -run TestOnCallDashboardArtifact`.

## SLO Document Artifact

The production SLO document lives at `docs/operations/slo.md`. It ties
customer-facing objectives to the versioned backend binaries
(`/usr/local/bin/yalla-api` and `/usr/local/bin/yalla-worker`), the Postgres
source-of-truth boundary, durable provisioning jobs, private Dokploy API
dependency, and the stable response-envelope contract. The SLO evidence surface
is intentionally narrow: `/metrics`, `/healthz`, `/readyz`, `/version`, and
the backup freshness probe.

The artifact requires runtime secrets to stay in operator-managed
configuration such as `/etc/yalla/control-plane.env`, keeps SLO labels
low-cardinality, and treats `request_id`, `correlation_id`, organization,
principal, resource, service, and job IDs as incident join hints rather than
labels. It documents `data.slo_burn_rates`, API availability, API latency,
provisioning job completion, backup freshness, audit durability, error budget
policy, structured JSON logs, readiness degradation metrics, policy decision
metrics, audit event metrics, dead-letter alerts, secret-redaction canaries,
support break-glass with `support.manage`, and opt-in external live-Dokploy
smoke tests that must never target production.

CI pins the SLO document artifact with
`go test ./internal/release/... -run TestSLODocumentArtifact`.

## Release Checklist Artifact

The production release checklist lives at
`docs/operations/release-checklist.md`. It binds release promotion to the
versioned backend binaries (`/usr/local/bin/yalla-api` and
`/usr/local/bin/yalla-worker`), the Customer / Agent / CI -> Postgres source
of truth -> provisioning worker -> private Dokploy API boundary, stable
`yalla.output.v1` and `yalla.error.v1` envelopes, request IDs, migration
safety, and the existing operations artifacts.

The checklist requires runtime secrets to stay in operator-managed
configuration such as `/etc/yalla/control-plane.env`, requires dry-run output
to show only redacted `YALLA_*` variable names, and pins the release gates:
`gofmt -w .`, `goimports -w .`, `go mod tidy`, `go test ./...`,
`go test -race ./...`, `go vet ./...`, `scripts/verify.sh`, and
`scripts/verify.sh --release`. It also documents `/healthz`, `/readyz`,
`/version`, `/metrics`, expected output shapes instead of full command
transcripts, structured JSON logs, dead-letter alerts, least-privilege access,
redaction of tokens, API keys, cookies, database URLs, Dokploy tokens, request
bodies, response bodies, and rendered environment values, plus the opt-in
external live-Dokploy smoke test that must never run against production.

CI pins the release checklist artifact with
`go test ./internal/release/... -run TestReleaseChecklistArtifact`.

## Security Review Checklist Artifact

The backend security review checklist lives at
`docs/development/security-review-checklist.md`. It binds review approval to
the versioned backend binaries (`/usr/local/bin/yalla-api` and
`/usr/local/bin/yalla-worker`), the Customer / Agent / CI -> Postgres source
of truth -> provisioning worker -> private Dokploy API boundary, stable
`yalla.output.v1` and `yalla.error.v1` envelopes, `request_id` propagation,
OpenAPI compatibility, auth, policy, quota, idempotency, audit, tenant
isolation, and fake-Dokploy-by-default testing.

The checklist pins the required gates: `gofmt -w .`, `goimports -w .`,
`go mod tidy`, `go test ./...`, `go test -race ./...`, `go vet ./...`,
`scripts/verify.sh`, `go test ./internal/controlplane/...`,
`go test -race ./internal/controlplane/...`,
`go test -run TestMigrations ./...`,
`go test -run TestPolicyMatrix ./...`,
`go test -run TestQuotaConcurrency ./...`,
`go test -run TestFakeDokploy ./...`, and
`go test ./internal/release/... -run TestSecurityReviewChecklistArtifact`.
It also documents expected `PASS`, `ok  `, `HTTP/1.1 200 OK`, and
`no changes` outputs; redacted environment placeholders such as
`YALLA_DATABASE_URL=<redacted:YALLA_DATABASE_URL>`; failure recovery for
formatting, contract, tenant-isolation, redaction, migration, and fake-Dokploy
failures; and the opt-in `YALLA_EXTERNAL_DOKPLOY=1 go test -run
TestLiveDokploySmoke ./...` smoke test that must never run against production.

CI pins the security review checklist artifact with
`go test ./internal/release/... -run TestSecurityReviewChecklistArtifact`.

## Rollback Checklist Artifact

The production rollback checklist lives at
`docs/operations/rollback-checklist.md`. It binds rollback decisions to the
versioned backend binaries (`/usr/local/bin/yalla-api` and
`/usr/local/bin/yalla-worker`), the Customer / Agent / CI -> Postgres source
of truth -> provisioning worker -> private Dokploy API boundary, stable
`yalla.output.v1` and `yalla.error.v1` envelopes, request IDs, correlation
IDs, migration reversibility, backup freshness, restore rehearsal evidence,
and durable job safety.

The checklist requires runtime secrets to stay in operator-managed
configuration such as `/etc/yalla/control-plane.env`, requires dry-run output
to show only redacted `YALLA_*` variable names, and requires rollback to use
versioned operations instead of ad hoc SQL. Required rollback environment
references use placeholders such as
`YALLA_DATABASE_URL=<redacted:YALLA_DATABASE_URL>`,
`YALLA_DOKPLOY_BASE_URL=<redacted:YALLA_DOKPLOY_BASE_URL>`,
`YALLA_DOKPLOY_TOKEN=<redacted:YALLA_DOKPLOY_TOKEN>`,
`YALLA_BACKUP_STATUS_FILE=<redacted:YALLA_BACKUP_STATUS_FILE>`, and
`YALLA_REHEARSAL_DATABASE_URL=<redacted:YALLA_REHEARSAL_DATABASE_URL>`.
It documents `/healthz`, `/readyz`, `/version`, `/metrics`, expected `PASS`,
`ok  `, `active`, `yalla.output.v1`, and `yalla.error.v1` output shapes,
structured JSON logs, dead-letter alerts, least-privilege access, redaction of
tokens, API keys, cookies, database URLs, Dokploy tokens, request bodies,
response bodies, and rendered environment values, plus the opt-in external
live-Dokploy smoke test that must never run against production.

CI pins the rollback checklist artifact with
`go test ./internal/release/... -run TestRollbackChecklistArtifact`.

## TLS Termination and Proxy Header Trust

The Yalla control-plane API binary (`cmd/yalla-api`) deliberately
does NOT terminate TLS itself.
**TLS is terminated at the operator's reverse proxy**
(ingress controller, load balancer, or front-door proxy), which
forwards the request to the API over an internal network. Keeping certificate material out of the API process
narrows the secret surface, leverages the proxy's vetted cipher
suite / HSTS / OCSP stapling defaults, and lets operators rotate
certificates without an API restart. The posture is pinned by
`internal/release/http_server_hardening_static_test.go`; a regression
in any one of the following is caught at build time:

- **No in-process TLS.** The API binary MUST NOT call
  `ListenAndServeTLS` or `ServeTLS`, and the constructed
  `*http.Server` MUST NOT set `TLSConfig` or `TLSNextProto`. Any
  TLS-termination shape inside the binary is rejected.
- **Slowloris guard.** Every `*http.Server` literal in the API
  binary MUST set a positive `ReadHeaderTimeout`. The current value
  is `10 * time.Second`. Removing the field, or initialising the
  server with the zero value, is rejected.
- **Closed-set proxy header trust.** The rate limiter resolves the
  caller's identity through `ClientIP(r)` in
  `internal/controlplane/httpapi/ratelimit.go`. The helper consults
  only two forwarding headers:
  - `X-Forwarded-For` — the **first hop only** is taken so a forged
    tail entry cannot displace the real client.
  - `X-Real-IP` as a fallback.
  No other forwarded-* family header is honoured. RFC 7239
  `Forwarded`, Akamai `True-Client-IP`, Cloudflare
  `CF-Connecting-IP`, Fastly `Fastly-Client-IP`, `X-Client-IP`,
  `X-Original-Forwarded-For`, and the meta-data variants
  (`X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-Port`,
  `X-Forwarded-Server`) are deliberately ignored. If the API is
  ever reachable directly — a network misconfiguration, an internal
  pivot, or a forgotten test fixture — an attacker who can reach it
  must not be able to spoof their identity past the IP bucket by
  sending one of those headers. The closed set is enforced by the
  static analyser; adding a new header to the trust list requires
  an explicit, reviewed change to the allow-list.

### Operator expectations

The reverse proxy MUST be configured to:

1. **Strip inbound `X-Forwarded-*` and `X-Real-IP` headers** from
   public traffic before setting its own. Otherwise an attacker
   can pre-populate the header and the proxy will forward it
   verbatim — the API will then trust the attacker-supplied value.
2. **Set `X-Forwarded-For`** to the immediate downstream client's
   IP address. The API only reads the first hop, so the proxy's
   append-on-each-hop semantics are honoured.
3. **Terminate TLS** with a modern cipher suite, an up-to-date
   certificate, and HSTS where appropriate. The API never sees
   the original ClientHello.
4. **Use an internal network or loopback** to reach the API. The
   API listener is HTTP-only and MUST NOT be exposed to the
   public internet directly.

## Admin Endpoint Isolation

The Yalla control-plane API binary (`cmd/yalla-api`) deliberately
ships **no `/debug/` surface**. There is no `/debug/pprof/*`, no
`/debug/vars`, no `/debug/requests`, and no `/debug/events` route on
the customer-facing listener — neither authenticated nor
unauthenticated. Goroutine profiles, heap snapshots, command-line
arguments, registered `expvar` variables, and live CPU profiles are
load-bearing operator-only secrets; exposing any of them on a
listener customers can reach is a build-blocking regression. The
posture is pinned by
`internal/release/admin_endpoint_isolation_static_test.go`; the
gate rejects any of the following shapes at build time:

- **No side-effecting debug imports.** Neither `cmd/yalla-api` nor
  any production source file under `internal/controlplane/httpapi`
  may import `net/http/pprof`, `expvar`, or
  `golang.org/x/net/trace`. A blank import alone is sufficient to
  register the surface on `http.DefaultServeMux`; the matcher
  rejects every form of import (blank, named, aliased) of those
  three paths.
- **Private mux only.** `httpapi.NewHandler` MUST construct its own
  mux via `http.NewServeMux()` and MUST NOT reference
  `http.DefaultServeMux` anywhere. The private mux severs the API
  listener from any default-mux registrations made elsewhere in the
  binary (a transitive dependency, a hand-rolled experiment, a
  future contributor's debugging helper). The matcher flags the
  absence of `http.NewServeMux()` and any reference to
  `DefaultServeMux` in the handler file.
- **Explicit `http.Server.Handler`.** The API binary's
  `*http.Server` composite literal in `cmd/yalla-api/main.go` MUST
  set `Handler` to a non-nil value. A nil `Handler` falls back to
  `http.DefaultServeMux` per the standard library's documented
  contract, and that fallback would re-introduce the exposure the
  private-mux contract disclaims. The matcher flags both the
  missing field and an explicit `Handler: nil`.
- **No `/debug/*` literal or `pprof.*` / `expvar.*` selector.** No
  production source file under `cmd/yalla-api` or
  `internal/controlplane/httpapi` may carry a `/debug/pprof`,
  `/debug/vars`, `/debug/requests`, or `/debug/events` string
  literal, name `http.DefaultServeMux`, or reference a `pprof.*` or
  `expvar.*` selector. The file-wide pass is belt-and-braces for
  the import scan: a regression that registers the routes through
  a hand-rolled handler or a vendored fork would still leave the
  path literal in source.

The runtime evidence half is implicit: any `/debug/*` request that
slips past the gates is intercepted by `notFoundRecorder` in
`internal/controlplane/httpapi/server.go` and returned as the
stable `yalla.error.v1` envelope with code `E_NOT_FOUND`, while
`telemetry.RequestLogging` records the rejected request in the
redacted structured log. The static analyser ensures we never
register the surface in the first place; `notFoundRecorder` is the
defence-in-depth wall.

The set of legitimate operator-visible routes on the API listener
is closed and documented in the OpenAPI document served at
`GET /openapi.json`: `GET /healthz`, `GET /readyz`,
`GET /healthz/backup`, `GET /version`, plus the customer-facing
`/v1/*` surface. Any genuine operational telemetry (profiling,
live heap snapshots, request traces) MUST be reached out-of-band
from the API process — for example, by attaching `dlv` to a
production replica from inside the cluster, or by exporting metrics
through the OpenTelemetry pipeline that already ships from
`internal/controlplane/telemetry`. The default-mux surface is not
the right transport for any of those.

## Support Access Review

Yalla support staff occasionally need to reach into a customer
organization to triage an incident the customer cannot debug from
the outside. The mechanism is the time-bounded **break-glass
session** orchestrated by `store.BreakGlassService` and exposed at
`POST/GET/DELETE /v1/organizations/{org_id}/break-glass`. Every
elevated-access decision lands on the immutable audit trail with
a stable metadata key so reviewers, alerting, and dashboards can
discover the cross-tenant access. The posture is pinned by
`internal/release/support_access_review_static_test.go` (BE-0358);
the gate rejects any of the following shapes at build time:

- **Audit elevation on every mutation.** Both
  `BreakGlassService.StartSession` and `BreakGlassService.Revoke`
  MUST append an `AuditEvent` whose `Metadata` map carries the
  key `breakGlassElevatedAccessKey` (the literal string
  `elevated_access`). The session row and the audit row are
  committed in the same `Store.Write` transaction; a session
  without its audit trail or an audit row without its session
  cannot exist. The matcher walks both methods on the
  `*BreakGlassService` receiver and rejects any required method
  whose body omits the audit-event stamp or whose method is
  renamed away.
- **Reason and user-agent scrubbing.** The operator-authored
  `reason` and the request's `User-Agent` reach the audit row
  through the store-layer redactor built by `output.NewRedactor`,
  so secrets a careless operator pasted into the reason field are
  scrubbed before persistence. The runtime evidence lives in
  `internal/controlplane/store/break_glass_internal_test.go`
  (`TestBuildSessionToCreateRedactsReasonValue`); the static gate
  asserts each load-bearing method references `svc.redactor` at
  least once so the redactor seam cannot drift.
- **Access-only — no customer credential mint.** The store-layer
  break-glass unit of work in
  `internal/controlplane/store/break_glass_service.go` MUST NOT
  reference any credential-minting collaborator
  (`APIKeyService`, `APIKeyRepository`, `APIKeyCreator`,
  `APIKeyRotator`, `APIKeyIssuer`, `IssueKey`, `MintKey`,
  `RotateKey`, `NewAPIKey`, `ServiceAccountKey`,
  `ServiceAccountKeys`). Break-glass records that a support
  principal reached into the target tenant; the policy engine
  continues to deny anything the principal's role does not
  authorize. The runtime evidence is
  `httpapi.TestSupportPrincipalCannotMintAPIKeys`.
- **Capability binding stays on `CapSupport`.**
  `internal/controlplane/policy/catalog.go` MUST bind
  `ActionAdminBreakGlass` to `CapSupport` in `defaultActionCatalog`
  AND `builtinRoleCaps` MUST grant `CapSupport` to `RoleSupport`
  only. The engine's cross-tenant exception clause is
  `roleCaps.has(CapSupport) && (required == CapRead || required
  == CapSupport)`; demoting the action out of `CapSupport` would
  silently lock support out, while widening `CapSupport` to
  another role would silently grant cross-tenant access to roles
  that have no support remit. The matcher walks both
  package-level maps and reports either drift.
- **Wire shape always advertises elevation.** The HTTP renderer
  `breakGlassSessionResourceOf` in
  `internal/controlplane/httpapi/break_glass.go` MUST hard-code
  `ElevatedAccess: true` in every projected
  `breakGlassSessionResource{...}` literal. A regression that
  omitted the field, projected it from the row, or made it
  conditional would silently strip the review signal from every
  list/get/start/revoke response.

Operators reviewing support access in production should:

1. Filter the audit log for events whose `metadata.elevated_access`
   equals `"true"`. Both `admin.break_glass.start` and
   `admin.break_glass.revoke` are captured, with the
   `target_organization_id`, `break_glass_session_id`,
   `expires_at`, and `ttl_seconds` ride-alongs.
2. Cross-reference the session id back to the durable
   `break_glass_sessions` row via the
   `GET /v1/organizations/{org_id}/break-glass` and
   `GET /v1/organizations/{org_id}/break-glass/{session_id}`
   endpoints — both return the wire shape with
   `elevated_access: true` and `active` computed against the
   current clock.
3. Terminate any session whose review reveals an unauthorized
   reach via `DELETE /v1/organizations/{org_id}/break-glass/
   {session_id}`. The revoke also lands an
   `elevated_access=true` audit row.

The break-glass mechanism is access-only and never mints customer
credentials, so a compromised support principal can be reviewed
and revoked through the audit trail without rotating customer API
keys.

## Environment Variable Redaction

Customer environment variables can carry production secrets — database
passwords, third-party API keys, signing keys, session tokens. The
`internal/controlplane/variables` package is the single place that holds
plaintext for every scope while it is being merged for a Dokploy render. A
regression that lets a raw plaintext or sealed ciphertext escape the
package via a slog record, a customer-facing JSON envelope, an error
message, or an `apierr.FieldViolation` reason would land the secret in
operator logs, customer-facing API responses, or the audit ring buffer —
all of which are effectively persisted (log shippers, on-call dashboards,
post-incident transcripts forward the byte).

**Threat model.** The variables package exposes three customer-visible
shapes: `ScopedVariable` (the input row), `Rendered` (a winning per-key
value), and `Resolved` (the full merged set). Every one of these carries
the plaintext bytes as a struct field — by design, since the resolver
needs the bytes to drive a Dokploy render. The package contract therefore
mandates **three structural redaction seams** between those structs and
any operator- or customer-visible surface:

1. `(ScopedVariable).LogValue`, `(Rendered).LogValue`,
   `(Resolved).LogValue` — slog.LogValuer hooks that replace
   plaintext/ciphertext-bearing fields with `output.Sentinel` before
   slog reflects the struct. A stray `slog.Info("v", v)` capture cannot
   surface the secret.
2. `(Resolved).Explain` — the customer-facing projection
   (`Explained` / `ExplainedVariable`) whose `Value` is always
   `output.Sentinel`. Every JSON envelope and audit-metadata payload
   that needs to surface the effective variable set goes through
   `Explain` first.
3. The package's error surfaces — no `fmt.Sprintf` / `fmt.Errorf` /
   `errors.New` / `apierr.Internal` / `apierr.InvalidInput` /
   `apierr.NotFound` / `apierr.Conflict` call, and no
   `apierr.FieldViolation{Reason: …, Field: …}` composite literal, may
   interpolate a `.Value` or `.SecretCiphertext` selector or a local
   identifier named `plaintext`. The latter is the resolver's
   conventional name for the bytes recovered through
   `secrets.Provider.Open`, so the name is load-bearing for the static
   guard.

**Runtime evidence.** `internal/controlplane/variables/env_var_redaction_test.go`
lands five table-driven runtime tests and two Go fuzz targets:

- `TestRedactionScopedVariableLogValueNeverLeaks` —
  `(ScopedVariable).LogValue` never lands the bracket-marker (and
  therefore neither the plaintext nor the sealed ciphertext bytes) in a
  JSON slog record, for every seed in the corpus.
- `TestRedactionRenderedLogValueNeverLeaks` — same invariant for
  `(Rendered).LogValue`.
- `TestRedactionResolvedLogValueNeverLeaks` — same invariant for
  `(Resolved).LogValue` (which slog also walks per element through the
  `Variables` slice's nested LogValuers).
- `TestRedactionExplainProjectionNeverLeaks` — every
  `(Resolved).Explain` projection's `ExplainedVariable.Value` is exactly
  `output.Sentinel` (bytes-equal, not just contains), and a
  `json.Marshal` of the projection contains no fuzz marker.
- `TestRedactionResolverOpenedSecretValueNeverEntersSlog` — drives the
  resolver end-to-end with a sealed row, opens it through the Plaintext
  provider, and asserts the post-Open plaintext never reaches a slog
  record or a JSON projection.
- `FuzzRedactionScopedVariableLogValue` — opt-in mutation-stage fuzzer
  that widens the corpus coverage of `(ScopedVariable).LogValue`.
- `FuzzRedactionExplain` — opt-in mutation-stage fuzzer that widens the
  corpus coverage of `(Resolved).Explain`.

`internal/controlplane/variables/env_var_redaction_static_test.go` is the
companion static-analysis half. It walks every non-test `.go` file in the
package and fails the build for any of the three structural rules above.
A self-check sub-test parses synthetic bad and good source snippets and
asserts each analyzer reports the expected diagnostics, so a regression
that weakens the analyzer itself is also caught.

The seed corpus mirrors the hostile shapes env-var redaction must survive
— long values, invalid UTF-8, embedded control characters, regex
metacharacters, JSON-escape sequences, NEL line terminator, the
`output.Sentinel` literal itself, and a marker-prefixed literal that
proves the leak detector still fires when the value happens to look like
the marker. CI runs the seed corpus only via `go test ./...`; `-fuzz` is
operator-opt-in.

**Scope exclusions.** Two input classes are deliberately scoped out:

1. A fuzz-supplied value containing the `FUZZENVMARKERLMN` marker itself
   would false-positive the leak detector. The fuzz targets skip it.
   `TestRedactionFuzzScopeExclusionsAreReal` pins the exclusion by
   asserting the seed corpus still includes a marker-prefixed literal so
   the seed-corpus path exercises the leak detector when the value
   happens to look like the marker.
2. The variable Key. Keys are validated against the resolver's
   POSIX-shell `envVarName` regex at the resolver entry, so a Key
   carrying control characters never reaches `LogValue` or `Explain` in
   production. The runtime targets fix Key to a valid identifier; the
   exclusion test confirms the resolver still rejects hostile-shaped
   keys.

**No live secrets.** The fuzz suite registers synthetic markers
(`"FUZZENVMARKERLMN"`) and synthetic values (the corpus or the fuzzer's
mutated raw bytes wrapped in marker brackets) — never real customer
secrets, real Dokploy tokens, or real API keys.

## Dokploy Token Isolation

The privileged Dokploy bearer token (`YALLA_DOKPLOY_TOKEN`) is the
master credential the Yalla control plane uses to mutate any resource
inside the operator's private Dokploy installation. A leak — into
operator logs, customer-facing JSON responses, the audit ring buffer,
or an error message — would compromise every customer organization
the Dokploy instance hosts. A regression that piped the token into a
customer-facing HTTP handler would let any authenticated customer
mint privileged Dokploy requests directly, bypassing the worker
queue, the audit trail, and Yalla's per-tenant policy decisions. The
posture below is pinned by
`internal/release/dokploy_token_isolation_static_test.go` (BE-0361);
the gate rejects any of the following shapes at build time, and the
runtime evidence in
`internal/controlplane/config/dokploy_token_isolation_test.go`,
`internal/controlplane/dokploy/client_test.go`
(`TestClientRedactsSecrets`, `TestClientLogValueRedactsToken`), and
the auth-failure path of `TestClientAuthorizationFailure` proves the
operator-visible projections never carry the bearer.

- **Single in-process consumer.** The Dokploy token MUST flow into
  exactly one in-process consumer — the typed `*Client` in
  `internal/controlplane/dokploy/client.go`, where it is bound to
  the unexported `token` field of `*Client`. The `Client` struct's
  bearer-token field MUST remain unexported (lowercase `token`); an
  exported `Token` field would let any caller read the secret via a
  selector. The matcher walks the `Client` struct's fields and
  rejects any exported field whose lowercased name is `token`.
- **One wire emission site.** The `.token` selector against a
  `*Client` receiver MUST appear in exactly one location across all
  production `.go` files under `internal/controlplane/dokploy` —
  the canonical `Authorization: Bearer <token>` header injection
  (`req.Header.Set("Authorization", "Bearer "+c.token)`) in
  `client.go`'s `attempt` method. The constructor's
  `token: token` composite-literal binding is a `KeyValueExpr.Key`,
  not a selector, and is the only other legitimate token-touching
  site. A regression that added a `fmt.Errorf("token %q rejected",
  c.token)`, a `slog.String("token", c.token)`, an audit-metadata
  stamp, or an envelope projection would surface the bytes in
  operator logs, error messages, or customer-facing responses; the
  matcher counts every `.token` selector across the production
  package and rejects any count other than 1, plus pins the single
  allowed location to `client.go`.
- **Customer-facing surface is quarantined.** No production source
  file under `internal/controlplane/httpapi` may name
  `dokploy.Client`, `dokploy.NewClient`, or `dokploy.Config` — the
  three token-bearing entry points of the dokploy package. The
  handler tree legitimately imports the dokploy package to consume
  the value enum (`dokploy.ServiceType`, `dokploy.ServiceApplication`,
  `dokploy.ServiceDatabase`, `dokploy.ServiceCompose`) for desired-
  state rendering; that surface carries no token. The matcher also
  rejects any SelectorExpr ending in `.DokployToken` (catching
  `config.DokployToken`, `cfg.DokployToken`, and any other receiver
  alike) and any reference to `EnvDokployToken` or
  `config.EnvDokployToken` from httpapi production sources — a
  handler that read the env-var directly would short-circuit the
  redaction seam and would let customer-facing code mint privileged
  Dokploy requests outside the worker boundary.
- **Operator-visible projections go through the redactor.**
  `(*Config).Redacted()` MUST stamp the `DokployToken` field via
  the local `redact(...)` closure so the returned `RedactedConfig`
  carries the `[REDACTED]` sentinel, not the secret. The matcher
  walks the Redacted method's returned composite literal, locates
  the `DokployToken` field, and rejects a value that is not a
  `redact(...)` call expression. `(*Config).LogValue()` MUST
  consult `c.Redacted()` first AND MUST NOT touch `c.DokployToken`
  directly; the redaction seam is the only thing standing between
  an accidental `slog.Any("config", c)` capture and the bearer
  landing in the structured log stream. The matcher pins both
  shapes.

**Runtime evidence.** Three table-driven tests under
`internal/controlplane/config/dokploy_token_isolation_test.go` close
the runtime half: every fixture installs the canonical
`BE0361DOKPLOYTOKENMARKERXYZ` marker prefix on the
`Config.DokployToken` field and asserts the marker never appears in
the `Redacted()` JSON projection, in the slog-JSON-handler output
under `slog.Any("config", c)`, or in the `(*Config).String()` debug
projection. The marker pattern is the leak detector — asserting the
token's bytes alone would false-positive whenever the value happens
to equal a substring of the stable projection text (e.g. the field
name `dokploy_token`), so the unique marker prefix is what makes the
detector load-bearing under fuzzed inputs.

**No live secrets.** The test suite installs synthetic marker
prefixes (`"BE0361DOKPLOYTOKENMARKERXYZ"`) — never real Dokploy
service tokens.

## Backup Encryption

The Yalla source-of-truth Postgres database is the only place
tenant identity, scoped grants, desired state, deployments, audit
history, and provisioning-job rows can be reconstructed from. A
lost or tampered backup is an unrecoverable outage — Dokploy can be
re-provisioned from desired state, but desired state cannot be
reconstructed from Dokploy. The backup pipeline is intentionally
**external** to the Yalla process: `pg_dump` / `pgBackRest` runs
under the operator's pipeline, encrypts every object with a KMS-
managed key under the operator's principal, and writes to object
storage neither the control-plane API nor the worker has **read
access** to. Yalla consumes exactly one signal — a single RFC3339
timestamp the pipeline atomically writes to the status file named
by `YALLA_BACKUP_STATUS_FILE`. The operator-facing detail lives in
`docs/operations/backup-restore.md` (KMS rotation cadence,
plaintext-WAL ban, restore audit-event posture); the Yalla-side
posture is pinned by
`internal/release/backup_encryption_static_test.go` (BE-0362). The
gate rejects any of the following shapes at build time, and the
runtime evidence in
`internal/controlplane/backup/encryption_isolation_test.go`
(`TestFileReporterEncryptionMarkerNeverLeaks`,
`TestFileReporterEncryptionMarkerSurvivesErrorWrapping`) and the
pre-existing `TestFileReporterParseErrorRedactsContent` (BE-0039)
plus the handler-side
`TestBackupHealthErrorMessageDoesNotLeakReporterError` prove the
redaction seam holds across encryption-shaped status-file content:

- **No backup data plane inside the Yalla process.** No production
  source file under `internal/controlplane/backup` may import a
  package whose presence implies the Yalla process produces,
  encrypts, ships, or restores backup data. The closed forbidden
  set is `crypto/aes`, `crypto/cipher`, `crypto/des`, `crypto/rc4`,
  `crypto/rsa`, `crypto/ecdsa`, `crypto/ed25519`, `crypto/tls`,
  `archive/zip`, `archive/tar`, `compress/gzip`, `compress/zlib`,
  `compress/flate`, `compress/bzip2`, `database/sql`,
  `github.com/jackc/pgx/v5`, `github.com/jackc/pgx/v5/pgxpool`,
  `os/exec`, and `net/http`. A regression that pulled any of these
  into the package would collapse the encryption boundary in two
  ways: (a) the encryption key (or bucket credential, or database
  role) would need to live inside the Yalla config surface, where
  the redaction seam alone cannot protect it once a decryption
  library is on the call path; (b) the same process handling
  customer requests would gain read access to the encrypted blobs,
  dissolving the no-read-access invariant.
- **`Reporter.Status` is the only port.** The `Reporter` interface
  declared in `internal/controlplane/backup/health.go` MUST expose
  exactly one method, named `Status`. A `Write`, `Backup`,
  `Restore`, `Encrypt`, `Decrypt`, `Upload`, or `Rotate` method
  would route a backup data plane through the read-only port. The
  matcher rejects every other method name and every embedded
  interface (so a future `embed io.Writer` cannot silently expand
  the surface). A renamed interface is also a regression because
  the gate would silently disable itself otherwise.
- **No write seams.** No production source file under
  `internal/controlplane/backup` may call `os.Create`,
  `os.CreateTemp`, `os.WriteFile`, `os.OpenFile`, `os.Mkdir`,
  `os.MkdirAll`, `os.Rename`, `os.Remove`, `os.RemoveAll`,
  `os.Symlink`, `os.Link`, `os.Truncate`, `os.Chmod`, `os.Chown`,
  `exec.Command`, or `exec.CommandContext`. The legitimate I/O is
  `os.ReadFile` against the operator-supplied status path —
  nothing else. A write-seam regression would indicate the Yalla
  process writes backup data, shells out to `pg_dump`, or mutates
  the operator's filesystem under the backup mount.
- **Operator-facing runbook is part of the public contract.**
  `docs/operations/backup-restore.md` MUST keep its
  `## Encryption expectations` section with the load-bearing
  substrings `KMS-managed key`, `read access`, `Plaintext WAL`,
  and `Auditability`. The runbook is how operators learn
  the KMS rotation cadence (90 days), the no-read-access
  invariant for the control-plane API and worker processes, the
  plaintext-WAL ban, and the audit-event contract for restores. A
  silent removal of any of those substrings is a regression on
  equal footing with a code change.

**Runtime evidence.** Four parameterised fixtures
(`kms-key-id`, `aes-wrap-blob`, `restore-failed-message`,
`pem-private-key`) install the canonical `BE0362KMSMARKERXYZ`
marker prefix inside encryption-shaped status-file payloads and
assert the marker never appears in the parse error, in any layer of
the wrapped error chain, or in the JSON projection of the returned
`backup.Status` struct. The marker pattern is the leak detector —
asserting the payload's bytes alone would false-positive whenever
the content happens to share a substring with a stable error phrase
(e.g. a fixture containing "is malformed" would trip the existing
"backup: status file is malformed" message), so the unique marker
prefix is what makes the detector load-bearing across fuzzed
inputs.

**No live secrets.** The test suite installs synthetic marker
prefixes (`"BE0362KMSMARKERXYZ"`) — never real KMS key material,
backup bucket credentials, or PEM private keys.

## Log Redaction Fuzzing

Every customer-controllable string that reaches a log record passes
through `internal/output.Redactor` first. The `Redactor` is the
**defence-in-depth** seam that strips three classes of secret-shaped
content from human-readable output:

1. Literal secrets the renderer was constructed with (the CLI's
   `--token`, refresh tokens, future explicitly-flagged inputs).
2. Authorization-class transport headers — `Authorization:`,
   `X-API-Key:`, `X-Auth-Token:` — regardless of casing or the
   value's content.
3. Token-bearing query parameters — `?token=`, `?api_key=`,
   `?access_token=`, `?x-auth-token=` and their `_`/`-` variants —
   regardless of casing or the value's content.

The first wall is error classification (every user-visible failure
is a typed `internal/errors.Error` with a stable `Code`, so secrets
never enter the error surface to begin with). The Redactor is the
second wall: even when a careless caller passes an URL that
smuggles `?token=abcd1234` through the request target, the
per-request log record in `internal/controlplane/telemetry/logging.go`
runs the entire target through `logRedactor.Redact` before slog
sees it.

**Threat model.** A regression that weakens any of the structural
rules — a renamed header, a relaxed regex, a `strings.ReplaceAll`
miss — would leak secrets into the structured log stream, where
operators expect redacted records. Once a secret reaches stdout or
the audit ring buffer, it is effectively persisted: log shippers,
on-call dashboards, and post-incident transcripts all carry it
forward. The fuzz suite below is the runtime evidence that the
Redactor's structural rules survive hostile inputs.

**Runtime evidence.** `internal/output/redact_fuzz_test.go` lands
four Go fuzz targets and a scope-exclusion regression:

- `FuzzRedactor_NoPanic` — `Redact` cannot be made to panic by any
  `(secret, haystack)` pair, because a panic inside the request
  logger would surface the unredacted URL in the runtime panic
  dump.
- `FuzzRedactor_ExplicitSecretNeverLeaks` — a literal secret
  registered with `NewRedactor` never appears in `Redact`'s output
  for any haystack within the contract scope.
- `FuzzRedactor_AuthorizationHeaderNeverLeaks` — the bearer regex
  scrubs every `Authorization:` / `X-API-Key:` / `X-Auth-Token:`
  line value, regardless of casing or value content.
- `FuzzRedactor_QueryTokenNeverLeaks` — the queryToken regex
  scrubs every supported key shape, regardless of casing or value
  content.
- `FuzzRedactor_Idempotent` — `Redact(Redact(s)) == Redact(s)` for
  every input in the contract scope, so a rewrite cannot oscillate
  between passes.

The seed corpus runs as part of `go test ./...`, so every commit
exercises the regression net even without `-fuzz`. The `-fuzz`
flag is operator-opt-in and exercises the random-mutation stage.

**Scope exclusions.** Three input classes are deliberately scoped
out of the fuzz domain because the contract does not promise them:

1. Secrets shorter than `minRedactableLen` (4) after `TrimSpace`
   are dropped by `NewRedactor` (a test fixture, not a real
   token).
2. Secrets that overlap the literal sentinel `[REDACTED]` in
   either direction would race the sentinel substring through
   `strings.ReplaceAll`. An operator who manages to pick
   `[REDACTED]` as a real secret has a worse problem than logging.
3. CR/LF inside a header-borne value ends the bearer regex match
   at the linebreak by design (one header per line); a value that
   wraps lines is a misfeature of the input, not the redactor.

`TestRedactor_FuzzScopeExclusionsAreReal` pins these exclusions
as the current behaviour. A future Redactor change that closes
one of the gaps (for example by replacing the explicit-secret
pass with a single regex substitution that does not re-scan
substituted text) MUST update both the fuzz scope comments and
this `SECURITY.md` section so the threat model stays accurate.

**No live secrets.** The fuzz suite registers synthetic markers
(`"FUZZAUTHMARKERXYZ"`, `"FUZZQRYMARKERZYX"`) and synthetic
secrets (the fuzzer's mutated raw bytes wrapped in `~…~` markers)
— never real `--token` values, real Dokploy tokens, or real
customer API keys.

## Rate Limit Bypass Resistance

The customer-facing HTTP rate-limit gate
(`internal/controlplane/httpapi/ratelimit.go`, BE-0035) bills three
in-memory token buckets in order: the resolved organization, the
resolved API key / session principal, and the resolved client IP.
The dimension name (`organization` / `api_key` / `ip`) is the only
identity Yalla puts on the wire. The bucket *identity* (a tenant
org id, an API key id, a client IP) is never echoed to the wire,
to the structured WARN log record, or to the `Decision.Bucket`
field. A regression that smuggled a bucket identity onto any of
those surfaces would turn the throttling signal into a
cross-tenant leak.

**Threat model.** Five bypass-shaped regressions are explicitly
out of scope for this control:

1. **Forged internal-worker claim.** The internal-worker
   credential scheme is the one and only bypass: a request whose
   principal authenticated through `auth.MethodInternalWorker`
   carries `ratelimit.Request.Exempt = true` and is
   unconditionally allowed. A regression that set `Exempt = true`
   on any code path other than "the resolved auth method is
   `auth.MethodInternalWorker`" — for example, a request that
   carries an `X-Yalla-Internal: 1` header, a path that begins
   with `/v1/internal`, or a private-range source IP — would let
   an external attacker spoof their way past the gate.
2. **Bucket-identity leak.** A `Decision.Bucket` value other than
   `ratelimit.BucketOrg`, `ratelimit.BucketKey`, or
   `ratelimit.BucketIP` would push the bucket identity into the
   `apierr.RateLimited` detail map and onto the wire envelope's
   `details["scope"]` slot.
3. **Non-canonical 429 emission.** A bare `http.Error`, a
   hand-rolled JSON `fmt.Fprintf`, or a direct
   `w.Write([]byte(...))` in the deny branch would either lose
   the stable `yalla.error.v1` envelope or embed the limiter's
   internal error string in the body. The only legal emission
   seam is `apienvelope.WriteError(w, requestID(r),
   apierr.RateLimited(decision.Bucket, retry))`.
4. **Un-wrapped route.** `server.go` MUST hold exactly one
   `RateLimit(...)` construction site and the per-route loop body
   MUST pass every served handler through `rateLimit(h)`. A
   regression that wrapped only some routes would let an
   attacker bypass the gate by hitting the un-wrapped route.
5. **`X-Forwarded-For` chain spoofing.** `ClientIP` parses only
   the first comma-separated entry of `X-Forwarded-For`. A bogus
   suffix cannot push the real client identity out of the bucket
   key; a forged prefix is acceptable only when a trusted reverse
   proxy is in front (the TLS/proxy header trust posture in
   SECURITY.md's "TLS Termination and Proxy Header Trust"
   section).

**Static evidence (structural half).** The static gate
`rate_limit_bypass_resistance_static_test.go`
(under `internal/release/`, BE-0363) walks the production AST
and asserts:

- Exactly one `Exempt = true` assignment lives in the
  `internal/controlplane/httpapi` package production tree, and
  it sits inside an `if` whose condition references
  `auth.MethodInternalWorker`.
- Every `Decision{Bucket: ...}` composite literal in
  `internal/controlplane/ratelimit/limiter.go` uses one of the
  three named constants (`BucketOrg`, `BucketKey`, `BucketIP`).
- The 429 emission seam in `ratelimit.go` is exactly one
  `apienvelope.WriteError` call wrapped around exactly one
  `apierr.RateLimited` call, with no `http.Error`,
  `fmt.Fprintf(w, ...)`, or `w.Write([]byte(...))` siblings.
- `server.go` holds exactly one `RateLimit(...)` construction
  site and exactly one `h = rateLimit(h)` per-route wrap.

A self-check
(`TestRateLimitBypassResistanceStaticAnalyzerDetectsRegressions`)
installs intentionally-broken fixtures and proves each matcher
flags its regression class, so the positive-case silence of the
production tree today is never a false negative.

**Runtime evidence (behavioural half).**
`internal/controlplane/httpapi/ratelimit_bypass_test.go` proves
the same invariants end-to-end through the middleware:

- A request with `X-Yalla-Internal: 1`,
  `X-Yalla-Auth-Method: internal_worker`, or any other
  attacker-controlled header CANNOT flip `Exempt` to true; the
  limiter still bills the customer bucket and the request is
  deniable.
- A request to `/v1/internal/...` cannot bypass the gate; the
  path is not a bypass signal.
- A request stamped with a non-internal-worker auth method
  (`auth.MethodAPIKey`) is rate-limited normally.
- A chained `X-Forwarded-For` value honours the first hop only;
  the bypass-marker tail never reaches the bucket key.
- A concurrent burst of 20 parallel requests against a single
  per-key bucket with `Burst=3` cannot grant more than 3
  successes (atomicity of the production `*ratelimit.Limiter`).
- The WARN log record emitted on a denial carries only the
  bucket dimension name; the bucket identity (principal id, org
  id, client IP) never appears in the record.
- The 429 wire envelope body carries `details["scope"]` equal to
  one of `organization` / `api_key` / `ip`, never the bucket
  identity.
- An anonymous request (no principal, no auth method) still
  consults the limiter and falls through to the IP bucket — the
  "send anonymous to skip the gate" bypass does not exist.

**Bypass-marker sentinel.** Every runtime test prefixes its
attacker-controlled fields with the constant
`bypassMarker = "BE0363RATELIMITBYPASSMARKERXYZ"` (longer than
any realistic header value), then asserts the marker never
reaches the limiter's `Exempt` flag, the deny log record's
non-path slots, or the 429 envelope body. The marker is the
leak detector — asserting on the bucket dimension name alone
would false-positive whenever the value happens to equal a
substring of the stable projection text.

**No live secrets.** The test suite uses synthetic marker
prefixes only — never real `Authorization` bearer tokens, real
Dokploy tokens, or real customer API keys.

## Unit Test Suite

Yalla's unit-and-integration test suite is the load-bearing
foundation under every other security gate in this document. If
`go test ./...` stops running on every push and PR, every
downstream gate (SQL injection resistance, cookie hardening,
backup encryption, rate-limit bypass resistance, ...) silently
stops being enforced — they are all `go test`-shaped invariants.
BE-0379 publishes the contract operators and AI agents rely on:

- **Scope.** Every Go package in this repository ships a
  `*_test.go` file. The single static defence is
  `internal/release/verification_suite_unit_tests_static_test.go`,
  which walks the repo and fails the build for any package that
  contains non-test `.go` source without a matching `_test.go`
  file AND is not in the closed exemption set
  `allowedPackagesWithoutUnitTests`. Every exemption carries a
  rationale that points to where the behaviour is actually
  covered (release tests for `cmd/yalla-api` boot, `internal/cli`
  for `cmd/yalla` glue, etc.); a stale exemption (an exempt
  package that has since gained tests) fails the build too.
- **Determinism.** The suite runs against deterministic fixtures
  only. The HTTP, store, policy, quota, and worker layers are
  exercised with fake Dokploy fixtures
  (`internal/controlplane/dokploy` and
  `internal/controlplane/worker` fakes); a live Dokploy smoke is
  opt-in via `YALLA_EXTERNAL_DOKPLOY=1 go test -run
  TestLiveDokploySmoke ./...` and never runs in the default gate.
  Postgres integration tests run against an isolated migrated
  database and never touch a shared instance.
- **Actionable failures.** Every contract test surfaces the
  failing request ID, resource ID, or envelope `code` and
  `request_id` field in its diagnostic so an operator reading the
  CI log can map the failure to the exact request without
  re-running the suite locally. Per-endpoint tests pin the
  `yalla.output.v1` / `yalla.error.v1` envelope shape so a wire
  contract regression is caught before it ships.
- **Redaction.** Test output, structured log capture, error
  envelopes, audit metadata, and dry-run payloads MUST stay
  redacted of secrets — bearer tokens, API keys, Dokploy tokens,
  customer cookies, and rendered environment-variable values are
  scrubbed by `internal/output.Redactor`. The redaction contract
  is fuzzed in `internal/output/redact_fuzz_test.go` (BE-0359) so
  a marker-bracketed value never survives the log path.
- **CI gating.** `go test ./...` runs on `ubuntu-latest`,
  `macos-latest`, and `windows-latest` for every push and every
  pull request via `.github/workflows/ci.yml` (the `test` job's
  step `Unit and integration tests`), and locally via
  `scripts/verify.sh` (step `# 4. Required: tests`). Both must
  pass before a commit lands in `main`. The same gate appears in
  the verification-gates table above as the row
  `| Tests | go test ./... | scripts/verify.sh, CI | Every push and PR |`,
  in `CONTRIBUTING.md` under
  `## Required Checks Before Every Commit`, and in
  `ralph/prd.json` under
  `verificationLoop.requiredLocalCommands` so an AI agent reading
  the PRD before picking up a story sees the gate without needing
  to discover it from shell scripts or CI workflows.

## Repository Integration Tests

Yalla's repository integration tests are the persistence-layer
gate that catches regressions before they reach the HTTP API.
The suite under `internal/controlplane/store/...` exercises every
repository method — organizations, users, API keys, projects,
environments, services, deployments, audit events, idempotency,
jobs, quota counters — against an isolated migrated Postgres
database using deterministic fixtures; it never depends on a live
Dokploy server, and any fake Dokploy interaction it consumes lives
in `internal/controlplane/dokploy` so the live external smoke
remains opt-in via `YALLA_EXTERNAL_DOKPLOY=1 go test -run
TestLiveDokploySmoke ./...`. The canonical command is
`go test ./internal/controlplane/store/...`. BE-0380 publishes the
contract operators and AI agents rely on:

- **Scope.** Every repository method ships tenant-isolation tests
  that prove cross-organization IDs cannot surface another
  tenant's rows. `TestMigrations` in
  `internal/controlplane/store/migrate/migrate_test.go` runs the
  migration ladder forward from an empty Postgres so a future
  contributor adding a migration cannot silently break the
  initial-bootstrap contract; the PRD's
  `go test -run TestMigrations ./...` command binds to that exact
  function name.
- **Determinism.** The repository tests run against deterministic
  fixtures only — an isolated migrated database per test run with
  no shared instance state, and any Dokploy interaction is
  satisfied by a fake Dokploy fixture from
  `internal/controlplane/dokploy`. A live Dokploy smoke is
  opt-in via `YALLA_EXTERNAL_DOKPLOY=1` and never runs in the
  default gate.
- **Actionable failures.** Every assertion surfaces the failing
  `resource_id` (organization_id, project_id, environment_id,
  service_id, deployment_id, audit event id) and — for
  HTTP-facing repository tests — the `request_id` so an operator
  reading the CI log can map the failure to the exact row or
  request without re-running the suite locally. Per-method tests
  pin the `yalla.output.v1` / `yalla.error.v1` envelope shape
  where the repository sits behind a handler, so a wire-contract
  regression is caught at the persistence boundary too.
- **Redaction.** Test output, structured log capture, error
  envelopes, audit metadata, and dry-run payloads MUST stay
  redacted of secrets — bearer tokens, API keys, Dokploy tokens,
  customer cookies, and rendered environment-variable values are
  scrubbed by `internal/output.Redactor`. Repository tests that
  serialize a row carrying a secret column (API key hash,
  environment-variable rendered value, Dokploy token) MUST flow
  through the redactor before logging or printing — the BE-0359
  fuzz harness in `internal/output/redact_fuzz_test.go` covers
  the marker-bracketed-value contract end-to-end.
- **CI gating.** `go test ./internal/controlplane/store/...` runs
  on `ubuntu-latest`, `macos-latest`, and `windows-latest` for
  every push and every pull request via
  `.github/workflows/ci.yml` (the `test` job's step `Repository
  integration tests`), and locally via `scripts/verify.sh`
  (step `# 6. Required: repository integration tests`). Both
  must pass before a commit lands in `main`. The same gate
  appears in the verification-gates table above as the row
  `| Repository integration tests | go test ./internal/controlplane/store/... | scripts/verify.sh, CI | Every push and PR |`,
  in `CONTRIBUTING.md` under `## Required Checks Before Every
  Commit`, and in `ralph/prd.json` under
  `verificationLoop.requiredBackendCommands` so an AI agent
  reading the PRD before picking up a story sees the gate
  without needing to discover it from shell scripts or CI
  workflows. The single static defence that pins every one of
  those surfaces is
  `internal/release/verification_suite_repo_integration_static_test.go`.

## HTTP Handler Contract Tests

Yalla's HTTP handler contract tests are the wire-contract gate that
catches API regressions before they reach a customer, an AI agent, or
a CI pipeline. The suite lives under
`internal/controlplane/httpapi/` in `*_contract_test.go` files —
every public HTTP endpoint ships one — and the canonical command is
`go test ./internal/controlplane/httpapi/...`. The suite exercises
the handler layer end-to-end against deterministic fixtures (fake
authenticators, fake repositories, fake Dokploy, an in-memory
`httptest.Server`); it never depends on a live Dokploy server, and
any external smoke remains opt-in via `YALLA_EXTERNAL_DOKPLOY=1
go test -run TestLiveDokploySmoke ./...`. BE-0381 publishes the
contract operators and AI agents rely on:

- **Scope.** Every public HTTP endpoint exposed by
  `internal/controlplane/httpapi` ships a `*_contract_test.go`
  file. The single static defence is
  `internal/release/verification_suite_handler_contract_tests_static_test.go`,
  which pins the existence of the canonical
  `me_contract_test.go` file (the `GET /v1/me` contract — the
  oldest and most-cited contract test in the repo) so the
  contract-test convention itself cannot be silently deleted, and
  pins the existence of the per-endpoint contract triple
  (`ServerWritesResponseDataOnlyToResponseWriter`,
  `RequestLogRedactsBearerToken`,
  `ErrorEnvelopeDoesNotLeakDependencyCause`) so a refactor that
  drops one of the three load-bearing assertions fails the gate.
- **Determinism.** The handler contract tests run against
  deterministic fixtures only — fake authenticators, fake
  repositories, fake Dokploy from `internal/controlplane/dokploy`
  and `internal/controlplane/worker`, an in-memory
  `httptest.Server`, and a deterministic `slog` capture. No
  contract test reaches a live Postgres, a live Dokploy, or any
  network. A live Dokploy smoke is opt-in via
  `YALLA_EXTERNAL_DOKPLOY=1` and never runs in the default gate.
- **Actionable failures.** Every contract test surfaces the
  failing `request_id` (and, where the endpoint owns a resource,
  the `resource_id`) and the envelope `code` field in its
  diagnostic so an operator reading the CI log can map the
  failure to the exact request without re-running the suite
  locally. Per-endpoint tests pin the `yalla.output.v1` /
  `yalla.error.v1` envelope shape so a wire-contract regression
  is caught before it ships.
- **Coverage rows.** Each contract test covers success,
  validation failure, authentication failure, authorization
  failure, and not-found behaviour where the endpoint owns a
  resource; quota-failure and conflict rows are covered where
  the endpoint mutates desired state. The contract triple
  (`ServerWritesResponseDataOnlyToResponseWriter` /
  `RequestLogRedactsBearerToken` /
  `ErrorEnvelopeDoesNotLeakDependencyCause`) is the load-bearing
  shared invariant every endpoint MUST keep: response data goes
  only through the `http.ResponseWriter` (never to stdout or
  stderr), the per-request structured log stays redacted of
  bearer credentials even on the authorization-failure path, and
  an error envelope built from a wrapped dependency cause never
  leaks that cause onto the wire.
- **Redaction.** Test output, structured log capture, error
  envelopes, audit metadata, and dry-run payloads MUST stay
  redacted of secrets — bearer tokens, API keys, Dokploy tokens,
  customer cookies, and rendered environment-variable values are
  scrubbed by `internal/output.Redactor`. The
  `RequestLogRedactsBearerToken` half of the contract triple
  asserts this end-to-end on the handler path; the BE-0359 fuzz
  harness in `internal/output/redact_fuzz_test.go` covers the
  marker-bracketed-value contract at the redactor itself.
- **CI gating.** `go test ./internal/controlplane/httpapi/...`
  runs on `ubuntu-latest`, `macos-latest`, and `windows-latest`
  for every push and every pull request via
  `.github/workflows/ci.yml` (the `test` job's step `HTTP
  handler contract tests`), and locally via `scripts/verify.sh`
  (step `# 7. Required: HTTP handler contract tests`). Both
  must pass before a commit lands in `main`. The same gate
  appears in the verification-gates table above as the row
  `| HTTP handler contract tests | go test ./internal/controlplane/httpapi/... | scripts/verify.sh, CI | Every push and PR |`,
  in `CONTRIBUTING.md` under `## Required Checks Before Every
  Commit`, and in `ralph/prd.json` under
  `verificationLoop.requiredBackendCommands` so an AI agent
  reading the PRD before picking up a story sees the gate
  without needing to discover it from shell scripts or CI
  workflows. The single static defence that pins every one of
  those surfaces is
  `internal/release/verification_suite_handler_contract_tests_static_test.go`.

## OpenAPI Schema Conformance Tests

Yalla's OpenAPI schema conformance tests are the published-document
gate that ensures the `/openapi.json` artifact every customer, AI
agent, CI pipeline, and downstream SDK reads is structurally
correct. The suite lives under `internal/controlplane/openapi/` —
the package that builds the OpenAPI 3.1 document from the neutral
`[]Endpoint` slice the `internal/controlplane/httpapi` route table
supplies — and the canonical command is
`go test ./internal/controlplane/openapi/...`. The suite exercises
the document builder end-to-end against deterministic fixtures (a
hand-curated public + authenticated endpoint pair, deterministic
JSON marshalling, redaction sentinels in every example); it never
depends on a live Dokploy server, and any external smoke remains
opt-in via `YALLA_EXTERNAL_DOKPLOY=1
go test -run TestLiveDokploySmoke ./...`. BE-0382 publishes the
contract operators and AI agents rely on:

- **Scope.** Every documented HTTP operation that
  `internal/controlplane/openapi` surfaces in the
  `/openapi.json` artifact is covered by the conformance suite.
  The single static defence is
  `internal/release/verification_suite_openapi_conformance_static_test.go`,
  which pins the existence of the canonical
  `openapi_conformance_test.go` file and the canonical
  `TestOpenAPIConformance` function (the load-bearing
  `-run TestOpenAPI` filter from
  `verificationLoop.requiredBackendCommands` binds to that exact
  function name) so the conformance convention itself cannot be
  silently deleted or renamed.
- **Determinism.** The OpenAPI conformance tests run against
  deterministic fixtures only — a hand-curated
  public+authenticated `[]Endpoint` slice, deterministic JSON
  marshalling driven by `marshalSortedMap`, and redaction
  sentinels from `internal/output.Sentinel` in every example
  body. No conformance test reaches a live Postgres, a live
  Dokploy, or any network. A live Dokploy smoke is opt-in via
  `YALLA_EXTERNAL_DOKPLOY=1` and never runs in the default gate.
- **Actionable failures.** Every conformance test surfaces the
  failing `operationId`, method, and path in its diagnostic so an
  operator reading the CI log can map the failure to the exact
  documented endpoint without re-running the suite locally. The
  schema-version contract pins the `yalla.output.v1` /
  `yalla.error.v1` envelope shape in the published
  `SuccessEnvelope` and `ErrorEnvelope` component schemas so a
  wire-contract regression is caught at document build time.
- **Coverage rows.** Each conformance test covers success
  (`SuccessEnvelope` with `schema_version` enum
  `yalla.output.v1`), error (`ErrorEnvelope` with
  `schema_version` enum `yalla.error.v1`), authentication
  (`ApiKeyAuth` security scheme requirement on every
  `RequiresAuth: true` endpoint and empty security on every
  public endpoint), authorization (`x-required-action` OpenAPI
  extension echoes the policy action constant), and path
  parameter declarations (`required: true`, `in: path`, string
  schema) where the endpoint owns one. The conformance triple
  (`TestOpenAPIConformance` / `TestOpenAPIEnvelopesReferenceStableSchemaVersions` /
  `TestOpenAPIExamplesAreRedacted`) is the load-bearing shared
  invariant every documented operation MUST keep: every endpoint
  declares both a documented success response and a stable
  error-envelope response, every envelope schema_version enum is
  pinned to the published constant, and every example body that
  resembles a credential is rendered through the redaction
  sentinel rather than a live secret.
- **Redaction.** Document examples, structured log capture,
  error envelopes, and dry-run payloads MUST stay redacted of
  secrets — bearer tokens, API keys, Dokploy tokens, customer
  cookies, and rendered environment-variable values are scrubbed
  by `internal/output.Redactor`. The `TestOpenAPIExamplesAreRedacted`
  conformance test asserts this end-to-end on the published
  document path; the BE-0359 fuzz harness in
  `internal/output/redact_fuzz_test.go` covers the
  marker-bracketed-value contract at the redactor itself.
- **CI gating.** `go test ./internal/controlplane/openapi/...`
  runs on `ubuntu-latest`, `macos-latest`, and `windows-latest`
  for every push and every pull request via
  `.github/workflows/ci.yml` (the `test` job's step `OpenAPI
  schema conformance tests`), and locally via `scripts/verify.sh`
  (step `# 8. Required: OpenAPI schema conformance tests`). Both
  must pass before a commit lands in `main`. The same gate
  appears in the verification-gates table above as the row
  `| OpenAPI schema conformance tests | go test ./internal/controlplane/openapi/... | scripts/verify.sh, CI | Every push and PR |`,
  in `CONTRIBUTING.md` under `## Required Checks Before Every
  Commit`, and in `ralph/prd.json` under
  `verificationLoop.requiredBackendCommands` so an AI agent
  reading the PRD before picking up a story sees the gate
  without needing to discover it from shell scripts or CI
  workflows. The single static defence that pins every one of
  those surfaces is
  `internal/release/verification_suite_openapi_conformance_static_test.go`.

## Policy Matrix Tests

Yalla's policy matrix tests are the RBAC + cross-tenant gate that
ensures the engine in `internal/controlplane/policy` deterministically
authorises every catalogued action for every built-in role and never
silently allows a cross-organization read or write. The suite lives
under `internal/controlplane/policy/` and the canonical command is
`go test -run TestPolicyMatrix ./...`. The suite exercises the
decision engine end-to-end against deterministic fixtures
(`principalIn(orgA, role)`, `resourceIn(orgA)`/`resourceIn(orgB)`,
the full `BuiltinRoles()` × `Actions()` cross-product); it never
depends on a live Postgres or a live Dokploy server, and any
external smoke remains opt-in via `YALLA_EXTERNAL_DOKPLOY=1
go test -run TestLiveDokploySmoke ./...`. BE-0383 publishes the
contract operators and AI agents rely on:

- **Scope.** Every built-in role × every catalogued action is
  exercised on an in-organization resource (`TestPolicyMatrix`)
  and on a foreign-organization resource
  (`TestPolicyMatrixDeniesCrossTenant`). The single static defence
  is
  `internal/release/verification_suite_policy_matrix_static_test.go`,
  which pins the existence of the canonical
  `internal/controlplane/policy/policy_test.go` file and the
  canonical `TestPolicyMatrix` + `TestPolicyMatrixDeniesCrossTenant`
  function pair (the load-bearing `-run TestPolicyMatrix` filter
  from `verificationLoop.requiredBackendCommands` binds to that
  prefix) so the matrix convention itself cannot be silently
  deleted or renamed.
- **Determinism.** The policy matrix tests run against
  deterministic fixtures only — in-memory `Principal`, `Resource`,
  and `Grant` values constructed by the package's test helpers,
  no I/O, no clock, no environment. No matrix test reaches a live
  Postgres, a live Dokploy, or any network. A live Dokploy smoke
  is opt-in via `YALLA_EXTERNAL_DOKPLOY` and never runs in the
  default gate.
- **Actionable failures.** Each matrix subtest is named
  `<role>/<action>` so a failing row in the CI log names the exact
  role and action pair an operator must investigate without
  re-running the suite locally. The cross-tenant matrix surfaces
  the expected `ReasonDeniedCrossTenant` (or, for the documented
  exceptions, `ReasonAllowedSelf` and `ReasonAllowedBySupport`) so
  a regression that silently flips a cross-org deny into an allow
  fails the matrix at the engine boundary, not at the persistence
  layer where the data has already leaked.
- **Coverage rows.** The matrix covers success
  (`ReasonAllowedByRole` and `ReasonAllowedSelf` for in-tenant
  decisions), validation failure (unknown actions deny via
  `ReasonDeniedUnknownAction`, unknown roles deny via
  `ReasonDeniedUnknownRole`), authorization failure
  (`ReasonDeniedNoCapability` for in-tenant decisions where the
  role's `capSet` does not satisfy the required capability), and
  tenant isolation
  (`ReasonDeniedCrossTenant` for every role × action pair except
  the documented `CapSelf` shortcut and the `CapSupport` bridge
  for CapRead / CapSupport actions). The action catalog maps every
  action constant to a `Capability` value (`CapSelf`, `CapRead`,
  `CapDeploy`, `CapWrite`, `CapAdmin`, `CapOwner`, `CapSupport`);
  the matrix iterates `Actions()` and `BuiltinRoles()` so a new
  action or a new role automatically widens the matrix without
  any test edit.
- **Schema-version contract.** Every public HTTP response that
  surfaces a policy denial uses the stable JSON envelope shape
  pinned by `yalla.output.v1` (success) and `yalla.error.v1`
  (error) so a wire-contract regression in how denials are
  reported is caught at the httpapi handler-contract layer
  (BE-0381) before it reaches a customer.
- **Redaction.** Policy decisions never embed secrets, tokens,
  API keys, cookies, or rendered environment variable values in
  the diagnostic surface. Decision reasons are typed string
  constants, principal IDs are non-secret identifiers, and any
  metadata carried alongside a denial is redacted through the
  shared output sentinel so a CI log or audit metadata blob never
  becomes the place a credential leaks.
- **CI cadence.** The matrix gate runs as a dedicated `Policy
  matrix tests` step in `.github/workflows/ci.yml`, under
  `# 9. Required: policy matrix tests` in `scripts/verify.sh`,
  as entry `9` in `CONTRIBUTING.md` under
  `## Required Checks Before Every Commit`, and in
  `ralph/prd.json` under
  `verificationLoop.requiredBackendCommands` so an AI agent
  reading the PRD before picking up a story sees the gate without
  needing to discover it from shell scripts or CI workflows.
  Every push and PR runs the gate; a live-Dokploy smoke remains
  opt-in via `YALLA_EXTERNAL_DOKPLOY=1`. The single static
  defence that pins every one of those surfaces is
  `internal/release/verification_suite_policy_matrix_static_test.go`.

## Policy Engine Conventions Artifact

The developer-facing policy-engine conventions guide is tracked at
`docs/development/policy-engine-conventions.md` and is pinned by
`go test ./internal/release/... -run TestPolicyEngineConventionsArtifact`.
The guide documents how to add or change `policy.Action` constants, update the
`internal/controlplane/policy/catalog.go` action catalog, build scoped
`policy.Resource` values, authorize with `policy.Engine.Authorize`, surface
typed `apierr.Forbidden` / `apierr.ScopeRequired` errors, record
`telemetry.PolicyDecisionMetrics`, preserve stable `yalla.output.v1` /
`yalla.error.v1` envelopes with `request_id`, and keep secrets, tokens, API
keys, cookies, rendered environment variable values, customer identifiers, and
live Dokploy credentials out of logs, errors, audit metadata, tests, docs, and
dry-run output.

The artifact test keeps the guide wired into `scripts/verify.sh`, the CI test
job, and this security policy so the policy conventions do not drift away from
the executable gate. The guide also records the exact focused verification
commands for policy changes: `go test ./internal/controlplane/policy/...`,
`go test -run TestPolicyMatrix ./...`, `go test -run TestTenantIsolation ./...`,
`go test -run TestAdminEndpoint ./...`, and the opt-in external smoke command
`YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...`, which must
never run against production.

## Quota Concurrency Tests

Yalla's quota concurrency tests are the hard-limit + cross-tenant
concurrency gate that ensures the checker in
`internal/controlplane/quota` deterministically rejects every reservation
that would exhaust a hard limit, even under parallel writers from the
same tenant, and never lets one organization's parallel reservations
leak into another's count. The suite lives under
`internal/controlplane/quota/` and the canonical command is
`go test -run TestQuotaConcurrency ./...`. The suite exercises the
checker end-to-end against deterministic fixtures (isolated, freshly
migrated Postgres database via `testutil.RequireMigratedDB`,
`seedQuotaOrg`, `seedOrgQuotaPolicy`, parallel goroutines driving
`store.Write`); it never depends on a live Dokploy server, and any
external smoke remains opt-in via `YALLA_EXTERNAL_DOKPLOY=1
go test -run TestLiveDokploySmoke ./...`. BE-0384 publishes the
contract operators and AI agents rely on:

- **Scope.** The two load-bearing concurrency invariants are
  exercised by the canonical function pair
  (`TestQuotaConcurrencyHardLimitNeverOverallocates` and
  `TestQuotaConcurrencyTenantIsolation`). The single static defence
  is
  `internal/release/verification_suite_quota_concurrency_static_test.go`,
  which pins the existence of the canonical
  `internal/controlplane/quota/quota_test.go` file and the canonical
  `TestQuotaConcurrencyHardLimitNeverOverallocates` +
  `TestQuotaConcurrencyTenantIsolation` function pair (the
  load-bearing `-run TestQuotaConcurrency` filter from
  `verificationLoop.requiredBackendCommands` binds to that prefix)
  so the concurrency convention itself cannot be silently deleted
  or renamed.
- **Determinism.** The quota concurrency tests run against
  deterministic fixtures only — an isolated migrated Postgres
  database seeded per test run with no shared instance state, and
  any Dokploy interaction stays out of the path entirely (the
  checker only touches Postgres). No concurrency test reaches a
  live Dokploy or any network. A live Dokploy smoke is opt-in via
  `YALLA_EXTERNAL_DOKPLOY` and never runs in the default gate.
  Tests skip cleanly when `YALLA_TEST_DATABASE_URL` is unset, so
  contributors without a local Postgres get a fast green run while
  CI gates on the real database.
- **Actionable failures.** Every diagnostic surfaces the
  organization ID (the load-bearing `organization_id` predicate
  that scopes the `FOR UPDATE` lock and every counter, sum, and
  reservation insert) and the resource so an operator reading the
  CI log can map the failure to the exact tenant and dimension
  without re-running the suite locally. A typed quota rejection
  surfaces as `yerr.CodeQuotaExceeded` carrying the recoverable
  `quota.ExceededDetail` (current, reserved, requested, limit) so
  a regression that shifts the counts is caught at the boundary,
  not at the persistence layer where the over-allocation has
  already happened.
- **Coverage rows.** The hard-limit invariant
  (`TestQuotaConcurrencyHardLimitNeverOverallocates`) drives
  `attempts` parallel writers against a single organization with a
  hard limit below `attempts`, asserts exactly `limit` writers see
  no error and the rest see `CodeQuotaExceeded`, and asserts the
  database row count agrees with the success count. The
  cross-tenant invariant
  (`TestQuotaConcurrencyTenantIsolation`) drives parallel writers
  against two organizations with independent hard limits, asserts
  each organization respects its own limit, and asserts the two
  tenants' active reservation rows sum to the two limits (no
  collapse into one bucket). The `FOR UPDATE` lock on the per-
  organization, per-resource usage counter row is what makes the
  hard-limit invariant hold; the `organization_id` predicate
  carried through every counter, sum, and insert is what makes
  the cross-tenant invariant hold.
- **Schema-version contract.** Every public HTTP response that
  surfaces a quota rejection uses the stable JSON envelope shape
  pinned by `yalla.output.v1` (success) and `yalla.error.v1`
  (error) so a wire-contract regression in how rejections are
  reported is caught at the httpapi handler-contract layer
  (BE-0381) before it reaches a customer.
- **Redaction.** Quota decisions never embed secrets, tokens, API
  keys, cookies, or rendered environment variable values in the
  diagnostic surface. `ExceededDetail` carries only the resource
  dimension name and four non-secret counts; the organization ID
  is a non-secret identifier; and any metadata carried alongside a
  rejection is redacted through the shared output sentinel so a
  CI log or audit metadata blob never becomes the place a
  credential leaks.
- **CI cadence.** The concurrency gate runs as a dedicated `Quota
  concurrency tests` step in `.github/workflows/ci.yml`, under
  `# 10. Required: quota concurrency tests` in `scripts/verify.sh`,
  as entry `10` in `CONTRIBUTING.md` under
  `## Required Checks Before Every Commit`, and in
  `ralph/prd.json` under
  `verificationLoop.requiredBackendCommands` so an AI agent
  reading the PRD before picking up a story sees the gate without
  needing to discover it from shell scripts or CI workflows.
  Every push and PR runs the gate; a live-Dokploy smoke remains
  opt-in via `YALLA_EXTERNAL_DOKPLOY=1`. The single static
  defence that pins every one of those surfaces is
  `internal/release/verification_suite_quota_concurrency_static_test.go`.

## Job Worker Lease Tests

Yalla's job worker lease tests are the exclusivity + shutdown-safety
gate that ensures the Postgres-backed claimer in
`internal/controlplane/worker` deterministically leases each queued
provisioning job to exactly one worker at a time and returns
in-flight leases to the queue when the worker is interrupted, so a
job is never run twice and never lost. The suite lives under
`internal/controlplane/worker/` and the canonical command is
`go test -run TestJobWorkerLease ./...`. The suite exercises the
claimer and run loop end-to-end against deterministic fixtures
(isolated, freshly migrated Postgres database via
`testutil.RequireMigratedDB`, `seedQueueOrg`, `enqueueJob`,
parallel goroutines driving `StoreClaimer.Claim` and `Loop.Run`);
it never depends on a live Dokploy server, and any external smoke
remains opt-in via `YALLA_EXTERNAL_DOKPLOY=1
go test -run TestLiveDokploySmoke ./...`. BE-0385 publishes the
contract operators and AI agents rely on:

- **Scope.** The two load-bearing lease invariants are exercised
  by the canonical function pair
  (`TestJobWorkerLeaseExclusivityNeverDoubleClaims` and
  `TestJobWorkerLeaseReleasedOnShutdownIsRetryable`). The single
  static defence is
  `internal/release/verification_suite_job_worker_lease_static_test.go`,
  which pins the existence of the canonical
  `internal/controlplane/worker/queue_test.go` file and the
  canonical
  `TestJobWorkerLeaseExclusivityNeverDoubleClaims` +
  `TestJobWorkerLeaseReleasedOnShutdownIsRetryable` function pair
  (the load-bearing `-run TestJobWorkerLease` filter from
  `verificationLoop.requiredBackendCommands` binds to that prefix)
  so the lease convention itself cannot be silently deleted or
  renamed.
- **Determinism.** The job worker lease tests run against
  deterministic fixtures only — an isolated migrated Postgres
  database seeded per test run with no shared instance state, a
  process-local lease owner per claimer, and any Dokploy
  interaction stays out of the path entirely (the claimer only
  touches Postgres). No lease test reaches a live Dokploy or any
  network. A live Dokploy smoke is opt-in via
  `YALLA_EXTERNAL_DOKPLOY` and never runs in the default gate.
  Tests skip cleanly when `YALLA_TEST_DATABASE_URL` is unset, so
  contributors without a local Postgres get a fast green run
  while CI gates on the real database.
- **Actionable failures.** Every diagnostic surfaces the job ID
  (`job_id`) and the organization ID so an operator reading the
  CI log can map the failure to the exact provisioning job and
  tenant without re-running the suite locally. The claim path
  surfaces the `attempt`, `max_attempts`, `request_id`, and
  `correlation_id` from `StoreClaimer.Claim`'s structured log so
  the lease lineage is traceable from request to retry; the
  release path surfaces the released `job_id` plus the same
  `request_id`/`correlation_id` so an interrupted lease is
  observable end-to-end through the audit trail.
- **Coverage rows.** The exclusivity invariant
  (`TestJobWorkerLeaseExclusivityNeverDoubleClaims`) drives two
  concurrent `StoreClaimer.Claim` calls against a single queued
  job; the `SELECT ... FOR UPDATE SKIP LOCKED` claim in the
  Postgres-backed claimer is what guarantees exactly one
  goroutine receives the lease and the other receives
  `(nil, nil)`. The shutdown-safety invariant
  (`TestJobWorkerLeaseReleasedOnShutdownIsRetryable`) drives a
  `Loop.Run` past a runner that blocks until cancellation,
  cancels the loop while the lease is in-flight, and asserts the
  persisted job is back to `retrying` with no stale lease owner
  and an immediate `next_run_at` — the `Loop.Run` shutdown path
  that invokes `Lease.Release` against a context detached from
  the cancelled loop context is what makes "the job is lost when
  the worker shuts down" impossible.
- **Schema-version contract.** Every public HTTP response that
  surfaces a provisioning job (status, failure summary, retry
  schedule) uses the stable JSON envelope shape pinned by
  `yalla.output.v1` (success) and `yalla.error.v1` (error) so a
  wire-contract regression in how lease outcomes are reported is
  caught at the httpapi handler-contract layer (BE-0381) before
  it reaches a customer.
- **Redaction.** Lease diagnostics never embed secrets, tokens,
  API keys, cookies, or rendered environment variable values in
  the surfaces a runner failure crosses. The runner error string
  is handed to the store transition through the redaction
  chokepoint, and any metadata carried alongside a job is
  redacted through the shared output sentinel so a CI log,
  audit metadata blob, or dead-letter row never becomes the
  place a credential leaks.
- **CI cadence.** The lease gate runs as a dedicated `Job worker
  lease tests` step in `.github/workflows/ci.yml`, under
  `# 11. Required: job worker lease tests` in `scripts/verify.sh`,
  as entry `11` in `CONTRIBUTING.md` under
  `## Required Checks Before Every Commit`, and in
  `ralph/prd.json` under
  `verificationLoop.requiredBackendCommands` so an AI agent
  reading the PRD before picking up a story sees the gate without
  needing to discover it from shell scripts or CI workflows.
  Every push and PR runs the gate; a live-Dokploy smoke remains
  opt-in via `YALLA_EXTERNAL_DOKPLOY=1`. The single static
  defence that pins every one of those surfaces is
  `internal/release/verification_suite_job_worker_lease_static_test.go`.

## Fake Dokploy Contract Tests

Yalla's fake Dokploy contract tests are the deterministic-fixtures +
recorder-redaction gate that ensures every worker, handler, or agent
test exercising Dokploy-shaped behaviour runs against the in-memory
fake in `internal/controlplane/dokploy/dokployfake` — never a live
Dokploy server — and that every request the test recorder captures
has its bearer token replaced by the shared output sentinel before
it can land in a CI log, an audit metadata blob, or a developer's
terminal. The canonical command is
`go test -run TestFakeDokploy ./...`. The suite exercises the fake
end-to-end against deterministic fixtures (two independent
`dokployfake.New()` servers minting byte-identical hierarchy IDs
across runs; a recorder that scrubs the Authorization header, all
header projections, and the body even when the caller deliberately
echoes the bearer into a request body); it never depends on a live
Dokploy server, and any external smoke remains opt-in via
`YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...`.
BE-0386 publishes the contract operators and AI agents rely on:

- **Scope.** The two load-bearing fake-Dokploy invariants are
  exercised by the canonical function pair
  (`TestFakeDokployContractDeterministicHierarchyIDs` and
  `TestFakeDokployContractRecordedRequestsRedactCredentials`). The
  single static defence is
  `internal/release/verification_suite_fake_dokploy_contract_static_test.go`,
  which pins the existence of the canonical
  `internal/controlplane/dokploy/dokployfake/dokployfake_test.go`
  file and the canonical
  `TestFakeDokployContractDeterministicHierarchyIDs` +
  `TestFakeDokployContractRecordedRequestsRedactCredentials`
  function pair (the load-bearing `-run TestFakeDokploy` filter
  from `verificationLoop.requiredBackendCommands` binds to that
  prefix) so the fake-Dokploy convention itself cannot be silently
  deleted or renamed.
- **Determinism.** The fake-Dokploy contract tests run against
  deterministic fixtures only — two independent
  `dokployfake.New()` servers driven through the same org ->
  project -> environment -> application -> deployment chain MUST
  mint byte-identical resource IDs (`org_1`, `proj_1`, `env_1`,
  `app_1`, `dep_1`) and MUST keep per-server state (request count,
  resource store, fault queue) isolated. The fake is in-memory,
  exposes no global state, and never reaches a live Dokploy or any
  network. A live Dokploy smoke is opt-in via
  `YALLA_EXTERNAL_DOKPLOY` and never runs in the default gate;
  `TestLiveDokploySmoke` is the documented opt-in entry point.
- **Actionable failures.** Every diagnostic surfaces the recorded
  request's `Method`, `Path`, and the index within
  `Server.Requests()` so an operator reading the CI log can map the
  failure to the exact request that drifted without re-running the
  suite locally. Determinism failures point the operator at the
  exact hierarchy layer that diverged between the two servers; the
  resource_id at every level is part of the diagnostic.
- **Coverage rows.** The determinism invariant
  (`TestFakeDokployContractDeterministicHierarchyIDs`) drives two
  fresh `dokployfake.New()` servers through the same Create chain
  and asserts every layer's resource ID is byte-identical and the
  per-server request counts stay isolated. The redaction invariant
  (`TestFakeDokployContractRecordedRequestsRedactCredentials`)
  drives a successful create, a GET that reads the resource back,
  and a deliberate failure-path POST whose body echoes the bearer
  token, then asserts every recorded request carries
  `AuthHeader == output.Sentinel`, `Headers[Authorization] ==
  output.Sentinel`, and no body retains the bearer — the recorder
  scrubs the secret regardless of the response status or the
  caller's body shape.
- **Schema-version contract.** Every public HTTP response that a
  worker surfaces after a fake-Dokploy interaction (provisioning
  job status, failure summary, retry schedule) uses the stable
  JSON envelope shape pinned by `yalla.output.v1` (success) and
  `yalla.error.v1` (error) so a wire-contract regression in how
  Dokploy-shaped outcomes are reported is caught at the httpapi
  handler-contract layer (BE-0381) before it reaches a customer.
- **Redaction.** Fake-Dokploy diagnostics never embed secrets,
  tokens, API keys, cookies, or rendered environment variable
  values in the surfaces a recorder request crosses. The recorder
  swaps the Authorization header for the shared output sentinel
  inline, and the body is scanned for the bearer literal before
  the test can read it back, so a CI log or audit metadata blob
  never becomes the place a Dokploy bearer leaks. The contract
  holds for every recorded request, not just the happy path.
- **CI cadence.** The fake-Dokploy gate runs as a dedicated
  `Fake Dokploy contract tests` step in `.github/workflows/ci.yml`,
  under `# 12. Required: fake Dokploy contract tests` in
  `scripts/verify.sh`, as entry `12` in `CONTRIBUTING.md` under
  `## Required Checks Before Every Commit`, and in
  `ralph/prd.json` under
  `verificationLoop.requiredBackendCommands` so an AI agent
  reading the PRD before picking up a story sees the gate without
  needing to discover it from shell scripts or CI workflows.
  Every push and PR runs the gate; a live-Dokploy smoke remains
  opt-in via `YALLA_EXTERNAL_DOKPLOY=1`. The single static
  defence that pins every one of those surfaces is
  `internal/release/verification_suite_fake_dokploy_contract_static_test.go`.

## Redaction Tests

Yalla's redaction tests are the secrets-never-leak-into-logs gate
that ensures every bearer token, API key, cookie, query-string
credential, and rendered environment variable value is replaced by
the shared `output.Sentinel` (`[REDACTED]`) before any surface a
human, AI agent, audit pipeline, or CI log can read it back. The
canonical command is `go test -run TestRedaction ./...`. The suite
exercises the central `Redactor` in `internal/output`, the per-tenant
scoped, rendered, and resolved variable redaction in
`internal/controlplane/variables`, and the CLI envelope, dry-run,
and multipart-upload redaction in `internal/cli`. It never depends
on a live Dokploy server, and any external smoke remains opt-in via
`YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...`.
BE-0387 publishes the contract operators, auditors, and AI agents
rely on:

- **Scope.** The two load-bearing canonical redaction invariants are
  exercised by the function pair
  (`TestRedactionContractStructuralPatternsAcrossKnownTransports`
  and `TestRedactionContractExplicitSecretsAndIdempotency`). The
  single static defence is
  `internal/release/verification_suite_redaction_static_test.go`,
  which pins the existence of the canonical
  `internal/output/redact_test.go` file and the canonical
  `TestRedactionContractStructuralPatternsAcrossKnownTransports` +
  `TestRedactionContractExplicitSecretsAndIdempotency` function pair
  (the load-bearing `-run TestRedaction` filter from
  `verificationLoop.requiredBackendCommands` binds to the
  `TestRedaction` prefix) so the redaction convention itself cannot
  be silently deleted or renamed. The prefix also matches every
  downstream redaction suite — `TestRedaction_*` in
  `internal/cli/redaction_security_test.go` and
  `internal/cli/redaction_security_multipart_test.go`,
  `TestRedactionLogValueMethodsReferenceSentinel`,
  `TestRedactionExplainedVariableLiteralsRedactValue`,
  `TestRedactionNoPlaintextInErrorSurface`,
  `TestRedactionStaticAnalyzerDetectsRegressions`,
  `TestRedactionScopedVariableLogValueNeverLeaks`,
  `TestRedactionRenderedLogValueNeverLeaks`,
  `TestRedactionResolvedLogValueNeverLeaks`,
  `TestRedactionExplainProjectionNeverLeaks`,
  `TestRedactionResolverOpenedSecretValueNeverEntersSlog`, and
  `TestRedactionFuzzScopeExclusionsAreReal` in
  `internal/controlplane/variables` — so a single failed gate fires
  across every package whose redaction posture matters.
- **Determinism.** The redaction tests run against deterministic
  fixtures only — distinctive literal probes
  (`REDACTION-CONTRACT-VALUE-…`, `REDACTION-CONTRACT-EXPLICIT-SECRET-…`)
  that make a leak detectable by literal substring match, not by
  hash mismatch. Every `Redactor` is constructed in-process per
  test, never reaches a live Dokploy or any network, and a live
  Dokploy smoke remains opt-in via `YALLA_EXTERNAL_DOKPLOY` and
  never runs in the default gate; `TestLiveDokploySmoke` is the
  documented opt-in entry point.
- **Actionable failures.** Every diagnostic names the transport
  shape that drifted (header name, query parameter, explicit
  secret, idempotency pass) and the literal probe that leaked, so
  an operator reading the CI log can map the failure to the exact
  redaction rule that regressed without re-running the suite
  locally. The downstream `request_id` and `resource_id`
  identifiers carried by the variables and CLI redaction tests
  surface for the per-tenant and per-envelope assertions.
- **Coverage rows.** The structural-transport invariant
  (`TestRedactionContractStructuralPatternsAcrossKnownTransports`)
  drives every supported transport — Authorization header
  (upper/lower casing), `X-API-Key` (upper/lower casing),
  `X-Auth-Token` (upper/lower casing), `?token=`, `?api_key=`,
  `?api-key=`, `?access_token=`, `?x-auth-token=` (first and
  trailing parameter positions) — asserts the bearer literal is
  scrubbed and the header/parameter name is preserved, pins the
  canonical sentinel value `[REDACTED]`, asserts non-secret query
  parameters pass through unchanged, and asserts the redactor is
  panic-free on hostile inputs (header lines without a colon,
  query parameters without a value, URLs with adjacent
  ampersands, NUL-prefixed strings). The explicit-secret +
  idempotency invariant
  (`TestRedactionContractExplicitSecretsAndIdempotency`) drives an
  explicit secret across every surrounding-character context
  (plain prose, JSON quoting, header context, query context,
  start of string, end of string, adjacent occurrence), pins
  sub-threshold/empty/whitespace secrets are dropped on
  construction, pins duplicate secrets are de-duplicated, pins
  `Redact(Redact(s)) == Redact(s)` across the contract corpus,
  pins empty-input pass-through, and pins the sentinel literal
  itself cannot be re-registered as a secret (so the redactor
  never scrubs its own marker).
- **Schema-version contract.** Every public HTTP response that
  surfaces a redacted value (CLI envelope, error envelope, audit
  metadata, dry-run output) uses the stable JSON envelope shape
  pinned by `yalla.output.v1` (success) and `yalla.error.v1`
  (error) so a wire-contract regression that re-introduces a
  plaintext secret in a response field is caught at the httpapi
  handler-contract layer (BE-0381) before it reaches a customer.
- **Redaction.** The contract itself IS that secrets, tokens, API
  keys, cookies, and rendered environment variable values never
  appear in customer-facing output, logs, errors, audit metadata,
  test output, or dry-run output. The canonical pair pins the
  structural net the central `Redactor` provides; the downstream
  per-package suites (`internal/cli/redaction_security_*_test.go`
  for the CLI surface, `internal/controlplane/variables/env_var_redaction_*_test.go`
  for the per-tenant variable surface, and
  `internal/output/redact_fuzz_test.go` for the fuzz harness from
  BE-0359) pin the contract at every place the secret can cross
  a boundary.
- **CI cadence.** The redaction gate runs as a dedicated
  `Redaction tests` step in `.github/workflows/ci.yml`, under
  `# 13. Required: redaction tests` in `scripts/verify.sh`, as
  entry `13` in `CONTRIBUTING.md` under
  `## Required Checks Before Every Commit`, and in
  `ralph/prd.json` under
  `verificationLoop.requiredBackendCommands` so an AI agent
  reading the PRD before picking up a story sees the gate without
  needing to discover it from shell scripts or CI workflows.
  Every push and PR runs the gate; a live-Dokploy smoke remains
  opt-in via `YALLA_EXTERNAL_DOKPLOY=1`. The single static
  defence that pins every one of those surfaces is
  `internal/release/verification_suite_redaction_static_test.go`.

## Fuzz Validator Tests

Yalla's fuzz validator tests are the hostile-input gate that
ensures the request-validation toolkit in
`internal/controlplane/validate` never panics on adversarial input,
never echoes a submitted value back into an error or audit
metadata, and covers every public validator. The suite lives in
`internal/controlplane/validate/fuzz_test.go` and the canonical
command is `go test -run TestFuzzValidator ./...`. The wrapper
pair (`TestFuzzValidatorContractCoversExpectedValidators` and
`TestFuzzValidatorContractSeedCorpusRejectsHostileInputs`) drives
every validator (`Name`, `Path`, `Domain`, `EnvVarName`,
`EnvVarValue`, `DecodeJSON`, `ImageRef`, `URL`, `GitBranch`)
through a shared hostile seed corpus under a `recover()` guard so
a regression surfaces with the offending validator AND the seed
index. The corresponding fuzz targets (`FuzzName`, `FuzzPath`,
`FuzzDomain`, `FuzzEnvVarName`, `FuzzEnvVarValue`,
`FuzzDecodeJSON`, `FuzzImageRef`, `FuzzURL`, `FuzzGitBranch`) pin
the no-panic invariant on every public validator under the same
seed corpus and accept Go's randomised driver via
`-fuzz=Fuzz<Name>` for opt-in soak runs. BE-0388 publishes the
contract operators and AI agents rely on:

- **Scope.** The suite exercises every public validator in
  `internal/controlplane/validate` against a fixed hostile seed
  corpus (long strings, invalid UTF-8, path traversal segments,
  embedded NUL bytes, control characters, Unicode tricks,
  embedded credentials, IPv4 literals, reserved DNS suffixes,
  binary garbage). The canonical-pair design pins the closed-set
  coverage so a new validator added without an accompanying Fuzz
  target trips the gate at the package-internal API; the runtime
  wrapper pins the "no panic" invariant so a regression that
  panics on a hostile seed fails fast with the offending
  validator name AND the seed index.
- **Determinism.** The seed corpus replays the same hostile
  inputs on every run. `go test ./...` runs each FuzzXxx
  function with its seed corpus only (no randomised driver); the
  randomised driver remains available as
  `go test -fuzz=Fuzz<Name>
  ./internal/controlplane/validate/...` for opt-in soak runs.
  No live Postgres is required and no live Dokploy is required;
  the opt-in external smoke remains `YALLA_EXTERNAL_DOKPLOY=1
  go test -run TestLiveDokploySmoke ./...`.
- **Actionable failures.** A panic on a hostile seed reports
  the offending validator name AND the seed index so an operator
  reading the CI log can map the failure to the exact validator
  + the exact input without re-running the suite locally. The
  wrapper uses `recover()` so a panic in one validator never
  hides a panic in another — every panic is surfaced; every
  recovered seed is named. Failures carry the `request_id` of
  the encompassing request when surfaced through downstream
  handlers; the underlying validator surface itself is pure and
  has no request context.
- **CI gating.** `go test -run TestFuzzValidator ./...` runs on
  `ubuntu-latest`, `macos-latest`, and `windows-latest` for
  every push and every pull request via
  `.github/workflows/ci.yml` (the `test` job's step
  `Fuzz validator tests`), and locally via `scripts/verify.sh`
  (step `# 14. Required: fuzz tests for validators`). Both
  must pass before a commit lands in `main`. The same gate
  appears in the verification-gates table above as the row
  `| Fuzz validator tests | go test -run TestFuzzValidator ./... | scripts/verify.sh, CI | Every push and PR |`,
  in `CONTRIBUTING.md` under `## Required Checks Before Every
  Commit`, and in `ralph/prd.json` under
  `verificationLoop.requiredBackendCommands` so an AI agent
  reading the PRD before picking up a story sees the gate
  without needing to discover it from shell scripts or CI
  workflows.
- **Envelope contract.** When a validator failure surfaces
  through a handler the resulting JSON envelope uses
  `yalla.error.v1` with code `E_INVALID_INPUT`; the success
  path uses `yalla.output.v1`. The fuzz suite itself is pure —
  it asserts the validators directly without going through an
  HTTP handler — so the envelope contract is pinned by the
  HTTP handler contract suite (BE-0381) and surfaces here only
  as the documented downstream invariant.
- **Redaction.** The no-value-echo invariant is the load-bearing
  redaction promise the fuzz suite carries: a rejected value
  must never appear in the validator's error reason, the audit
  metadata, or the test failure output. The shared
  `internal/output.Redactor` provides the structural net every
  downstream caller uses; the fuzz suite verifies the per-
  validator commitment that the toolkit itself does not echo
  submitted values back. The `FuzzEnvVarValue` and `FuzzURL`
  targets explicitly assert this — if a within-bounds,
  well-formed value produces a violation, the value MUST NOT
  appear in `err.Error()`.
- **Self-locating.** The CI step, verify.sh step header,
  CONTRIBUTING entry, this section, the PRD command, and the
  canonical reference file are all pinned by
  `internal/release/verification_suite_fuzz_validators_static_test.go`.
  A drift on any single surface (rename, renumber, deletion)
  fails ONE test, not six.

## Migration Tests From Empty DB

Yalla's migrations-from-empty-DB suite is the bootstrap gate that
ensures every fresh control-plane deploy can lay down the entire
schema from version 0. The runner lives in
`internal/controlplane/store/migrate` and the canonical command is
`go test -run TestMigrationsEmptyDB ./...`. The wrapper pair
(`TestMigrationsEmptyDBContractCoversAllNumberedFiles` and
`TestMigrationsEmptyDBContractAppliesEmbeddedLadderToEmptyDatabase`)
lives in `migrate_test.go` next to the existing baseline checks.
The first member pins the closed-set coverage invariant — every
`NNNN_*.up.sql` file in the embedded migrations directory MUST
surface as a loaded `Migration`, strictly ascending and gap-free
from version 1, with a non-empty up SQL body and a 64-character
sha256 hex checksum — and runs without a Postgres dependency. The
second member pins the applies-cleanly runtime invariant — a
throwaway database created from `YALLA_TEST_DATABASE_URL` accepts
the embedded ladder in order, the `schema_migrations` ledger ends
with one clean row per migration (correct embedded checksum,
dirty=false), and a second `Up` is a no-op — and skips cleanly
when `YALLA_TEST_DATABASE_URL` is unset so the suite stays green
on machines without Postgres. BE-0389 publishes the contract
operators and AI agents rely on:

- **Scope.** The suite exercises the migration runner against an
  empty database — the load-bearing scenario every fresh deploy
  starts with. The closed-set coverage member binds to the
  canonical `NNNN_` filename grammar so a file added without the
  loader picking it up — or a numbered file accidentally renamed
  to a non-numbered form — trips the gate at the package-internal
  API. The applies-cleanly member binds to the
  `schema_migrations` ledger so a regression in the
  transaction-per-migration contract (a partial row left after a
  rollback, a migration that fails on an empty database, a
  checksum drift from the on-disk file) surfaces with the
  offending migration version AND the row reference an operator
  can grep the failure log for.
- **Determinism.** The closed-set coverage member is fully
  deterministic — it walks the embedded FS and replays the same
  filename grammar match on every run, no Postgres needed. The
  applies-cleanly member uses an isolated, throwaway database
  named with `crypto/rand` entropy (one fresh database per test
  run; dropped on cleanup) so it never depends on shared state
  and is parallel-safe. No live Dokploy is required; the opt-in
  external smoke remains `YALLA_EXTERNAL_DOKPLOY=1 go test -run
  TestLiveDokploySmoke ./...`. When `YALLA_TEST_DATABASE_URL` is
  unset the applies-cleanly member skips cleanly — no false
  failure on machines without Postgres.
- **Actionable failures.** A failed coverage check reports the
  offending filename (e.g. `0033_new_thing.up.sql`) and the
  resolved version so the operator can map the failure to the
  exact file without re-running the suite locally. A failed
  apply reports the offending migration version AND the
  resource_id (`schema_migrations.version=N`) so the operator
  can trace the failure to the exact migration. When migrations
  run through an admin endpoint or a worker job the resulting
  envelope carries the request_id of the encompassing request;
  the underlying runner surface itself is pure and has no
  request context.
- **CI gating.** `go test -run TestMigrationsEmptyDB ./...` runs
  on `ubuntu-latest`, `macos-latest`, and `windows-latest` for
  every push and every pull request via
  `.github/workflows/ci.yml` (the `test` job's step
  `Migration tests from empty DB`), and locally via
  `scripts/verify.sh` (step
  `# 15. Required: migration tests from empty DB`). Both must
  pass before a commit lands in `main`. The same gate appears in
  the verification-gates table above as the row
  `| Migration tests from empty DB | go test -run TestMigrationsEmptyDB ./... | scripts/verify.sh, CI | Every push and PR |`,
  in `CONTRIBUTING.md` under `## Required Checks Before Every
  Commit`, and in `ralph/prd.json` under
  `verificationLoop.requiredBackendCommands` so an AI agent
  reading the PRD before picking up a story sees the gate
  without needing to discover it from shell scripts or CI
  workflows.
- **Envelope contract.** When a migration failure surfaces
  through an admin endpoint or worker job the resulting JSON
  envelope uses `yalla.error.v1` with a typed migration error
  code; the success path uses `yalla.output.v1`. The
  empty-DB suite itself is pure — it asserts the runner
  directly without going through an HTTP handler — so the
  envelope contract is pinned by the HTTP handler contract
  suite (BE-0381) and surfaces here only as the documented
  downstream invariant.
- **Redaction.** Migration SQL bodies never contain customer
  secrets — the runner refuses to apply a migration whose
  checksum mismatches the embedded file, so a "secret embedded
  in a migration" regression cannot reach a production database
  unobserved. Migration failure messages name the offending
  version and filename, never the raw SQL body. The shared
  `internal/output.Redactor` provides the structural net every
  downstream caller uses so a leaked DSN or token in a
  migration-runner log is impossible by construction.
- **Self-locating.** The CI step, verify.sh step header,
  CONTRIBUTING entry, this section, the PRD command, and the
  canonical reference file are all pinned by
  `internal/release/verification_suite_migrations_empty_db_static_test.go`.
  A drift on any single surface (rename, renumber, deletion)
  fails ONE test, not six.

## Migration Downgrade Safety Tests

The migration-downgrade-safety suite (BE-0390) is the operator
recovery gate. It pins the contract between Yalla's migration runner
(`internal/controlplane/store/migrate`) and every operator who must
roll a control-plane database back to recover from a botched deploy:
every numbered `NNNN_*.up.sql` migration MUST ship with a non-empty
matching `NNNN_*.down.sql` down script partner, no `.down.sql` may be an orphan,
and the embedded ladder MUST round-trip cleanly — Up applies the
ladder, `Down(0)` empties the `schema_migrations` ledger without
returning `ErrIrreversible`, and a second Up re-applies the ladder
with identical checksums and dirty=false on every row.

- **Suite scope.** The canonical reference test file is
  `internal/controlplane/store/migrate/migrate_test.go`. It declares
  the two functions the `go test -run TestMigrationsDowngradeSafety
  ./...` filter binds to:
  - `TestMigrationsDowngradeSafetyContractCoversAllDownFiles` —
    walks the embedded migrations directory through the loader's
    filename grammar `NNNN_*.{up,down}.sql`, asserts every up has a
    matching non-empty down, no down is an orphan, and
    `LoadMigrations` surfaces every embedded down file as a
    non-empty `DownSQL`. Runs on every developer machine and every
    CI runner — no Postgres required — so the regression surfaces
    deterministically.
  - `TestMigrationsDowngradeSafetyContractRoundTripsEmbeddedLadder`
    — applies the embedded ladder to an isolated throwaway
    Postgres database, calls `Down(0)`, asserts the ledger is
    empty, then calls Up a second time and asserts the
    `schema_migrations` rows match the first-Up checksums with
    dirty=false on every row. The throwaway database is created
    by `testPool` when `YALLA_TEST_DATABASE_URL` is set and the
    test skips with `t.Skip` otherwise — the suite stays green on
    machines without Postgres without silently passing.
- **Deterministic by default.** The closed-set reversibility test
  reads the embedded fixtures every run. The round-trip test uses
  an isolated, throwaway database that is dropped on cleanup. The
  optional opt-in `YALLA_EXTERNAL_DOKPLOY=1 go test -run
  TestLiveDokploySmoke ./...` smoke test is the only external
  surface, and it never runs by default.
- **Schema-version contract.** Migration runner failures surface
  through the `yalla.error.v1` envelope when invoked via an admin
  endpoint or worker job; success responses use
  `yalla.output.v1`. The envelope `request_id` field maps every
  failure to a single request trace.
- **Actionable failures.** Every assertion in the canonical pair
  carries the offending migration version AND a `resource_id`
  (`schema_migrations.version=N`) so an operator can map the
  failure to the exact migration without re-running the suite
  locally. An `ErrIrreversible` during `Down(0)` is impossible by
  construction once the closed-set reversibility test passes,
  because the runtime gate would never reach an up-only migration.
- **Self-locating.** The CI step, verify.sh step header,
  CONTRIBUTING entry, this section, the PRD command, and the
  canonical reference file are all pinned by
  `internal/release/verification_suite_migration_downgrade_safety_static_test.go`.
  A drift on any single surface (rename, renumber, deletion)
  fails ONE test, not six.

## Load Smoke Tests

The load smoke suite (BE-0392) is the bootstrap-surface
burst-stability gate. It exists to catch regressions a single-request
test cannot: a request_id generator that silently collides under
contention, an unbounded handler that allocates a fresh logger per
request and pushes the runtime into memory pressure, a recently-added
middleware that echoes the inbound `Authorization` value back
verbatim in a response header, or a partial envelope that drops
`schema_version` under sustained load. The canonical pair
(`TestLoadSmokeContractCoversCoreEndpoints` and
`TestLoadSmokeContractRunsBurstWithStableEnvelopes`) lives in
`internal/controlplane/httpapi/load_smoke_test.go` and binds to the
PRD's `-run TestLoadSmoke` filter; the static defence for every
collateral surface lives in
`internal/release/verification_suite_load_smoke_static_test.go`.

- **Closed-set bootstrap coverage.** The first pair member walks the
  in-memory endpoint table the burst harness iterates and asserts it
  stays non-empty, free of duplicate (method, path) tuples, scoped
  to the bootstrap surface (paths under `/v1/` are explicitly
  rejected because they would require authenticated fixtures that
  defeat the deterministic-by-default contract), and that every
  entry carries a valid HTTP method. Today the closed set is
  `/healthz`, `/readyz`, and `/version` — the three paths the public
  HTTP handler can serve with no backing state. The matcher trips at
  the package-internal API with no infrastructure dependency, so a
  typo or scope-creep regression surfaces on every developer
  machine.
- **Burst stability under concurrency.** The second pair member spins
  the public HTTP handler up in-process via `httptest.NewServer`,
  fires `loadSmokeWorkers * loadSmokeIterationsPerWorker` (16 × 32 =
  512) concurrent requests per endpoint, and asserts every response
  carries the canonical status, a stable `yalla.output.v1` envelope
  with `ok=true`, a SafeID-clean `request_id`, a `request_id`
  unique across the whole burst (no two responses may share an id),
  and no secret-shaped substring (`yka_`, `Bearer `, `Set-Cookie`,
  `postgres://`, `DOKPLOY_TOKEN`) in body or header. Public-facing
  error envelopes carry `yalla.error.v1`; the burst-stability member
  surfaces both schemas through the same failure path so an
  unexpected error envelope under burst is treated as a regression.
- **Deterministic by default.** Both pair members run without
  Postgres, without a live Dokploy server, and without any fake
  Dokploy fixtures being touched — the bootstrap surface is the one
  part of the API that needs no backing infrastructure. Operators
  can therefore run the gate on every machine, every CI runner, and
  in every sandboxed environment without provisioning external
  state. The opt-in `YALLA_EXTERNAL_DOKPLOY` environment variable
  remains the escape hatch for the broader external smoke suite
  (`TestLiveDokploySmoke`); the load smoke gate never reaches it.
- **Actionable failures.** Every assertion failure surfaces with the
  offending endpoint (`GET /healthz` etc.) AND the observed
  `request_id` (or `<missing>` when the response carried none), so
  an operator can correlate the gate failure with the specific
  in-flight request in their logs and metrics dashboards without
  re-running the suite locally. Body and header redaction failures
  carry the offending secret-marker substring so the operator can
  immediately identify which redaction contract drifted.
- **CI cadence.** The dedicated `Load smoke tests` step runs on
  `Every push and PR` in `.github/workflows/ci.yml`, mirroring the
  local `scripts/verify.sh` step 17. Both surfaces invoke the
  identical `go test -run TestLoadSmoke ./...` command so a passing
  local gate predicts a passing CI gate.
- **Self-locating.** The CI step, verify.sh step header,
  CONTRIBUTING entry, this section, the PRD command, and the
  canonical reference file are all pinned by
  `internal/release/verification_suite_load_smoke_static_test.go`.
  A drift on any single surface (rename, renumber, deletion) fails
  ONE test, not six. Secrets, tokens, API keys, cookies, and
  rendered environment variable values are redacted in fake Dokploy
  fixtures, the bootstrap envelope, the response headers, and every
  log line the burst harness might observe.

## Chaos Tests For Dokploy Timeouts

The chaos-timeout suite (BE-0393) is the typed-Dokploy-client
chaos-classification gate. It exists to catch a class of regressions
a single-request unit test cannot: a per-attempt timeout misclassified
as `E_INTERNAL` or `E_UNAVAILABLE` after a code refactor, a POST
quietly retried after a timeout that would duplicate a provisioning
side effect, an idempotent GET or DELETE that stopped retrying inside
its bounded budget, a `telemetry.HeaderRequestID` that fails to
propagate from the calling context into every Dokploy attempt so an
operator cannot correlate a timeout with the originating request, or
an Authorization header that leaks a Dokploy bearer-token literal
into the error chain or the recorded request fixtures even under
`chaosWorkers * chaosIterationsPerWorker` concurrent goroutines per
scenario. The canonical pair
(`TestChaosDokployTimeoutsCoversCallSites` and
`TestChaosDokployTimeoutsMapsToTypedTimeoutEnvelope`) lives in
`internal/controlplane/dokploy/chaos_dokploy_timeouts_test.go` and
binds to the PRD's `-run TestChaosDokployTimeouts` filter; the
static defence for every collateral surface lives in
`internal/release/verification_suite_chaos_dokploy_timeouts_static_test.go`.

- **Scope.** The two load-bearing chaos invariants are exercised by
  the canonical function pair. The first member walks an in-memory
  closed-set scenario table covering the typed client's GET, POST,
  and DELETE call sites (`GetDeployment`, `EnsureOrganization`,
  `RemoveService`) and asserts every entry maps to
  `yerr.CodeTimeout` attributed to `apierr.DependencyDokploy` with
  an attempt count consistent with the idempotency rule (POST = 1;
  GET and DELETE = 1 + MaxRetries). The second member spins the
  typed Dokploy client up against a per-iteration in-process
  `dokployfake.Server`, queues `expectedAttempts` `TimeoutFault`
  entries whose delay outlasts the per-attempt timeout, and asserts
  every returned error is a typed `*yerr.Error` with the expected
  code, dependency, attempt count, and request-id propagation. The
  single static defence is
  `internal/release/verification_suite_chaos_dokploy_timeouts_static_test.go`,
  which pins the existence of the canonical
  `chaos_dokploy_timeouts_test.go` file and the canonical
  `TestChaosDokployTimeoutsCoversCallSites` +
  `TestChaosDokployTimeoutsMapsToTypedTimeoutEnvelope` function
  pair (the load-bearing `-run TestChaosDokployTimeouts` filter
  from `verificationLoop.requiredBackendCommands` binds to the
  `TestChaosDokployTimeouts` prefix) so the chaos-timeout
  convention itself cannot be silently deleted or renamed.
- **Determinism.** The chaos-timeout tests run against
  deterministic fixtures only — a per-iteration `dokployfake.Server`
  constructed in-process with no shared instance state, a
  bounded-budget retry client whose `RetryBaseDelay`/`RetryMaxDelay`
  collapse the production backoff to sub-millisecond so the suite
  stays fast, and `TimeoutFault` entries whose delay is bounded by
  the per-attempt context cancellation so the wall-clock cost is
  predictable. No chaos test reaches a live Dokploy or any network.
  A live Dokploy smoke is opt-in via `YALLA_EXTERNAL_DOKPLOY` and
  never runs in the default gate; `TestLiveDokploySmoke` is the
  documented opt-in entry point.
- **Actionable failures.** Every diagnostic surfaces the offending
  scenario name AND the observed `request_id` from the
  `telemetry.NewRequestID()` seed propagated through the call
  context so an operator reading the CI log can map the failure to
  the exact chaos scenario and in-flight request without re-running
  the suite locally. The attempt-count mismatch path reports both
  observed and expected counts so an idempotency-rule regression
  surfaces with the exact divergence.
- **Coverage rows.** The closed-set chaos-scenario coverage member
  (`TestChaosDokployTimeoutsCoversCallSites`) drives the entire
  typed client surface — `GET /api/deployments/<id>` retried inside
  the bounded budget, `POST /api/organizations` attempted exactly
  once, `DELETE /api/services/<id>` retried inside the bounded
  budget — and the runtime classification member
  (`TestChaosDokployTimeoutsMapsToTypedTimeoutEnvelope`) drives
  every scenario through the production `Client.do` /
  `Client.attempt` / `Client.transportError` chain so an
  end-to-end regression in the per-attempt timeout, the
  idempotency-aware retry budget, the typed-error mapping, or the
  redaction chokepoint surfaces on the first iteration that fires.
- **Schema-version contract.** Every public HTTP response that
  surfaces a Dokploy-timeout failure (a provisioning job marked
  failed, an admin diagnostic that reports the upstream as
  `unavailable`, an error envelope returned to the customer) uses
  the stable JSON envelope shape pinned by `yalla.output.v1`
  (success) and `yalla.error.v1` (error). The chaos-timeout suite
  itself asserts on the typed `*yerr.Error` boundary the envelope
  is built from, so a regression that drifted the wire shape would
  also fail the upstream handler-contract suite (BE-0381) and the
  OpenAPI conformance suite (BE-0382).
- **Redaction.** Test output, error chains, audit metadata, and
  the recorded request fixtures the fake exposes via
  `Server.Requests()` MUST stay redacted of secrets — the Dokploy
  bearer token literal, the canonical Yalla API key prefix
  (`yka_`), the `Bearer ` scheme value, and the literal
  `DOKPLOY_TOKEN` env-var name are scrubbed by
  `internal/output.Redactor` and the fake's `record()` chokepoint
  before any byte reaches a test log or an audit blob. The chaos
  suite walks the whole `errors.Unwrap` chain and every recorded
  request's `Authorization` field looking for these markers, so a
  leaked credential surfaces with the marker substring that
  drifted.
- **CI cadence.** The chaos-timeout gate runs as a dedicated
  `Chaos tests for Dokploy timeouts` step in
  `.github/workflows/ci.yml`, under
  `# 18. Required: chaos tests for Dokploy timeouts` in
  `scripts/verify.sh`, as entry `18` in `CONTRIBUTING.md` under
  `## Required Checks Before Every Commit`, and in
  `ralph/prd.json` under
  `verificationLoop.requiredBackendCommands` so an AI agent
  reading the PRD before picking up a story sees the gate without
  needing to discover it from shell scripts or CI workflows.
  Every push and PR runs the gate; a live-Dokploy smoke remains
  opt-in via `YALLA_EXTERNAL_DOKPLOY=1`. The single static
  defence that pins every one of those surfaces is
  `internal/release/verification_suite_chaos_dokploy_timeouts_static_test.go`.

## Chaos Tests For Postgres Disconnects

The chaos-disconnect suite (BE-0394) is the store-layer
chaos-classification gate. It exists to catch a class of regressions a
single-request unit test cannot: a Postgres connection drop
misclassified as `E_INTERNAL` or `E_TIMEOUT` after a code refactor, a
store-layer call that classifies a transient transport failure as a
permanent failure and refuses to retry, a `request_id` that fails to
propagate through the per-op context so an operator cannot correlate a
disconnect with the originating request, or a DSN password literal
leaking into the error chain even under
`chaosPostgresWorkers * chaosPostgresIterationsPerWorker` concurrent
goroutines per scenario. The canonical pair
(`TestChaosPostgresDisconnectsCoversCallSites` and
`TestChaosPostgresDisconnectsMapsToTypedUnavailableEnvelope`) lives in
`internal/controlplane/store/chaos_postgres_disconnects_test.go` and
binds to the PRD's `-run TestChaosPostgresDisconnects` filter; the
static defence for every collateral surface lives in
`internal/release/verification_suite_chaos_postgres_disconnects_static_test.go`.

- **Scope.** The two load-bearing chaos invariants are exercised by
  the canonical function pair. The first member walks an in-memory
  closed-set scenario table covering the pgxpool surface every store
  method uses (`Pool.Ping`, `Pool.Acquire`, `Pool.Begin`, `Pool.Exec`,
  `Pool.Query`) and asserts every entry maps to `yerr.CodeUnavailable`
  attributed to `apierr.DependencyStore`. The second member spins a
  fresh `pgxpool.Pool` up against a per-iteration in-process
  `fakepg.Server`, queues a `DisconnectFault` per pool op, fires the
  scenario's call under a context carrying a SafeID `request_id`,
  wraps the resulting pgx error through `apierr.StoreUnavailable`
  (the single public classifier chokepoint the store layer's
  call-site surfaces use), and asserts every wrapped error is a typed
  `*yerr.Error` with `Code=yerr.CodeUnavailable`, attributed to
  `apierr.DependencyStore`, with the fake recording at least one
  accepted TCP connection per attempt. The single static defence is
  `internal/release/verification_suite_chaos_postgres_disconnects_static_test.go`,
  which pins the existence of the canonical
  `chaos_postgres_disconnects_test.go` file and the canonical
  `TestChaosPostgresDisconnectsCoversCallSites` +
  `TestChaosPostgresDisconnectsMapsToTypedUnavailableEnvelope` function
  pair (the load-bearing `-run TestChaosPostgresDisconnects` filter
  from `verificationLoop.requiredBackendCommands` binds to the
  `TestChaosPostgresDisconnects` prefix) so the chaos-disconnect
  convention itself cannot be silently deleted or renamed. The
  classification chokepoint is `apierr.StoreUnavailable`, which
  produces a `*yerr.Error` whose `Code=yerr.CodeUnavailable` and
  whose dependency tag is `apierr.DependencyStore`.
- **Determinism.** The chaos-disconnect tests run against
  deterministic fixtures only — a per-iteration `fakepg.Server`
  constructed in-process with no shared instance state, a fresh
  `pgxpool.Pool` per iteration whose `ConnectTimeout` is bounded by
  `chaosPostgresConnectTimeout` so a single attempt completes well
  under one second, and `DisconnectFault` entries that close the
  accepted TCP socket gracefully (FIN, not RST) so pgx's dial
  completes and the chaos error surfaces on the startup-handshake
  read — the same failure mode an actual Postgres restart or network
  partition produces in production. No chaos test reaches a live
  Postgres, a live Dokploy, or any external network.
- **Actionable failures.** Every diagnostic surfaces the offending
  scenario name AND the observed `request_id` from
  `telemetry.NewRequestID()` propagated through the call context via
  `telemetry.WithCorrelation` so an operator reading the CI log can
  map the failure to the exact chaos scenario and in-flight request
  without re-running the suite locally. The accepted-connection
  assertion reports the observed count so a regression that
  short-circuited pgx without ever attempting a network connect
  surfaces with the exact divergence.
- **Coverage rows.** The closed-set chaos-scenario coverage member
  (`TestChaosPostgresDisconnectsCoversCallSites`) drives the entire
  pgxpool public surface — `Pool.Ping` for health checks, `Pool.Acquire`
  for per-request connection use, `Pool.Begin` for transactional
  writes, `Pool.Exec` for one-shot mutating statements, `Pool.Query`
  for one-shot reads — and the runtime classification member
  (`TestChaosPostgresDisconnectsMapsToTypedUnavailableEnvelope`) drives
  every scenario through the production `apierr.StoreUnavailable`
  wrapper so an end-to-end regression in the classifier chokepoint,
  the dependency attribution, or the wrapped envelope's static
  message surfaces on the first iteration that fires.
- **Schema-version contract.** Every public HTTP response that
  surfaces a Postgres-disconnect failure (a request that fails because
  the datastore is briefly unreachable, an admin diagnostic that
  reports the store as `unavailable`, an error envelope returned to
  the customer) uses the stable JSON envelope shape pinned by
  `yalla.output.v1` (success) and `yalla.error.v1` (error). The
  chaos-disconnect suite itself asserts on the typed `*yerr.Error`
  boundary the envelope is built from, so a regression that drifted
  the wire shape would also fail the upstream handler-contract suite
  (BE-0381) and the OpenAPI conformance suite (BE-0382).
- **Redaction.** Test output, error chains, audit metadata, and the
  wrapped envelope's rendered message MUST stay redacted of secrets —
  the sentinel password literal embedded in every chaos DSN MUST
  NEVER appear at any level of the wrapped cause chain, and the
  wrapped envelope's `Error()` message MUST stay static
  (`apierr.StoreUnavailable`'s rendered message is "the Yalla
  datastore is temporarily unavailable") so neither the DSN password
  nor the DSN username sentinel echoes into a test log or an audit
  blob. The chaos suite walks the whole `errors.Unwrap` chain looking
  for the password marker and re-asserts both markers against the
  wrapped envelope's rendered string, so a leaked credential
  surfaces with the marker substring that drifted.
- **CI cadence.** The chaos-disconnect gate runs as a dedicated
  `Chaos tests for Postgres disconnects` step in
  `.github/workflows/ci.yml`, under
  `# 19. Required: chaos tests for Postgres disconnects` in
  `scripts/verify.sh`, as entry `19` in `CONTRIBUTING.md` under
  `## Required Checks Before Every Commit`, and in
  `ralph/prd.json` under
  `verificationLoop.requiredBackendCommands` so an AI agent
  reading the PRD before picking up a story sees the gate without
  needing to discover it from shell scripts or CI workflows.
  Every push and PR runs the gate. The single static defence that
  pins every one of those surfaces is
  `internal/release/verification_suite_chaos_postgres_disconnects_static_test.go`.

## Idempotency Replay Tests

The idempotency-replay suite (BE-0395) is the HTTP idempotency
middleware replay gate. It exists to catch a class of regressions a
single-request unit test cannot: a retry that re-runs the wrapped
handler and double-creates a project, a recorded body that drifts on
replay so an agent sees a different `request_id` on the second
call, an in-memory recorder that returns truncated bytes under
concurrent retries, or a submitted request body reflected into the
recorded envelope so a sentinel marker placed inside the body would
surface in an audit log. The canonical pair
(`TestIdempotencyReplayCoversCallSites` and
`TestIdempotencyReplayPreservesByteIdenticalEnvelope`) lives in
`internal/controlplane/httpapi/idempotency_replay_test.go` and binds
to the PRD's `-run TestIdempotencyReplay` filter; the static defence
for every collateral surface lives in
`internal/release/verification_suite_idempotency_replay_static_test.go`.

- **Scope.** The two load-bearing replay invariants are exercised by
  the canonical function pair. The first member walks a closed-set
  scenario table covering every outcome category the middleware
  records: a success scenario that renders a `yalla.output.v1`
  envelope at 202 Accepted, a validation-failure scenario that
  renders a `yalla.error.v1` envelope at 400 Bad Request with
  `E_INVALID_INPUT`, an authorization-failure scenario at 403
  Forbidden with `E_FORBIDDEN`, and a not-found scenario at 404 Not
  Found with `E_NOT_FOUND`. For each scenario the test asserts the
  wrapped handler runs exactly once, the second response's status
  equals the first, the second response's body is byte-identical to
  the first, the replay carries the `Idempotency-Replayed: true`
  header, and the recorded body carries the schema_version it
  advertises on the wire. The 5xx server-failure case is deliberately
  excluded from the replay closed set — the middleware's contract
  releases the claim on 5xx so a retry re-runs the handler rather
  than replaying an unfinished result, and that exclusion is pinned
  separately by `TestRequireIdempotencyServerErrorIsNotRecorded`. The
  second member seeds a completed claim and fires
  `replayWorkers * replayIterationsPerWorker` concurrent retries
  against the same `Idempotency-Key`, asserting every retry observes
  the same status, the same byte-identical body, the
  `Idempotency-Replayed: true` header, and that the wrapped handler
  is never invoked. The single static defence is
  `internal/release/verification_suite_idempotency_replay_static_test.go`,
  which pins the existence of the canonical
  `idempotency_replay_test.go` file and the canonical
  `TestIdempotencyReplayCoversCallSites` +
  `TestIdempotencyReplayPreservesByteIdenticalEnvelope` function
  pair (the load-bearing `-run TestIdempotencyReplay` filter from
  `verificationLoop.requiredBackendCommands` binds to the
  `TestIdempotencyReplay` prefix) so the replay convention itself
  cannot be silently deleted or renamed.
- **Determinism.** The idempotency-replay tests run against
  deterministic fixtures only — a per-scenario in-process
  `fakeIdempotencyStore` constructed with no shared instance state,
  a per-scenario `recordingHandler` whose invocation count is the
  closed-set bound, and seeded claims whose recorded bodies are
  byte-literal `yalla.output.v1` envelopes (a structural comparison
  would mask a whitespace drift). No replay test reaches a live
  Postgres, a live Dokploy, or any external network.
- **Actionable failures.** Every diagnostic surfaces the offending
  scenario name AND, where relevant, the iteration index from the
  concurrent burst so an operator reading the CI log can map the
  failure to the exact replay scenario without re-running the suite
  locally. The byte-identical-envelope member reports the iteration
  count plus the observed body bytes so a regression that drifted
  the recorder under contention surfaces with the exact divergence.
- **Schema-version contract.** Every public HTTP response the
  middleware records — a recorded 202 success, a recorded 400
  validation failure, a recorded 403 authorization failure, a
  recorded 404 not-found — uses the stable JSON envelope shape
  pinned by `yalla.output.v1` (success) and `yalla.error.v1`
  (error). The replay suite asserts the schema_version literal
  survives byte-identically into the recorded claim AND the replayed
  response, so a regression that re-rendered the envelope on replay
  (and dropped or drifted the schema_version) trips here even if the
  parsed JSON stayed semantically equivalent.
- **Redaction.** A sentinel marker placed inside the submitted
  request body MUST NEVER appear in the first rendered response, in
  the recorded claim body, or in the replayed response — the
  middleware records the already-rendered, already-redacted
  apienvelope body, so a regression that started recording the raw
  handler output or reflecting the request body into the envelope
  would surface with the marker substring. Test output, error
  chains, audit metadata, and the recorded envelope MUST stay
  redacted of secrets.
- **CI cadence.** The idempotency-replay gate runs as a dedicated
  `Idempotency replay tests` step in `.github/workflows/ci.yml`,
  under `# 20. Required: idempotency replay tests` in
  `scripts/verify.sh`, as entry `20` in `CONTRIBUTING.md` under
  `## Required Checks Before Every Commit`, and in `ralph/prd.json`
  under `verificationLoop.requiredBackendCommands` so an AI agent
  reading the PRD before picking up a story sees the gate without
  needing to discover it from shell scripts or CI workflows.
  Every push and PR runs the gate. The single static defence that
  pins every one of those surfaces is
  `internal/release/verification_suite_idempotency_replay_static_test.go`.

## Audit Completeness Tests

The audit-completeness suite (BE-0396) is the audit-log completeness
gate. It exists to catch a class of regressions a single-call unit
test cannot: a denied authorization decision that is never written to
the audit log because the deny path forgot to call
`audit.Auditor.Record`, a recorded event that drops its `request_id`
because the auth middleware regressed, a cross-write under contention
where one emitter's `request_id` lands on another's recorded event,
or a sensitive-shaped metadata value reflected unredacted into a
recorded `Metadata` value or — worse — into a non-Metadata field.
The canonical pair (`TestAuditCompletenessCoversCallSites` and
`TestAuditCompletenessPreservesRecordedFieldsUnderContention`) lives
in `internal/controlplane/audit/audit_completeness_test.go` and binds
to the PRD's `-run TestAuditCompleteness` filter; the static defence
for every collateral surface lives in
`internal/release/verification_suite_audit_completeness_static_test.go`.

- **Scope.** The two load-bearing audit-completeness invariants are
  exercised by the canonical function pair. The first member walks a
  closed-set scenario table covering every canonical action surface
  (`policy.Action` constants for organization, project, environment,
  service, api_keys, limits) recorded as BOTH an `allowed` decision
  AND a `denied` decision via `audit.Auditor.Record`. For each
  scenario the test asserts the recorded `store.AuditEvent` carries a
  non-empty `Action`, `ResourceKind`, `ResourceID`, `Decision`,
  `Reason`, `OrganizationID`, `ActorID`, `ActorKind`, `RequestID`,
  and `CorrelationID`, every value matches the scenario inputs
  byte-for-byte (the `policy.Decision` verdict surfaces as the
  recorded `AuditDecisionAllowed` or `AuditDecisionDenied`, the
  `policy.Action` surfaces as the recorded `Action`, the
  `policy.Resource.Kind` surfaces as the recorded `ResourceKind`),
  the sensitive-shaped metadata value is replaced with
  `output.Sentinel` in the recorded `Metadata` map, and the sentinel
  marker does NOT leak into any non-Metadata recorded field. The
  second member seeds a single shared `audit.Auditor` from
  `auditCompletenessWorkers * auditCompletenessIterationsPerWorker`
  goroutines each firing a recorded decision with a distinct
  `request_id`, and asserts the recorder captured exactly that many
  events, every event's `RequestID` resolves to its emitter (no
  drop, no duplicate, no cross-write), every event carries the
  matching organization id and a non-empty actor id, the sentinel
  marker stays redacted on every event, and the marker substring
  does NOT appear in any captured event's `Action`, `Reason`,
  `ResourceID`, `IPAddress`, or `UserAgent`. The single static
  defence is
  `internal/release/verification_suite_audit_completeness_static_test.go`,
  which pins the existence of the canonical
  `audit_completeness_test.go` file and the canonical
  `TestAuditCompletenessCoversCallSites` +
  `TestAuditCompletenessPreservesRecordedFieldsUnderContention`
  function pair (the load-bearing `-run TestAuditCompleteness`
  filter from `verificationLoop.requiredBackendCommands` binds to
  the `TestAuditCompleteness` prefix) so the audit-completeness
  convention itself cannot be silently deleted or renamed.
- **Determinism.** The audit-completeness tests run against
  deterministic fixtures only — the in-package `fakeRecorder` (a
  zero-mutex stand-in for `*store.AuditRepository` reused from
  `audit_test.go` by the coverage member) and the file-local
  `concurrentAuditRecorder` (a mutex-guarded recorder used only by
  the contention burst). The principal and `telemetry.Correlation`
  are constructed in-process via the shared `ctxWith` helper. No
  audit-completeness test reaches a live Postgres, a live Dokploy,
  or any external network.
- **Actionable failures.** Every diagnostic surfaces the offending
  scenario name (for the coverage member) or the worker + iteration
  index (for the burst member) AND the observed `request_id` so an
  operator reading the CI log can map the failure to the exact
  recorded emission without re-running the suite locally. The
  per-emitter field-fidelity member reports the exact field whose
  fidelity drifted (a missing `RequestID`, a mis-attributed
  `OrganizationID`, a recorded `Decision` whose value disagrees
  with the scenario verdict) so a regression in the audit recorder
  under contention surfaces with the exact divergence.
- **Schema-version contract.** Every public HTTP response the
  audited mutating endpoints render — a 2xx `yalla.output.v1`
  success envelope, a 4xx `yalla.error.v1` validation /
  authorization / not-found envelope — flows through the same
  audit chokepoint the canonical pair exercises. The audit-
  completeness suite asserts the audit log preserves the
  identifying fields the envelope's `request_id` carried, so a
  regression that re-rendered the envelope and dropped the
  `request_id` from the audit row trips here even if the parsed
  JSON stayed semantically equivalent.
- **Redaction.** A sentinel marker placed under a sensitive-shaped
  metadata key MUST NEVER appear in the recorded `Metadata` value
  — `audit.Auditor.Record` runs every metadata value through the
  redactor before persistence, and the audit-completeness gate
  asserts the recorded value is replaced wholesale with
  `output.Sentinel`. The marker substring MUST also NEVER appear in
  any non-Metadata recorded field (`Action`, `ResourceID`,
  `Reason`, `IPAddress`, `UserAgent`); a regression that reflected
  metadata into a non-Metadata field would surface with the marker
  substring. Test output, error chains, audit metadata, and the
  recorded event MUST stay redacted of secrets.
- **CI cadence.** The audit-completeness gate runs as a dedicated
  `Audit completeness tests` step in `.github/workflows/ci.yml`,
  under `# 21. Required: audit completeness tests` in
  `scripts/verify.sh`, as entry `21` in `CONTRIBUTING.md` under
  `## Required Checks Before Every Commit`, and in `ralph/prd.json`
  under `verificationLoop.requiredBackendCommands` so an AI agent
  reading the PRD before picking up a story sees the gate without
  needing to discover it from shell scripts or CI workflows.
  Every push and PR runs the gate. The single static defence that
  pins every one of those surfaces is
  `internal/release/verification_suite_audit_completeness_static_test.go`.

## Pagination Stability Tests

The pagination-stability suite (BE-0397) is the list-endpoint cursor
stability gate. It exists to catch a class of regressions a
single-call unit test cannot: a list endpoint that silently
duplicates rows under a concurrent insert, a cursor that decodes
without sort/direction integrity checking and lets a caller mix
cursors across endpoints, a wire-shape switch from base64url to a
non-URL-safe encoding that breaks CDN caching guarantees, or a
cross-tenant cursor that leaks rows because the store layer dropped
the orgID scope. The canonical pair
(`TestPaginationStabilityCoversCallSites` and
`TestPaginationStabilityPreservesPagesUnderInserts`) lives in
`internal/controlplane/pagination/pagination_stability_test.go` and
binds to the PRD's `-run TestPaginationStability` filter; the
static defence for every collateral surface lives in
`internal/release/verification_suite_pagination_stability_static_test.go`.

- **Scope.** The two load-bearing pagination-stability invariants
  are exercised by the canonical function pair. The first member
  walks a closed-set scenario table covering every canonical
  list-endpoint shape (empty set, single row, exact page, multi-page
  no remainder, multi-page with trailing partial, small-page
  descending, ascending) and asserts no duplicates and no drops in
  the paged traversal — every seeded row in the coverage tenant
  appears exactly once across the cursor stream, the terminal
  page's `next_cursor` is empty exactly when there are no further
  rows, every emitted Page carries a non-nil Items slice, every
  emitted cursor round-trips through `DecodeCursor` with matching
  Sort and Direction, the encoded cursor wire shape stays
  base64url-safe (no padding, no `+`, no `/`, no `=`, no
  whitespace), and a cursor issued for the coverage tenant yields
  zero rows when applied against a cross tenant. The second member
  seeds a single shared `concurrentPaginationStore` with
  `paginationStabilitySeedRows` rows under one tenant and a reader
  paginates end-to-end at `paginationStabilityPageSize` while
  `paginationStabilityWorkers * paginationStabilityIterationsPerWorker`
  goroutines fire mixed insert + delete operations against the
  same tenant; it asserts the reader's cursor stream contains no
  duplicate ids across pages, every undeleted seed row appears
  exactly once, no row deleted before the reader could observe it
  resurrects in any subsequent page, and the traversal terminates
  via an empty `next_cursor` within a safety bound. The single
  static defence is
  `internal/release/verification_suite_pagination_stability_static_test.go`,
  which pins the existence of the canonical
  `pagination_stability_test.go` file and the canonical
  `TestPaginationStabilityCoversCallSites` +
  `TestPaginationStabilityPreservesPagesUnderInserts` function
  pair (the load-bearing `-run TestPaginationStability` filter
  from `verificationLoop.requiredBackendCommands` binds to the
  `TestPaginationStability` prefix) so the pagination-stability
  convention itself cannot be silently deleted or renamed.
- **Determinism.** The pagination-stability tests run against
  deterministic fixtures only — the in-package `fakeStore` (a
  zero-mutex list fixture declared in `page_test.go` and reused by
  the coverage member) and the file-local
  `concurrentPaginationStore` (a mutex-guarded list fixture used
  only by the contention burst). The seeded ids and createdAt
  values are constants — every test run paginates the identical
  initial set, the burst's insert ids are derived from the worker
  + iteration index, and the delete targets are chosen so the
  reader only observes them on later pages. No
  pagination-stability test reaches a live Postgres, a live
  Dokploy, or any external network.
- **Actionable failures.** Every diagnostic surfaces the offending
  scenario name (for the coverage member) or the worker +
  iteration index (for the burst member) AND the offending row id
  so an operator reading the CI log can map the failure to the
  exact in-flight traversal without re-running the suite locally.
  The list-endpoint envelope each scenario exercises carries an
  originating `request_id`; a regression that dropped the cursor
  stability under contention surfaces with the divergent row id
  bound to the iteration it came from, and the diagnostic names
  every required pagination invariant (no duplicates, no drops,
  cursor opaqueness, no cross-tenant leak) that the regression
  violated.
- **Schema-version contract.** Every public HTTP response a list
  endpoint renders — a 2xx `yalla.output.v1` success envelope
  carrying `Page[T]` as the items + next_cursor + total_estimate
  payload, a 4xx `yalla.error.v1` validation envelope when a
  cursor or limit is malformed — flows through the cursor
  chokepoint the canonical pair exercises. The
  pagination-stability suite asserts the cursor wire shape is
  stable under every scenario (base64url with the
  `EncodeCursor` / `DecodeCursor` round-trip preserving Sort and
  Direction), so a regression that changed the encoded payload
  schema would trip here even if the parsed JSON stayed
  semantically equivalent.
- **Redaction.** The cursor wire payload is redacted of tenant
  identifiers by construction — `pagination.Cursor` carries
  Position, Sort, and Direction but NEVER an organization id —
  so the opaque cursor cannot be a reflection channel and a
  caller cannot hand-craft a cursor to read another tenant's
  rows. The coverage member exercises a cross-tenant probe
  (a cursor issued for the coverage tenant applied against a
  sibling tenant's store) and asserts zero rows surface; the
  cursor-decoder rejects schema-version mismatches so a
  tampered cursor surfaces as a stable 400 instead of a silent
  cross-tenant read. Test output, error chains, and audit
  metadata stay redacted of secrets, and the wire cursor is
  base64url-safe so an intermediate CDN or log shipper cannot
  reflect it into a URL position that escapes URL-safety
  guarantees.
- **Tenant isolation.** Cross-tenant cursors do not leak rows.
  The store layer scopes every list query by organization id
  before the cursor is consulted; the cursor only carries a
  position within the already-tenant-scoped set. A cursor
  issued for tenant A pointed at tenant B's store yields zero
  rows from tenant A and zero rows of tenant B that tenant A
  could not already see. The canonical pair pins this with a
  cross-tenant probe in the coverage member.
- **CI cadence.** The pagination-stability gate runs as a
  dedicated `Pagination stability tests` step in
  `.github/workflows/ci.yml`, under
  `# 22. Required: pagination stability tests` in
  `scripts/verify.sh`, as entry `22` in `CONTRIBUTING.md` under
  `## Required Checks Before Every Commit`, and in
  `ralph/prd.json` under
  `verificationLoop.requiredBackendCommands` so an AI agent
  reading the PRD before picking up a story sees the gate
  without needing to discover it from shell scripts or CI
  workflows. Every push and PR runs the gate. The single static
  defence that pins every one of those surfaces is
  `internal/release/verification_suite_pagination_stability_static_test.go`.

## Tenant Isolation Tests

The tenant-isolation suite (BE-0398) is the cross-tenant authorization
gate. It exists to catch a class of regressions a single-call unit
test cannot: a role drift that quietly allowed `RoleAdmin` to read
another tenant's project, a re-ordering of `policy.Engine.Decide`'s
short-circuits that let a cross-tenant resource bypass the
disabled-principal check, a scoped `Grant` that silently bridged
tenants because the engine forgot to compare `Grant.Scope.OrganizationID`
against `Principal.OrganizationID`, or a custom-role hook regression
that minted CapWrite across tenants. The canonical pair
(`TestTenantIsolationCoversCallSites` and
`TestTenantIsolationPreservesScopeUnderContention`) lives in
`internal/controlplane/policy/tenant_isolation_test.go` and binds to
the PRD's `-run TestTenantIsolation` filter; the static defence for
every collateral surface lives in
`internal/release/verification_suite_tenant_isolation_static_test.go`.

- **Scope.** The two load-bearing tenant-isolation invariants are
  exercised by the canonical function pair. The first member walks a
  closed-set scenario table covering every built-in role
  (`RoleOwner`, `RoleAdmin`, `RoleDeveloper`, `RoleViewer`,
  `RoleCI`, `RoleSupport`) × every catalogued `policy.Action` ×
  resources whose `Scope.OrganizationID` is the cross tenant, and
  asserts the engine's verdict matches the engine's documented
  cross-tenant ordering: `CapSelf` actions are
  organization-independent and surface `ReasonAllowedSelf`; the
  support role's `CapSupport` bridges the tenant boundary for
  `CapRead` and `CapSupport` actions only and surfaces
  `ReasonAllowedBySupport`; every other (role, action) pair on a
  cross-tenant resource surfaces `ReasonDeniedCrossTenant`. The
  closed set also covers the three short-circuit guards that MUST
  precede the cross-tenant check — a missing principal surfaces
  `ReasonDeniedNoPrincipal`, a disabled principal surfaces
  `ReasonDeniedPrincipalDisabled`, an uncatalogued action surfaces
  `ReasonDeniedUnknownAction` — and asserts a scoped `Grant` whose
  `Scope.OrganizationID` is the cross tenant is silently ignored by
  the engine (`ReasonDeniedNoCapability`, never
  `ReasonAllowedByGrant`). The second member fires
  `tenantIsolationWorkers * tenantIsolationIterationsPerWorker`
  goroutines against a single shared `policy.Engine` constructed via
  `NewEngine()`, each goroutine drawing a tuple from the same
  coverage table and asserting the verdict it observed matches the
  verdict its OWN tuple predicts — a cross-write that swapped two
  goroutines' principals or resources under the race would fail the
  per-iteration assertion even when the aggregate verdict counts
  matched. The single static defence is
  `internal/release/verification_suite_tenant_isolation_static_test.go`,
  which pins the existence of the canonical
  `tenant_isolation_test.go` file and the canonical
  `TestTenantIsolationCoversCallSites` +
  `TestTenantIsolationPreservesScopeUnderContention` function pair
  (the load-bearing `-run TestTenantIsolation` filter from
  `verificationLoop.requiredBackendCommands` binds to the
  `TestTenantIsolation` prefix) so the tenant-isolation convention
  itself cannot be silently deleted or renamed.
- **Determinism.** The tenant-isolation tests run against
  deterministic fixtures only — the in-process `policy.Engine`
  constructed via `NewEngine()` with the package's default action
  catalog, principals and resources built from constant tenant ids
  (`orgA`, `orgB`), and the closed-set role × action coverage table
  enumerated from `policy.BuiltinRoles()` and `policy.Actions()`.
  The contention burst's per-goroutine tuple is derived from the
  worker + iteration index and indexes into the coverage table, so
  every test run exercises the identical decision set. No
  tenant-isolation test reaches a live Postgres, a live Dokploy, or
  any external network.
- **Actionable failures.** Every diagnostic surfaces the offending
  tuple's role + action + tenant pair (for the coverage member) or
  the worker + iteration index AND the offending tuple (for the
  burst member) so an operator reading the CI log can map the
  failure to a specific decision without re-running the suite
  locally. The mapped HTTP envelope each cross-tenant denial
  exercises carries an originating `request_id`; a regression that
  flipped a cross-tenant verdict surfaces with the divergent tuple
  bound to the iteration it came from, and the diagnostic names
  every required tenant-isolation invariant
  (`ReasonDeniedCrossTenant`, the short-circuit ordering, the
  grant-never-bridges-tenants rule) that the regression violated.
- **Schema-version contract.** Every public HTTP response the
  authorization middleware renders — a 2xx `yalla.output.v1`
  success envelope when the engine returns allow, a 4xx
  `yalla.error.v1` envelope (`apierr.Unauthenticated` mapped to
  HTTP 401 when the principal is missing, `apierr.Forbidden`
  mapped to HTTP 403 for every other deny, and a deliberate
  remapping to `yerr.CodeNotFound` at the handler layer for
  cross-tenant resources so the existence of another tenant's row
  is never revealed by status alone) — flows through
  `policy.Engine.Authorize`, the chokepoint the canonical pair
  exercises. The tenant-isolation suite asserts the engine's
  decision shape is stable under every scenario so a regression
  that changed the verdict for a (role, action, cross-tenant)
  triple would trip here even if the wire shape stayed valid JSON.
- **Redaction.** The error message
  `policy.Engine.Authorize` places on the wire carries only the
  action and the stable reason code — never the principal ID, the
  resource ID, or any organization id — so a 403 cannot be used as
  a side-channel to confirm another tenant's resource exists. The
  coverage member exercises a cross-tenant probe for every role
  and every action and asserts the rendered error message stays
  free of every cross-tenant identifier; the burst member preserves
  this contract under contention. Test output, error chains, and
  audit metadata stay redacted of secrets — the tenant-isolation
  suite never logs principal ids, resource ids, or cross-tenant
  organization ids.
- **Tenant isolation.** This suite IS the tenant-isolation gate.
  Cross-tenant resource access is denied with
  `ReasonDeniedCrossTenant` for every role except the support
  role's `CapSupport` bridge (limited to `CapRead` and
  `CapSupport` actions). Scoped `Grant`s never bridge tenants —
  a `Grant.Scope.OrganizationID` that does not match the
  `Principal.OrganizationID` is silently ignored by the engine. The
  canonical pair pins both invariants with a closed-set coverage
  table AND a contention burst, so a regression in either the
  cross-tenant short-circuit or the grant-tenant comparison trips
  the gate.
- **CI cadence.** The tenant-isolation gate runs as a dedicated
  `Tenant isolation tests` step in `.github/workflows/ci.yml`,
  under `# 23. Required: tenant isolation tests` in
  `scripts/verify.sh`, as entry `23` in `CONTRIBUTING.md` under
  `## Required Checks Before Every Commit`, and in
  `ralph/prd.json` under
  `verificationLoop.requiredBackendCommands` so an AI agent
  reading the PRD before picking up a story sees the gate without
  needing to discover it from shell scripts or CI workflows.
  Every push and PR runs the gate. The single static defence that
  pins every one of those surfaces is
  `internal/release/verification_suite_tenant_isolation_static_test.go`.

## Backup Restore Rehearsal Tests

The backup and restore rehearsal suite (BE-0399) is the
backup-and-restore-loop gate. It exists to catch a class of
regressions a single-call unit test cannot: a reporter that quietly
returned a 200 envelope on a malformed status, a parse-error path
that started echoing the file content into the wire message, a
freshness predicate switched from `Age <= MaxAge` to `Age < MaxAge`
so the on-boundary value flapped, or a regression that turned the
`pristine post-restore` case into a 5xx because the missing-file
sentinel was dropped. The canonical pair
(`TestBackupRestoreRehearsalCoversCallSites` and
`TestBackupRestoreRehearsalPreservesContractUnderContention`) lives
in `internal/controlplane/backup/backup_restore_rehearsal_test.go`
and binds to the PRD's `-run TestBackupRestoreRehearsal` filter; the
static defence for every collateral surface lives in
`internal/release/verification_suite_backup_restore_static_test.go`.

- **Scope.** The two load-bearing rehearsal invariants are exercised
  by the canonical function pair. The first member walks a
  closed-set scenario table that covers every documented
  `backup.FileReporter` state across the operator's backup-and-
  restore loop: (1) the pristine post-restore state where the status
  path is wired but no backup has landed yet surfaces
  `ErrNoBackupRecorded` so a freshly-provisioned environment is
  healthy rather than a 5xx; (2) the successful rehearsal where a
  recently-landed `RFC3339` timestamp is parsed and reported with
  `Configured=true`, the operator-chosen `MaxAge` mirrored on the
  returned Status, and `Status.Fresh` reporting true against the
  configured freshness threshold; (3) the on-`MaxAge` boundary case
  where `Age == MaxAge` still satisfies `Status.Fresh` so the probe
  does not flap at the boundary; (4) the past-window case where
  `Age > MaxAge` surfaces stale so an operator sees the gate failure;
  (5) the zero-`MaxAge` opt-out where any `Age` yields fresh so a
  probe shipped before the operator picks a threshold does not flap;
  (6) the clock-skew clamp where a status timestamp in the future
  preserves `Status.LastSuccessAt` untouched but clamps `Age` to zero
  so downstream JSON rendering and `Status.Fresh` get a well-defined
  non-negative value; (7) the whitespace-tolerant parse where the
  reporter parses cleanly through surrounding whitespace or a
  trailing newline; (8) the empty-status, whitespace-only, and
  malformed-status cases that each surface a typed `yerr.CodeServer`
  error whose rendered message names the status file path but never
  echoes the content; (9) the secret-seeded status file where the
  parse error stays free of the seeded marker — the redaction
  guard the entire suite hinges on; (10) the `Unconfigured()`
  zero-state where `Configured=false` and `Status.Fresh` returns true
  unconditionally; and (11) the cancelled-context case where a
  shutting-down probe surfaces `context.Canceled` rather than an
  I/O error. The second member fires
  `rehearsalWorkers * rehearsalIterationsPerWorker` goroutines
  against a single shared `FileReporter` per scenario, each goroutine
  drawing a fixture from the same coverage table and asserting the
  observation it recorded matches the predicate the fixture's
  scenario predicts — a cross-write under the race that swapped two
  goroutines' fixtures would fail the per-iteration assertion even
  when the aggregate pass count matched. The single static defence is
  `internal/release/verification_suite_backup_restore_static_test.go`,
  which pins the existence of the canonical
  `backup_restore_rehearsal_test.go` file and the canonical
  `TestBackupRestoreRehearsalCoversCallSites` +
  `TestBackupRestoreRehearsalPreservesContractUnderContention`
  function pair (the load-bearing `-run TestBackupRestoreRehearsal`
  filter from `verificationLoop.requiredBackendCommands` binds to
  the `TestBackupRestoreRehearsal` prefix) so the rehearsal
  convention itself cannot be silently deleted or renamed.
- **Determinism.** The rehearsal tests run against deterministic
  fixtures only — `t.TempDir`-backed status files seeded with
  per-scenario content, `FileReporter` instances constructed via
  `NewFileReporter` against an injected fixed clock, and the closed
  set of states the reporter is documented to surface. The
  contention burst's per-goroutine fixture is derived from the worker
  + iteration index and indexes into the coverage table, so every
  test run exercises the identical decision set. No rehearsal test
  reaches a live Postgres, a live Dokploy, or any external network.
- **Actionable failures.** Every diagnostic surfaces the offending
  scenario name (for the coverage member) or the worker + iteration
  index AND the offending scenario (for the burst member) so an
  operator reading the CI log can map the failure to a specific
  rehearsal state without re-running the suite locally. The mapped
  HTTP envelope each typed-error rehearsal exercises carries an
  originating `request_id`; the rendered error message names the
  status file path (the AC3 resource id) so an operator can correlate
  the failure with the specific source the reporter was wired to.
- **Schema-version contract.** Every public HTTP response the
  `/healthz/backup` handler renders — a 2xx `yalla.output.v1` success
  envelope on `ErrNoBackupRecorded` and on a successfully parsed
  status, and a 5xx `yalla.error.v1` envelope on a typed
  `yerr.CodeServer` (mapped to `apierr.StoreUnavailable` at the
  handler boundary) — flows through `backup.FileReporter.Status`,
  the chokepoint the canonical pair exercises. The rehearsal suite
  asserts the reporter's `(Status, error)` shape is stable under
  every documented scenario so a regression that changed the
  reporter's verdict for any rehearsal state would trip here even if
  the wire shape stayed valid JSON.
- **Redaction.** The error the reporter emits names the status file
  path but never echoes the file's content, so a status file
  accidentally seeded with a secret (a misconfigured pipeline
  writing a DSN, an API key, or a session token instead of a
  timestamp) cannot leak through the wire error string. The
  coverage member exercises a secret-seeded fixture and asserts the
  rendered error message stays free of the seeded marker; the burst
  member preserves this contract under contention. Test output,
  error chains, and audit metadata stay redacted of secrets — the
  rehearsal suite never logs file content, only the path and the
  typed code.
- **Tenant isolation.** The rehearsal suite is process-global by
  design — `FileReporter` reports the state of the operator's single
  backup-and-restore pipeline, not per-tenant data — and therefore
  has no tenant boundary to enforce. The per-tenant data-isolation
  contract is enforced by the dedicated tenant-isolation suite
  (BE-0398) and the per-row repository isolation tests under
  `internal/controlplane/store/`.
- **CI cadence.** The rehearsal gate runs as a dedicated
  `Backup restore rehearsal tests` step in
  `.github/workflows/ci.yml`, under
  `# 24. Required: backup and restore rehearsal tests` in
  `scripts/verify.sh`, as entry `24` in `CONTRIBUTING.md` under
  `## Required Checks Before Every Commit`, and in
  `ralph/prd.json` under
  `verificationLoop.requiredBackendCommands` so an AI agent reading
  the PRD before picking up a story sees the gate without needing to
  discover it from shell scripts or CI workflows. Every push and PR
  runs the gate. The single static defence that pins every one of
  those surfaces is
  `internal/release/verification_suite_backup_restore_static_test.go`.

## Release Build Tests

The release build suite (BE-0401) is the release-derivation gate. It
exists to catch a class of regressions a single-call unit test cannot:
a renamed (OS, arch) coordinate that broke the npm wrapper's URL
builder, a flipped archive extension that confused the Homebrew
formula's untar step, a dropped windows `.exe` suffix that left
the installed binary unrunnable, a checksums-template drift that
desynced the per-version checksums file from the published archives,
or a regression that introduced shared mutable state in the
`internal/release` package and surfaced racing projections under
contention. The canonical pair
(`TestReleaseBuildCoversCallSites` and
`TestReleaseBuildPreservesContractUnderContention`) lives in
`internal/release/release_build_test.go` and binds to the PRD's
`-run TestReleaseBuild` filter; the static defence for every
collateral surface lives in
`internal/release/verification_suite_release_build_static_test.go`.

- **Scope.** The two load-bearing release-derivation invariants are
  exercised by the canonical function pair. The first member walks a
  closed-set scenario table built from `release.SupportedTargets` and
  asserts every documented (OS, arch) coordinate yields the predicted
  `ArchiveExt`, `BinaryName`, `ArchiveName`, and `ChecksumsName` for
  a fixed sample version. The set itself is part of the closed-set
  coverage: every documented coordinate (linux/amd64, linux/arm64,
  darwin/amd64, darwin/arm64, windows/amd64, windows/arm64) MUST
  appear exactly once and no off-list coordinate may slip in. The
  second member fires
  `releaseBuildWorkers * releaseBuildIterationsPerWorker` goroutines
  against a shared slice of `release.SupportedTargets`-derived
  scenarios, each goroutine asserting the projection for its OWN
  scenario matches the predicted values; a cross-write under the race
  that swapped two goroutines' scenarios would fail the per-iteration
  assertion even when the aggregate pass count matched. The single
  static defence is
  `internal/release/verification_suite_release_build_static_test.go`,
  which pins the existence of the canonical
  `release_build_test.go` file and the canonical
  `TestReleaseBuildCoversCallSites` +
  `TestReleaseBuildPreservesContractUnderContention` function pair
  (the load-bearing `-run TestReleaseBuild` filter from
  `verificationLoop.requiredBackendCommands` binds to the
  `TestReleaseBuild` prefix) so the release-derivation convention
  itself cannot be silently deleted or renamed.
- **Determinism.** The release build tests run against deterministic
  fixtures only — `release.SupportedTargets` is a compile-time
  constant table, the projections are pure functions of the
  `(OS, arch, version)` tuple, and the contention burst's per-
  goroutine fixture is derived from the worker + iteration index and
  indexes into the closed-set scenario table so every test run
  exercises the identical decision set. No release build test reaches
  a live Postgres, a live Dokploy, the GoReleaser binary, or any
  external network.
- **Actionable failures.** Every diagnostic surfaces the offending
  scenario name (for the coverage member) or the worker + iteration
  index AND the offending scenario (for the burst member) so an
  operator reading the CI log can map the failure to a specific
  (OS, arch) coordinate without re-running the suite locally. The
  scenario name is the `<os>_<arch>` form embedded in the archive
  name template, so an operator can correlate the failure with the
  exact GoReleaser target, npm wrapper URL, or Homebrew/Scoop/WinGet
  manifest entry.
- **Schema-version contract.** The release build suite exercises pure
  string projections — it does not render JSON envelopes — but the
  release surface it pins is the contract every released `yalla`
  binary's `--json` output relies on: the version string embedded by
  `-X main.Version` flows from the same archive-name template the
  suite covers, and a regression that desynced the archive name from
  the version stamp would break the `yalla.output.v1` `data.version`
  field downstream. The release_test.go suite that already runs the
  GoReleaser config / npm wrapper / workflow consistency checks
  remains untouched and continues to enforce the cross-tool
  invariants those tests document.
- **Redaction.** The release build tests never log secrets — the
  projection functions take only the (OS, arch, version) tuple and
  return a string, so test output, error chains, and diagnostic
  envelopes carry no credentials, no tokens, no Dokploy URLs, no
  database DSNs, and no environment variable values.
- **Tenant isolation.** The release build suite is process-global by
  design — `release.SupportedTargets` describes the distribution
  matrix, not per-tenant data — and therefore has no tenant boundary
  to enforce. The per-tenant data-isolation contract is enforced by
  the dedicated tenant-isolation suite (BE-0398) and the per-row
  repository isolation tests under `internal/controlplane/store/`.
- **CI cadence.** The release build gate runs as a dedicated
  `Release build tests` step in `.github/workflows/ci.yml`, under
  `# 25. Required: release build tests` in `scripts/verify.sh`, as
  entry `25` in `CONTRIBUTING.md` under
  `## Required Checks Before Every Commit`, and in `ralph/prd.json`
  under `verificationLoop.requiredBackendCommands` so an AI agent
  reading the PRD before picking up a story sees the gate without
  needing to discover it from shell scripts or CI workflows. Every
  push and PR runs the gate. The single static defence that pins
  every one of those surfaces is
  `internal/release/verification_suite_release_build_static_test.go`.

## Config Validation Tests

The config validation suite (BE-0402) is the configuration-loader
gate. It exists to catch a class of regressions a single-call unit
test cannot: a relaxed `YALLA_DATABASE_URL` scheme check that
silently accepted a `mysql://` DSN, a `YALLA_SECRET_KEYS` entry
that snuck through with non-hex characters, an out-of-range
`YALLA_SHUTDOWN_TIMEOUT` that wedged graceful shutdown, a strict
profile that booted with a missing operational field, a feature-
flag parser that swallowed a malformed value, a rate-limit override
that escaped the documented bounds, or a redaction regression that
echoed the offending value into an error string and leaked a
credential into operator logs, audit metadata, or test output. The
canonical pair (`TestConfigValidationCoversCallSites` and
`TestConfigValidationPreservesContractUnderContention`) lives in
`internal/controlplane/config/config_validation_test.go` and binds
to the PRD's `-run TestConfigValidation` filter; the static defence
for every collateral surface lives in
`internal/release/verification_suite_config_validation_static_test.go`.

- **Scope.** The two load-bearing validation invariants are
  exercised by the canonical function pair. The first member walks
  a closed-set scenario table built from every documented rule in
  `config.Validate` and every documented strict-profile presence
  check in `config.requireStrictFields` (invalid profile, invalid
  log level, invalid listen address, invalid public URL, invalid
  Dokploy URL, non-postgres `YALLA_DATABASE_URL` scheme, short
  signing key, wrong-length / non-hex `YALLA_SECRET_KEYS` entry,
  malformed / too-small / too-large shutdown timeout, non-absolute
  backup status file path, malformed / negative backup max age,
  bad feature-flag value / empty flag name, negative or oversized
  rate-limit RPS / burst / idle TTL, malformed bool / int rate-
  limit overrides, and the strict-profile presence checks for
  `YALLA_PUBLIC_URL`, `YALLA_DATABASE_URL`, `YALLA_SIGNING_KEYS`,
  `YALLA_SECRET_KEYS`, `YALLA_DOKPLOY_BASE_URL`, and
  `YALLA_DOKPLOY_TOKEN`) and asserts each yields a typed
  `*yerr.Error` with `Code == CodeConfig`, an error message that
  names the offending env var, and zero echo of the seeded secret
  marker. The set itself is part of the closed-set coverage: a
  future relaxation of one rule must be a deliberate edit to both
  the validator and the scenario table. The second member fires
  `configValidationWorkers * configValidationIterationsPerWorker`
  goroutines that each build their own env map from the scenario
  table (via the package's `MapLookup` test seam) and run
  `config.Load(MapLookup(env))`, each goroutine asserting the rule
  its OWN scenario predicts; a cross-write under the race that
  swapped two goroutines' scenarios would fail the per-iteration
  assertion even when the aggregate pass count matched. The single
  static defence is
  `internal/release/verification_suite_config_validation_static_test.go`,
  which pins the existence of the canonical
  `config_validation_test.go` file and the canonical
  `TestConfigValidationCoversCallSites` +
  `TestConfigValidationPreservesContractUnderContention` function
  pair (the load-bearing `-run TestConfigValidation` filter from
  `verificationLoop.requiredBackendCommands` binds to the
  `TestConfigValidation` prefix) so the validation convention
  itself cannot be silently deleted or renamed.
- **Typed-error contract.** Every documented validator branch
  returns a typed `*yerr.Error` whose `Code` field equals
  `yerr.CodeConfig`. That code is the load-bearing exit pivot the
  API binary (`cmd/yalla-api`) and the worker binary
  (`cmd/yalla-worker`) translate to a deterministic non-zero exit;
  an `error` returned as a plain `errors.New` value would silently
  downgrade the exit path to a generic "unknown error" and a
  misconfigured process would either fail with an unclassified
  diagnostic or — worse — enter the request path. The coverage
  member asserts the typed code for every scenario.
- **Determinism.** The config validation tests run against
  deterministic fixtures only — the scenario table is a compile-
  time constant, the validator is a pure function from the env map
  to a `*Config` or a typed `*yerr.Error` value, and the
  contention burst's per-goroutine fixture is derived from the
  worker + iteration index and indexes into the closed-set
  scenario table so every test run exercises the identical
  decision set. No config validation test reaches the process
  environment, the network, a live Postgres, a live Dokploy, or
  any external service. The test seam `config.MapLookup` adapts an
  in-memory map to the validator's `LookupFunc` signature so the
  real process environment never bleeds into assertions and the
  burst's per-goroutine env can be built without contention on
  shared state.
- **Actionable failures.** Every diagnostic surfaces the scenario
  name (for the coverage member) or the worker + iteration index
  AND the offending scenario (for the burst member) so an operator
  reading the CI log can map the failure to a specific validator
  branch without re-running the suite locally. The scenario name
  is descriptive (`invalid_database_scheme`, `non_hex_secret_key`,
  `strict_missing_dokploy_token`, etc.) so an operator can
  correlate the failure with the exact env var or rule that
  drifted, and the originating `request_id` is carried through the
  process startup chain when the API binary fails to boot.
- **Schema-version contract.** The config validation suite
  exercises typed `*yerr.Error` values directly — it does not
  render HTTP envelopes — but the typed-error surface it pins is
  the contract every customer-facing wire response downstream
  relies on: a `CodeConfig` error surfaces through
  `internal/output`'s envelope renderer as `yalla.error.v1` with a
  stable `code` field, and the success path the validator gates
  surfaces through `yalla.output.v1` envelopes. A regression that
  silently lost the typed code would break the wire schema for
  every downstream caller.
- **Redaction.** The config validation tests seed the baseline
  strict env with the `SUPERSECRETMARKER` literal embedded in the
  `YALLA_DATABASE_URL`, `YALLA_SIGNING_KEYS`, and
  `YALLA_DOKPLOY_TOKEN` positions and assert no validation error
  message ever echoes the marker. Validation errors describe which
  env var failed without echoing its value, even when the
  offending value is itself a secret. This is the structural
  redaction predicate every operator log, audit metadata record,
  and test output line downstream of `config.Load` relies on. The
  matcher is deliberately a substring check on the rendered error
  string so a future regression that introduced an `%v` formatter
  over the offending value would fail the predicate on its first
  scenario.
- **Tenant isolation.** The config validation suite is process-
  global by design — `config.Load` resolves the binary-wide
  startup config, not per-tenant data — and therefore has no
  tenant boundary to enforce. The per-tenant data-isolation
  contract is enforced by the dedicated tenant-isolation suite
  (BE-0398) and the per-row repository isolation tests under
  `internal/controlplane/store/`.
- **CI cadence.** The config validation gate runs as a dedicated
  `Config validation tests` step in `.github/workflows/ci.yml`,
  under `# 26. Required: config validation tests` in
  `scripts/verify.sh`, as entry `26` in `CONTRIBUTING.md` under
  `## Required Checks Before Every Commit`, and in `ralph/prd.json`
  under `verificationLoop.requiredBackendCommands` so an AI agent
  reading the PRD before picking up a story sees the gate without
  needing to discover it from shell scripts or CI workflows. Every
  push and PR runs the gate. The single static defence that pins
  every one of those surfaces is
  `internal/release/verification_suite_config_validation_static_test.go`.

## Admin Endpoint Tests

The admin-endpoint suite (BE-0403) is the authorization gate for the
tagged-admin HTTP routes the control-plane API binary (`cmd/yalla-api`)
ships behind a single role. The four admin actions — `admin.read`,
`admin.import`, `admin.reconcile`, and `admin.break_glass` — authorise
cross-tenant inspection, mutating reconciliation, importing pre-existing
Dokploy resources into Yalla, and opening elevated cross-tenant access
sessions. Each is catalogued as `CapSupport`, and `CapSupport` is held
only by `RoleSupport` in the built-in role-to-capability matrix; the
engine's cross-tenant exception clause admits `CapSupport` OR `CapRead`
so a same-tenant Support principal authorises `admin.*` via
`ReasonAllowedByRole` and a cross-tenant Support principal authorises
through `ReasonAllowedBySupport`. Every admin endpoint's resource scope
is org-rooted by construction (`Kind=KindOrganization`, only
`OrganizationID` pinned) so the policy engine's `covers()` rule denies
every project-, environment-, and service-scoped grant at the boundary
with `ReasonDeniedOutOfScope` — even a Support-role grant scoped to a
project cannot widen to the admin endpoints. The gate is run by
`go test -run TestAdminEndpoint ./...`.

The canonical pair lives in
`internal/controlplane/policy/admin_endpoint_policy_test.go`:

- `TestAdminEndpointCoversCallSites` walks the closed-set cartesian
  product of every tagged-admin HTTP route registered in
  `internal/controlplane/httpapi/routes.go`
  (`GET /v1/admin/dokploy/drift`, `POST /v1/admin/dokploy/reconcile`,
  `POST /v1/admin/dokploy/import`,
  `GET /v1/admin/organizations/{org_id}/dokploy-refs`,
  `POST /v1/admin/break-glass`,
  `DELETE /v1/admin/break-glass/{session_id}`) × every built-in role
  (`RoleOwner`, `RoleAdmin`, `RoleDeveloper`, `RoleViewer`, `RoleCI`,
  `RoleSupport`) × the same-tenant / cross-tenant axes × the grant
  containment positions (project-, environment-, service-scoped
  grants), asserting `policy.Engine.Decide` returns the predicted
  `(Allow, Reason)` for every row. The closed-set self-check at the
  head of the test catches drift in either direction: a new admin
  endpoint that ships without a row, or an existing admin endpoint
  that drops its row. Two additional structural self-checks fire fast
  at the catalog and role-matrix seams: every admin action is
  catalogued as `CapSupport` in `defaultActionCatalog`, and
  `builtinRoleCaps` admits `CapSupport` for exactly `RoleSupport` and
  for no other built-in role.
- `TestAdminEndpointPreservesContractUnderContention` fires
  `adminEndpointWorkers * adminEndpointIterationsPerWorker` goroutines
  that each draw a row from the same scenario table by deterministic
  mod-index (NOT per-goroutine random selection — that would defeat
  the per-iteration prediction contract), build their own Principal /
  Resource, evaluate `policy.Engine.Decide` against a single shared
  Engine instance, and assert the per-iteration verdict. A regression
  that introduced shared mutable state in the engine — a cached
  role-cap table, a `sync.Once` mutating a per-action capability map,
  a leaky `builtinRoleCaps` reuse — would surface as a per-iteration
  assertion failure even if the aggregate pass count matched.

Both members are deterministic by design: the engine is a pure
function from `(principal, action, resource)` to a `Decision` value,
and no test reaches the process environment, the network, a live
Postgres, a live Dokploy, or any external service. Failures are
actionable: the closed-set table encodes `(method, path, role,
scope, axis)` into every scenario name so a per-row failure points
the operator at the exact admin endpoint, role, and scope that
drifted. Decision Reasons are drawn from the closed `Reason` set
in `internal/controlplane/policy/policy.go` and never carry
caller-supplied data; the contention burst seeds a sentinel literal
into every Principal ID and the assertion scans the Reason string
for it, so a future engine change that started echoing
principal-supplied data into the Reason would fail the redaction
canary on its first iteration. The wire envelopes the admin
endpoints produce on a deny path remain stable
`yalla.error.v1` JSON shapes — the gate is at the policy seam, not
the wire seam, but the seam guarantees the wire envelope cannot
quietly drift past it. The gate is documented as a dedicated
`Admin endpoint tests` step in `.github/workflows/ci.yml`, under
`# 27. Required: admin endpoint tests` in `scripts/verify.sh`, as
entry `27` in `CONTRIBUTING.md` under
`## Required Checks Before Every Commit`, and in `ralph/prd.json`
under `verificationLoop.requiredBackendCommands` so an AI agent
reading the PRD before picking up a story sees the gate without
needing to discover it from shell scripts or CI workflows. Every
push and PR runs the gate. The single static defence that pins
every one of those surfaces is
`internal/release/verification_suite_admin_endpoint_static_test.go`.

## Break-Glass Tests

The break-glass suite (BE-0404) is the validator gate for the
elevated cross-tenant access chokepoint. The `POST /v1/admin/break-glass`
endpoint opens an elevated session against a target tenant; the
session is recorded as an immutable audit row stamped with
`metadata.elevated_access = "true"` and the unit of work is
access-only (the service MUST NOT mint or rotate any credential).
The pure decision logic that gates a session-row insert is
`BreakGlassService.buildSessionToCreate`: it returns a typed
`*yerr.Error` of code `CodeInvalidInput` carrying a
`FieldViolation` that names the offending field path
(`organization_id`, `actor_id`, `actor_kind`, `reason`, or `ttl`)
when an input violates the documented rules, returns a populated
`BreakGlassSession` with `ExpiresAt = StartedAt + min(TTL,
breakGlassMaxTTL)` when the input is accepted, and never echoes
the submitted reason value into the typed error string. The gate
is run by `go test -run TestBreakGlass ./...`.

The canonical pair lives in
`internal/controlplane/store/break_glass_canonical_test.go`:

- `TestBreakGlassCoversCallSites` walks a closed-set scenario
  table built from every documented validator rule
  (`organization_id_blank`, `actor_id_blank`, `actor_kind_unknown`,
  `actor_kind_blank`, `reason_blank`, `reason_oversize`,
  `ttl_zero`, `ttl_negative`, `ttl_capped`) and every documented
  accept path (baseline valid input, `actor_kind=usr`,
  `actor_kind=sa`, TTL strictly greater than `breakGlassMaxTTL` is
  capped). Each row predicts the validator's outcome
  deterministically: accept rows assert `ExpiresAt - StartedAt ==
  min(TTL, breakGlassMaxTTL)` and that the operator-supplied
  marker survives in the persisted `Reason` (the marker is not a
  secret transport pattern so the redactor leaves it intact);
  reject rows assert a typed `*yerr.Error` with
  `Code == CodeInvalidInput` and a `FieldViolation` under the
  expected field path, plus zero echo of the seeded marker in the
  error message, in any `FieldViolation.Reason`, or in the
  `fmt`-formatted error metadata. Three closed-set self-checks
  fire fast at the head of the test before any row is walked:
  every documented validator rule is exercised by at least one
  scenario, every accepted `actor_kind` is covered by an accept
  scenario, and the redactor leaves the marker intact (so the
  marker-survival predicate on accept rows is meaningful).
- `TestBreakGlassPreservesContractUnderContention` fires
  `breakGlassWorkers * breakGlassIterationsPerWorker` goroutines
  (32 × 64 = 2048 iterations) that each draw a row from the same
  scenario table by deterministic mod-index (NOT per-goroutine
  random selection — that would defeat the per-iteration
  prediction contract), build their own `StartBreakGlassInput` by
  applying the scenario's mutator to a fresh baseline, call
  `buildSessionToCreate` against a single shared
  `*BreakGlassService` instance, and assert the per-iteration
  verdict. A regression that introduced shared mutable state in
  the validator — a cached profile-defaults table, a `sync.Once`
  mutating a per-scenario map, a leaky redactor reuse — would
  surface as a per-iteration assertion failure even if the
  aggregate pass count matched.

Both members are deterministic by design:
`buildSessionToCreate` is a pure function of (input, now) to
either a `BreakGlassSession` or a typed `*yerr.Error` value, and
no test reaches the process environment, the network, a live
Postgres, a live Dokploy, or any external service. Failures are
actionable: every scenario name encodes the rule it exercises
(`baseline valid input is accepted`, `blank actor_id is rejected`,
`ttl strictly greater than breakGlassMaxTTL is capped`, etc.) so
a per-row failure points the operator at the exact rule that
drifted. The wire envelopes the break-glass endpoint produces on
a reject path remain stable `yalla.error.v1` JSON shapes — the
gate is at the validator seam, not the wire seam, but the seam
guarantees the wire envelope cannot quietly drift past it. The
unit of work the service runs around `buildSessionToCreate` is
access-only by construction (the `BreakGlassService` struct
holds no API-key minting or rotation dependency); the
support-access-review gate (BE-0358) enforces that invariant
structurally at the package level, and the policy-engine gate
(BE-0403) enforces the role-allow set for `admin.break_glass` so
only `RoleSupport` can reach the endpoint. The gate is
documented as a dedicated `Break-glass tests` step in
`.github/workflows/ci.yml`, under
`# 28. Required: break-glass tests` in `scripts/verify.sh`, as
entry `28` in `CONTRIBUTING.md` under
`## Required Checks Before Every Commit`, and in `ralph/prd.json`
under `verificationLoop.requiredBackendCommands` so an AI agent
reading the PRD before picking up a story sees the gate without
needing to discover it from shell scripts or CI workflows. Every
push and PR runs the gate. The single static defence that pins
every one of those surfaces is
`internal/release/verification_suite_break_glass_static_test.go`.

## Reconciliation Tests

The reconciliation suite (BE-0405) is the planner gate for the
reconcile loop's pure classifier chokepoint
`reconcile.Diff(desired, actual) reconcile.Plan`. The reconcile
loop is the only customer-facing surface that consumes both the
Yalla desired-state snapshot (source of truth) and the live
Dokploy actual-state snapshot (defence-in-depth) in the same
evaluation. `Diff` is a deterministic function from
`(DesiredOrganization, ActualOrganization)` to a `Plan` whose
every `Action` carries a stable closed-set tag `(ActionType,
DriftKind, DriftReason)`. The gate is run by
`go test -run TestReconciliation ./...`.

The closed-set coverage invariant pins four structural reconcile
contracts in one place: every documented `DriftReason`
(`env_var_changed`, `env_var_missing`, `env_var_extra`,
`domain_missing`, `domain_renamed`, `service_missing`,
`database_missing`, `service_type_changed`,
`resource_unmanaged`) MUST be exercised by at least one scenario
row; every documented `ActionType` (`update_env_var`,
`ensure_domain`, `remove_extra_env_var`, `review_missing_service`,
`review_missing_database`, `review_renamed_domain`,
`review_service_type_change`, `mark_unmanaged`) MUST also be
exercised by at least one row; `Diff(desired, actual)` MUST be
deterministic — calling it twice on the same inputs yields equal
plans; and the value-free classification invariant pins that
desired env-var values reach `Action.DesiredValue` (the single
value-routing field a Repairer adapter consumes) but NEVER
appear in `Action.Type`, `Action.Kind`, `Action.Reason`,
`Action.EnvVarKey`, `Action.Service`, `Action.Domain`, or
`Action.Unmanaged`. The safety dispatch invariant routes
`safe` drift to the auto-repair path, `dangerous` drift to the
review queue, and `unmanaged` drift to quarantine; a regression
that flipped a `dangerous` kind to `safe` would let the engine
auto-repair drift it must not touch and would surface here as a
closed-set tag mismatch on the affected scenario row.

The canonical pair (`TestReconciliationCoversCallSites` and
`TestReconciliationPreservesContractUnderContention`) lives in
`internal/controlplane/reconcile/reconcile_canonical_test.go`
and binds to the PRD's `-run TestReconciliation` filter. The
first member walks a closed scenario table built from every
documented `DriftReason` and `ActionType` of `reconcile.Diff`,
seeds `RECONCILESECRETMARKER` into desired env-var values on
env-var rows, and asserts the marker survives in
`Action.DesiredValue` but is absent from every other field of
every emitted action. The second member fires
`reconcileWorkers * reconcileIterationsPerWorker` goroutines
that each draw a row from the same scenario table by
deterministic mod-index, build their own (desired, actual) pair,
call `reconcile.Diff` directly, and assert the per-iteration
verdict. A cross-write under the race that swapped two
goroutines' scenarios — or a future regression that introduced
shared mutable state in the package (a cached reason table, a
`sync.Once` mutating a per-action map, a `sync.Pool` reused
without reset) — would fail the per-iteration assertion even
when the aggregate pass count matched. Both members are
deterministic by design: `Diff` is a pure function from
`(desired, actual)` to a `Plan` and neither member reaches the
process environment, the network, a live Postgres, a live
Dokploy, or any external service.

When the suite fails, every actionable failure message names
the scenario row that drifted, the closed-set tag the row
predicted, and the closed-set tag the planner actually emitted,
so operators do not need to read the canonical pair to triage.
Errors propagate through the same `yalla.error.v1` envelope
shape any other backend test produces; success rows assert the
plan's `OrganizationID` is non-empty so the tenant-scoping
invariant is enforced on every row. The redaction contract is
exercised in two directions: on env-var scenarios the marker
MUST survive into `Action.DesiredValue` (a Repairer adapter
needs to write the desired value back), and the marker MUST NOT
echo into any classification field of any action. Only a Yalla
service principal with `support` role can trigger a manual
reconciliation; the gate is documented as a dedicated
`Reconciliation tests` step in `.github/workflows/ci.yml`, under
`# 29. Required: reconciliation tests` in `scripts/verify.sh`,
as entry `29` in `CONTRIBUTING.md` under
`## Required Checks Before Every Commit`, and in `ralph/prd.json`
under `verificationLoop.requiredBackendCommands` so an AI agent
reading the PRD before picking up a story sees the gate without
needing to discover it from shell scripts or CI workflows. Every
push and PR runs the gate. The single static defence that pins
every one of those surfaces is
`internal/release/verification_suite_reconciliation_static_test.go`.

## Import Dry-Run Tests

The import dry-run suite (BE-0406) is the operator-facing
preview gate for the migrateimport package. The pure-classifier
chokepoint is
`(*migrateimport.Importer).Plan(ctx, PlanInput) (Plan, error)`:
the planner walks the live Dokploy snapshot, queries the
Repository port for slug collisions and pre-existing links, and
emits a deterministic `Plan` whose every `PlanItem` carries a
stable closed-set tag `(ResourceLevel, ItemStatus, ItemReason)`.
A Yalla operator runs this gate to preview which pre-existing
Dokploy resources would become customer-visible if the operator
committed to an `OwnerAssignment`; the dry-run itself MUST
never write to the Repository and MUST never query the
Repository when invoked without an assignment (the pending-
owner short-circuit). The gate is run by
`go test -run TestImportDryRun ./...`.

The closed-set coverage invariant pins five structural import-
dry-run contracts in one place: every documented `ItemStatus`
(`ready`, `pending_owner`, `skip_duplicate`,
`skip_missing_parent`, `skip_unsupported_type`,
`skip_already_imported`) MUST be exercised by at least one
scenario row; every documented `ItemReason`
(`ready_to_import`, `explicit_owner_missing`,
`duplicate_name_in_parent`, `missing_parent_import`,
`unsupported_service_type`, `already_linked`) MUST also be
exercised by at least one row; `Plan(ctx, in)` MUST be
deterministic — calling it twice on the same inputs with the
same seeded Repository state yields equal plans; the value-free
classification invariant pins that untrusted Dokploy display
names reach `ProposedDisplay` (the deliberate value-routing
field operators read in audits) but NEVER appear in `Status`,
`Reason`, or `Level`; and the dry-run purity invariant pins
that `Plan` is read-only — no `CreateProject`,
`CreateEnvironment`, or `CreateService` call ever shows up on
the Repository, and a no-`OwnerAssignment` call never touches
the Repository at all.

The canonical pair (`TestImportDryRunCoversCallSites` and
`TestImportDryRunPreservesContractUnderContention`) lives in
`internal/controlplane/migrateimport/import_dry_run_canonical_test.go`
and binds to the PRD's `-run TestImportDryRun` filter. The
first member walks a closed scenario table built from every
documented `ItemStatus` and `ItemReason` of `Importer.Plan`,
seeds `importsecretmarker` into untrusted Dokploy display
names on every row, and asserts the marker survives in
`ProposedDisplay` but is absent from every closed-set tag field
of every emitted item. The second member fires
`importDryRunWorkers * importDryRunIterationsPerWorker`
goroutines that each draw a row from the same scenario table
by deterministic mod-index, build their own (Snapshot, fake
Repository, OwnerAssignment) triple, construct an Importer,
and assert the per-iteration verdict. A cross-write under the
race that swapped two goroutines' scenarios — or a future
regression that introduced shared mutable state in the package
(a cached owner table, a `sync.Once` mutating a per-action
map, a `sync.Pool` reused without reset) — would fail the
per-iteration assertion even when the aggregate pass count
matched. Both members are deterministic by design: `Plan` is a
deterministic function of its inputs and the seeded Repository
state, and neither member reaches the process environment, the
network, a live Postgres, a live Dokploy, or any external
service.

When the suite fails, every actionable failure message names
the scenario row that drifted, the closed-set tag the row
predicted, and the closed-set tag the planner actually emitted,
so operators do not need to read the canonical pair to triage.
Errors propagate through the same `yalla.error.v1` envelope
shape any other backend test produces; success rows assert the
plan's `DokployOrganizationID` is non-empty so the tenant-
scoping invariant is enforced on every row. The redaction
contract is exercised in two directions: every scenario seeds
the marker into Dokploy display names and asserts the marker
survives into `ProposedDisplay` (the operator review surface
needs to render the human-authored name), and the marker MUST
NOT echo into `Status`, `Reason`, or `Level` of any emitted
item. Only a Yalla service principal with the `admin` role can
trigger an import via the eventual
`POST /v1/admin/dokploy/import` admin endpoint; the gate is
documented as a dedicated `Import dry-run tests` step in
`.github/workflows/ci.yml`, under
`# 30. Required: import dry-run tests` in `scripts/verify.sh`,
as entry `30` in `CONTRIBUTING.md` under
`## Required Checks Before Every Commit`, and in
`ralph/prd.json` under `verificationLoop.requiredBackendCommands`
so an AI agent reading the PRD before picking up a story sees
the gate without needing to discover it from shell scripts or
CI workflows. Every push and PR runs the gate. The single
static defence that pins every one of those surfaces is
`internal/release/verification_suite_import_dry_run_static_test.go`.

## Service Desired-State Golden Tests

The service desired-state golden suite (BE-0407) pins the
dokploy renderer's pure desired-state projection. The
chokepoint is
`(*dokploy.Renderer).Render(in RenderInput) (RenderedSpec, error)` —
the single point at which Yalla's source-of-truth hierarchy
(organization, project, environment, service) is projected
into the desired Dokploy spec the provisioning worker will
reconcile. The renderer is a deterministic pure function of
its input: no I/O, no clock, no package-level shared state.
A Yalla operator who reads a `RenderedSpec` `Summary` in a
log, an audit record, or a dry-run preview MUST be able to
predict the rendered spec from the input alone. The gate is
run by `go test -run TestServiceDesiredState ./...`.

The closed-set coverage invariant pins five structural
desired-state contracts in one place: every documented
`ServiceType` (`application`, `compose`, `database`) MUST be
exercised by at least one scenario row; every documented
`ServiceRole` (`web`, `worker`, `cron`) MUST be exercised by
at least one application scenario row; every documented
application `Builder` (`dockerfile`, `nixpacks`, `image`,
`drop-artifact`) MUST be exercised by at least one row; every
documented database `Engine` (`postgres`, `mysql`, `mariadb`,
`mongo`, `redis`) MUST be exercised by at least one database
scenario row; and every documented `EnvironmentTier`
(`staging`, `production`, `preview`) MUST be exercised by at
least one row. The determinism invariant pins that
`Render(in)` is a deterministic function of its input —
calling it twice on the same `RenderInput` MUST yield equal
`RenderedSpec` values (same fields, same variable order, same
domain order, same label order). The value-free `Summary`
invariant pins that the redacted `Summary` JSON, the slog
`LogValue` group, and the `Summary.String()` form NEVER carry
a raw variable Value even when the canonical pair seeds a
secret marker into every level of the variable hierarchy.

The canonical pair (`TestServiceDesiredStateCoversCallSites`
and `TestServiceDesiredStatePreservesContractUnderContention`)
lives in
`internal/controlplane/dokploy/service_desired_state_canonical_test.go`
and binds to the PRD's `-run TestServiceDesiredState`
filter. The first member walks a closed scenario table built
from every documented `ServiceType`, `ServiceRole`,
`Builder`, `Engine`, and `EnvironmentTier` value, seeds the
secret marker into organization, project, environment, AND
service variables, and asserts the marker is absent from the
`Summary` JSON, the slog `LogValue` group, and the
`Summary.String()` form for every row. The second member
fires `serviceDesiredStateContentionWorkers *
serviceDesiredStateContentionIterationsPerWorker` goroutines
that each draw a row from the same scenario table by
deterministic mod-index, construct a fresh `Renderer` via
`dokploy.NewRenderer()` per iteration, and assert the per-
iteration verdict (the predicted `ServiceType`,
`ServiceRole`, `Builder`, `Engine`, `EnvironmentTier`, and
the value-free `Summary`). The per-iteration Renderer pins
the contract that construction is cheap and `Render` is a
pure function of its input — a regression that smuggled in a
package-level cache, a `sync.Once` mutating a per-call map,
or a `sync.Pool` reused without resetting would surface as a
per-iteration mismatch even when the aggregate pass count
matched. Both members are deterministic by design and reach
neither the process environment, the network, a live
Postgres, a live Dokploy, nor any external service.

When the suite fails, every actionable failure message names
the scenario row that drifted, the closed-set tag the row
predicted, and the closed-set tag the renderer actually
emitted, so operators do not need to read the canonical pair
to triage. Errors propagate through the same
`yalla.error.v1` envelope shape any other backend test
produces. The redaction contract is the safety guarantee
that lets Yalla render a `RenderedSpec` into a log line, an
audit record, or a dry-run preview without exposing a
customer's `ORG_TOKEN`, `PROJECT_TOKEN`, `ENV_TOKEN`, or
`API_TOKEN` — the value-free `Summary` projection replaces
every variable Value with the redaction sentinel before
serialisation, and the canonical pair asserts that contract
end-to-end for every row in the closed scenario table.

The gate is documented as a dedicated
`Service desired-state golden tests` step in
`.github/workflows/ci.yml`, as step `# 31. Required: service
desired-state golden tests` in `scripts/verify.sh`, as item
31 in `CONTRIBUTING.md` under
`## Required Checks Before Every Commit`, and in
`ralph/prd.json` under
`verificationLoop.requiredBackendCommands` so an AI agent
reading the PRD before picking up a story sees the gate
without needing to discover it from shell scripts or CI
workflows. Every push and PR runs the gate. The single
static defence that pins every one of those surfaces is
`internal/release/verification_suite_service_desired_state_static_test.go`.

## Deployment Lifecycle End-to-End Tests

The deployment lifecycle end-to-end suite (BE-0408) pins the
deployment lifecycle's pure projection chokepoint
`(store.Deployment).LogValue() slog.Value` — the redaction-safe
debug surface every slog record capturing a `store.Deployment`
funnels through. The deployment lifecycle is the customer-visible
state machine `queued -> running -> succeeded | failed |
cancelled | rolled_back`; `LogValue` is a deterministic pure
function of its input that projects the lifecycle row's
closed-set tags (`DeploymentSource` ∈ {`git`, `image`, `manual`},
`DeploymentStatus` ∈ {`queued`, `running`, `succeeded`, `failed`,
`cancelled`, `rolled_back`}) without echoing any caller- or
operator-supplied free-text field. The gate is run by
`go test -run TestDeploymentLifecycleE2E ./...`.

The closed-set coverage invariant pins five structural lifecycle
contracts in one place: every documented `DeploymentSource`
(`git`, `image`, `manual`) MUST be exercised by at least one
scenario row; every documented `DeploymentStatus` (`queued`,
`running`, `succeeded`, `failed`, `cancelled`, `rolled_back`)
MUST be exercised by at least one scenario row; every
non-terminal row MUST carry a nil `FinishedAt` and every
terminal row MUST carry a set `FinishedAt` — the same invariant
the `deployments_finished_consistent` table CHECK enforces at
Postgres, pinned at the Go projection so an in-memory regression
is caught before the row reaches the database; `LogValue` MUST
be a deterministic function of its input — calling it twice on
the same row MUST yield equal `slog.Value` projections (same
group, same fields, same order); and the value-free LogValue
invariant pins that the projected slog group NEVER carries
`SourceRef`, `IdempotencyKey`, `ErrorMessage`, `RequestID`, or
`CorrelationID` even when the canonical pair seeds a secret
marker into every one of those free-text fields. The structural
whitelist/blacklist split is asserted through the JSON slog
handler so a regression that switched the text format still
trips the contract.

The canonical pair (`TestDeploymentLifecycleE2ECoversCallSites`
and `TestDeploymentLifecycleE2EPreservesContractUnderContention`)
lives in
`internal/controlplane/store/deployment_lifecycle_e2e_canonical_test.go`
and binds to the PRD's `-run TestDeploymentLifecycleE2E` filter.
The first member walks a closed scenario table built from every
documented `DeploymentSource` and `DeploymentStatus` value,
asserts the terminal-implies-`FinishedAt` lifecycle invariant
per row, seeds the secret marker into `SourceRef`,
`IdempotencyKey`, `ErrorMessage`, `RequestID`, and
`CorrelationID`, and asserts the marker is absent from the
rendered slog projection for every row. The second member fires
`deploymentLifecycleContentionWorkers *
deploymentLifecycleContentionIterationsPerWorker` goroutines
that each draw a row from the same scenario table by
deterministic mod-index, construct a fresh `Deployment` per
iteration, and assert the per-iteration verdict (the predicted
`Source`, `Status`, lifecycle-timestamp consistency, and the
value-free LogValue). The per-iteration Deployment pins the
contract that construction is cheap and `LogValue` is a pure
function of its input — a regression that smuggled in a
package-level cache, a `sync.Once` mutating a per-call map, or a
`sync.Pool` reused without resetting would surface as a
per-iteration mismatch even when the aggregate pass count
matched. Both members are deterministic by design and reach
neither the process environment, the network, a live Postgres,
a live Dokploy, nor any external service.

When the suite fails, every actionable failure message names
the scenario row that drifted, the closed-set tag the row
predicted, and the closed-set tag the projection actually
emitted (or the secret marker it leaked), so operators do not
need to read the canonical pair to triage. Errors propagate
through the same `yalla.error.v1` envelope shape any other
backend test produces. The redaction contract is the safety
guarantee that lets Yalla render a `store.Deployment` into a
log line, an audit record, or a dashboard panel without
exposing a customer's branch name, idempotency key, raw error
string, or correlation identifier — the value-free `LogValue`
projection omits every free-text field by construction, and the
canonical pair asserts that contract end-to-end for every row
in the closed scenario table.

The gate is documented as a dedicated
`Deployment lifecycle end-to-end tests` step in
`.github/workflows/ci.yml`, as step `# 32. Required: deployment
lifecycle end-to-end tests` in `scripts/verify.sh`, as item 32
in `CONTRIBUTING.md` under
`## Required Checks Before Every Commit`, and in
`ralph/prd.json` under
`verificationLoop.requiredBackendCommands` so an AI agent
reading the PRD before picking up a story sees the gate without
needing to discover it from shell scripts or CI workflows.
Every push and PR runs the gate. The single static defence that
pins every one of those surfaces is
`internal/release/verification_suite_deployment_lifecycle_e2e_static_test.go`.

## Race Detector

The race-detector suite (BE-0391) is the data-race gate. Go's race
detector wraps every `Test*` function the suite runs and turns any
unsynchronised read/write to shared memory into a hard test failure
with stack traces that point at the racing goroutines. Yalla's
control-plane carries enough concurrent code paths — the quota
checker's per-organization `FOR UPDATE` lock, the worker queue's
lease loop, the audit emitter's shared buffers, the Dokploy client's
connection pool, the variable resolver's per-request cache — that a
silent regression in any one of them would void the runtime
guarantees every other verification gate (BE-0379..BE-0390) pins.
This suite is the only gate that flips the `-race` flag on, so its
absence makes every concurrency invariant a paper invariant.

- **Umbrella scope.** The canonical command
  `go test -race ./...` runs the entire repository test suite under
  the race detector. There is no `-run` filter — the gate is
  umbrella by design, the same shape as the unit-test gate
  (BE-0379). A data race anywhere in the codebase (under `cmd/`,
  under `internal/`, in `pkg/` if ever added) trips this gate. The
  focused variant `go test -race ./internal/controlplane/...` runs
  the backend-only race sweep as a mid-iteration helper an agent
  can run without paying the full umbrella cost.
- **Deterministic by default.** The race detector adds no
  non-determinism of its own — the underlying tests still rely on
  the same deterministic fixtures every other gate uses (fake
  Dokploy fixtures, sealed crypto fixtures, embedded migrations,
  hand-rolled per-test Postgres databases). A flake under
  `go test -race ./...` is either (a) a latent data race in the
  code under test, or (b) a test that depended on goroutine
  scheduling order — both are bugs the gate is designed to catch,
  not noise to retry around.
- **Actionable failures.** Race detector reports include the full
  stack of the racing goroutine pair, the address of the contested
  memory location, and the source files / lines where the
  unsynchronised read and write occurred. For handler-path races,
  the request_id from the test's logged envelope can be
  cross-referenced against the slog record to map the failure back
  to the offending HTTP request; for worker-path races, the
  resource_id of the contested provisioning job surfaces in the
  same way. Failures are loud enough that an operator hitting a
  CI red can map the stack to the exact concurrent code path
  without re-running the suite locally.
- **No live Dokploy dependency.** The race-detector run uses the
  same fake Dokploy fixtures every other gate uses. A live Dokploy
  server is reachable only through the opt-in
  `YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...`
  escape hatch, which is itself a separately marked external
  smoke. The umbrella race-detector run never reaches a real
  Dokploy host by accident.
- **Stable envelopes preserved.** Tests that exercise HTTP handlers
  under the race detector continue to assert the
  `yalla.output.v1` success envelope and the `yalla.error.v1`
  error envelope — the race detector does not change response
  shapes, only failure modes. A handler that produces a stable
  envelope under `go test ./...` will produce the same envelope
  under `go test -race ./...`; a divergence is itself a race.
- **Redacted test output.** Secrets, tokens, API keys, cookies,
  and rendered environment variable values are redacted in every
  log line, error string, audit metadata field, and test-output
  fixture the suite emits — the race detector adds stack traces
  to failures but does NOT bypass the redaction layer. A
  race-detector failure whose stack happens to capture a struct
  containing a token still surfaces the token through the same
  `Redacted()` / `LogValue()` / `String()` shims every other gate
  uses.
- **CI cadence.** `Race detector` is a dedicated step in the
  `test` job on every push and PR (`scripts/verify.sh`, CI). It
  runs alongside `Unit and integration tests` and every focused
  `-run` step so a race regression in any one of them fails its
  own labelled step rather than getting buried inside the
  umbrella log.
- **Self-locating.** The CI step, verify.sh step header,
  CONTRIBUTING entry, this section, and the PRD's
  `verificationLoop.requiredLocalCommands` /
  `verificationLoop.requiredBackendCommands` entries are all
  pinned by
  `internal/release/verification_suite_race_detector_static_test.go`.
  A drift on any single surface (rename, renumber, deletion)
  fails ONE test, not five.

## External Live-Dokploy Smoke Tests

Every other Dokploy-touching suite Yalla ships uses the in-process
fake Dokploy server (`internal/controlplane/dokploy/dokployfake`) so
the gate stays green on every developer machine without external
infrastructure. The external live-Dokploy smoke is the SOLE exception:
when an operator opts in by setting `YALLA_EXTERNAL_DOKPLOY=1` (along
with `YALLA_EXTERNAL_DOKPLOY_BASE_URL` and
`YALLA_EXTERNAL_DOKPLOY_TOKEN`), the canonical command
`YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...`
reaches an actual Dokploy server, exercises a read-only
`GetServiceStatus` intent end-to-end, and surfaces failures with the
request_id / resource_id / typed `yerr` code the operator can map
back to the Yalla audit log. The smoke is the only entry in the PRD's
`verificationLoop.optionalWhenConfigured` array; it never appears in
`verificationLoop.requiredBackendCommands` because its CI cadence is
nightly + manual, not "Every push and PR".

- **Closed-set opt-in coverage.** Every documented value of
  `YALLA_EXTERNAL_DOKPLOY` (unset, empty, `0`, whitespace, `false`,
  `1`) is exercised by
  `TestLiveDokploySmokeRespectsOptInFlag`. Only the canonical `1`
  value flips the smoke into its live path; every other value is a
  deterministic `t.Skip` so a stray export never half-enables the
  smoke. When the opt-in flag is set but a required env var is
  missing, the loader returns a typed `yerr.Error` with
  `Code = E_CONFIG` naming the missing variable — the wire failure is
  actionable without grepping the test code.
- **Deterministic skip default.** Running
  `go test -run TestLiveDokploySmoke ./...` on a developer laptop
  without `YALLA_EXTERNAL_DOKPLOY=1` is a green PASS, not a failure.
  The fast `ci.yml` test job exercises the same command — the smoke
  `t.Skip`s there cleanly so the default CI run on every push and PR
  never reaches a real Dokploy.
- **Opt-in / nightly / manual CI gating.** The dedicated workflow
  `.github/workflows/external-smoke.yml` runs the canonical command
  with `YALLA_EXTERNAL_DOKPLOY: "1"` injected, on `workflow_dispatch`
  (operators run on demand) and on a nightly `schedule` (the smoke is
  exercised continuously when repository secrets are configured).
  The workflow is deliberately separate from `ci.yml` so the default
  push/PR run can never reach a real Dokploy host by accident, even
  if a regression dropped the smoke's internal opt-in guard.
- **Actionable failures.** Every error path in the smoke surfaces a
  typed `*yerr.Error` from the Dokploy client; the wire error names
  the affected env var, the Dokploy operation, the HTTP status, and
  the upstream's redacted error body. The smoke's request flows
  through the same `request_id`-carrying telemetry path the
  production handlers use, so a CI red can be cross-referenced
  against the live Dokploy's audit log without re-running the suite
  locally.
- **Stable envelopes preserved.** The smoke does not directly emit a
  wire envelope, but it pins the property that the Dokploy client's
  typed errors flow into the upstream `yalla.error.v1` shape unchanged.
  A regression that swapped a `CodeNotFound` for `CodeServer` would
  fail the smoke's typed-code assertion; a regression that smuggled
  the bearer token into the wire body would fail the smoke's
  redaction assertion.
- **Redaction contract.** The Dokploy client's `Redactor` strips the
  bearer token from every error surface — including the cause chain
  wrapped under `apierr.Internal` for an upstream 401. The smoke
  pins this property by injecting a sentinel token into a synthetic
  upstream that echoes the token back; a regression that bypassed
  the redactor would fail the synthetic-server branch deterministically
  on every push and PR. Secrets, tokens, API keys, cookies, and
  rendered environment variable values are redacted in every log
  line, error string, and test-output fixture the suite emits.
- **No mutation of live state.** When an operator supplies
  `YALLA_EXTERNAL_DOKPLOY_PROBE_SERVICE` the smoke calls
  `GetServiceStatus` against that service id (read-only). When the
  variable is absent the smoke calls `GetServiceStatus` against a
  deterministically non-existent service id and asserts a typed
  `yerr.CodeNotFound`. Either branch proves reachability and
  authentication; neither branch mutates Dokploy state. The smoke
  never deploys, never restarts, and never deletes.
- **Self-locating.** The opt-in workflow, the verify.sh optional step
  #29, the CONTRIBUTING.md opt-in entry, this section, the PRD's
  `verificationLoop.optionalWhenConfigured` entry, and the canonical
  pair file
  (`internal/controlplane/dokploy/live_dokploy_smoke_test.go` with
  `TestLiveDokploySmokeRespectsOptInFlag` and
  `TestLiveDokploySmokeExercisesLiveEndpoint`) are all pinned by
  `internal/release/verification_suite_external_dokploy_smoke_static_test.go`.
  A drift on any single surface (rename, renumber, deletion) fails
  ONE test, not six.

## Disclosure Timeline (Best Effort)

1. **Day 0** — report received, acknowledgement sent.
2. **Day 1–7** — triage, severity assessment, reproduction.
3. **Day 7–30** — fix authored, embargoed PR prepared, advisory
   drafted on GitHub Security Advisories.
4. **Release day** — patched binary released, advisory published,
   reporter credited (unless they ask otherwise).
