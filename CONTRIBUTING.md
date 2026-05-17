# Contributing to Yalla

Yalla is a CLI for AI agents, so the bar for predictability is
unusually high: every flag, exit code, JSON envelope, and error code
is part of a public contract. This document tells you the minimum you
need to satisfy before opening a pull request.

## TL;DR

```bash
# From the repo root.
scripts/verify.sh
```

If `scripts/verify.sh` exits 0 you are good to push. If it reports an
optional tool as missing, install it or document the skip in
`ralph/progress.txt` — the project policy is **never silently skip a
check**.

To install the repository pre-commit hook:

```bash
scripts/install-hooks.sh
```

The hook runs `scripts/verify.sh --strict --release`, which mirrors the
CI test, security, lint, and release dry-run gates before Git creates a
commit.

## Required Checks Before Every Commit

These are non-negotiable. CI runs them on every push and pull request,
and they must all pass on every commit you propose:

1. `gofmt -w .`
2. `go mod tidy`
3. `go vet ./...`
4. `go test ./...`
5. `go test -race ./...`
6. `go test ./internal/controlplane/store/...`
7. `go test ./internal/controlplane/httpapi/...`
8. `go test ./internal/controlplane/openapi/...`
9. `go test -run TestPolicyMatrix ./...`
10. `go test -run TestQuotaConcurrency ./...`
11. `go test -run TestJobWorkerLease ./...`
12. `go test -run TestFakeDokploy ./...`
13. `go test -run TestRedaction ./...`
14. `go test -run TestFuzzValidator ./...`
15. `go test -run TestMigrationsEmptyDB ./...`
16. `go test -run TestMigrationsDowngradeSafety ./...`
17. `go test -run TestLoadSmoke ./...`
18. `go test -run TestChaosDokployTimeouts ./...`
19. `go test -run TestChaosPostgresDisconnects ./...`
20. `go test -run TestIdempotencyReplay ./...`

`scripts/verify.sh` runs the full set in one command and is the local
mirror of the `test` job in `.github/workflows/ci.yml`. Step 6 — the
repository integration suite under `internal/controlplane/store/...` —
is the persistence-layer gate documented in BE-0380; even though
`go test ./...` covers the same packages, the dedicated invocation is
defence-in-depth and surfaces a faster, more targeted failure if any
repository-layer regression slips in. Step 7 — the HTTP handler
contract suite under `internal/controlplane/httpapi/...` — is the
wire-contract gate documented in BE-0381; the dedicated invocation is
defence-in-depth on the same principle so a narrowing of the umbrella
`go test ./...` step would still leave the contract gate firing as a
fast, targeted failure rather than buried inside the umbrella log.
Step 8 — the OpenAPI schema conformance suite under
`internal/controlplane/openapi/...` — is the published-document gate
documented in BE-0382; the dedicated invocation is defence-in-depth
on the same principle so a narrowing of the umbrella
`go test ./...` step would still leave the OpenAPI conformance gate
firing as a fast, targeted failure rather than buried inside the
umbrella log. Step 9 — the policy matrix suite bound by the
`-run TestPolicyMatrix` filter — is the RBAC + cross-tenant gate
documented in BE-0383; the dedicated invocation is defence-in-depth
on the same principle so a narrowing of the umbrella
`go test ./...` step would still leave the matrix gate firing as a
fast, targeted failure rather than buried inside the umbrella log.
Step 10 — the quota concurrency suite bound by the
`-run TestQuotaConcurrency` filter — is the hard-limit + cross-tenant
concurrency gate documented in BE-0384; the dedicated invocation is
defence-in-depth on the same principle so a narrowing of the umbrella
`go test ./...` step would still leave the concurrency gate firing as
a fast, targeted failure rather than buried inside the umbrella log.
Step 11 — the job worker lease suite bound by the
`-run TestJobWorkerLease` filter — is the exclusivity +
shutdown-safety gate documented in BE-0385; the dedicated invocation
is defence-in-depth on the same principle so a narrowing of the
umbrella `go test ./...` step would still leave the lease gate
firing as a fast, targeted failure rather than buried inside the
umbrella log. Step 12 — the fake Dokploy contract suite bound by
the `-run TestFakeDokploy` filter — is the deterministic-fixtures +
recorder-redaction gate documented in BE-0386; the dedicated
invocation is defence-in-depth on the same principle so a narrowing
of the umbrella `go test ./...` step would still leave the
fake-Dokploy gate firing as a fast, targeted failure rather than
buried inside the umbrella log. Step 13 — the redaction suite bound
by the `-run TestRedaction` filter — is the
secrets-never-leak-into-logs gate documented in BE-0387; the
dedicated invocation is defence-in-depth on the same principle so a
narrowing of the umbrella `go test ./...` step would still leave the
redaction gate firing as a fast, targeted failure rather than buried
inside the umbrella log. The filter binds across every package whose
tests assert the redaction contract — the central `Redactor` in
`internal/output`, the per-tenant variable redaction in
`internal/controlplane/variables`, and the CLI envelope and dry-run
redaction in `internal/cli` — so a regression in any one of them
trips the dedicated step before it can ship under the umbrella log.
Step 14 — the fuzz validator suite bound by the
`-run TestFuzzValidator` filter — is the
hostile-input-never-panics-or-leaks gate documented in BE-0388; the
dedicated invocation is defence-in-depth on the same principle so a
narrowing of the umbrella `go test ./...` step would still leave the
fuzz gate firing as a fast, targeted failure rather than buried
inside the umbrella log. The canonical pair
(`TestFuzzValidatorContractCoversExpectedValidators` and
`TestFuzzValidatorContractSeedCorpusRejectsHostileInputs`) lives in
`internal/controlplane/validate/fuzz_test.go` next to the `FuzzName`
/ `FuzzPath` / `FuzzDomain` / `FuzzEnvVarName` / `FuzzEnvVarValue` /
`FuzzDecodeJSON` / `FuzzImageRef` / `FuzzURL` / `FuzzGitBranch`
targets it pins; the wrapper drives every validator through the
shared hostile seed corpus (long strings, invalid UTF-8, traversal
sequences, embedded NUL, control characters, Unicode tricks) under
a `recover()` guard so a regression surfaces with the offending
validator AND the seed index. The optional randomised driver
remains available as `go test -fuzz=Fuzz<Name>
./internal/controlplane/validate/...` for soak runs.
Step 15 — the migrations-from-empty-DB suite bound by the
`-run TestMigrationsEmptyDB` filter — is the empty-database
bootstrap gate documented in BE-0389; the dedicated invocation is
defence-in-depth on the same principle so a narrowing of the
umbrella `go test ./...` step would still leave the migration-runner
gate firing as a fast, targeted failure rather than buried inside
the umbrella log. The canonical pair
(`TestMigrationsEmptyDBContractCoversAllNumberedFiles` and
`TestMigrationsEmptyDBContractAppliesEmbeddedLadderToEmptyDatabase`)
lives in `internal/controlplane/store/migrate/migrate_test.go`. The
first member pins the closed-set coverage invariant — every
`NNNN_*.up.sql` file in the embedded migrations directory MUST
surface as a loaded `Migration`, strictly ascending and gap-free
from version 1 — and runs without a Postgres dependency so a
new-file-missing-from-the-loader regression trips on every
developer machine. The second member pins the applies-cleanly
invariant — a throwaway database accepts the embedded ladder in
order, the `schema_migrations` ledger ends with one clean row per
migration (correct checksum, dirty=false), and a second `Up` is a
no-op — and skips cleanly when `YALLA_TEST_DATABASE_URL` is unset
so the suite stays green on machines without Postgres. Failures
surface with the offending migration version AND the resource_id
(`schema_migrations.version=N`) so an operator can map the failure
to the exact migration without re-running the suite locally.

Step 17 — the load smoke suite bound by the `-run TestLoadSmoke`
filter — is the bootstrap-surface burst-stability gate documented in
BE-0392; the dedicated invocation is defence-in-depth on the same
principle so a narrowing of the umbrella `go test ./...` step would
still leave the burst gate firing as a fast, targeted failure rather
than buried inside the umbrella log. The canonical pair
(`TestLoadSmokeContractCoversCoreEndpoints` and
`TestLoadSmokeContractRunsBurstWithStableEnvelopes`) lives in
`internal/controlplane/httpapi/load_smoke_test.go`. The first member
pins the closed-set bootstrap-coverage invariant — the endpoint
table the burst harness iterates MUST stay non-empty, free of
duplicates, scoped to the bootstrap surface (`/healthz`, `/readyz`,
`/version`, nothing under `/v1/`), and every entry MUST carry a
valid HTTP method — and runs without any infrastructure dependency
so a typo or scope-creep regression trips on every developer
machine. The second member pins the burst-stability invariant — the
in-process public HTTP handler accepts
`loadSmokeWorkers * loadSmokeIterationsPerWorker` concurrent
requests per endpoint and every response carries the canonical
status, a stable `yalla.output.v1` envelope with ok=true, a
SafeID-clean `request_id` unique across the whole burst, and no
secret-shaped substring in body or header. Failures surface with
the offending endpoint AND the observed request_id so an operator
can correlate the gate failure with a specific in-flight request
without re-running the suite locally. Both members are
deterministic by design: the bootstrap surface is the one part of
the API that needs no backing infrastructure, so the load smoke
gate stays green on every machine without Postgres or a live
Dokploy server.

Step 18 — the chaos-timeout suite bound by the
`-run TestChaosDokployTimeouts` filter — is the typed-Dokploy-client
chaos-classification gate documented in BE-0393; the dedicated
invocation is defence-in-depth on the same principle so a narrowing
of the umbrella `go test ./...` step would still leave the chaos gate
firing as a fast, targeted failure rather than buried inside the
umbrella log. The canonical pair
(`TestChaosDokployTimeoutsCoversCallSites` and
`TestChaosDokployTimeoutsMapsToTypedTimeoutEnvelope`) lives in
`internal/controlplane/dokploy/chaos_dokploy_timeouts_test.go`. The
first member pins the closed-set chaos-scenario coverage invariant —
the scenario table the burst harness iterates MUST stay non-empty,
free of duplicate names, scoped to the typed client surface (GET,
POST, DELETE) and to the idempotency rule (POST attempted exactly
once; GET and DELETE attempted 1 + MaxRetries), and every entry MUST
map to `yerr.CodeTimeout` attributed to `apierr.DependencyDokploy` —
and runs without any infrastructure dependency so a typo or
classification-regression trips on every developer machine. The
second member pins the runtime chaos invariant — the typed Dokploy
client spun up against a per-iteration fake-Dokploy server and
firing `chaosWorkers * chaosIterationsPerWorker` concurrent scenario
invocations MUST yield only failures that are typed `*yerr.Error`
values with `Code=yerr.CodeTimeout`, attribute to
`apierr.DependencyDokploy`, carry the caller's
`telemetry.HeaderRequestID` into every recorded attempt, leave every
recorded Authorization header redacted to `output.Sentinel`, and
carry no Dokploy bearer-token literal in any wrapped cause. Failures
surface with the offending scenario name AND the observed request_id
so an operator can correlate the gate failure with a specific
in-flight chaos run without re-running the suite locally. Both
members are deterministic by design: the in-process fake-Dokploy is
the only dependency the chaos harness needs, the `TimeoutFault`
primitive honours `r.Context().Done()` so each per-attempt deadline
cancels the in-flight request, and the gate stays green on every
machine without Postgres or a live Dokploy server.

Step 19 — the chaos-disconnect suite bound by the
`-run TestChaosPostgresDisconnects` filter — is the store-layer
chaos-classification gate documented in BE-0394; the dedicated
invocation is defence-in-depth on the same principle so a narrowing
of the umbrella `go test ./...` step would still leave the chaos gate
firing as a fast, targeted failure rather than buried inside the
umbrella log. The canonical pair
(`TestChaosPostgresDisconnectsCoversCallSites` and
`TestChaosPostgresDisconnectsMapsToTypedUnavailableEnvelope`) lives in
`internal/controlplane/store/chaos_postgres_disconnects_test.go`. The
first member pins the closed-set chaos-scenario coverage invariant —
the scenario table the burst harness iterates MUST stay non-empty,
free of duplicate names, scoped to the pgxpool surface every store
method uses (`Ping`, `Acquire`, `Begin`, `Exec`, `Query`), and every
entry MUST map to `yerr.CodeUnavailable` attributed to
`apierr.DependencyStore` — and runs without any infrastructure
dependency so a typo or classification-regression trips on every
developer machine. The second member pins the runtime chaos invariant
— a fresh `pgxpool.Pool` wired against a per-iteration
`fakepg.Server` (a tiny in-process TCP listener that gracefully closes
accepted connections so pgx fails on its startup-handshake read) and
firing `chaosPostgresWorkers * chaosPostgresIterationsPerWorker`
concurrent scenario invocations MUST yield only failures that wrap
via `apierr.StoreUnavailable` into typed `*yerr.Error` values with
`Code=yerr.CodeUnavailable`, attribute to `apierr.DependencyStore`,
record at least one accepted TCP connection per attempt, leave the
wrapped envelope's rendered message free of any DSN field (neither
the sentinel password nor the sentinel username), and carry no
sentinel password literal in any wrapped cause. Failures surface with
the offending scenario name AND the observed request_id so an
operator can correlate the gate failure with a specific in-flight
chaos run without re-running the suite locally. Both members are
deterministic by design: the in-process `fakepg.Server` is the only
dependency the chaos harness needs, no live Postgres is required, the
fake closes accepted connections gracefully so pgx's dial completes
and the chaos error surfaces on the startup-handshake read, and the
gate stays green on every machine without Postgres or a live Dokploy
server.

Step 20 — the idempotency-replay suite bound by the
`-run TestIdempotencyReplay` filter — is the HTTP idempotency
middleware replay gate documented in BE-0395; the dedicated
invocation is defence-in-depth on the same principle so a narrowing
of the umbrella `go test ./...` step would still leave the replay
gate firing as a fast, targeted failure rather than buried inside the
umbrella log. The canonical pair
(`TestIdempotencyReplayCoversCallSites` and
`TestIdempotencyReplayPreservesByteIdenticalEnvelope`) lives in
`internal/controlplane/httpapi/idempotency_replay_test.go`. The first
member pins the closed-set replay-coverage invariant — for every
outcome category the middleware records (a 202 `yalla.output.v1`
success envelope, a 400 `E_INVALID_INPUT` validation failure, a 403
`E_FORBIDDEN` authorization failure, a 404 `E_NOT_FOUND` not-found
failure), a second request with the same `Idempotency-Key` and the
same body MUST receive the byte-identical recorded envelope, the
same status, and an `Idempotency-Replayed: true` header without
re-invoking the wrapped handler, and a sentinel marker placed inside
the submitted request body MUST NOT leak into the recorded claim or
the replayed response. The 5xx server-failure case is deliberately
excluded from the replay closed set — the middleware releases the
claim on 5xx so a retry re-runs the handler rather than replaying an
unfinished result. The second member pins the deterministic-replay
invariant under contention — seeding a completed claim and firing
`replayWorkers * replayIterationsPerWorker` concurrent retries
against the same key MUST yield byte-identical replayed bodies,
identical statuses, the `Idempotency-Replayed: true` header on
every retry, and exactly zero handler invocations across the burst.
Both members are deterministic by design: the in-process
`fakeIdempotencyStore` is the only dependency the replay harness
needs, no live Postgres is required, and the gate stays green on
every machine without Postgres or a live Dokploy server.

## Required Checks Before Every Release

Cutting a release tag enables the `release` workflow, which produces
binaries, archives, and downstream packages (Homebrew, Scoop, WinGet,
npm). Before tagging:

1. Run `scripts/verify.sh --release` locally — this layers the
   release-config dry run on top of the commit gate.
2. Confirm the security gate is green:
   - `govulncheck ./...` — no high-severity advisories.
   - `staticcheck ./...` — clean.
   - `golangci-lint run ./...` — clean.
3. Confirm the release gate is green:
   - `goreleaser check` — config valid.
   - `goreleaser release --snapshot --clean` — archives build.
4. Review the dependency diff since the last tag (`go list -m -json
   all`) and update `SECURITY.md` if any threat assumption changed.
5. Spot-check `yalla manifest --json` and the JSON schemas published
   under `yalla schema list --json` for unintentional removals or
   exit-code remappings.

The CI pipeline mirrors steps 1–3 automatically. Step 4 is a human
checklist item that is part of the dependency-review expectation in
US-0011.

## Optional Tools

The required checks above use only the Go toolchain. The optional
tools below are part of the security gate, configured in this repo,
and run on every PR in CI. Install them locally for a faster feedback
loop:

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
go install honnef.co/go/tools/cmd/staticcheck@latest
# golangci-lint: see https://golangci-lint.run/welcome/install/
# goreleaser:    see https://goreleaser.com/install/
```

`scripts/verify.sh --strict` treats a missing optional tool as a
failure; use it from CI scripts that need a hard gate.

## Coding Conventions

- Cobra commands return typed `*errors.Error` from `internal/errors`
  via `RunE`; never let `fmt.Errorf` escape a `RunE`.
- All visible output flows through `internal/output.Renderer`. Hand-
  rolled JSON in commands is a contract violation — there is exactly
  one schema-versioned envelope per shape.
- `--json` data lives on stdout; everything else (logs, prompts,
  warnings, errors) lives on stderr.
- Stable codes/flags/exit-codes are public API. Renaming or removing
  one is a breaking change, requires a SemVer bump, and must be
  documented in the release notes.
- Tests construct the root via `cli.NewRootCommand` (or, preferably,
  `internal/testutil.RunArgs`) so they exercise the production exit-
  code path.

## Dependency Review Checklist

Before adding or upgrading a third-party Go module:

1. **Justify it.** Add a one-line note in the PR description
   explaining why the standard library is insufficient.
2. **License.** Confirm the dependency is on the allowlist in
   `.github/workflows/dependency-review.yml` (MIT, Apache-2.0,
   BSD-2/3-Clause, ISC, MPL-2.0, CC0-1.0, Unlicense, 0BSD). Anything
   else needs a separate, documented exception.
3. **Maintenance.** Check the upstream repo for recent activity and
   open security advisories. Avoid abandonware.
4. **Surface area.** Prefer narrow, leaf packages over kitchen-sink
   frameworks. Stdlib first, focused module second, framework last.
5. **Reproducibility.** Pin to a specific minor version and run
   `go mod tidy` so `go.sum` is updated.
6. **Vulnerability scan.** Run `govulncheck ./...` after the upgrade
   — the CI security gate will run it again, but local feedback is
   faster.
7. **Update docs.** If the new dependency changes a public schema or
   error-code surface, update the manifest, schemas, and any AGENTS.md
   files in directories you touched.

The CI pipeline runs `actions/dependency-review-action` on every PR
and will fail the build automatically when these expectations are
violated.

## Working with AI Coding Agents (Ralph Loop)

Yalla is built with the Ralph Loop methodology. Each iteration
implements one user story from `ralph/prd.json`, runs the required
checks, and appends to `ralph/progress.txt`. If you are running a
loop:

- Read `ralph/progress.txt`'s `## Codebase Patterns` section first.
- Follow the AGENTS.md files in the directories you touch.
- Treat every leaked secret in tests, logs, dry-run output, or error
  envelopes as a release blocker — see `SECURITY.md` for the full
  contract.

## Reporting Security Issues

See [`SECURITY.md`](./SECURITY.md). Do not open a public issue for a
security problem.
