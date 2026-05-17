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
umbrella log.

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
