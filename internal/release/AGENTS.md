# internal/release

Source of truth for the public distribution matrix.

- `SupportedTargets`, `ArchiveExt`, `BinaryName`, `ArchiveName`, and
  `ChecksumsName` are **public API** for downstream tooling: the npm wrapper
  uses the same archive naming, future US-0010 (channel-aware upgrade) reads
  these to map a download to a target. Renaming or reordering values is a
  breaking change.
- The tests in this package validate `.goreleaser.yaml`, the npm wrapper
  files under `npm/`, and the GitHub Actions workflows together. They are
  the only place that holds GoReleaser, GoReleaser archive naming, and the
  npm wrapper to a single contract.
- Tests walk up to `go.mod` to find the project root rather than hard-coding
  `../..`. Keep that helper if the package ever moves.
- Do **not** depend on a real `goreleaser` binary from this package — the
  CI workflow runs `goreleaser check` separately. Everything here must work
  with the standard Go toolchain only.

## Dependency vulnerability scanning (BE-0354)

`dependency_scan_static_test.go` is the load-bearing static defence for
the supply-chain gate. It pins five surfaces in one file:

- `.github/workflows/ci.yml` — the `security` job's `govulncheck`,
  `staticcheck`, and `golangci-lint` steps. The govulncheck step MUST
  install from `golang.org/x/vuln/cmd/govulncheck` and MUST run
  `govulncheck ./...` on the whole module. A scoped invocation
  (`govulncheck github.com/...`) is rejected — the gate only works on
  the full module.
- `.github/workflows/dependency-review.yml` — the PR job uses the
  canonical `actions/dependency-review-action@v<N>` reference with
  `fail-on-severity` in `{high, moderate, low}` (never `critical` —
  that would let real-world high advisories slip through) and an
  `allow-licenses` superset of `{MIT, Apache-2.0, BSD-2-Clause,
  BSD-3-Clause}`. Dropping any of those four would silently block the
  most common OSS modules from review.
- `scripts/verify.sh` — pins the literal `govulncheck ./...` call and
  the `golang.org/x/vuln/cmd/govulncheck` install reference so the
  local commit gate runs the same scanner as CI.
- `CONTRIBUTING.md` — pins the "Dependency Review Checklist" section
  and the references contributors need (the govulncheck command, the
  dependency-review-action name).
- `SECURITY.md` — pins the published verification-gates table row so
  the public security policy and the CI gate stay in lockstep.

When adding a new supply-chain control (a fresh CI scanner, a new
required licence on the allow-list, a tightened severity threshold),
update both the workflow file AND the matcher in this test file in the
same edit. The self-check
(`TestDependencyScanStaticAnalyzerDetectsRegressions`) feeds synthetic
fixtures through every matcher so over-tightening (a real upgrade
trips the analyser) and under-tightening (a real regression slips
through) are both caught at the AST.
