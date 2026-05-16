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

## Container image hardening (BE-0355)

`container_hardening_static_test.go` pins the production container
posture across three surfaces:

- **`Dockerfile`** — parsed by a small in-test Dockerfile parser
  (`parseDockerfile`) that joins backslash continuations, resolves
  global ARG defaults, and groups instructions under their owning
  FROM stage. The matchers assert: (1) multi-stage build present,
  (2) runtime base image is `gcr.io/distroless/static-debian12:nonroot`
  (ARG-expanded), (3) runtime stage carries `USER nonroot:nonroot`
  (the canonical user+group form, not bare `USER nonroot`), (4) the
  builder stage's joined RUN payload contains every member of
  `requiredBuilderBuildFlags` (`CGO_ENABLED=0`, `-trimpath`, `-s -w`),
  (5) `ENTRYPOINT` is declared in the runtime stage, (6) no
  `ADD <url>` instruction exists in any stage, (7) no ENV key in any
  stage matches a member of `forbiddenSecretEnvFragments`
  (case-insensitive), (8) no RUN body in the runtime stage matches a
  member of `forbiddenRuntimePackageInstalls`, (9) every
  `COPY --from=...` in the runtime stage carries
  `--chown=nonroot:nonroot`.
- **`docker-compose.yml`** — the matchers assert the `postgres`
  service's `image` matches `postgres:<digits>` (never `postgres` and
  never `postgres:latest`) and a non-empty `healthcheck` is declared.
- **`SECURITY.md`** — the test pins the verification-gates table row
  AND the dedicated `## Container Image Hardening` section so the
  public security posture stays in lockstep with the Dockerfile.

Self-check (`TestContainerHardeningStaticAnalyzerDetectsRegressions`)
drives every matcher with synthetic known-good AND known-bad
Dockerfile + compose fixtures so over- and under-tightening are both
caught. When tightening or widening the hardening contract (e.g. a
new forbidden ENV fragment, a new required build flag, a different
runtime base image), update the constants at the top of the test
file AND the regression-fixture catalogue in the same edit. The
package's existing `projectRoot` helper is reused so the test stays
location-independent.

## TLS and proxy header trust (BE-0356)

`http_server_hardening_static_test.go` pins the operator-facing
contract that (a) the API binary does not terminate TLS itself and
(b) the rate limiter trusts only a closed set of forwarded-IP
headers. Three real-file matchers run alongside one synthetic
self-check (`TestHTTPServerHardeningStaticAnalyzerDetectsRegressions`):

- **`cmd/yalla-api/main.go`** — `findAPITLSRegressions` walks the
  AST and rejects: (1) any call whose selector name is in
  `forbiddenAPITLSCallSelectors` (`ListenAndServeTLS`, `ServeTLS`),
  regardless of receiver; (2) any `http.Server` composite literal
  that omits a field from `requiredHTTPServerFields`
  (`ReadHeaderTimeout` is the Slowloris guard) OR contains a field
  from `forbiddenAPITLSStructFields` (`TLSConfig`, `TLSNextProto`);
  (3) any assignment whose LHS selector is in
  `forbiddenAPITLSStructFields` (the post-construction mutation
  seam). The matcher uses the package-qualified type selector
  `http.Server`, so unrelated structs in `main.go` are not scanned.
- **`internal/controlplane/httpapi/ratelimit.go`** —
  `findProxyHeaderTrustRegressions` runs two passes. The scoped
  pass locates the `ClientIP` function by name and walks every
  `*.Header.Get("...")` inside it; any literal not in
  `allowedProxyHeaderLiterals` (`X-Forwarded-For`, `X-Real-IP`,
  case-sensitive) is flagged. The scoped pass also asserts the
  body references `RemoteAddr` so the fallback chain stays intact.
  The file-wide pass walks every string literal in the file and
  flags any whose lower-cased form is in
  `forbiddenProxyHeaderLiterals` (RFC 7239 `Forwarded`,
  `True-Client-IP`, `CF-Connecting-IP`, `Fastly-Client-IP`,
  `X-Client-IP`, `X-Forwarded-{Host,Proto,Server,Port}`,
  `X-Original-Forwarded-For`). If `ClientIP` is missing entirely
  the matcher emits a single "missing function" hit so the gate
  cannot pass silently when its target is removed.
- **`SECURITY.md`** —
  `TestHTTPServerHardeningSecurityDocumentsTLSAndProxyTrust` pins
  the `## TLS Termination and Proxy Header Trust` heading, the
  verification-gates table row, and the canonical substrings
  (`TLS is terminated at the operator's reverse proxy`,
  `ReadHeaderTimeout`, `X-Forwarded-For`, `X-Real-IP`, and the
  test file path itself). The substrings carry the load-bearing
  facts so a future reader does not have to open the test file to
  learn the contract.

When adding or removing a trusted forwarding header, update
`allowedProxyHeaderLiterals` AND the `ClientIP` body AND the
SECURITY.md section in the same edit. When adding or removing a
required `http.Server` hardening field (e.g. a future
`MaxHeaderBytes` cap), update `requiredHTTPServerFields` AND the
`http.Server` construction in `cmd/yalla-api/main.go` AND the
SECURITY.md "Slowloris guard" bullet in the same edit. The
self-check sub-tests for each matcher MUST be extended with a
fresh known-bad fixture in the same edit so over- and
under-tightening of the analyser are both caught.
