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

## Admin endpoint isolation (BE-0357)

`admin_endpoint_isolation_static_test.go` pins the operator-facing
contract that the customer-facing API listener ships NO `/debug/*`
surface — no pprof, no expvar, no `golang.org/x/net/trace`, no
default-mux fallback. Four real-file matchers run alongside one
synthetic self-check
(`TestAdminEndpointIsolationStaticAnalyzerDetectsRegressions`):

- **`cmd/yalla-api/main.go` + `internal/controlplane/httpapi/*.go`
  (non-test files)** — `findForbiddenAdminImports` walks the AST's
  import declarations and rejects any path in
  `forbiddenAdminImports` (`net/http/pprof`, `expvar`,
  `golang.org/x/net/trace`). The match is path-based, so blank
  imports (`_ "net/http/pprof"`), named imports
  (`pprof "net/http/pprof"`), and aliased imports
  (`rogue "net/http/pprof"`) are all caught — the side-effect
  registration fires regardless of the local alias. Test files
  (`*_test.go`) are deliberately skipped via `adminProductionFiles`
  so a future runtime regression test can simulate the threat
  without tripping the gate.
- **`cmd/yalla-api/main.go`** — `findAdminHandlerRegressions`
  locates every `http.Server` composite literal (via
  `isAdminHTTPServerCompositeLit`, the package-qualified
  `http.Server` selector) and rejects: (1) the absence of the
  `Handler` key entirely (the Go zero value falls back to
  `http.DefaultServeMux`), and (2) `Handler: nil` explicitly (same
  fallback, written down). The matcher targets only `http.Server`
  literals so unrelated structs in main.go are untouched.
- **`internal/controlplane/httpapi/server.go`** —
  `findAdminPrivateMuxRegressions` runs two orthogonal passes
  against the handler file. The first asserts a call to
  `http.NewServeMux()` appears somewhere in the file; the absence
  means the gate cannot prove the handler is built on a private
  mux. The second walks every SelectorExpr and rejects any whose
  `Sel.Name` equals `DefaultServeMux` — this catches
  `http.DefaultServeMux.Handle("…", …)`, passing
  `http.DefaultServeMux` as an argument, or returning it from a
  function. Both passes are required because a regression that
  builds a private mux AND ALSO hands routes to the default mux
  would slip past either pass in isolation.
- **`cmd/yalla-api/main.go` + `internal/controlplane/httpapi/*.go`
  (non-test files)** — `findAdminDebugLiteralRegressions` runs the
  belt-and-braces literal scan. The string-literal pass rejects any
  literal containing a member of `forbiddenAdminLiterals`
  (`/debug/pprof`, `/debug/vars`, `/debug/requests`, `/debug/events`,
  `http.DefaultServeMux`); the selector pass rejects any
  SelectorExpr whose root identifier is in
  `forbiddenAdminSelectorPackages` (`pprof`, `expvar`). The literal
  scan is case-sensitive (the stdlib paths are case-sensitive at
  the HTTP layer); the selector scan catches an unaliased import
  use (`pprof.Index`, `expvar.Handler`) even when the import
  scanner would have missed a different import path.
- **`SECURITY.md`** —
  `TestAdminEndpointIsolationSecurityDocumented` pins the
  `## Admin Endpoint Isolation` heading, the verification-gates
  table row, and the canonical substrings (`net/http/pprof`,
  `expvar`, `http.NewServeMux`, `/debug/`, and the test file path
  itself). The substrings carry the load-bearing facts so a future
  reader does not have to open the test file to learn the contract.

When adding a new debug-shaped import that has a LEGITIMATE
production purpose (this is intentionally rare — most diagnostic
tooling belongs out-of-band), update `forbiddenAdminImports` AND
the SECURITY.md "No side-effecting debug imports" bullet AND the
self-check fixture catalogue in the same edit. When adding a new
operator-visible route to the API listener (analogous to
`/healthz/backup`), it goes through the same `apiRoute` table the
customer-facing routes use — not a side-channel — so the gate
keeps holding. The self-check sub-tests for each matcher MUST be
extended with a fresh known-bad fixture in the same edit so over-
and under-tightening of the analyser are both caught. The
`adminProductionFiles` helper sorts its output so a regression in
ANY production file in scope produces a deterministic diagnostic.

## Support access review (BE-0358)

`support_access_review_static_test.go` pins the operator-facing
contract that every break-glass mutation lands on the immutable
audit trail with `metadata.elevated_access == "true"`, that the
unit of work is access-only (no credential mint), that the policy
catalog keeps `admin.break_glass` bound to `CapSupport` and
grants `CapSupport` to `RoleSupport` only, and that the HTTP
renderer always advertises elevation. Five real-file matchers
run alongside one synthetic self-check
(`TestSupportAccessReviewStaticAnalyzerDetectsRegressions`):

- **`internal/controlplane/store/break_glass_service.go`** —
  `findSupportAuditElevationRegressions` walks every FuncDecl
  whose receiver is `*BreakGlassService` and indexes the
  required-method set (`supportRequiredMethodNames` =
  `StartSession`, `Revoke`). A missing required method is a
  named diagnostic; a present method whose body has no
  `AuditEvent{...}` literal containing
  `Metadata: map[string]string{breakGlassElevatedAccessKey: ...}`
  is rejected. `supportKeyIsElevatedAccess` accepts EITHER the
  package-private identifier `breakGlassElevatedAccessKey` OR the
  bare string literal `"elevated_access"` — both land on the same
  dashboard column. When adding a new break-glass mutation method
  (e.g. a future `ExtendSession`), append the method name to
  `supportRequiredMethodNames` in the same edit.
- **`internal/controlplane/store/break_glass_service.go`** —
  `findSupportRedactorRegressions` walks the same required-method
  set and asserts each method body contains at least one
  selector expression rooted at the conventional receiver alias
  `svc` (`supportServiceReceiverName`) with `Sel.Name ==
  "redactor"` (`supportRedactorFieldName`). The runtime evidence
  lives in `internal/controlplane/store/break_glass_internal_test.go`
  (`TestBuildSessionToCreateRedactsReasonValue`); the static gate
  catches a regression that silently drops the redactor seam. The
  matcher relies on the receiver alias being uniform; the
  store-layer convention is `svc` everywhere in the file.
- **`internal/controlplane/store/break_glass_service.go`** —
  `findSupportCredMintRegressions` walks every `*ast.Ident` in
  the file and rejects any name in
  `forbiddenCredMintIdentifiers` (`APIKeyService`,
  `APIKeyRepository`, `APIKeyCreator`, `APIKeyRotator`,
  `APIKeyIssuer`, `IssueKey`, `MintKey`, `RotateKey`,
  `NewAPIKey`, `ServiceAccountKey`, `ServiceAccountKeys`).
  The scan is file-wide and case-sensitive: every credential-
  bearing surface in this `store` package is one of those
  identifiers, so the closed set covers the threat model
  completely today. A future credential type should either join
  the list (if break-glass must stay away from it) or be
  reviewed.
- **`internal/controlplane/policy/catalog.go`** —
  `findSupportPolicyCatalogRegressions` runs two passes. Pass 1
  walks the `defaultActionCatalog` map literal (located by name
  via `supportFindMapLiteral`) and asserts the entry
  `ActionAdminBreakGlass: CapSupport` is present and unaltered.
  Pass 2 walks the `builtinRoleCaps` map literal and asserts
  `CapSupport` (located as an argument to the `newCapSet(...)`
  call) appears ONLY in `RoleSupport`'s row AND that
  `RoleSupport`'s row DOES include `CapSupport`. Either drift
  silently routes support access through a different engine
  clause. `supportFindMapLiteral` returns nil if the variable is
  missing or its initialiser is not a map literal; the matcher
  emits a named diagnostic in that case so a rename forces an
  explicit update.
- **`internal/controlplane/httpapi/break_glass.go`** —
  `findSupportElevatedAccessProjectionRegressions` locates the
  package-level `breakGlassSessionResourceOf` function and walks
  its body. The matcher requires at least one
  `breakGlassSessionResource{...}` composite literal whose
  `ElevatedAccess` key-value pair has the literal identifier
  `true` as its value. A missing function, a literal that omits
  the field entirely, a `false` literal, and a value projected
  from the row (e.g. `s.ElevatedAccess`) are all rejected — the
  client uses this flag to decide whether to display the
  "elevated" banner and a row-sourced value would be untrusted.
- **`SECURITY.md`** —
  `TestSupportAccessReviewSecurityDocumented` pins the
  `## Support Access Review` heading, the verification-gates
  table row, and the canonical substrings (`elevated_access`,
  `admin.break_glass`, `CapSupport`, `output.NewRedactor`, and
  the test file path itself). The substrings carry the load-
  bearing facts so a future reader does not have to open the
  test file to learn the contract.

When adding a new break-glass mutation method, update
`supportRequiredMethodNames` AND add the method to
`break_glass_service.go` with the audit-event stamp AND extend
the self-check fixture catalogue with a fresh known-bad case in
the same edit. When changing the audit-metadata key name, update
`supportElevatedAccessKeyIdent` AND
`supportElevatedAccessKeyLiteral` AND the SECURITY.md substring
list in the same edit — analytics, alerting, and the review
endpoints all branch on the exact key. When adding a new
credential type to the `store` package, decide whether
break-glass must stay away from it and (if so) extend
`forbiddenCredMintIdentifiers` in the same edit; otherwise
document why the new surface is access-only.

## Verification suite: unit tests for every package (BE-0379)

`verification_suite_unit_tests_static_test.go` is the load-bearing
defence for the meta-contract "every Go package in this repo
ships unit tests and the suite is gated on every push and PR." A
silent erosion of that contract — a new package added without
tests, the test step quietly removed from `ci.yml`, the
verify.sh row reordered — defeats every downstream security
gate in this file, because they are all `go test`-shaped
invariants that only fire if `go test ./...` actually runs.

The single file pins SIX surfaces in one place:

- **Repo tree.** `findPackagesMissingTests` walks the repo from
  `projectRoot` and reports every directory that has a non-test
  `.go` file but no `*_test.go` file AND is not in
  `allowedPackagesWithoutUnitTests`. The exemption set is a
  closed map: every entry carries a rationale that points to
  where coverage actually lives (release tests for
  `cmd/yalla-api` boot, `internal/cli` tests for `cmd/yalla`
  glue, `internal/controlplane/worker` tests for
  `cmd/yalla-worker` loop logic, doc-only placeholder for
  `internal/controlplane/jobs`). The companion test
  `TestVerificationSuiteExemptionSetIsTight` asserts every
  exempt directory (a) still exists and (b) still lacks tests,
  so a stale exemption (a package that has since gained a
  `*_test.go`) fails the build too.
- **`.github/workflows/ci.yml`** — the test job's step
  `- name: Unit and integration tests` MUST run
  `go test ./...` and the matrix MUST cover `ubuntu-latest`,
  `macos-latest`, and `windows-latest`. Dropping a host
  silently narrows the per-developer-platform coverage; using
  a narrower test pattern (e.g. `./internal/...`) silently
  drops `cmd/*` and any future top-level package.
- **`scripts/verify.sh`** — the canonical step header
  `# 4. Required: tests` and the literal `go test ./...`
  invocation MUST stay in lockstep with the CI gate so a
  successful local run predicts a successful CI run.
- **`CONTRIBUTING.md`** — the
  `## Required Checks Before Every Commit` section MUST list
  `` 4. `go test ./...` `` so a new contributor satisfies the
  gate before opening a PR. The numeric prefix is part of the
  contract — it keeps verify.sh and CONTRIBUTING.md aligned.
- **`SECURITY.md`** — the public verification-gates table row
  `| Tests | go test ./... | scripts/verify.sh, CI | Every push and PR |`
  AND the dedicated `## Unit Test Suite` section MUST stay
  present. The section is the operator-facing publication of
  the determinism (`fake Dokploy`, `YALLA_EXTERNAL_DOKPLOY`
  opt-in), actionable-failure (`request ID`), redaction
  (`redacted`), and CI-cadence (`Every push and PR`) contracts;
  every load-bearing substring is pinned by
  `requiredSecuritySectionSubstrings`.
- **`ralph/prd.json`** — the
  `verificationLoop.requiredLocalCommands` array MUST contain
  the literal `go test ./...` so an AI agent reading the PRD
  before picking up a story sees the gate from the contract
  document, not by inferring it from CI or shell scripts.

Self-check (`TestVerificationSuiteUnitTestsAnalyzerDetectsRegressions`)
drives every matcher with synthetic known-good AND known-bad
fixtures: a tree where one package is non-exempt and untested;
the same tree with the offender added to the exemption map; a
tree where an ignored prefix wraps the offender; a fully-tested
tree; a test-only directory; a synthetic SECURITY.md fixture
missing one of the required substrings; a synthetic complete
fixture; a synthetic PRD missing `go test ./...`; and the
inverse. The self-check is what guarantees over-tightening (a
matcher that flags a legitimate edit) and under-tightening (a
matcher that misses a real regression) both fail visibly.

When adding a new top-level command package or a new
`internal/<area>` package, EITHER add a `*_test.go` file in the
same edit OR add an entry to `allowedPackagesWithoutUnitTests`
with a rationale that points to where the behaviour is actually
covered. When changing the CI test step name, the verify.sh
step header, the CONTRIBUTING.md numeric prefix, the
SECURITY.md row, or the PRD verification-loop array, update the
matching constant in `verification_suite_unit_tests_static_test.go`
in the same edit. The matchers fail loudly on drift; do not
"fix" them by relaxing the assertion — the assertion IS the
contract.

## Verification suite: repository integration tests (BE-0380)

`verification_suite_repo_integration_static_test.go` is the
load-bearing static defence for the repository-integration gate
documented in BE-0380. It pins SIX surfaces in one file so a
future contributor changing any of them fails ONE test, not six:

- `.github/workflows/ci.yml` — the `test` job's dedicated
  `Repository integration tests` step running
  `go test ./internal/controlplane/store/...`. Defence-in-depth:
  a narrowing of the umbrella `Unit and integration tests` step
  would still leave this gate firing as a fast, targeted
  failure rather than buried inside the umbrella log.
- `scripts/verify.sh` — the local commit gate runs the same
  canonical command under the canonical header
  `# 6. Required: repository integration tests`. The numeric
  prefix is part of the contract: reorders must be deliberate.
- `CONTRIBUTING.md` — the Required Checks Before Every Commit
  numbered list carries entry
  `6. \`go test ./internal/controlplane/store/...\`` so a
  contributor sees the gate before opening a PR.
- `SECURITY.md` — the Required Verification Gates table carries
  the `Repository integration tests` row AND a dedicated
  `## Repository Integration Tests` section explains the
  tenant-isolation, determinism, actionable-failure (with
  `request_id` / `resource_id`), fake-Dokploy, opt-in
  `YALLA_EXTERNAL_DOKPLOY` external-smoke, and redaction
  contracts auditors and operators rely on.
- `ralph/prd.json` — the verification-loop's
  `requiredBackendCommands` array carries
  `go test ./internal/controlplane/store/...` so an AI agent
  reading the PRD before picking up a story sees the gate from
  the contract document.
- `internal/controlplane/store/migrate/migrate_test.go` —
  `func TestMigrations` MUST exist. The PRD's
  `go test -run TestMigrations ./...` binds to that exact
  function name; a rename (e.g. `TestMigrationsForward`)
  silently de-gates the migration-ladder bootstrap.

The self-check
`TestVerificationSuiteRepoIntegrationAnalyzerDetectsRegressions`
drives every matcher with synthetic known-good AND known-bad
fixtures so over-tightening (a legitimate change trips the
analyser) and under-tightening (a real regression slips
through) are both caught at the package-internal API. When
changing the CI step name, the verify.sh header, the
CONTRIBUTING.md numeric prefix, the SECURITY.md row or
section, the PRD command, or the migrations function name,
update the matching constant in
`verification_suite_repo_integration_static_test.go` in the
same edit. The matchers fail loudly on drift; the assertion IS
the contract.

## Verification suite: HTTP handler contract tests (BE-0381)

`verification_suite_handler_contract_tests_static_test.go` is
the load-bearing static defence for the HTTP handler contract
gate documented in BE-0381. It pins SIX surfaces in one file so
a future contributor changing any of them fails ONE test, not
six:

- `.github/workflows/ci.yml` — the `test` job's dedicated
  `HTTP handler contract tests` step running
  `go test ./internal/controlplane/httpapi/...`.
  Defence-in-depth: a narrowing of the umbrella
  `Unit and integration tests` step would still leave this
  gate firing as a fast, targeted failure rather than buried
  inside the umbrella log.
- `scripts/verify.sh` — the local commit gate runs the same
  canonical command under the canonical header
  `# 7. Required: HTTP handler contract tests`. The numeric
  prefix is part of the contract: reorders must be deliberate.
- `CONTRIBUTING.md` — the Required Checks Before Every Commit
  numbered list carries entry
  `7. \`go test ./internal/controlplane/httpapi/...\`` so a
  contributor sees the gate before opening a PR.
- `SECURITY.md` — the Required Verification Gates table carries
  the `HTTP handler contract tests` row AND a dedicated
  `## HTTP Handler Contract Tests` section explains the
  determinism, actionable-failure (with `request_id` /
  `resource_id`), contract-triple
  (`ServerWritesResponseDataOnlyToResponseWriter`,
  `RequestLogRedactsBearerToken`,
  `ErrorEnvelopeDoesNotLeakDependencyCause`), envelope-pinning
  (`yalla.output.v1` / `yalla.error.v1`), fake-Dokploy, opt-in
  `YALLA_EXTERNAL_DOKPLOY` external-smoke, and redaction
  contracts auditors and operators rely on.
- `ralph/prd.json` — the verification-loop's
  `requiredBackendCommands` array carries
  `go test ./internal/controlplane/httpapi/...` so an AI agent
  reading the PRD before picking up a story sees the gate from
  the contract document.
- `internal/controlplane/httpapi/me_contract_test.go` — the
  canonical reference contract test file MUST exist AND MUST
  declare the contract triple
  (`TestMeServerWritesResponseDataOnlyToResponseWriter`,
  `TestMeRequestLogRedactsBearerToken`,
  `TestMeErrorEnvelopeDoesNotLeakDependencyCause`). The
  `GET /v1/me` endpoint is the oldest and most-cited contract
  example in the repo; deleting the file or renaming one of
  the triple silently kills the load-bearing convention every
  other `*_contract_test.go` follows.

The self-check
`TestVerificationSuiteHandlerContractAnalyzerDetectsRegressions`
drives every matcher with synthetic known-good AND known-bad
fixtures so over-tightening (a legitimate change trips the
analyser) and under-tightening (a real regression slips
through) are both caught at the package-internal API. When
changing the CI step name, the verify.sh header, the
CONTRIBUTING.md numeric prefix, the SECURITY.md row or
section, the PRD command, the canonical contract file path,
or any contract-triple function name, update the matching
constant in
`verification_suite_handler_contract_tests_static_test.go` in
the same edit. The matchers fail loudly on drift; the
assertion IS the contract.

## Verification suite: OpenAPI schema conformance tests (BE-0382)

`verification_suite_openapi_conformance_static_test.go` is the
load-bearing static defence for the OpenAPI schema conformance
gate documented in BE-0382. It pins SIX surfaces in one file so
a future contributor changing any of them fails ONE test, not
six:

- `.github/workflows/ci.yml` — the `test` job's dedicated
  `OpenAPI schema conformance tests` step running
  `go test ./internal/controlplane/openapi/...`.
  Defence-in-depth: a narrowing of the umbrella
  `Unit and integration tests` step would still leave this
  gate firing as a fast, targeted failure rather than buried
  inside the umbrella log.
- `scripts/verify.sh` — the local commit gate runs the same
  canonical command under the canonical header
  `# 8. Required: OpenAPI schema conformance tests`. The
  numeric prefix is part of the contract: reorders must be
  deliberate.
- `CONTRIBUTING.md` — the Required Checks Before Every Commit
  numbered list carries entry
  `8. \`go test ./internal/controlplane/openapi/...\`` so a
  contributor sees the gate before opening a PR.
- `SECURITY.md` — the Required Verification Gates table carries
  the `OpenAPI schema conformance tests` row AND a dedicated
  `## OpenAPI Schema Conformance Tests` section explains the
  determinism, actionable-failure (with `operationId`),
  conformance-triple (`TestOpenAPIConformance`,
  `TestOpenAPIEnvelopesReferenceStableSchemaVersions`,
  `TestOpenAPIExamplesAreRedacted`), envelope-pinning
  (`yalla.output.v1` / `yalla.error.v1`), `x-required-action`,
  path-parameter shape, opt-in `YALLA_EXTERNAL_DOKPLOY`
  external-smoke, and redaction contracts auditors and
  operators rely on.
- `ralph/prd.json` — the verification-loop's
  `requiredBackendCommands` array carries
  `go test ./internal/controlplane/openapi/...` so an AI agent
  reading the PRD before picking up a story sees the gate from
  the contract document. The companion
  `go test -run TestOpenAPI ./...` filter (already present in
  the PRD) binds to the conformance-triple function names; a
  rename to a name that does not match the `TestOpenAPI`
  prefix silently de-gates the conformance suite for any
  caller relying on the filter, so the canonical-funcs entries
  in this static test pin every triple member to the
  `TestOpenAPI…` prefix.
- `internal/controlplane/openapi/openapi_conformance_test.go`
  — the canonical reference conformance test file MUST exist
  AND MUST declare the conformance triple
  (`TestOpenAPIConformance`,
  `TestOpenAPIEnvelopesReferenceStableSchemaVersions`,
  `TestOpenAPIExamplesAreRedacted`). The triple covers the
  three load-bearing wire invariants the published
  `/openapi.json` artifact MUST keep: every documented
  operation has a success response and a stable error envelope
  response with the correct security wiring and path-parameter
  shape; every envelope component schema pins the
  `schema_version` enum to the published Go constants
  (`output.SuccessSchema` / `yerr.SchemaVersion`); and every
  example body that resembles a credential is rendered through
  `output.Sentinel`.

The self-check
`TestVerificationSuiteOpenAPIConformanceAnalyzerDetectsRegressions`
drives every matcher with synthetic known-good AND known-bad
fixtures so over-tightening (a legitimate change trips the
analyser) and under-tightening (a real regression slips
through) are both caught at the package-internal API. When
changing the CI step name, the verify.sh header, the
CONTRIBUTING.md numeric prefix, the SECURITY.md row or
section, the PRD command, the canonical conformance file
path, or any conformance-triple function name, update the
matching constant in
`verification_suite_openapi_conformance_static_test.go` in
the same edit. The matchers fail loudly on drift; the
assertion IS the contract.

## Verification suite: policy matrix tests (BE-0383)

`verification_suite_policy_matrix_static_test.go` is the
load-bearing static defence for the RBAC + cross-tenant gate.
The canonical command is `go test -run TestPolicyMatrix ./...`
and the canonical reference file is
`internal/controlplane/policy/policy_test.go`, which declares
the matrix function pair `TestPolicyMatrix` (every built-in
role × every catalogued action on an in-organization resource)
and `TestPolicyMatrixDeniesCrossTenant` (every built-in role
× every catalogued action on a foreign-organization resource).
The pair binds to the PRD's `-run TestPolicyMatrix` filter via
the `TestPolicyMatrix` prefix, so a rename to a function whose
name does not match the prefix silently de-gates the matrix
suite. The static test pins SIX surfaces in one file so a
future contributor changing any one of them fails ONE test,
not six:

- `.github/workflows/ci.yml` — the `test` job's
  `Policy matrix tests` step MUST run
  `go test -run TestPolicyMatrix ./...`. The dedicated step
  is defence-in-depth on the same principle as BE-0380 /
  BE-0381 / BE-0382: a narrowing of the umbrella
  `go test ./...` step would still leave the matrix gate
  firing as a fast targeted failure.
- `scripts/verify.sh` — the local commit gate's
  `# 9. Required: policy matrix tests` block MUST invoke the
  same canonical command. The numeric prefix is part of the
  contract: a reorder must be a deliberate edit to both the
  matching constant in this test file AND the script.
- `CONTRIBUTING.md` — the Required Checks Before Every Commit
  section MUST list the canonical command as entry
  `9. \`go test -run TestPolicyMatrix ./...\`` so
  contributors know the gate before they open a PR. The
  numeric prefix keeps verify.sh and CONTRIBUTING.md in
  lockstep with BE-0379's `4. go test ./...`, BE-0380's
  `6. go test ./internal/controlplane/store/...`,
  BE-0381's `7. go test ./internal/controlplane/httpapi/...`,
  and BE-0382's `8. go test ./internal/controlplane/openapi/...`.
- `SECURITY.md` — the Required Verification Gates table MUST
  contain the `Policy matrix tests` row, AND a dedicated
  `## Policy Matrix Tests` section MUST explain the
  exhaustive-coverage / cross-tenant-invariant / determinism
  / actionable-failure / opt-in-external / redaction
  contracts so the public security posture stays in lockstep
  with the engine.
- `ralph/prd.json` —
  `verificationLoop.requiredBackendCommands` MUST list
  `go test -run TestPolicyMatrix ./...` so an AI agent
  reading the PRD before picking up a story sees the gate
  without needing to discover it from shell scripts or CI
  workflows.
- `internal/controlplane/policy/policy_test.go` — the
  canonical reference matrix test file MUST exist AND MUST
  declare the matrix function pair. The pair captures the
  two load-bearing matrix invariants the engine MUST keep:
  in-tenant decisions resolve via the
  `ReasonAllowedSelf`/`ReasonAllowedByRole`/`ReasonDeniedNoCapability`
  branches per the role's `capSet`, and cross-tenant
  decisions resolve to `ReasonAllowedSelf` (CapSelf),
  `ReasonAllowedBySupport` (support's CapSupport bridging
  `CapRead` / `CapSupport` only), or `ReasonDeniedCrossTenant`
  (everything else) — the engine's cross-org leak invariant.

The self-check
`TestVerificationSuitePolicyMatrixAnalyzerDetectsRegressions`
drives every matcher with synthetic known-good AND known-bad
fixtures so over-tightening (a legitimate change trips the
analyser) and under-tightening (a real regression slips
through) are both caught at the package-internal API. When
changing the CI step name, the verify.sh header, the
CONTRIBUTING.md numeric prefix, the SECURITY.md row or
section, the PRD command, the canonical matrix file path, or
either matrix-pair function name, update the matching
constant in `verification_suite_policy_matrix_static_test.go`
in the same edit. The matchers fail loudly on drift; the
assertion IS the contract.

## Verification suite: quota concurrency tests (BE-0384)

`verification_suite_quota_concurrency_static_test.go` is the
load-bearing static defence for the hard-limit + cross-tenant
concurrency gate. The canonical command is
`go test -run TestQuotaConcurrency ./...` and the canonical
reference file is
`internal/controlplane/quota/quota_test.go`, which declares
the concurrency function pair
`TestQuotaConcurrencyHardLimitNeverOverallocates` (parallel
reservations against one organization with a hard limit below
the attempt count resolve to exactly `limit` successes and the
rest rejected with `yerr.CodeQuotaExceeded`, with the database
row count agreeing) and `TestQuotaConcurrencyTenantIsolation`
(parallel reservations against two organizations each respect
their own hard limit and never leak across tenants — the two
tenants' active reservations sum to the two limits, never
collapse into one bucket). The pair binds to the PRD's
`-run TestQuotaConcurrency` filter via the
`TestQuotaConcurrency` prefix, so a rename to a function whose
name does not match the prefix silently de-gates the
concurrency suite. The static test pins SIX surfaces in one
file so a future contributor changing any one of them fails
ONE test, not six:

- `.github/workflows/ci.yml` — the `test` job's
  `Quota concurrency tests` step MUST run
  `go test -run TestQuotaConcurrency ./...`. The dedicated
  step is defence-in-depth on the same principle as BE-0380 /
  BE-0381 / BE-0382 / BE-0383: a narrowing of the umbrella
  `go test ./...` step would still leave the concurrency
  gate firing as a fast targeted failure.
- `scripts/verify.sh` — the local commit gate's
  `# 10. Required: quota concurrency tests` block MUST
  invoke the same canonical command. The numeric prefix is
  part of the contract: a reorder must be a deliberate edit
  to both the matching constant in this test file AND the
  script.
- `CONTRIBUTING.md` — the Required Checks Before Every
  Commit section MUST list the canonical command as entry
  `10. \`go test -run TestQuotaConcurrency ./...\`` so
  contributors know the gate before they open a PR. The
  numeric prefix keeps verify.sh and CONTRIBUTING.md in
  lockstep with BE-0379's `4. go test ./...`, BE-0380's
  `6. go test ./internal/controlplane/store/...`,
  BE-0381's `7. go test ./internal/controlplane/httpapi/...`,
  BE-0382's `8. go test ./internal/controlplane/openapi/...`,
  and BE-0383's `9. go test -run TestPolicyMatrix ./...`.
- `SECURITY.md` — the Required Verification Gates table MUST
  contain the `Quota concurrency tests` row, AND a dedicated
  `## Quota Concurrency Tests` section MUST explain the
  hard-limit-never-overallocates / cross-tenant-isolation /
  determinism / actionable-failure / opt-in-external /
  redaction contracts so the public security posture stays
  in lockstep with the checker.
- `ralph/prd.json` —
  `verificationLoop.requiredBackendCommands` MUST list
  `go test -run TestQuotaConcurrency ./...` so an AI agent
  reading the PRD before picking up a story sees the gate
  without needing to discover it from shell scripts or CI
  workflows.
- `internal/controlplane/quota/quota_test.go` — the
  canonical reference concurrency test file MUST exist AND
  MUST declare the concurrency function pair. The pair
  captures the two load-bearing concurrency invariants the
  checker MUST keep: `FOR UPDATE` on the per-organization,
  per-resource usage counter row makes "two units of work
  both decide they have headroom" impossible, and the
  `organization_id` predicate carried through every counter,
  sum, and insert makes "two tenants flatten into one
  bucket" impossible.

The self-check
`TestVerificationSuiteQuotaConcurrencyAnalyzerDetectsRegressions`
drives every matcher with synthetic known-good AND known-bad
fixtures so over-tightening (a legitimate change trips the
analyser) and under-tightening (a real regression slips
through) are both caught at the package-internal API. When
changing the CI step name, the verify.sh header, the
CONTRIBUTING.md numeric prefix, the SECURITY.md row or
section, the PRD command, the canonical concurrency file
path, or either concurrency-pair function name, update the
matching constant in
`verification_suite_quota_concurrency_static_test.go` in the
same edit. The matchers fail loudly on drift; the assertion
IS the contract.

## Verification suite: job worker lease tests (BE-0385)

`verification_suite_job_worker_lease_static_test.go` is the
single-file static defence for the job-worker-lease
meta-contract: "a queued provisioning job is leased to exactly
one worker at a time, and a worker interrupted mid-job returns
the lease to the queue so the job is not lost." The canonical
reference lease test file is
`internal/controlplane/worker/queue_test.go`, which declares
the lease function pair
`TestJobWorkerLeaseExclusivityNeverDoubleClaims` (two
concurrent `StoreClaimer.Claim` calls against a single queued
job — exactly one returns a lease and the other returns
`(nil, nil)`; the surviving lease runs the job to success and
the row carries no stale lease afterward) and
`TestJobWorkerLeaseReleasedOnShutdownIsRetryable` (a
`Loop.Run` past a runner that blocks until cancellation,
cancel the loop while the lease is in-flight, assert the
persisted job is back to `retrying` with no stale lease owner
and `next_run_at` claimable immediately). The pair binds to
the PRD's `-run TestJobWorkerLease` filter via the
`TestJobWorkerLease` prefix, so a rename to a function whose
name does not match the prefix silently de-gates the lease
suite. The static test pins SIX surfaces in one file so a
future contributor changing any one of them fails ONE test,
not six:

- `.github/workflows/ci.yml` — the `test` job's
  `Job worker lease tests` step MUST run
  `go test -run TestJobWorkerLease ./...`. The dedicated step
  is defence-in-depth on the same principle as BE-0380 /
  BE-0381 / BE-0382 / BE-0383 / BE-0384: a narrowing of the
  umbrella `go test ./...` step would still leave the lease
  gate firing as a fast targeted failure.
- `scripts/verify.sh` — the local commit gate's
  `# 11. Required: job worker lease tests` block MUST invoke
  the same canonical command. The numeric prefix is part of
  the contract: a reorder must be a deliberate edit to both
  the matching constant in this test file AND the script.
  Inserting required step #11 between #10 (quota concurrency)
  and the optionals renumbered 11→12 / 12→13 / 13→14 / 14→15
  in the same edit (govulncheck / staticcheck / golangci-lint
  / goreleaser).
- `CONTRIBUTING.md` — the Required Checks Before Every Commit
  section MUST list the canonical command as entry
  `11. \`go test -run TestJobWorkerLease ./...\`` so
  contributors know the gate before they open a PR. The
  numeric prefix keeps verify.sh and CONTRIBUTING.md in
  lockstep with BE-0379's `4. go test ./...`, BE-0380's
  `6. go test ./internal/controlplane/store/...`, BE-0381's
  `7. go test ./internal/controlplane/httpapi/...`, BE-0382's
  `8. go test ./internal/controlplane/openapi/...`, BE-0383's
  `9. go test -run TestPolicyMatrix ./...`, and BE-0384's
  `10. go test -run TestQuotaConcurrency ./...`.
- `SECURITY.md` — the Required Verification Gates table MUST
  contain the `Job worker lease tests` row, AND a dedicated
  `## Job Worker Lease Tests` section MUST explain the
  exclusivity / shutdown-safety / determinism /
  actionable-failure / opt-in-external / redaction contracts
  so the public security posture stays in lockstep with the
  worker.
- `ralph/prd.json` —
  `verificationLoop.requiredBackendCommands` MUST list
  `go test -run TestJobWorkerLease ./...` so an AI agent
  reading the PRD before picking up a story sees the gate
  without needing to discover it from shell scripts or CI
  workflows.
- `internal/controlplane/worker/queue_test.go` — the canonical
  reference lease test file MUST exist AND MUST declare the
  lease function pair. The pair captures the two load-bearing
  lease invariants the worker MUST keep:
  `SELECT ... FOR UPDATE SKIP LOCKED` on the provisioning_jobs
  row makes "two workers both leased the same job" impossible,
  and the `Loop.Run` shutdown path that calls `Lease.Release`
  against a context detached from the cancelled loop context
  makes "the job is lost when the worker shuts down"
  impossible.

The self-check
`TestVerificationSuiteJobWorkerLeaseAnalyzerDetectsRegressions`
drives every matcher with synthetic known-good AND known-bad
fixtures so over-tightening (a legitimate change trips the
analyser) and under-tightening (a real regression slips
through) are both caught at the package-internal API. When
changing the CI step name, the verify.sh header, the
CONTRIBUTING.md numeric prefix, the SECURITY.md row or
section, the PRD command, the canonical lease file path, or
either lease-pair function name, update the matching constant
in `verification_suite_job_worker_lease_static_test.go` in
the same edit. The matchers fail loudly on drift; the
assertion IS the contract.

## Verification suite: fake Dokploy contract tests (BE-0386)

`verification_suite_fake_dokploy_contract_static_test.go` is
the single-file static defence for the fake-Dokploy
meta-contract: "every worker/handler/agent test exercising
Dokploy-shaped behaviour runs against the deterministic
in-memory fake — never a live Dokploy server — and every
request the recorder captures has its bearer redacted before
it can land in a CI log." The canonical reference fake-Dokploy
test file is
`internal/controlplane/dokploy/dokployfake/dokployfake_test.go`,
which declares the fake-Dokploy function pair
`TestFakeDokployContractDeterministicHierarchyIDs` (two
independent `dokployfake.New()` servers driven through the
same Create chain mint byte-identical resource IDs at every
level — `org_1`, `proj_1`, `env_1`, `app_1`, `dep_1` — and
keep per-server request counts isolated) and
`TestFakeDokployContractRecordedRequestsRedactCredentials` (a
successful create, a GET, and a failure-path POST whose body
deliberately echoes the bearer token; every recorded request
carries `AuthHeader == output.Sentinel`,
`Headers[Authorization] == output.Sentinel`, and no body
retains the bearer literal). The pair binds to the PRD's
`-run TestFakeDokploy` filter via the `TestFakeDokploy`
prefix, so a rename to a function whose name does not match
the prefix silently de-gates the fake-Dokploy suite. The
static test pins SIX surfaces in one file so a future
contributor changing any one of them fails ONE test, not six:

- `.github/workflows/ci.yml` — the `test` job's
  `Fake Dokploy contract tests` step MUST run
  `go test -run TestFakeDokploy ./...`. The dedicated step
  is defence-in-depth on the same principle as BE-0380 /
  BE-0381 / BE-0382 / BE-0383 / BE-0384 / BE-0385: a
  narrowing of the umbrella `go test ./...` step would still
  leave the fake-Dokploy gate firing as a fast targeted
  failure.
- `scripts/verify.sh` — the local commit gate's
  `# 12. Required: fake Dokploy contract tests` block MUST
  invoke the same canonical command. The numeric prefix is
  part of the contract: a reorder must be a deliberate edit
  to both the matching constant in this test file AND the
  script. Inserting required step #12 between #11 (job worker
  lease) and the optionals renumbered 12→13 / 13→14 / 14→15
  / 15→16 in the same edit (govulncheck / staticcheck /
  golangci-lint / goreleaser).
- `CONTRIBUTING.md` — the Required Checks Before Every Commit
  section MUST list the canonical command as entry
  `12. \`go test -run TestFakeDokploy ./...\`` so
  contributors know the gate before they open a PR. The
  numeric prefix keeps verify.sh and CONTRIBUTING.md in
  lockstep with BE-0379's `4. go test ./...`, BE-0380's
  `6. go test ./internal/controlplane/store/...`, BE-0381's
  `7. go test ./internal/controlplane/httpapi/...`, BE-0382's
  `8. go test ./internal/controlplane/openapi/...`, BE-0383's
  `9. go test -run TestPolicyMatrix ./...`, BE-0384's
  `10. go test -run TestQuotaConcurrency ./...`, and
  BE-0385's `11. go test -run TestJobWorkerLease ./...`.
- `SECURITY.md` — the Required Verification Gates table MUST
  contain the `Fake Dokploy contract tests` row, AND a
  dedicated `## Fake Dokploy Contract Tests` section MUST
  explain the determinism / recorder-redaction /
  actionable-failure / opt-in-external / schema-version
  contracts so the public security posture stays in lockstep
  with the fake.
- `ralph/prd.json` —
  `verificationLoop.requiredBackendCommands` MUST list
  `go test -run TestFakeDokploy ./...` so an AI agent
  reading the PRD before picking up a story sees the gate
  without needing to discover it from shell scripts or CI
  workflows.
- `internal/controlplane/dokploy/dokployfake/dokployfake_test.go` —
  the canonical reference fake-Dokploy test file MUST exist
  AND MUST declare the fake-Dokploy function pair. The pair
  captures the two load-bearing invariants the fake MUST
  keep: independent `dokployfake.New()` servers produce
  byte-identical hierarchy IDs (so any test using the fake
  is reproducible across runs and goroutines), and the
  recorder swaps the Authorization header for the shared
  `output.Sentinel` AND scans the body for the bearer
  literal before any caller can read it back (so a CI log
  never becomes the place a Dokploy bearer leaks).

The self-check
`TestVerificationSuiteFakeDokployContractAnalyzerDetectsRegressions`
drives every matcher with synthetic known-good AND known-bad
fixtures so over-tightening (a legitimate change trips the
analyser) and under-tightening (a real regression slips
through) are both caught at the package-internal API. When
changing the CI step name, the verify.sh header, the
CONTRIBUTING.md numeric prefix, the SECURITY.md row or
section, the PRD command, the canonical fake-Dokploy file
path, or either pair function name, update the matching
constant in
`verification_suite_fake_dokploy_contract_static_test.go` in
the same edit. The matchers fail loudly on drift; the
assertion IS the contract.

## Verification suite: redaction tests (BE-0387)

`verification_suite_redaction_static_test.go` is the
single-file static defence for the redaction meta-contract:
"secrets, tokens, API keys, cookies, and rendered environment
variable values never appear in customer-facing output, logs,
errors, audit metadata, test output, or dry-run output."
The canonical reference redaction test file is
`internal/output/redact_test.go`, which declares the
redaction function pair
`TestRedactionContractStructuralPatternsAcrossKnownTransports`
(pins the structural net every transport must cross: the
canonical sentinel literal `[REDACTED]`, the
Authorization/X-API-Key/X-Auth-Token header scrubbing across
casing, the `?token=`/`?api_key=`/`?access_token=`/`?x-auth-token=`
query-parameter scrubbing across positions, the non-secret
query-parameter pass-through, and panic-free behaviour on
hostile inputs) and
`TestRedactionContractExplicitSecretsAndIdempotency`
(pins explicit-secret scrubbing across surrounding-character
contexts, sub-threshold/empty/whitespace secret dropping on
construction, duplicate de-duplication,
`Redact(Redact(s)) == Redact(s)` idempotency across the
contract corpus, empty-input pass-through, and the
sentinel-cannot-be-re-registered-as-a-secret invariant). The
pair binds to the PRD's `-run TestRedaction` filter via the
`TestRedaction` prefix, so a rename to a function whose name
does not match the prefix silently de-gates the redaction
suite. The static test pins SIX surfaces in one file so a
future contributor changing any one of them fails ONE test,
not six:

- `.github/workflows/ci.yml` — the `test` job's
  `Redaction tests` step MUST run
  `go test -run TestRedaction ./...`. The dedicated step is
  defence-in-depth on the same principle as BE-0380 /
  BE-0381 / BE-0382 / BE-0383 / BE-0384 / BE-0385 / BE-0386:
  a narrowing of the umbrella `go test ./...` step would
  still leave the redaction gate firing as a fast targeted
  failure.
- `scripts/verify.sh` — the local commit gate's
  `# 13. Required: redaction tests` block MUST invoke the
  same canonical command. The numeric prefix is part of the
  contract: a reorder must be a deliberate edit to both the
  matching constant in this test file AND the script.
  Inserting required step #13 between #12 (fake Dokploy
  contract) and the optionals renumbered 13→14 / 14→15 /
  15→16 / 16→17 in the same edit (govulncheck / staticcheck
  / golangci-lint / goreleaser).
- `CONTRIBUTING.md` — the Required Checks Before Every Commit
  section MUST list the canonical command as entry
  `13. \`go test -run TestRedaction ./...\`` so contributors
  know the gate before they open a PR. The numeric prefix
  keeps verify.sh and CONTRIBUTING.md in lockstep with
  BE-0379's `4. go test ./...`, BE-0380's
  `6. go test ./internal/controlplane/store/...`, BE-0381's
  `7. go test ./internal/controlplane/httpapi/...`, BE-0382's
  `8. go test ./internal/controlplane/openapi/...`, BE-0383's
  `9. go test -run TestPolicyMatrix ./...`, BE-0384's
  `10. go test -run TestQuotaConcurrency ./...`, BE-0385's
  `11. go test -run TestJobWorkerLease ./...`, and BE-0386's
  `12. go test -run TestFakeDokploy ./...`.
- `SECURITY.md` — the Required Verification Gates table MUST
  contain the `Redaction tests` row, AND a dedicated
  `## Redaction Tests` section MUST explain the
  structural-transport / explicit-secret / idempotency /
  panic-free / actionable-failure / opt-in-external /
  schema-version contracts so the public security posture
  stays in lockstep with the redactor.
- `ralph/prd.json` —
  `verificationLoop.requiredBackendCommands` MUST list
  `go test -run TestRedaction ./...` so an AI agent reading
  the PRD before picking up a story sees the gate without
  needing to discover it from shell scripts or CI workflows.
- `internal/output/redact_test.go` — the canonical reference
  redaction test file MUST exist AND MUST declare the
  redaction function pair. The pair captures the two
  load-bearing redaction invariants the `Redactor` MUST keep:
  the structural net scrubs every supported transport (the
  Authorization, X-API-Key, and X-Auth-Token header families
  across casing; the token, api_key, api-key, access_token,
  and x-auth-token query-parameter families across casing
  and position), and an explicit secret registered via
  `NewRedactor` is replaced by Sentinel everywhere it appears
  regardless of surrounding characters, with the Redactor
  staying idempotent under repeated application and unable to
  scrub its own sentinel.

The self-check
`TestVerificationSuiteRedactionAnalyzerDetectsRegressions`
drives every matcher with synthetic known-good AND known-bad
fixtures so over-tightening (a legitimate change trips the
analyser) and under-tightening (a real regression slips
through) are both caught at the package-internal API. When
changing the CI step name, the verify.sh header, the
CONTRIBUTING.md numeric prefix, the SECURITY.md row or
section, the PRD command, the canonical redaction file path,
or either pair function name, update the matching constant
in `verification_suite_redaction_static_test.go` in the same
edit. The matchers fail loudly on drift; the assertion IS
the contract.

## Verification suite: fuzz tests for validators (BE-0388)

`verification_suite_fuzz_validators_static_test.go` is the
single-file static defence for the validator hostile-input
meta-contract: "no validator ever panics on hostile input,
no validator echoes a submitted value back into an error or
log, and every public validator has a corresponding Fuzz
target." The canonical reference fuzz test file is
`internal/controlplane/validate/fuzz_test.go`, which declares
the fuzz function pair
`TestFuzzValidatorContractCoversExpectedValidators` (pins the
closed-set coverage invariant — every public validator in
`internal/controlplane/validate` MUST have a corresponding
`Fuzz<Name>` target so the seed corpus replays hostile inputs
deterministically under `go test -run TestFuzzValidator ./...`
AND under `go test -fuzz=<target>
./internal/controlplane/validate/...`) and
`TestFuzzValidatorContractSeedCorpusRejectsHostileInputs`
(pins the no-panic runtime invariant — every validator
survives every hostile seed without panicking; the wrapper
drives every validator under a `recover()` guard so a panic
surfaces with the offending validator name AND the seed
index). The pair binds to the PRD's `-run TestFuzzValidator`
filter via the `TestFuzzValidator` prefix, so a rename to a
function whose name does not match the prefix silently
de-gates the fuzz suite. The wrapper sits next to the nine
`FuzzName` / `FuzzPath` / `FuzzDomain` / `FuzzEnvVarName` /
`FuzzEnvVarValue` / `FuzzDecodeJSON` / `FuzzImageRef` /
`FuzzURL` / `FuzzGitBranch` targets it pins; deleting any
target trips the closed-set coverage matcher with the exact
validator name.

The static test pins SIX surfaces in one file so a future
contributor changing any one of them fails ONE test, not six:

- `.github/workflows/ci.yml` — the `test` job's
  `Fuzz validator tests` step MUST run
  `go test -run TestFuzzValidator ./...`. The dedicated step
  is defence-in-depth on the same principle as BE-0380 /
  BE-0381 / BE-0382 / BE-0383 / BE-0384 / BE-0385 / BE-0386 /
  BE-0387: a narrowing of the umbrella `go test ./...` step
  would still leave the fuzz gate firing as a fast targeted
  failure.
- `scripts/verify.sh` — the local commit gate's
  `# 14. Required: fuzz tests for validators` block MUST
  invoke the same canonical command. The numeric prefix is
  part of the contract: a reorder must be a deliberate edit
  to both the matching constant in this test file AND the
  script. Inserting required step #14 between #13 (redaction
  tests) and the optionals renumbered 14→15 / 15→16 / 16→17 /
  17→18 in the same edit (govulncheck / staticcheck /
  golangci-lint / goreleaser). This is EIGHT consecutive
  required-step insertions with optional renumbering.
- `CONTRIBUTING.md` — the Required Checks Before Every Commit
  section MUST list the canonical command as entry
  `14. \`go test -run TestFuzzValidator ./...\`` so
  contributors know the gate before they open a PR. The
  numeric prefix keeps verify.sh and CONTRIBUTING.md in
  lockstep with BE-0379's `4. go test ./...`, BE-0380's
  `6. go test ./internal/controlplane/store/...`, BE-0381's
  `7. go test ./internal/controlplane/httpapi/...`, BE-0382's
  `8. go test ./internal/controlplane/openapi/...`, BE-0383's
  `9. go test -run TestPolicyMatrix ./...`, BE-0384's
  `10. go test -run TestQuotaConcurrency ./...`, BE-0385's
  `11. go test -run TestJobWorkerLease ./...`, BE-0386's
  `12. go test -run TestFakeDokploy ./...`, and BE-0387's
  `13. go test -run TestRedaction ./...`.
- `SECURITY.md` — the Required Verification Gates table MUST
  contain the `Fuzz validator tests` row, AND a dedicated
  `## Fuzz Validator Tests` section MUST explain the
  no-panic / no-value-echo / closed-set-coverage /
  deterministic-seed-corpus / actionable-failure /
  opt-in-external / `-fuzz=` / schema-version contracts so
  the public security posture stays in lockstep with the
  validate toolkit.
- `ralph/prd.json` —
  `verificationLoop.requiredBackendCommands` MUST list
  `go test -run TestFuzzValidator ./...` so an AI agent
  reading the PRD before picking up a story sees the gate
  without needing to discover it from shell scripts or CI
  workflows.
- `internal/controlplane/validate/fuzz_test.go` — the
  canonical reference fuzz test file MUST exist AND MUST
  declare the fuzz function pair. The pair captures the two
  load-bearing fuzz invariants the validate toolkit MUST
  keep: every public validator has a Fuzz target (the
  closed-set coverage invariant pinned by reading the file's
  own source under `runtime.Caller` so a future package move
  auto-updates the lookup), and every validator survives
  every hostile seed without panicking (the no-panic runtime
  invariant pinned by `recover()`-wrapped invocations across
  the shared seed corpus).

The self-check
`TestVerificationSuiteFuzzValidatorsAnalyzerDetectsRegressions`
drives every matcher with synthetic known-good AND known-bad
fixtures so over-tightening (a legitimate change trips the
analyser) and under-tightening (a real regression slips
through) are both caught at the package-internal API. When
changing the CI step name, the verify.sh header, the
CONTRIBUTING.md numeric prefix, the SECURITY.md row or
section, the PRD command, the canonical fuzz file path, or
either pair function name, update the matching constant in
`verification_suite_fuzz_validators_static_test.go` in the
same edit. The matchers fail loudly on drift; the assertion
IS the contract.

## Verification suite: migration tests from empty DB (BE-0389)

`verification_suite_migrations_empty_db_static_test.go` is the
single-file static defence for the migrations-from-empty-DB
meta-contract: "every numbered `NNNN_*.up.sql` file in the
embedded migrations directory surfaces as a loaded `Migration`,
the embedded ladder applies cleanly to an empty Postgres
database in order, the `schema_migrations` ledger ends with one
clean row per migration, and a second `Up` is a no-op." The
canonical reference migration test file is
`internal/controlplane/store/migrate/migrate_test.go`, which
declares the canonical pair
`TestMigrationsEmptyDBContractCoversAllNumberedFiles` (pins
the closed-set coverage invariant — every `NNNN_*.up.sql` file
in the embedded migrations directory MUST surface as a loaded
`Migration`, strictly ascending and gap-free from version 1,
with a non-empty up SQL body and a 64-character sha256 hex
checksum; runs without a Postgres dependency) and
`TestMigrationsEmptyDBContractAppliesEmbeddedLadderToEmptyDatabase`
(pins the applies-cleanly runtime invariant — a throwaway
database accepts the embedded ladder in order, the
`schema_migrations` ledger ends with one clean row per
migration with correct embedded checksum and dirty=false, and
a second `Up` is a no-op; skips cleanly when
`YALLA_TEST_DATABASE_URL` is unset). The pair binds to the
PRD's `-run TestMigrationsEmptyDB` filter via the
`TestMigrationsEmptyDB` prefix, so a rename to a function whose
name does not match the prefix silently de-gates the empty-DB
suite. The first member exercises the embedded FS directly so
it runs on every developer machine without Postgres; the
second member exercises an isolated, throwaway database (one
fresh database per test run, dropped on cleanup) so it never
depends on shared state and is parallel-safe.

The static test pins SIX surfaces in one file so a future
contributor changing any one of them fails ONE test, not six:

- `.github/workflows/ci.yml` — the `test` job's
  `Migration tests from empty DB` step MUST run
  `go test -run TestMigrationsEmptyDB ./...`. The dedicated
  step is defence-in-depth on the same principle as BE-0380 /
  BE-0381 / BE-0382 / BE-0383 / BE-0384 / BE-0385 / BE-0386 /
  BE-0387 / BE-0388: a narrowing of the umbrella
  `go test ./...` step would still leave the empty-DB gate
  firing as a fast targeted failure.
- `scripts/verify.sh` — the local commit gate's
  `# 15. Required: migration tests from empty DB` block MUST
  invoke the same canonical command. The numeric prefix is
  part of the contract: a reorder must be a deliberate edit
  to both the matching constant in this test file AND the
  script. Inserting required step #15 between #14 (fuzz
  validator tests) and the optionals renumbered 15→16 /
  16→17 / 17→18 / 18→19 in the same edit (govulncheck /
  staticcheck / golangci-lint / goreleaser). This is NINE
  consecutive required-step insertions with optional
  renumbering.
- `CONTRIBUTING.md` — the Required Checks Before Every Commit
  section MUST list the canonical command as entry
  `15. \`go test -run TestMigrationsEmptyDB ./...\`` so
  contributors know the gate before they open a PR. The
  numeric prefix keeps verify.sh and CONTRIBUTING.md in
  lockstep with BE-0379's `4. go test ./...`, BE-0380's
  `6. go test ./internal/controlplane/store/...`, BE-0381's
  `7. go test ./internal/controlplane/httpapi/...`, BE-0382's
  `8. go test ./internal/controlplane/openapi/...`, BE-0383's
  `9. go test -run TestPolicyMatrix ./...`, BE-0384's
  `10. go test -run TestQuotaConcurrency ./...`, BE-0385's
  `11. go test -run TestJobWorkerLease ./...`, BE-0386's
  `12. go test -run TestFakeDokploy ./...`, BE-0387's
  `13. go test -run TestRedaction ./...`, and BE-0388's
  `14. go test -run TestFuzzValidator ./...`.
- `SECURITY.md` — the Required Verification Gates table MUST
  contain the `Migration tests from empty DB` row, AND a
  dedicated `## Migration Tests From Empty DB` section MUST
  explain the closed-set-coverage / applies-cleanly /
  deterministic-by-default / actionable-failure /
  opt-in-external / schema-version contracts so the public
  security posture stays in lockstep with the migration
  runner.
- `ralph/prd.json` —
  `verificationLoop.requiredBackendCommands` MUST list
  `go test -run TestMigrationsEmptyDB ./...` so an AI agent
  reading the PRD before picking up a story sees the gate
  without needing to discover it from shell scripts or CI
  workflows.
- `internal/controlplane/store/migrate/migrate_test.go` — the
  canonical reference migration test file MUST exist AND MUST
  declare the function pair. The pair captures the two
  load-bearing migration invariants the runner MUST keep:
  every `NNNN_*.up.sql` file surfaces as a loaded `Migration`
  (the closed-set coverage invariant pinned by walking the
  embedded FS through the loader's filename grammar), and the
  embedded ladder applies cleanly to an empty database
  leaving the ledger in a clean state (the applies-cleanly
  runtime invariant pinned by a throwaway database that
  skips when `YALLA_TEST_DATABASE_URL` is unset).

The self-check
`TestVerificationSuiteMigrationsEmptyDBAnalyzerDetectsRegressions`
drives every matcher with synthetic known-good AND known-bad
fixtures so over-tightening (a legitimate change trips the
analyser) and under-tightening (a real regression slips
through) are both caught at the package-internal API. When
changing the CI step name, the verify.sh header, the
CONTRIBUTING.md numeric prefix, the SECURITY.md row or
section, the PRD command, the canonical migration test file
path, or either pair function name, update the matching
constant in
`verification_suite_migrations_empty_db_static_test.go` in the
same edit. The matchers fail loudly on drift; the assertion
IS the contract.

## Verification suite: race detector tests (BE-0391)

`verification_suite_race_detector_static_test.go` is the
load-bearing static defence for the data-race gate. The
canonical command is `go test -race ./...` (an UMBRELLA
invocation, not a `-run` filter). Race detector is the only
verification gate that flips the runtime `-race` flag on, so
its absence makes every concurrency invariant other gates pin
(quota concurrency BE-0384, job worker leases BE-0385,
fake-Dokploy contract BE-0386, redaction emitters BE-0387) a
paper invariant: their tests would still pass under a
regression that introduced a race, because the race only
manifests with the detector enabled. The umbrella shape
mirrors BE-0379's `go test ./...` gate — there is no canonical
test-function pair to pin because the `-race` flag wraps every
`Test*` function the suite runs, unlike BE-0383..BE-0390 whose
`-run` filter binds to a specific function-name prefix.

The static test pins FIVE surfaces in one file so a future
contributor changing any one of them fails ONE test, not five:

- `.github/workflows/ci.yml` — the `test` job's
  `Race detector` step MUST run `go test -race ./...`. The
  dedicated step is defence-in-depth on the same principle as
  BE-0379..BE-0390: a future narrowing of the umbrella
  `go test ./...` step would still leave the race gate firing
  as a fast targeted failure rather than buried inside the
  umbrella log.
- `scripts/verify.sh` — the local commit gate's
  `# 5. Required: race detector` block MUST invoke the same
  canonical command. The numeric prefix is part of the
  contract: a reorder must be a deliberate edit to both the
  matching constant in this test file AND the script. Slot
  #5 has been stable since BE-0379's #4
  (`go test ./...`) and predates every BE-0380..BE-0390
  insertion at slots #6..#16; a future required-step
  insertion BETWEEN #4 and #6 must update the matching
  constant in the same edit.
- `CONTRIBUTING.md` — the Required Checks Before Every Commit
  section MUST list the canonical command as entry
  `5. \`go test -race ./...\`` so contributors know the gate
  before they open a PR. The numeric prefix keeps verify.sh
  and CONTRIBUTING.md in lockstep with BE-0379's
  `4. go test ./...`, BE-0380's
  `6. go test ./internal/controlplane/store/...`, BE-0381's
  `7. go test ./internal/controlplane/httpapi/...`, BE-0382's
  `8. go test ./internal/controlplane/openapi/...`, BE-0383's
  `9. go test -run TestPolicyMatrix ./...`, BE-0384's
  `10. go test -run TestQuotaConcurrency ./...`, BE-0385's
  `11. go test -run TestJobWorkerLease ./...`, BE-0386's
  `12. go test -run TestFakeDokploy ./...`, BE-0387's
  `13. go test -run TestRedaction ./...`, BE-0388's
  `14. go test -run TestFuzzValidator ./...`, BE-0389's
  `15. go test -run TestMigrationsEmptyDB ./...`, and
  BE-0390's `16. go test -run TestMigrationsDowngradeSafety
  ./...`.
- `SECURITY.md` — the Required Verification Gates table MUST
  contain the `Race detector` row, AND a dedicated
  `## Race Detector` section MUST explain the
  data-race-as-test-failure / umbrella-scope /
  deterministic-by-default / actionable-failure /
  opt-in-external / redacted-test-output / stable-envelope /
  every-push-and-PR contracts so the public security posture
  stays in lockstep with the runtime gate.
- `ralph/prd.json` —
  `verificationLoop.requiredLocalCommands` MUST list
  `go test -race ./...` AND
  `verificationLoop.requiredBackendCommands` MUST list
  `go test -race ./internal/controlplane/...` so an AI agent
  reading the PRD before picking up a story sees both the
  umbrella race gate and the focused backend race gate
  without needing to discover them from CI workflows or
  shell scripts. The two-entry pin is a BE-0391-specific
  extension to the template — every prior verification-suite
  story pinned a single PRD command because the canonical
  command WAS the umbrella; BE-0391 pins TWO because the
  race detector has a faster mid-iteration variant
  (backend-only) an agent can run without paying the full
  umbrella cost, and the contract must keep that variant
  visible in the PRD too.

The self-check
`TestVerificationSuiteRaceDetectorAnalyzerDetectsRegressions`
drives every matcher with synthetic known-good AND known-bad
fixtures so over-tightening (a legitimate change trips the
analyser) and under-tightening (a real regression slips
through) are both caught at the package-internal API. When
changing the CI step name, the verify.sh header, the
CONTRIBUTING.md numeric prefix, the SECURITY.md row or
section, or the PRD commands, update the matching constant
in `verification_suite_race_detector_static_test.go` in the
same edit. The matchers fail loudly on drift; the assertion
IS the contract.

## Verification suite: load smoke tests (BE-0392)

`verification_suite_load_smoke_static_test.go` pins the load
smoke gate. It is the load-bearing static defence for the
contract between Yalla's public bootstrap surface
(`/healthz`, `/readyz`, `/version`) and every operator, AI
agent, or CI gate that polls those endpoints under burst
load: every response carries a stable `yalla.output.v1`
envelope with `ok=true`, every response carries a
SafeID-clean `request_id` unique to that request, and no
response leaks a secret-shaped substring in body or header
even when fired by `loadSmokeWorkers *
loadSmokeIterationsPerWorker` concurrent goroutines per
endpoint. The canonical pair
(`TestLoadSmokeContractCoversCoreEndpoints` and
`TestLoadSmokeContractRunsBurstWithStableEnvelopes`) lives
in `internal/controlplane/httpapi/load_smoke_test.go` and
binds to the PRD's `-run TestLoadSmoke` filter. Both pair
members are deterministic — they run without Postgres and
without a live Dokploy server — because the bootstrap
surface is the one part of the API that needs no backing
infrastructure. The static test pins SIX surfaces in one
file: the CI `Load smoke tests` step (`.github/workflows/ci.yml`),
the verify.sh step #17 header (`scripts/verify.sh`), the
CONTRIBUTING.md entry #17, the SECURITY.md row + dedicated
`## Load Smoke Tests` section, the PRD command in
`verificationLoop.requiredBackendCommands`, and the canonical
pair file's existence with both function declarations
present. The self-check
(`TestVerificationSuiteLoadSmokeAnalyzerDetectsRegressions`)
drives every matcher with synthetic known-good AND
known-bad fixtures so over-tightening (a legitimate change
trips the analyser) and under-tightening (a real regression
slips through) are both caught at the package-internal API.
When changing the CI step name, the verify.sh header, the
CONTRIBUTING.md numeric prefix, the SECURITY.md row or
section, or the PRD commands, update the matching constant
in `verification_suite_load_smoke_static_test.go` in the
same edit. The matchers fail loudly on drift; the assertion
IS the contract.

## Verification suite: chaos tests for Dokploy timeouts (BE-0393)

`verification_suite_chaos_dokploy_timeouts_static_test.go`
pins the chaos-timeout gate. It is the load-bearing static
defence for the contract between Yalla's typed Dokploy
client and every operator, AI agent, audit reviewer, or
upstream retry surface that consumes a Dokploy-timeout
failure: every chaos-timeout failure surfaces as a
`*yerr.Error` with `Code=yerr.CodeTimeout` attributed to
`apierr.DependencyDokploy`, the caller's
`telemetry.HeaderRequestID` propagates into every recorded
attempt, the per-attempt timeout fires inside the bounded
retry budget (POST attempted exactly once; GET and DELETE
attempted 1 + `MaxRetries`), every Authorization header is
redacted to `output.Sentinel` on the wire, and no Dokploy
bearer token leaks at any level of the wrapped cause chain
even when fired by `chaosWorkers *
chaosIterationsPerWorker` concurrent goroutines per
scenario. The canonical pair
(`TestChaosDokployTimeoutsCoversCallSites` and
`TestChaosDokployTimeoutsMapsToTypedTimeoutEnvelope`) lives
in
`internal/controlplane/dokploy/chaos_dokploy_timeouts_test.go`
and binds to the PRD's `-run TestChaosDokployTimeouts`
filter. Both pair members are deterministic — they spin a
per-iteration `dokployfake.Server` up in-process and never
reach a live Dokploy server or any Postgres — because the
fake's `TimeoutFault` honours `r.Context().Done()` so each
per-attempt deadline cancels the in-flight request and the
harness finishes well under one second. The static test
pins SIX surfaces in one file: the CI
`Chaos tests for Dokploy timeouts` step
(`.github/workflows/ci.yml`), the verify.sh step #18 header
(`scripts/verify.sh`), the CONTRIBUTING.md entry #18, the
SECURITY.md row + dedicated
`## Chaos Tests For Dokploy Timeouts` section, the PRD
command in `verificationLoop.requiredBackendCommands`, and
the canonical pair file's existence with both function
declarations present. The self-check
(`TestVerificationSuiteChaosDokployTimeoutsAnalyzerDetectsRegressions`)
drives every matcher with synthetic known-good AND
known-bad fixtures so over-tightening (a legitimate change
trips the analyser) and under-tightening (a real regression
slips through) are both caught at the package-internal API.
When changing the CI step name, the verify.sh header, the
CONTRIBUTING.md numeric prefix, the SECURITY.md row or
section, or the PRD commands, update the matching constant
in `verification_suite_chaos_dokploy_timeouts_static_test.go`
in the same edit. The matchers fail loudly on drift; the
assertion IS the contract.

## Verification suite: chaos tests for Postgres disconnects (BE-0394)

`verification_suite_chaos_postgres_disconnects_static_test.go`
pins the chaos-disconnect gate. It is the load-bearing
static defence for the contract between Yalla's store layer
and every operator, AI agent, audit reviewer, or upstream
retry surface that consumes a Postgres-disconnect failure:
every chaos-disconnect failure surfaces as a `*yerr.Error`
with `Code=yerr.CodeUnavailable` attributed to
`apierr.DependencyStore` via `apierr.StoreUnavailable`, the
caller's `request_id` propagates through the per-op context,
the per-iteration `fakepg.Server` records at least one
accepted TCP connection per attempt (so a regression that
short-circuited pgx without ever attempting a network
connect trips here), the wrapped envelope's rendered
`Error()` message stays static (apierr.StoreUnavailable
MUST NOT echo any pgx cause-chain field — neither the DSN
password nor the DSN username), and no DSN password literal
leaks at any level of the wrapped cause chain even when
fired by `chaosPostgresWorkers *
chaosPostgresIterationsPerWorker` concurrent goroutines per
scenario. The canonical pair
(`TestChaosPostgresDisconnectsCoversCallSites` and
`TestChaosPostgresDisconnectsMapsToTypedUnavailableEnvelope`)
lives in
`internal/controlplane/store/chaos_postgres_disconnects_test.go`
and binds to the PRD's `-run TestChaosPostgresDisconnects`
filter. Both pair members are deterministic — they spin a
per-iteration `fakepg.Server` (a tiny in-process TCP
listener under `internal/controlplane/store/fakepg`) up and
never reach a live Postgres or any live Dokploy — because
the fake closes accepted connections gracefully (FIN, not
RST) so pgx's dial completes and the chaos error surfaces
on the startup-handshake read, the same failure mode an
actual Postgres restart or network partition produces. The
static test pins SIX surfaces in one file: the CI
`Chaos tests for Postgres disconnects` step
(`.github/workflows/ci.yml`), the verify.sh step #19 header
(`scripts/verify.sh`), the CONTRIBUTING.md entry #19, the
SECURITY.md row + dedicated
`## Chaos Tests For Postgres Disconnects` section, the PRD
command in `verificationLoop.requiredBackendCommands`, and
the canonical pair file's existence with both function
declarations present. The self-check
(`TestVerificationSuiteChaosPostgresDisconnectsAnalyzerDetectsRegressions`)
drives every matcher with synthetic known-good AND
known-bad fixtures so over-tightening (a legitimate change
trips the analyser) and under-tightening (a real regression
slips through) are both caught at the package-internal API.
When changing the CI step name, the verify.sh header, the
CONTRIBUTING.md numeric prefix, the SECURITY.md row or
section, or the PRD commands, update the matching constant
in `verification_suite_chaos_postgres_disconnects_static_test.go`
in the same edit. The matchers fail loudly on drift; the
assertion IS the contract.

## Verification suite: idempotency replay tests (BE-0395)

`verification_suite_idempotency_replay_static_test.go` pins
the idempotency-replay gate. It is the load-bearing static
defence for the contract between Yalla's HTTP idempotency
middleware and every agent, CI runner, audit reviewer, or
operator that retries an unsafe request: a second request
with the same `Idempotency-Key` and the same body replays
the original response byte-identically — same status, same
envelope bytes, with the `Idempotency-Replayed: true`
header — without re-invoking the wrapped handler, for every
outcome category the middleware records (success,
validation failure, authorization failure, not-found
failure), even under concurrent retry contention, and
without reflecting any sentinel marker from the submitted
request body into the recorded claim or the replayed
response. The canonical pair
(`TestIdempotencyReplayCoversCallSites` and
`TestIdempotencyReplayPreservesByteIdenticalEnvelope`) lives
in `internal/controlplane/httpapi/idempotency_replay_test.go`
and binds to the PRD's `-run TestIdempotencyReplay` filter.
Both pair members are deterministic — they use the
in-process `fakeIdempotencyStore` and the package-local
`recordingHandler`, so the gate stays green on every
developer machine without a live Postgres or any external
dependency. The 5xx server-failure case is deliberately
excluded from the replay closed set — the middleware
releases the claim on 5xx so a retry re-runs the handler
rather than replaying an unfinished result, and that
exclusion is pinned separately by
`TestRequireIdempotencyServerErrorIsNotRecorded` in the
same file. The static test pins SIX surfaces in one file:
the CI `Idempotency replay tests` step
(`.github/workflows/ci.yml`), the verify.sh step #20 header
(`scripts/verify.sh`), the CONTRIBUTING.md entry #20, the
SECURITY.md row + dedicated `## Idempotency Replay Tests`
section, the PRD command in
`verificationLoop.requiredBackendCommands`, and the
canonical pair file's existence with both function
declarations present. The self-check
(`TestVerificationSuiteIdempotencyReplayAnalyzerDetectsRegressions`)
drives every matcher with synthetic known-good AND
known-bad fixtures so over-tightening (a legitimate change
trips the analyser) and under-tightening (a real regression
slips through) are both caught at the package-internal API.
When changing the CI step name, the verify.sh header, the
CONTRIBUTING.md numeric prefix, the SECURITY.md row or
section, or the PRD commands, update the matching constant
in `verification_suite_idempotency_replay_static_test.go`
in the same edit. The matchers fail loudly on drift; the
assertion IS the contract.

## Verification suite: audit completeness tests (BE-0396)

`verification_suite_audit_completeness_static_test.go` pins
the audit-completeness gate. It is the load-bearing static
defence for the contract between Yalla's `audit.Auditor`
chokepoint and every operator, auditor, or incident-response
agent that reads the audit log: every security-relevant
policy decision recorded through `audit.Auditor.Record`
surfaces as a `store.AuditEvent` that carries the full
closed set of identifying fields (`Action`, `ResourceKind`,
`ResourceID`, `Decision` allowed | denied, `Reason`,
`OrganizationID`, `ActorID`, `ActorKind`, `RequestID`,
`CorrelationID`) for BOTH allowed AND denied decisions
across every canonical action surface (organization /
project / environment / service / api_key / grants / admin
break-glass), with every metadata value redacted before
persistence so a sentinel marker placed under a
sensitive-shaped key never reaches the audit log, and
under concurrent emission no event is dropped, spuriously
added, or cross-written with another emitter's fields.
The canonical pair (`TestAuditCompletenessCoversCallSites`
and `TestAuditCompletenessPreservesRecordedFieldsUnderContention`)
lives in
`internal/controlplane/audit/audit_completeness_test.go`
and binds to the PRD's `-run TestAuditCompleteness` filter.
Both pair members are deterministic — they use the
in-package `fakeRecorder` (reused from `audit_test.go` by
the coverage member) and a file-local
`concurrentAuditRecorder` (a mutex-guarded recorder used
only by the contention burst), so the gate stays green on
every developer machine without a live Postgres or any
external dependency. The static test pins SIX surfaces in
one file: the CI `Audit completeness tests` step
(`.github/workflows/ci.yml`), the verify.sh step #21 header
(`scripts/verify.sh`), the CONTRIBUTING.md entry #21, the
SECURITY.md row + dedicated `## Audit Completeness Tests`
section, the PRD command in
`verificationLoop.requiredBackendCommands`, and the
canonical pair file's existence with both function
declarations present. The self-check
(`TestVerificationSuiteAuditCompletenessAnalyzerDetectsRegressions`)
drives every matcher with synthetic known-good AND
known-bad fixtures so over-tightening (a legitimate change
trips the analyser) and under-tightening (a real regression
slips through) are both caught at the package-internal API.
When changing the CI step name, the verify.sh header, the
CONTRIBUTING.md numeric prefix, the SECURITY.md row or
section, or the PRD commands, update the matching constant
in `verification_suite_audit_completeness_static_test.go`
in the same edit. The matchers fail loudly on drift; the
assertion IS the contract.

## Verification suite: pagination stability tests (BE-0397)

`verification_suite_pagination_stability_static_test.go`
pins the pagination-stability gate. It is the load-bearing
static defence for the contract between Yalla's
`pagination.Page[T]` / `EncodeCursor` / `DecodeCursor`
chokepoint and every agent, CI runner, operator, or audit
reviewer that paginates a list endpoint: end-to-end paged
traversal MUST visit every row exactly once (no duplicates,
no drops), the cursor wire shape MUST stay opaque
(base64url, no padding, no `+`, no `/`, no `=`, no
whitespace, no embedded tenant identifier), the cursor MUST
be stable under concurrent inserts and deletes (no
duplicates across pages, no resurrection of a row already
deleted from the stream, inserts above the boundary never
appear on subsequent pages), and cross-tenant cursors MUST
NOT leak rows. The canonical pair
(`TestPaginationStabilityCoversCallSites` and
`TestPaginationStabilityPreservesPagesUnderInserts`) lives
in
`internal/controlplane/pagination/pagination_stability_test.go`
and binds to the PRD's `-run TestPaginationStability`
filter. Both pair members are deterministic — they use the
in-package `fakeStore` (declared in `page_test.go`) for the
coverage member and a file-local
`concurrentPaginationStore` (a mutex-guarded sibling of
`fakeStore`) for the contention burst, so the gate stays
green on every developer machine without a live Postgres or
any external dependency. The static test pins SIX surfaces
in one file: the CI `Pagination stability tests` step
(`.github/workflows/ci.yml`), the verify.sh step #22 header
(`scripts/verify.sh`), the CONTRIBUTING.md entry #22, the
SECURITY.md row + dedicated `## Pagination Stability Tests`
section, the PRD command in
`verificationLoop.requiredBackendCommands`, and the
canonical pair file's existence with both function
declarations present. The self-check
(`TestVerificationSuitePaginationStabilityAnalyzerDetectsRegressions`)
drives every matcher with synthetic known-good AND
known-bad fixtures so over-tightening (a legitimate change
trips the analyser) and under-tightening (a real regression
slips through) are both caught at the package-internal API.
When changing the CI step name, the verify.sh header, the
CONTRIBUTING.md numeric prefix, the SECURITY.md row or
section, or the PRD commands, update the matching constant
in `verification_suite_pagination_stability_static_test.go`
in the same edit. The matchers fail loudly on drift; the
assertion IS the contract.

## Verification suite: tenant isolation tests (BE-0398)

`verification_suite_tenant_isolation_static_test.go` pins
the tenant-isolation gate. It is the load-bearing static
defence for the contract between Yalla's `policy.Engine`
chokepoint and every agent, CI runner, operator, or audit
reviewer that touches an authenticated endpoint: for every
built-in role × every catalogued `policy.Action` against a
cross-tenant resource, the engine's verdict MUST match the
documented cross-tenant ordering — `CapSelf` →
`ReasonAllowedSelf`, support role's `CapSupport` on
`CapRead`/`CapSupport` → `ReasonAllowedBySupport`,
everything else → `ReasonDeniedCrossTenant` — AND the three
short-circuit guards (`ReasonDeniedNoPrincipal`,
`ReasonDeniedPrincipalDisabled`,
`ReasonDeniedUnknownAction`) MUST precede the cross-tenant
check, AND a scoped `Grant` whose `Scope.OrganizationID`
is the cross tenant MUST be silently ignored (grants never
bridge tenants). The canonical pair
(`TestTenantIsolationCoversCallSites` and
`TestTenantIsolationPreservesScopeUnderContention`) lives
in `internal/controlplane/policy/tenant_isolation_test.go`
and binds to the PRD's `-run TestTenantIsolation` filter.
Both pair members are deterministic — they construct an
in-process `policy.Engine` via `NewEngine()` from the
package's default action catalog, build principals and
resources from constant tenant ids (`orgA`, `orgB`), and
the contention burst fires
`tenantIsolationWorkers * tenantIsolationIterationsPerWorker`
goroutines against a single shared engine with each
goroutine asserting its OWN tuple's predicted verdict, so
the gate stays green on every developer machine without a
live Postgres or any external dependency. The static test
pins SIX surfaces in one file: the CI `Tenant isolation
tests` step (`.github/workflows/ci.yml`), the verify.sh
step #23 header (`scripts/verify.sh`), the CONTRIBUTING.md
entry #23, the SECURITY.md row + dedicated
`## Tenant Isolation Tests` section, the PRD command in
`verificationLoop.requiredBackendCommands`, and the
canonical pair file's existence with both function
declarations present. The self-check
(`TestVerificationSuiteTenantIsolationAnalyzerDetectsRegressions`)
drives every matcher with synthetic known-good AND
known-bad fixtures so over-tightening (a legitimate change
trips the analyser) and under-tightening (a real regression
slips through) are both caught at the package-internal API.
When changing the CI step name, the verify.sh header, the
CONTRIBUTING.md numeric prefix, the SECURITY.md row or
section, or the PRD commands, update the matching constant
in `verification_suite_tenant_isolation_static_test.go` in
the same edit. The matchers fail loudly on drift; the
assertion IS the contract.

## Verification suite: backup and restore rehearsal tests (BE-0399)

`verification_suite_backup_restore_static_test.go` pins the
backup and restore rehearsal gate. It is the load-bearing
static defence for the contract between Yalla's
`backup.FileReporter` chokepoint and every agent, CI
runner, operator, or audit reviewer that touches the
unauthenticated `GET /healthz/backup` probe: every
documented reporter state — pristine post-restore with
`ErrNoBackupRecorded`, fresh, on-`MaxAge` boundary, stale,
zero-`MaxAge` opt-out, clock-skew clamp to `Age=0`,
whitespace-tolerant parse, empty, whitespace-only,
malformed, secret-seeded with the parse error stripped of
the seeded marker, `Unconfigured()` zero-state, cancelled
context — MUST yield the predicted `(Status, error)` pair,
and every typed `yerr.CodeServer` error MUST name the
status file path without echoing the file's content. The
canonical pair (`TestBackupRestoreRehearsalCoversCallSites`
and
`TestBackupRestoreRehearsalPreservesContractUnderContention`)
lives in
`internal/controlplane/backup/backup_restore_rehearsal_test.go`
and binds to the PRD's `-run TestBackupRestoreRehearsal`
filter. Both pair members are deterministic — they
construct `FileReporter` instances against
`t.TempDir`-backed fixtures with injected clocks, share
each reporter across burst goroutines, and the contention
burst fires
`rehearsalWorkers * rehearsalIterationsPerWorker`
goroutines against a single reporter per scenario with each
goroutine asserting its OWN fixture's predicate, so the
gate stays green on every developer machine without a live
Postgres or any external dependency. The static test pins
SIX surfaces in one file: the CI `Backup restore rehearsal
tests` step (`.github/workflows/ci.yml`), the verify.sh
step #24 header (`scripts/verify.sh`), the CONTRIBUTING.md
entry #24, the SECURITY.md row + dedicated
`## Backup Restore Rehearsal Tests` section, the PRD
command in `verificationLoop.requiredBackendCommands`, and
the canonical pair file's existence with both function
declarations present. The self-check
(`TestVerificationSuiteBackupRestoreAnalyzerDetectsRegressions`)
drives every matcher with synthetic known-good AND
known-bad fixtures so over-tightening (a legitimate change
trips the analyser) and under-tightening (a real regression
slips through) are both caught at the package-internal API.
When changing the CI step name, the verify.sh header, the
CONTRIBUTING.md numeric prefix, the SECURITY.md row or
section, or the PRD commands, update the matching constant
in `verification_suite_backup_restore_static_test.go` in
the same edit. The matchers fail loudly on drift; the
assertion IS the contract.
