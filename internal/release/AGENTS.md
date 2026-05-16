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
