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
| TLS and proxy header trust | `go test ./internal/release/... -run TestHTTPServerHardening` | CI `test` job, `scripts/verify.sh` | Every push and PR |
| Admin endpoint isolation | `go test ./internal/release/... -run TestAdminEndpointIsolation` | CI `test` job, `scripts/verify.sh` | Every push and PR |
| Support access review | `go test ./internal/release/... -run TestSupportAccessReview` | CI `test` job, `scripts/verify.sh` | Every push and PR |
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

## Disclosure Timeline (Best Effort)

1. **Day 0** — report received, acknowledgement sent.
2. **Day 1–7** — triage, severity assessment, reproduction.
3. **Day 7–30** — fix authored, embargoed PR prepared, advisory
   drafted on GitHub Security Advisories.
4. **Release day** — patched binary released, advisory published,
   reporter credited (unless they ask otherwise).
