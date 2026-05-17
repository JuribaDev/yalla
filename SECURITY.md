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

## Disclosure Timeline (Best Effort)

1. **Day 0** — report received, acknowledgement sent.
2. **Day 1–7** — triage, severity assessment, reproduction.
3. **Day 7–30** — fix authored, embargoed PR prepared, advisory
   drafted on GitHub Security Advisories.
4. **Release day** — patched binary released, advisory published,
   reporter credited (unless they ask otherwise).
