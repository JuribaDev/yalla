# External Live-Dokploy Smoke Test Guide

This guide documents how to run the opt-in external live-Dokploy smoke tests for
 the Yalla Control Plane backend binaries `/usr/local/bin/yalla-api` and
 `/usr/local/bin/yalla-worker`. The smoke is the only suite that reaches a real
 Dokploy server; every other Dokploy-touching test uses the in-process fake
 Dokploy server under `internal/controlplane/dokploy/dokployfake`.

Customer / Agent / CI traffic must flow through the Yalla API; customers must
never receive Dokploy API tokens or call Dokploy directly. The smoke exercises
 the typed Dokploy client through a read-only intent end-to-end against a
 disposable non-production Dokploy instance.

## Architecture boundary

```text
Customer / Agent / CI -> Yalla API -> Postgres source of truth -> provisioning worker -> private Dokploy API
```

The smoke lives at `internal/controlplane/dokploy/live_dokploy_smoke_test.go` and
 declares two load-bearing functions:

- `TestLiveDokploySmokeRespectsOptInFlag` — exercises every documented value of
  `YALLA_EXTERNAL_DOKPLOY` (unset, empty, `0`, whitespace, `false`, `1`). Only
  the canonical `1` value flips the smoke into its live path; every other value
  yields a deterministic `t.Skip`.
- `TestLiveDokploySmokeExercisesLiveEndpoint` — when the opt-in flag is set,
  constructs a real Dokploy client and exercises a read-only intent against the
  configured base URL; when unset, the live branch skips cleanly while the
  redaction-contract branch runs unconditionally.

The meta-contract that keeps the smoke discoverable and safe is pinned by
`internal/release/verification_suite_external_dokploy_smoke_static_test.go`:
 `.github/workflows/external-smoke.yml`, `scripts/verify.sh`,
 `CONTRIBUTING.md`, `SECURITY.md`, `ralph/prd.json`, and the canonical smoke
 file itself are all validated together so a regression on any single surface
 fails one test.

## Required environment variables

Export these variables before running the smoke. All values must point to a
 disposable non-production Dokploy instance.

```bash
# Opt-in flag (required)
export YALLA_EXTERNAL_DOKPLOY=1

# Dokploy instance coordinates (required when opt-in is set)
export YALLA_EXTERNAL_DOKPLOY_BASE_URL=<redacted:YALLA_EXTERNAL_DOKPLOY_BASE_URL>
export YALLA_EXTERNAL_DOKPLOY_TOKEN=<redacted:YALLA_EXTERNAL_DOKPLOY_TOKEN>

# Optional probe service for live endpoint test
export YALLA_EXTERNAL_DOKPLOY_PROBE_SERVICE=<redacted:YALLA_EXTERNAL_DOKPLOY_PROBE_SERVICE>
```

The document must never contain rendered tokens, cookies, API keys, database URLs, Dokploy tokens, or rendered environment variable values.

## Verification commands

Run the smoke locally after confirming the target is disposable and
 non-production:

```bash
YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...
```

Expected output when the opt-in flag is unset (default developer-laptop
 behaviour):

```text
ok      github.com/juribadev/yalla/internal/controlplane/dokploy 0.123s
```

The smoke `t.Skip`s cleanly so the default `go test ./...` run on every push
 and PR is green without external infrastructure.

Expected output when the opt-in flag is set and the Dokploy instance is
 reachable:

```text
ok      github.com/juribadev/yalla/internal/controlplane/dokploy 2.456s
```

A failure surfaces a typed `yerr.Error` with `request_id`, the affected Dokploy
 operation, the HTTP status, and the upstream's redacted error body. Map the
 `request_id` back to the Yalla audit log for triage.

Run the focused static checks that pin the smoke meta-contract:

```bash
go test ./internal/release/... -run TestVerificationSuiteExternalDokploySmoke
```

Run the commit gate before marking any smoke-related change complete:

```bash
gofmt -w .
goimports -w .
go mod tidy
go test ./...
go test -race ./...
go vet ./...
scripts/verify.sh
```

If `goimports` is not installed, document that in `ralph/progress.txt` and still
 run the rest of the required checks.

## CI gating cadence

The dedicated workflow `.github/workflows/external-smoke.yml` runs the smoke:

- On `workflow_dispatch` — operators run on demand.
- On a nightly `schedule` — the smoke runs every night at 03:13 UTC when
  repository secrets are configured.

The workflow is deliberately separate from `.github/workflows/ci.yml` so the
 default push/PR run can never reach a real Dokploy host by accident.

## Contracts and safety checklist

Every smoke run must preserve these contracts:

- **Deterministic skip default.** Running `go test -run TestLiveDokploySmoke ./...`
  without `YALLA_EXTERNAL_DOKPLOY=1` is a green PASS, not a failure.
- **Opt-in only.** The smoke must never run against production. Use a disposable
  Dokploy instance with throwaway resources and credentials.
- **Actionable failures.** Every error path surfaces a typed `*yerr.Error` from
  the Dokploy client with `request_id` and `resource_id` for audit-log joins.
- **Stable envelopes preserved.** The smoke pins the property that Dokploy
  client typed errors flow into the upstream `schema_version: yalla.error.v1` shape unchanged.
- **Redaction contract.** The Dokploy client's `Redactor` strips the authorization token
  from every error surface. Secrets, tokens, API keys, cookies, and rendered
  environment variable values are redacted in every log line, error string, and
  test-output fixture.
- **No mutation of live state.** The canonical smoke uses a read-only intent.
  When adding new live tests, keep them read-only unless explicitly designed for
  a mutable teardown path.

## Failure recovery

Use these recovery steps when the smoke fails or behaves unexpectedly:

1. Confirm the opt-in was intentional and the target is disposable:

   ```bash
   echo "YALLA_EXTERNAL_DOKPLOY=$YALLA_EXTERNAL_DOKPLOY"
   echo "YALLA_EXTERNAL_DOKPLOY_BASE_URL=$YALLA_EXTERNAL_DOKPLOY_BASE_URL"
   ```

   Do not echo the token. Verify the base URL points at a non-production host.

2. If the smoke skips when it should run, check the opt-in flag value:

   ```bash
   export YALLA_EXTERNAL_DOKPLOY=1
   ```

   Only the exact value `1` enables the live path.

3. If the smoke fails with a Dokploy connection error, verify the base URL and
   network path. The typed error names the missing or unreachable variable
   without echoing any token.

4. If the smoke fails with a redaction assertion, inspect
   `internal/controlplane/dokploy/live_dokploy_smoke_test.go` and the Dokploy
   client's `Redactor` first. Do not print raw headers, bodies, tokens, or
   credentials while debugging.

5. If a meta-contract static test fails, inspect
   `internal/release/verification_suite_external_dokploy_smoke_static_test.go`
   to identify which surface drifted (CI workflow, verify.sh, CONTRIBUTING,
   SECURITY.md, PRD, or the canonical smoke file).

6. Normal verification gates must never require a live Dokploy server. Default
   CI and local commit gates should remain on fake Dokploy only.

7. For additional failure recovery guidance, consult the fake-Dokploy usage
   guide at `docs/development/fake-dokploy-usage.md`.
