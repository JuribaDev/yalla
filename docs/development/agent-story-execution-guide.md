# Yalla Control Plane agent story execution guide

This guide documents how autonomous coding agents execute backend user stories
for the Yalla Control Plane. It is intended for AI agents and human operators
who need to understand the exact execution contract.

## Scope

The execution flow remains:

```text
Agent reads ralph/prd.json and ralph/progress.txt
  -> checks out branch codex/yalla-control-plane-backend
  -> implements ONE highest-priority story where passes: false
  -> runs quality checks
  -> updates ralph/prd.json (passes: true) and ralph/progress.txt
  -> commits with conventional-commit message
```

Agents work on one story per iteration, commit frequently, and never skip
verification.

## Required environment

Normal story execution uses local or isolated test infrastructure. Use redacted
placeholders in notes and command transcripts:

```bash
YALLA_DATABASE_URL=<redacted:YALLA_DATABASE_URL>
YALLA_DOKPLOY_BASE_URL=<redacted:YALLA_DOKPLOY_BASE_URL>
YALLA_DOKPLOY_TOKEN=<redacted:YALLA_DOKPLOY_TOKEN>
```

Do not paste resolved values. If a focused integration suite needs Postgres,
start only the local dependency stack and keep the database isolated from
production:

```bash
docker compose up -d postgres
```

Normal story execution must never require a live Dokploy server. The external
smoke test is opt-in, non-production only, and must never run against production:

```bash
YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...
```

## Story picking workflow

1. Read `ralph/prd.json` to identify the project, branch name, and user stories.
2. Read `ralph/progress.txt` to learn codebase patterns and prior learnings.
3. Check the current git branch; switch to `codex/yalla-control-plane-backend`
   if needed.
4. Select the highest-priority backend story where `passes: false`.
5. Implement that single story end to end.

## Required quality checks

Before every commit, run the full required gate from the repository root:

```bash
gofmt -w .
goimports -w .        # optional; skip if not installed
go mod tidy
go test ./...
go test -race ./...
go vet ./...
```

Backend stories that touch persistence, migrations, jobs, quota, policy, or
worker behavior must also run the focused backend suites:

```bash
go test ./internal/controlplane/...
go test -race ./internal/controlplane/...
go test -run TestMigrations ./...
go test -run TestPolicyMatrix ./...
go test -run TestQuotaConcurrency ./...
go test -run TestFakeDokploy ./...
```

When configured, also run:

```bash
golangci-lint run ./...
staticcheck ./...
govulncheck ./...
```

The `scripts/verify.sh` script automates the required gate and reports missing
optional tools explicitly rather than skipping them silently.

Expected output for healthy runs:

```text
ok      github.com/juribadev/yalla/internal/controlplane/...    1.234s
ok      github.com/juribadev/yalla/internal/controlplane/store/...    2.345s
ok      github.com/juribadev/yalla/internal/controlplane/httpapi/...  0.567s
PASS
ok      github.com/juribadev/yalla/internal/release/...    0.123s
```

## Commit convention

Use conventional commits scoped to the affected module:

```text
feat(controlplane): [BE-0001] - Create backend Go module layout
feat(auth): [BE-0015] - Implement API key hashing and lookup
feat(policy): [BE-0018] - Implement RBAC and scoped grants engine
```

## PRD and progress updates

After a story passes all checks:

1. Update `ralph/prd.json` so the completed story has `"passes": true`.
2. Append a progress entry to `ralph/progress.txt` with:
   - What was implemented
   - Files changed
   - Verification run and results
   - Remaining risks or follow-ups
   - Learnings for future iterations

## Contract checks

Confirm public API behavior stays stable and agent-friendly. Every endpoint
must demonstrate success, validation failure, authorization failure, and
not-found behavior in tests:

- Success responses use `schema_version: yalla.output.v1`.
- Error responses use `schema_version: yalla.error.v1`.
- Every response, log record, audit record, and request-created job carries a
  `request_id`.
- stable error codes are used for every failure path.
- All endpoints map to a required action constant.
- tenant isolation is enforced for every customer-data query.
- quota checks are transactional with desired-state writes.
- Jobs are idempotent and retry-safe.
- Audit events exist for mutations and denials.
- Secrets are redacted in every log line, error, and test output.

## Safety rules

- Never expose broad Dokploy raw API access through customer-facing endpoints.
- Never give customers Dokploy API tokens.
- Never skip auth, policy, quota, audit, or idempotency before mutating state.
- Never print secrets, tokens, database URLs, or rendered environment values in
  logs, errors, audit metadata, tests, or dry-run output. Service logs must never contain tokens, cookies, API keys, database URLs,
  Dokploy tokens, or rendered environment values. Logs, errors, audit metadata, tests, and dry-run output must never contain
  tokens, cookies, API keys, database URLs, Dokploy tokens, or rendered
  environment values.
- Never let cross-tenant IDs reveal data from another organization.
- Never mutate Dokploy before Yalla auth, policy, quota, desired-state write,
  idempotency, and audit requirements are satisfied.
- Build fake Dokploy fixtures for normal tests; live Dokploy smoke tests are
  opt-in only.

## Failure recovery

The following failure recovery guidance helps agents recover from common
verification or infrastructure problems:

- If `go test ./...` fails, read the failure, fix the code, and re-run.
- If migrations fail, check `docker compose logs postgres` and ensure the
  database is reachable with the correct `YALLA_DATABASE_URL`.
- If race detector fails, inspect shared state in handlers or repositories and
  add synchronization.
- If `goimports` is not installed, document the skip in `ralph/progress.txt`.
- If `golangci-lint`, `staticcheck`, or `govulncheck` are not installed,
  document the skip explicitly; never skip verification silently.
- If a story is interrupted by a runner timeout, the next run picks the first
  unfinished story from `ralph/prd.json` automatically.
