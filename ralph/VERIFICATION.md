# Yalla Verification Loops

This document defines the verification commands Ralph (and humans) run before every commit. The harness backing every test lives in `internal/testutil`; see that package's `AGENTS.md` for the helper API.

## Two loops

### Focused loop — while editing one story

Use this on every save while iterating on a single user story. It is the fastest cycle that still catches regressions in the touched files.

```bash
# Format the touched files (not the whole tree).
gofmt -w .

# Run only the package(s) you edited. Replace ./internal/cli with the
# package path that matches your work.
go test ./internal/cli/...

# Run vet against the same package set.
go vet ./internal/cli/...
```

Every command and API story should also include at least one `--json`
golden assertion (via `testutil.GoldenJSON`) so deterministic output is
locked in without hand-maintained string literals. Regenerate goldens with:

```bash
go test ./... -run TestSomeName -update-golden
```

`-update-golden` is registered by the testutil package and is recognised by every test binary that imports it.

### Full loop — before every commit

This is the contract. A commit may not land unless every step here passes.

```bash
gofmt -w .
go mod tidy
go vet ./...
go test ./...
go test -race ./...
```

If a tool is locally available, also run the optional gates:

```bash
goimports -w .
golangci-lint run ./...
staticcheck ./...
govulncheck ./...
goreleaser check
```

If a tool is **not** installed, document that in `ralph/progress.txt` for the story rather than skipping silently.

### Database-backed loop — before production readiness claims

Run this when a story changes control-plane persistence, migrations, durable
jobs, tenant isolation, quota concurrency, readiness gates, or distributed rate
limits. It requires throwaway local Postgres and Redis instances and must never
point at production:

```bash
docker compose up -d postgres
export YALLA_TEST_DATABASE_URL='postgres://yalla:yalla@127.0.0.1:5432/yalla_test?sslmode=disable'
export YALLA_TEST_REDIS_URL='redis://127.0.0.1:6379/15'
./scripts/verify.sh --with-postgres
```

The `--with-postgres` mode fails immediately when `YALLA_TEST_DATABASE_URL` or
`YALLA_TEST_REDIS_URL` is unset, then runs the full verification script plus
the database-backed control-plane checks and the Redis-backed distributed
rate-limiter check. Postgres-backed Go tests run with package parallelism
`-p 1` and test function parallelism `-parallel 1` by default so local Postgres
does not fail from connection exhaustion; set
`YALLA_POSTGRES_TEST_PARALLELISM` to a larger positive integer only when the
test database is sized for it. The Postgres phase defaults
`YALLA_POSTGRES_TEST_TIMEOUT` to `30m` because the serial store package runs
the full integration suite under the race detector:

```bash
go test -timeout 30m -p 1 -parallel 1 ./...
go test -timeout 30m -p 1 -parallel 1 -race ./internal/controlplane/...
go test -timeout 30m -p 1 -parallel 1 -run 'TestMigrations|TestQuotaConcurrency|TestTenantIsolation' ./internal/controlplane/...
go test ./internal/controlplane/ratelimit/... -run TestRedisLimiter -count=1
go vet ./...
```

## Contract assertions every command test must enforce

Every command test built on `internal/testutil` is expected to assert each of the following items that apply to the command under test:

1. **JSON validity** — `MustBeValidJSON` or `DecodeSuccess`/`DecodeError`. Single document, well-formed, correct `schema_version`.
2. **Stdout / stderr separation** — `AssertStdoutEmpty` on every error path, `AssertStderrEmpty` on every JSON-success path. Diagnostics never leak onto stdout.
3. **Exit codes** — `AssertExit` against the canonical `errors.Code.ExitCode()` value. Magic numbers are forbidden in tests; always derive from the typed code.
4. **Secret redaction** — `AssertNotContains(t, res.Stdout+res.Stderr, token)` whenever a command handles auth, with `token` set to a unique, non-trivial literal so any redactor bypass is obvious.
5. **Schema version** — `DecodeSuccess` and `DecodeError` already verify `schema_version` is `yalla.output.v1` or `yalla.error.v1` respectively; never re-check it ad hoc.
6. **Golden output** — at least one stable surface (manifest, schema get, error envelope) pinned via `GoldenJSON` with `DefaultJSONNormalizers()`.

## API operation contract tests

For every Dokploy OpenAPI operation story:

1. Use `testutil.LookupOperation(t, opID)` to resolve the operation from the embedded spec.
2. Stand up a `testutil.RecordingServer(t, handler)` and drive the request through `yalla api call <opID> --input ...` via `testutil.Run`.
3. Use `testutil.AssertOperationCalled(t, rec, opID, method, path)` to verify the wire shape matches the spec.
4. Add at least one success path (200/204) and one representative failure path (4xx → typed `errors.Code` → mapped exit code).

## Re-baseline after a public surface change

Adding a global flag, a top-level command, an error code, or an env var is a public-API change. Before commit:

1. Update the explicit registry test (`internal/cli/root_test.go::TestRoot_RegistersAllRequiredGlobalFlags`, manifest tests, error-code parity test).
2. Regenerate any affected goldens with `-update-golden` and review the diff manually.
3. Bump SemVer scope appropriately — see `ralph/prd.json` notes for what counts as breaking.
