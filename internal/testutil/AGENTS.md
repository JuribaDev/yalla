# internal/testutil

Shared verification harness for the yalla CLI. Every command, API, and contract test should reach for the helpers here before rolling its own.

- `Run(t, opts, args...)` and `RunArgs(t, args...)` drive the production exit-code path through `cli.ExecuteForTest`. The returned `RunResult{Stdout, Stderr, Exit}` matches what the binary prints; tests must NEVER call `cli.NewRootCommand` + `cmd.Execute` themselves — they would lose the typed-error banner and exit-code mapping.
- `IsolateEnv(t)` clears every `YALLA_*` env var. Call it from any test that touches config, output, or the renderer. `WriteTempConfig(t, contents)` seeds a per-test config file and exports `$YALLA_CONFIG`.
- JSON envelope assertions: `DecodeSuccess`/`DecodeSuccessInto` for `yalla.output.v1`, `DecodeError`/`AssertExitForCode` for `yalla.error.v1`. They check `schema_version` automatically — that contract is part of the public API.
- `AssertStdoutEmpty`, `AssertStderrEmpty`, `AssertStderrContains`, and `AssertNotContains` enforce the stdout-is-data-only and redaction contracts. `AssertNotContains(t, output, token)` is the secret-leak regression net for every command that handles auth.
- `Golden(t, name, got, opts)` and `GoldenJSON(t, name, got, normalisers...)` write to `testdata/<name>.golden`. Run `go test -update-golden ./...` to regenerate. Use `DefaultJSONNormalizers()` for any envelope that surfaces request ids, trace ids, durations, or timestamps so goldens stay deterministic across runs.
- HTTP fixtures: `NewServer(t, handler)` is the everyday Dokploy stand-in (sets `YALLA_BASE_URL` and `YALLA_TOKEN`); `RecordingServer(t, handler)` adds a request log so contract tests can assert exactly what was sent. `RoundTripperFunc` is the bypass for transport-level error injection.
- `LookupOperation(t, opID)` resolves an OpenAPI operation from `api.Default()` and fails the test with a hint when the id is missing — the canonical entry point for API operation contract tests.
- The harness uses `testing.TB` so helpers work from `*testing.T` and `*testing.B` alike. Helpers that mutate process-global state (`t.Setenv`, `t.TempDir`) check the runtime type and fail loudly if a custom `TB` is passed.

## Don't

- Don't import `internal/testutil` from non-test code — it is for `_test.go` only and uses test-only flags.
- Don't import `internal/testutil` from `package cli` test files (they live in the same module subtree as cli.ExecuteForTest's caller). Use the local helpers (`runRootArgs`, `runExecuteWith`) inside `internal/cli`; testutil is for external test packages.
- Don't write directly to `testdata/`. Always go through `Golden`/`GoldenJSON` so `-update-golden` keeps working.
- Don't bypass `IsolateEnv` in tests that touch config or the renderer. A developer with `YALLA_TOKEN` exported in their shell will otherwise see flaky tests and occasionally a real token in a buffer.
