# internal/cli

Conventions for the Cobra command tree.

- `NewRootCommand(streams, build)` is the only constructor; never reach for
  package-level globals. Keep all command construction injectable so tests can
  drive it with in-memory buffers.
- Cobra's own writers (`SetOut`, `SetErr`) are routed to **stderr** so help,
  usage, error banners, and `--version` output never violate the
  stdout-is-data-only contract. Subcommands emit data through
  `IOStreamsFromContext(cmd.Context()).Out`.
- Flags shared across the tree live as persistent flags on the root command and
  are mirrored into `GlobalFlags` via `PersistentPreRunE`. Subcommands read
  them via `GlobalFlagsFromContext(cmd.Context())`.
- New global flags must update `internal/cli/root_test.go::TestRoot_RegistersAllRequiredGlobalFlags`.
- Set `SilenceErrors` and `SilenceUsage` on every command so error rendering
  stays under the control of the typed error layer.
- Top-level error rendering lives in `error_render.go` and is the **only**
  place a top-level cobra failure should be printed. Subcommands return
  `*errors.Error` from `internal/errors` so `renderTerminalError` can map
  the stable Code to its exit code and JSON envelope automatically.
- `executeWith(streams, build)` is the testable seam behind `Execute`. Tests
  drive it with `*bytes.Buffer` streams to assert exit codes, JSON envelopes
  (`yalla.error.v1`), and stdout silence on failure.
- All command output (data, logs, errors) must flow through
  `internal/output.Renderer`. Never write directly to `cmd.OutOrStderr()`,
  `cmd.OutOrStdout()`, or `os.Stdout` — that bypasses the `yalla.output.v1`
  envelope and the secret redactor.
- `buildRoot` returns `(*cobra.Command, *GlobalFlags)`. The flags pointer is
  consumed only by the renderer so it can read `--json` and `--token` even
  when cobra returns an error before `PersistentPreRunE` populates the
  context.

## Configuration (US-0003)

- `PersistentPreRunE` calls `internal/config.Loader.Load` exactly once and
  stashes the resolved `*config.Config` on the command context via
  `config.WithConfig`. Subcommands read it via `config.FromContext(ctx)`.
  **Never** call `Loader.Load` from inside a subcommand `RunE` — the
  precedence chain (CLI flag > env > file > default) lives in one place.
- The resolved values are also mirrored back into `*GlobalFlags` so the
  parse-time error renderer (which only has the flag pointer) honours
  env-var-only `--json` mode and redacts tokens supplied via env or file.
- The error renderer's env fallback runs through
  `envSnapshotForRenderer`. Tests **must** override this variable (the
  `main_test.go` `TestMain` resets it to a deterministic empty snapshot)
  before asserting on JSON-mode behaviour.
- New env vars in the public agent contract belong in
  `internal/config/config.go` (`EnvBaseURL`, `EnvToken`, `EnvConfig`,
  `EnvOutput`, `EnvNoInput`). Adding one is a minor change; renaming or
  removing one is major.
- Subcommands construct their `output.Renderer` via `rendererFromContext`
  to inherit JSON mode + the secret redactor seeded from the resolved
  token. Hand-rolling a `Renderer` in a `RunE` skips the redactor and is a
  contract violation.
- `--no-input` is a global flag and is *not* enforced centrally: every
  command that might prompt has to read `cfg.NoInput` itself and return
  `*errors.Error{Code: errors.CodeNoInput}` before consulting stdin. The
  current commands (`config`, `auth`) never prompt, so they ignore the flag
  by construction.

## API & schema commands (US-0004)

- `yalla api` and `yalla schema` are read-only inspection trees backed by
  the Yalla Control Plane `/openapi.json` endpoint. They must fetch the
  backend OpenAPI document with `Authorization: Bearer <token>` and must
  never fall back to the embedded Dokploy OpenAPI registry as the public CLI
  command contract.
- Operations and schemas are emitted in **operationId-sorted** order. Any
  command that needs a different order (e.g. group-by-tag) must build its
  own slice from `Registry.Operations()` rather than mutate the registry.
- Unknown `--tag` values map to `errors.CodeInvalidInput`; unknown
  operationIds in `schema get <op>` map to `errors.CodeNotFound`. The two
  codes diverge so scripts can distinguish "user mistyped a filter" (exit
  2) from "operation removed upstream" (exit 5).
- The JSON envelope for `api operations`, `schema list`, and `schema get`
  always includes `spec_title`, `spec_version`, and `spec_sha256` so an
  agent can verify which backend API document was used without a separate
  `--version` round trip.
- Schema bodies (`json.RawMessage`) are emitted verbatim. Do **not**
  re-serialize through `interface{}` — that breaks the canonical key order
  and silently reflows numeric precision.

## Raw API executor (US-0005)

- `yalla api call <operationId>` is no longer a normal-user raw Dokploy
  executor. It must return `E_UNSUPPORTED` unless a future backend-mediated,
  admin-only, audited diagnostic route is explicitly added.
- Normal commands must call product routes on the Yalla backend through
  `newYallaAPIClient` / `yallaJSONRequest`, using bearer auth and backend
  envelopes. They must not send `x-api-key` or construct Dokploy operation
  requests in `internal/cli`.
- HTTP status mapping for backend calls flows through `yallaResultError`
  after unwrapping backend error envelopes. Keep stdout for successful data
  and stderr for typed errors.

## Manifest, docs, and completion (US-0007)

- `yalla manifest`, `yalla docs`, and `yalla completion` are introspection
  commands: they read the live `*cobra.Command` tree. The manifest
  deliberately does not expose the embedded Dokploy operation registry; use
  `yalla api operations` and `yalla schema get` for runtime backend OpenAPI
  discovery.
- The manifest's inner payload carries its own `manifest_schema`
  (`yalla.manifest.v1`) **inside** the standard `yalla.output.v1`
  envelope. Bumping either constant is a public-API change.
- `collectCommandTree` and `collectFlagSet` are the canonical projections
  for any command/flag introspection; reuse them rather than re-walking
  pflag yourself. Both are deterministic (alphabetical) so JSON diffs
  stay clean across yalla versions.
- `isInternalCobraCmd` filters Cobra's auto-added `help` and
  `__complete*` helpers out of every introspection surface (manifest,
  docs, future tooling). The auto-added `completion` is suppressed
  earlier via `cmd.CompletionOptions.DisableDefaultCmd = true` in
  `buildRoot`; do **not** re-enable it without coordinating with
  `newCompletionCommand()`.
- `yalla docs markdown` writes either to `--output-dir` (one file per
  command, file names join the path with underscores) or to stdout (a
  single combined document). With `--json` the file-output path emits
  the file list and the stdout path wraps the combined Markdown in the
  envelope's `data.content` field. The stdout-human path writes
  Markdown through `Renderer.Human` (so the redactor still scrubs any
  accidental token reference); per-file writes go through `os.WriteFile`
  with mode `0o644` because the tree is meant to be world-readable.
- `yalla completion <shell>` reuses Cobra's built-in generators
  (`GenBashCompletionV2`, `GenZshCompletion`, `GenFishCompletion`,
  `GenPowerShellCompletionWithDesc`). Adding a new shell means
  appending to `supportedShells` AND extending `generateCompletion`;
  the manifest test (`TestManifest_JSONListsAllSubcommands`) will fail
  if the two diverge.
- The completion script is the one and only place outside the redactor
  that writes raw bytes to `Renderer.Out()` in human mode. Shell scripts
  cannot tolerate substring substitution and yalla never embeds tokens
  in generated completions, so the redaction bypass is sound.
- Adding any new top-level command requires updating the
  `wantTopLevel` slice in `TestManifest_JSONListsAllSubcommands` so
  the manifest contract stays explicit (the same friction as
  `TestRoot_RegistersAllRequiredGlobalFlags` for global flags).

## Channel-aware upgrade (US-0010)

- `yalla upgrade` is the only command that imports `internal/upgrade`,
  and the only place that may write to the on-disk yalla binary. Keep
  it that way: every other subcommand should `import` neither the
  package nor the seam vars, so "never auto-update silently during
  normal commands" is an architectural property rather than a runtime
  flag.
- The HTTP test seams — `upgradeCheckBaseURL`,
  `upgradeApplyArchiveURL`, `upgradeApplyChecksums`,
  `upgradeProbeFactory`, and the two `*ClientFactory` vars — are
  upgrade-specific. Tests override them via `t.Cleanup` so production
  code stays free of branch-on-tests conditionals.
- `--yes` is gated to `ChannelManual`. Every other channel returns
  `*errors.Error{Code: CodeUnsupported}` (exit 10) with a hint that
  names the package-manager command. Loosening the gate would violate
  the PRD's "self-update is allowed only for unmanaged/manual
  binaries" contract.
- Adding a new top-level command (today: upgrade) requires updating
  `wantTopLevel` in
  `manifest_cmd_test.go::TestManifest_JSONListsAllSubcommands`; the
  test is intentionally explicit so a forgotten registration trips the
  manifest contract before it ships.
- Curated commands (US-0012) MUST be declared in
  `internal/curated`'s `defaultCommands` slice with a non-empty
  `OperationIDs` list before the Cobra command is wired here. The
  manifest payload (`curated_commands`) reads from
  `curated.Default()`; `runManifest` takes the registry as a parameter
  so tests can drive a custom catalogue without touching the global.
  Curated commands never replace raw API coverage — `yalla api call`
  is unsupported for normal users, while `yalla schema get` stays available
  for backend operations discovered from `/openapi.json`.

## Tests

- `TestMain` in `main_test.go` unsets every `YALLA_*` env var and pins
  `envSnapshotForRenderer` to an empty snapshot. New tests must NOT rely on
  the host shell's environment leaking through.
- Tests that mutate the env via `t.Setenv` cannot use `t.Parallel`. Use the
  `withTempConfig` helper to seed a writable `YALLA_CONFIG` per test.
- For end-to-end command assertions use `runRootArgs(t, args...)`. It runs
  `buildRoot` + `cmd.Execute()` + `renderTerminalError` so the captured
  stderr matches what the binary prints in production.

## Backend-Only Coverage

- `backend_only_contract_test.go` is the guardrail for the normal CLI
  surface. Add cases there when a command is migrated to a backend route, and
  assert exact method/path/body plus bearer auth with no `x-api-key`.
- `backend_api_worker_integration_test.go` is the Postgres-backed
  CLI → API → durable job → worker/fake-Dokploy regression. Extend it when a
  new command needs end-to-end proof that the CLI only talks to the backend
  while Dokploy mutation is executed by the worker path.
