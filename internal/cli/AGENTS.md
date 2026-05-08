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

## Tests

- `TestMain` in `main_test.go` unsets every `YALLA_*` env var and pins
  `envSnapshotForRenderer` to an empty snapshot. New tests must NOT rely on
  the host shell's environment leaking through.
- Tests that mutate the env via `t.Setenv` cannot use `t.Parallel`. Use the
  `withTempConfig` helper to seed a writable `YALLA_CONFIG` per test.
- For end-to-end command assertions use `runRootArgs(t, args...)`. It runs
  `buildRoot` + `cmd.Execute()` + `renderTerminalError` so the captured
  stderr matches what the binary prints in production.
