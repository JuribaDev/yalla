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
