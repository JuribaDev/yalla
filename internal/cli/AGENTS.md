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
  stays under the control of the typed error layer (US-0002 onwards).
