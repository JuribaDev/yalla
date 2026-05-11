# internal/upgrade

Channel-aware self-update for yalla.

- `Detect(Probe)` is a **pure** function: no subprocesses, no filesystem
  reads, no network calls. Every dependency (binary path, GOOS, env
  lookup) is injected so tests are hermetic regardless of the host
  layout. The test matrix in `detect_test.go` is the source of truth for
  channel decisions; adding a new channel means adding a row there.
- The channel constants (`ChannelHomebrew`, `ChannelNPM`, `ChannelNPX`,
  `ChannelScoop`, `ChannelWinGet`, `ChannelManual`, `ChannelUnknown`)
  are public API: `yalla upgrade --check --json` emits the raw string.
  Renaming a value is a breaking change that must update the CLI tests
  and the docs together.
- `PlanFor(channel, binaryPath)` is the only place that maps a channel
  to a package-manager command. Every channel except `ChannelManual`
  must keep `SelfUpgradable=false`; the CLI's `--yes` path enforces
  this at runtime by returning `E_UNSUPPORTED` for non-manual
  channels. The PRD's "self-update is allowed only for unmanaged/manual
  binaries" contract lives here.
- `Check(ctx, CheckOptions)` talks to GitHub Releases via injected
  `*http.Client` and `BaseURL`. Tests **must** point at an
  `httptest.Server`; never let a unit test reach the public API.
- `ApplyManual(ctx, ApplyOptions)` is the only function that writes to
  the on-disk binary. Order is: download checksums → download archive
  → SHA-256 verify → extract → atomic rename. A checksum mismatch must
  abort before any rename so the running binary is never replaced with
  an unverified blob.
- `ParseSemVer` and `Compare` cover yalla's release tag grammar
  (`MAJOR.MINOR.PATCH[-pre][+build]`); they intentionally do **not**
  pull in an external semver dependency. Loosening the grammar (e.g.
  accepting non-numeric majors) is a public-API change.
- The package never imports `internal/cli` or `internal/config`. The
  CLI layer (`internal/cli/upgrade_cmd.go`) is the only consumer, and
  it owns translation from `*config.Config` and `BuildInfo` into
  `CheckOptions` / `ApplyOptions`.
