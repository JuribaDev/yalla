# internal/release

Source of truth for the public distribution matrix.

- `SupportedTargets`, `ArchiveExt`, `BinaryName`, `ArchiveName`, and
  `ChecksumsName` are **public API** for downstream tooling: the npm wrapper
  uses the same archive naming, future US-0010 (channel-aware upgrade) reads
  these to map a download to a target. Renaming or reordering values is a
  breaking change.
- The tests in this package validate `.goreleaser.yaml`, the npm wrapper
  files under `npm/`, and the GitHub Actions workflows together. They are
  the only place that holds GoReleaser, GoReleaser archive naming, and the
  npm wrapper to a single contract.
- Tests walk up to `go.mod` to find the project root rather than hard-coding
  `../..`. Keep that helper if the package ever moves.
- Do **not** depend on a real `goreleaser` binary from this package — the
  CI workflow runs `goreleaser check` separately. Everything here must work
  with the standard Go toolchain only.
