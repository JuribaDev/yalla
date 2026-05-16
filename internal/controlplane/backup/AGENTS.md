# backup

Central authority for reporting Yalla Control Plane database backup status to
the HTTP API. The package is a leaf: it depends only on the standard library
and `internal/errors`, so its predicates are cheap to call from anywhere — the
unauthenticated `/healthz/backup` handler today, and any future operator-
facing surface tomorrow.

## Boundary

- `backup` defines a `Status` value, a `Reporter` interface, a `FileReporter`
  that parses the operator's status file, and an `Unconfigured()` reporter
  for processes that have not wired the backup-status path.
- `backup` reads exactly one file — the path supplied at construction. It
  never writes the file, never invokes `pg_dump`, never opens a database
  connection, never calls a cloud-storage API, and never logs the file
  content.
- `backup` never imports `store`, `httpapi`, `worker`, `dokploy`, `apierr`,
  or `audit`. The package is a leaf — callers depend on it; it depends on no
  Yalla code beyond `internal/errors`.

## Conventions

- The status file format is intentionally trivial: a single RFC3339
  timestamp on the first line, optionally with surrounding whitespace. A
  trailing newline is permitted. Anything else is a parse error.
- Parse errors are wrapped with `yerr.CodeServer` and name the configured
  path. They never echo the file's content, so a status file accidentally
  seeded with a secret cannot leak through an error string. The
  `TestFileReporterParseErrorRedactsContent` test pins that invariant.
- A missing status file is reported as a sentinel `ErrNoBackupRecorded`
  rather than a generic I/O error. Callers — primarily the HTTP probe —
  match on the sentinel to render a "no backup yet" message instead of a
  500.
- `Status.MaxAge` is treated as opt-in. A zero MaxAge disables the freshness
  predicate: `Status.Fresh()` returns true unconditionally so a probe that
  ships before the operator picks a threshold does not flap.
- `Reporter.Status(ctx)` accepts a context so the file read can be cancelled
  by a shutting-down request. The current `FileReporter` uses a plain
  `os.ReadFile`, which is non-blocking enough on a small status file that
  the context cancellation only matters in pathological cases; the
  interface keeps the seam in place for future remote reporters.

## Wiring

- HTTP handlers receive a `Reporter` rather than the concrete `FileReporter`
  so a process with no backup integration can pass `Unconfigured()`. Tests
  pass `Unconfigured()` by default and swap in a fake for the dedicated
  backup-health tests.
- The `cmd/yalla-api` binary picks between `Unconfigured()` and a
  `FileReporter` at startup based on `Config.BackupStatusFile`. The
  `Config.BackupMaxAge` flows into `FileReporter.MaxAge` so operators control
  the freshness threshold per profile.
- The `httpapi.NewHandler` signature carries the Reporter as a positional
  port; passing `nil` is permitted and is treated identically to
  `Unconfigured()`. The test guard `TestBackupHealthHandler` covers both
  the nil and `Unconfigured` paths.
