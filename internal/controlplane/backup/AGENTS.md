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

## Backup encryption boundary (BE-0362)

The package is the Yalla-side terminator of an external encryption
boundary: the operator's pipeline encrypts every backup object under a
KMS-managed key and writes the encrypted blob to storage neither the
control-plane API nor the worker has read access to. The Yalla process
consumes exactly one signal — a single RFC3339 timestamp at
`YALLA_BACKUP_STATUS_FILE`. The boundary is pinned by
`internal/release/backup_encryption_static_test.go` and the runtime
fixtures in `encryption_isolation_test.go`. Two rules are load-bearing
for anyone editing this package:

- **No backup data plane.** Never add an import from the forbidden
  set (`crypto/aes`, `crypto/cipher`, `archive/zip`, `compress/gzip`,
  `database/sql`, `github.com/jackc/pgx/v5`, `os/exec`, `net/http`,
  …). Never add a write seam (`os.Create`, `os.WriteFile`,
  `os.OpenFile`, `exec.Command`, …) — `os.ReadFile` against the
  operator-supplied path is the only legitimate I/O. The static gate
  in `internal/release/` rejects every other shape at build time, so
  a regression fails CI before review.
- **`Reporter` exposes one method.** The `Reporter` interface MUST
  remain `Status(ctx) (Status, error)` — adding a `Write`, `Backup`,
  `Restore`, `Encrypt`, or `Upload` method would route a backup data
  plane through the read-only port and is rejected by the static
  gate. If a future story needs a second port (e.g. a "report
  freshness" predicate already on `Status.Fresh()`), add a separate
  interface in this package; do not widen `Reporter`.

When adding an encryption-shaped fixture to
`encryption_isolation_test.go`, prefix the content with the
`BE0362KMSMARKERXYZ` marker so the leak detector remains anchored on
the marker rather than on per-fixture bytes — the marker is the
load-bearing assertion across fuzzed input shapes.
