// Package backup is the central authority for reporting the operational
// state of the Yalla Control Plane database backup process. It is a leaf
// package: it has no I/O of its own beyond reading a single status file the
// operator's backup pipeline writes, and it depends only on the standard
// library. HTTP handlers and operators consume it to surface "when did the
// last successful database backup land" without coupling the API process to
// any particular backup driver.
//
// # Boundary
//
// Yalla does not run the backup itself. Backups are produced by an external
// operator workflow — typically pg_dump or pgBackRest invoked from a
// scheduled job — that runs alongside, but outside, the API and worker
// processes. The contract the backup package owns is the post-success
// handshake between that workflow and the running API:
//
//  1. The operator pipeline runs a backup.
//  2. On success, the pipeline writes a single RFC3339 timestamp to the
//     status file named by [config.EnvBackupStatusFile]
//     (YALLA_BACKUP_STATUS_FILE).
//  3. The Yalla Control Plane API reads that file on demand to answer the
//     unauthenticated GET /healthz/backup probe.
//
// The package never writes to the status file; that is the operator's
// responsibility. It never reads the database; the database connection
// belongs to other packages. It never invokes pg_dump or any cloud-storage
// API; the operator pipeline owns those.
//
// # Status semantics
//
// Three states are exposed through [Reporter]:
//
//   - Unconfigured — no status path is wired. [Status.Configured] is false
//     and the timestamp/age fields are zero. This is the default for the
//     local and test profiles, and for any operator who has not opted in to
//     the backup-health surface.
//   - Configured but pending — the status path is wired but the file does
//     not exist yet (the first backup has not landed, or the volume is
//     freshly provisioned). The reporter returns [ErrNoBackupRecorded], a
//     sentinel a caller can match to render a "no backup yet" message
//     rather than a generic failure.
//   - Configured and reporting — the status file exists and parses cleanly
//     to an RFC3339 timestamp. [Status.LastSuccessAt] carries the parsed
//     value and [Status.Age] is computed against the injected clock.
//
// Errors from a corrupt status file, an unreadable file, or any other I/O
// failure are returned wrapped through [yerr.CodeServer]. The wrapped
// message names the field that failed without echoing the file's content,
// so a status file accidentally seeded with a secret cannot leak through an
// error string.
//
// # Freshness
//
// A non-zero [Status.MaxAge] turns the reporter into a freshness predicate:
// [Status.Fresh] reports whether Age <= MaxAge. The MaxAge value is
// configured by the operator and is the contract between the backup
// schedule and the health probe. A daily backup with a two-hour grace
// period maps to MaxAge=26h, for example. Operators may leave MaxAge zero
// to opt out of the freshness check; the probe still reports the age, but
// makes no claim about it.
//
// # Redaction
//
// The backup status file is treated as untrusted: its content is parsed but
// never logged or echoed in error messages. A status file that contains a
// secret by mistake (a misconfigured pipeline writing a DSN instead of a
// timestamp) yields a typed parse error with no payload — the file path is
// reported, the file content is not. Tests prove this contract.
//
// # Wiring
//
// Handlers depend on [Reporter] rather than the concrete [FileReporter] so
// processes with no backup integration can pass [Unconfigured]() — for
// example, the test profile and any non-production process. A future
// in-memory reporter for integration tests or an HTTP-driven reporter for a
// cloud-managed backup service plugs into the same interface without
// changing handler code.
package backup
