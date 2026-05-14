// Package audit is the Yalla Control Plane audit service. It is the single
// place application code turns a policy decision into an immutable audit
// record, so field mapping and redaction are applied uniformly to every
// security-relevant event.
//
// # Responsibilities
//
// The [Auditor] takes an [Entry] — a request-side description of an
// authorization decision — and the principal and correlation identifiers
// carried on the request context, and writes one [store.AuditEvent] through a
// narrow [Recorder] port. It records both verdicts: an allowed decision and a
// denied decision are equally part of the trail, so the audit log answers
// "who was refused what" as well as "who did what".
//
// # Redaction
//
// Audit metadata is free-form diff and context detail, so it is the most
// likely place for a secret to leak into the log. The Auditor redacts every
// metadata value before it is persisted: a value under a secret-shaped key
// (anything containing token, secret, password, credential, ...) is replaced
// wholesale with output.Sentinel, and every other value — plus the user agent
// — is scrubbed of known secret transport patterns (Authorization headers,
// token-bearing query parameters) by an output.Redactor. Keys are preserved
// as-is so the shape of the diff stays auditable. The persistence layer
// (internal/controlplane/store) treats metadata as already redacted; redaction
// is this package's contract.
//
// # Boundaries
//
// The Auditor depends on the [Recorder] port rather than a concrete
// repository, so it is unit-testable without a database; the production
// adapter is *store.AuditRepository. [Auditor.Record] takes the caller's
// *store.Tx, so an audit write can share the transaction of the mutation it
// records (an in-unit-of-work audit) or run in its own short transaction (a
// denied decision at the HTTP boundary, before any mutation). The audit table
// is append-only and rejects updates at the database level; this package adds
// no mutation surface of its own.
package audit
