# internal/controlplane/audit

The audit service: the single place application code turns a `policy.Decision`
into an immutable audit record.

- `Auditor.Record(ctx, *store.Tx, Entry)` builds a `store.AuditEvent` from the
  `Entry` plus the principal (`policy.PrincipalFromContext`) and correlation
  ids (`telemetry.FromContext`) carried on the context, then appends it through
  the narrow `Recorder` port. **Both verdicts are recorded** — a denied
  decision is as much a part of the trail as an allowed one.
- **Redaction is this package's contract.** `redactMetadata` replaces a value
  under a secret-shaped key (`isSensitiveKey` — token/secret/password/
  credential/...) wholesale with `output.Sentinel`, and scrubs every other
  value (and the user agent) of known secret transport patterns via an
  `output.Redactor`. Keys are never redacted. `store` treats `metadata` as
  already-redacted. When you add a place audit metadata comes from, do not
  bypass `Auditor.Record`.
- The org an event is filed under: the **principal's** org if a principal was
  resolved, else the **resource's** org (so an unauthenticated denial is still
  tenant-scoped); neither known → `apierr.Invalid`.
- `Recorder` is a port (satisfied by `*store.AuditRepository`) so the Auditor
  is unit-testable with a fake and a `nil` `*store.Tx`. Persistence is
  integration-tested in `package store_test`; redaction and mapping are
  unit-tested here.
- Dependency direction: `audit` imports `store`/`policy`/`telemetry`/`output`;
  none of those import `audit`. The Auditor is not yet wired into a composition
  root — the HTTP middleware and store units of work that call it land in
  later stories.
