# Backup & restore runbook — Yalla Control Plane database

This document is the source of truth for how the Yalla Control Plane Postgres
database is backed up, restored, and rehearsed. It is owned by Backend
Operations. Anything that contradicts this file in a wiki, ticket, or Slack
thread is wrong.

Story: **BE-0039** — *Implement backup and restore plan for control-plane DB*.

## Why this matters

The control-plane database is the source of truth for every tenant, user, API
key, scoped grant, project, environment, service, deployment, quota, audit
event, and provisioning-job row. A lost database means lost desired state,
unauditable history, and an outage that no Dokploy redeploy can repair.
Dokploy itself can be re-provisioned from desired state; the desired state
cannot be reconstructed from Dokploy.

Treat this runbook as production-critical and update it alongside any change
that affects backup frequency, retention, encryption, or restore steps.

## Backup contract

| Field                | Value                                                                       |
| -------------------- | --------------------------------------------------------------------------- |
| Frequency            | Full logical backup every **24 hours** at 02:00 UTC                          |
| Incremental WAL      | Continuous WAL archival every **60 seconds** (RPO ≤ 1 minute)                |
| Retention — full     | **30 daily snapshots**, **12 weekly snapshots**, **6 monthly snapshots**     |
| Retention — WAL      | **48 hours** of contiguous WAL (covers any restore point within 2 days)     |
| Storage              | Encrypted object storage, **AES-256-GCM at rest**, KMS-managed key          |
| Transport            | TLS 1.2+ end-to-end; the backup agent never writes plaintext to local disk  |
| Access               | Backup bucket is private; restore requires break-glass MFA + ticketed reason |
| RTO target           | **≤ 30 minutes** to bring a restored standby up                              |
| RPO target           | **≤ 1 minute** (via WAL stream)                                              |
| Owner on call        | Backend Operations rotation (PagerDuty: `yalla-be-ops`)                     |

The frequency, retention, RTO, and RPO are the customer-facing contract.
Changing any of them is a breaking change to the SLO and requires a
follow-up PRD story.

## Encryption expectations

1. **At rest**: every object the backup pipeline writes is encrypted under a
   KMS-managed key. The key is rotated every 90 days; rotation is the
   operator's responsibility, not Yalla's.
2. **In transit**: the backup agent connects to Postgres over TLS using the
   same certificate bundle the control-plane API uses. The pipeline ships
   the encrypted backup to object storage over HTTPS. Plaintext WAL must
   never be written to disk; the agent streams from Postgres directly into
   the encrypted stream.
3. **Key access**: only the backup agent's IAM principal and a separate
   "restore-operator" principal can read the backups. The control-plane API
   and worker processes have **no** read access to the backup bucket.
4. **Auditability**: every restore (success or failure) emits an audit
   event with code `operations.backup.restore` and a redacted hint naming
   the restore point. Failed restores are paged.

## Secrets / redaction

The backup pipeline must **never** write secrets to logs, the status file, or
the destination bucket's metadata. Specifically:

- The Postgres DSN, signing keys, Dokploy token, and any rendered
  environment variable value never appear in a backup log line.
- The status file the pipeline writes (see below) contains **only** an
  RFC3339 timestamp. The Yalla API treats anything else as a parse error
  and refuses to echo the offending content.
- The backup agent's own credentials (the Postgres role and the object-
  storage key) are sourced from the operator's secret store and are never
  echoed by `--debug` or `--dry-run` invocations.

These rules are enforced in code by `internal/controlplane/backup` and by
the BE-0039 contract tests. A pipeline that violates them must be treated
as a security incident, not a documentation gap.

## Operator pipeline hand-shake

The Yalla API does **not** run the backup. The backup is produced by an
external operator workflow (`pg_dump` or `pgBackRest`, depending on the
profile). On every **successful** run, the operator workflow writes a single
RFC3339 timestamp to the file named by the `YALLA_BACKUP_STATUS_FILE`
environment variable. That is the only signal the API consumes.

Recommended shape of the status file (`/var/lib/yalla/backup.status`):

```text
2026-05-16T03:00:00Z
```

That is it — one timestamp, optional trailing newline. The Yalla API will
expose this timestamp through the unauthenticated `GET /healthz/backup`
probe.

The pipeline must:

1. Run `pg_dump --format=custom --no-acl --no-owner --compress=9 ...` against
   the control-plane Postgres role, streaming the output to the encrypted
   transport target.
2. On success, write the current UTC timestamp to the status file. The
   write must be atomic (write to `<path>.tmp` then `os.Rename`) so a
   partially-written status file never confuses the probe.
3. On failure, leave the status file untouched. The Yalla probe will
   continue to report the previous successful timestamp; the pipeline must
   page on its own failure path.

## Health probe contract

The API exposes `GET /healthz/backup` with the following stable wire shape.

Configured, healthy:

```json
{
  "schema_version": "yalla.output.v1",
  "ok": true,
  "data": {
    "configured": true,
    "fresh": true,
    "last_success_at": "2026-05-16T03:00:00Z",
    "age_seconds": 21600,
    "max_age_seconds": 93600
  },
  "request_id": "req_..."
}
```

Configured, stale: identical to the above but `"fresh": false`. Operators
are expected to alert on `fresh == false`.

Configured, no backup yet recorded (freshly provisioned environment):

```json
{
  "schema_version": "yalla.output.v1",
  "ok": true,
  "data": {
    "configured": true,
    "fresh": false,
    "max_age_seconds": 93600,
    "detail": "no successful backup recorded yet"
  },
  "request_id": "req_..."
}
```

Unconfigured (the default for local and test profiles):

```json
{
  "schema_version": "yalla.output.v1",
  "ok": true,
  "data": {
    "configured": false,
    "fresh": true
  },
  "request_id": "req_..."
}
```

Unreadable status source — the file exists but cannot be read or parsed:

```json
{
  "schema_version": "yalla.error.v1",
  "ok": false,
  "error": {
    "code": "E_UNAVAILABLE",
    "message": "backup status is unavailable",
    "hint": "the operator backup-status source is unreadable or malformed; check the pipeline that writes YALLA_BACKUP_STATUS_FILE",
    "documentation_url": "https://docs.yalla.dev/api/errors/E_UNAVAILABLE"
  },
  "request_id": "req_..."
}
```

The endpoint is **unauthenticated** so probes (Prometheus blackbox, k8s
liveness, on-call dashboards) can consume it without rotating credentials.
It never reveals tenant data — only the operational backup timestamp.

## Configuration

| Variable                    | Required in production | Notes                                              |
| --------------------------- | ---------------------- | -------------------------------------------------- |
| `YALLA_BACKUP_STATUS_FILE`  | Yes                    | Absolute path the pipeline writes the timestamp to |
| `YALLA_BACKUP_MAX_AGE`      | Yes                    | Go duration, e.g. `26h`; powers the `fresh` field  |

Both default to empty / zero. An empty `YALLA_BACKUP_STATUS_FILE` makes the
API render the "unconfigured" envelope; an empty `YALLA_BACKUP_MAX_AGE`
disables the `fresh` predicate (it stays `true` and the operator must alert
on `age_seconds` directly).

The settings live in `internal/controlplane/config`; tests cover absolute-
path validation, duration parsing, the redacted projection, and the
log-safe log-value snapshot.

## Restore procedure

This is the **on-call** procedure. Treat every step as load-bearing — never
skip a step to save time.

1. **Open an incident** in PagerDuty (`yalla-be-ops`) and announce the
   restore in `#yalla-ops` with the target restore point and the affected
   environment.
2. **Freeze writes**: pause the worker fleet (`kubectl scale deploy
   yalla-worker --replicas=0`) and put the API into read-only mode
   (`YALLA_READ_ONLY=1`, then `kubectl rollout restart deploy yalla-api`).
   This is the only way to guarantee the restored database does not race
   against in-flight provisioning jobs.
3. **Provision a fresh database**: spin up an empty Postgres of the same
   major version on the operator's restore VPC. Do **not** restore over the
   primary; restores always land on a fresh instance the operator promotes
   afterwards.
4. **Restore the snapshot**: `pg_restore --clean --if-exists
   --no-owner --no-acl --jobs=4 -d <fresh-dsn> <snapshot>`. The snapshot
   filename names the timestamp; the restore-operator role's IAM principal
   is the only one with read access to the bucket.
5. **Replay WAL**: if the restore point is later than the snapshot,
   continue WAL replay until `recovery_target_time` matches the chosen
   point. WAL retention covers the last 48 hours.
6. **Apply migrations**: run `yalla-api --migrate-only` against the
   restored DSN. The applied migration version must match what the API
   binary expects; a mismatch aborts the restore.
7. **Smoke-test**: run the canary suite (`scripts/canary.sh <restored-dsn>`)
   which exercises one read from every public endpoint family. The smoke
   test is required to pass before traffic is switched.
8. **Switch traffic**: update the API's `YALLA_DATABASE_URL` (or the secret
   ref) to point at the restored DSN, then `kubectl rollout restart deploy
   yalla-api`. Confirm `/readyz` flips to ready before any worker is
   resumed.
9. **Resume workers**: scale `yalla-worker` back to its target replicas.
   Confirm `GET /v1/organizations/{org_id}/audit-events` is producing new
   rows on the restored database.
10. **Emit audit event**: post a one-line incident summary to the audit
    trail by running `yalla-admin audit emit --code
    operations.backup.restore --hint "<restore-point> via <ticket>"`. This
    is the only step that requires a human in the loop — the redacted hint
    is the permanent operator record.
11. **Close the incident** with the timeline (freeze → restore → smoke →
    cutover → resume) and the actual restore point reached. Schedule a
    blameless review within five business days.

## Rehearsal — required in staging every quarter

A restore that has never been rehearsed is a restore that does not work.
Every quarter (or before a major Postgres upgrade), Backend Operations runs
the restore procedure end-to-end against **staging** and times each step.
Pass criteria:

- The full restore (steps 3 through 7) completes within **30 minutes** —
  the production RTO target.
- The canary suite passes on the restored database.
- The audit event for the rehearsal is emitted with hint `"rehearsal
  <YYYY-QQ>"`.
- A short rehearsal report is filed in `docs/operations/rehearsals/` (one
  Markdown file per quarter; create the directory on first use).

To run the rehearsal:

```bash
# 1. Take a fresh snapshot of staging (do NOT use a prod snapshot — the
#    rehearsal MUST validate the staging pipeline end-to-end).
YALLA_PROFILE=staging ./scripts/backup-trigger.sh

# 2. Restore into a throwaway instance.
YALLA_PROFILE=staging \
  YALLA_REHEARSAL_DATABASE_URL=<throwaway-dsn> \
  deploy/operations/restore-rehearsal.sh --apply --snapshot <snapshot-path>

# 3. Run the canary suite against the restored DSN.
./scripts/canary.sh <throwaway-dsn>

# 4. Tear down the throwaway database.
dropdb --if-exists <throwaway-db-name>
```

The restore rehearsal command is versioned in this repository under
`deploy/operations/restore-rehearsal.sh`. It restores only into a throwaway
`YALLA_REHEARSAL_DATABASE_URL`, runs `/usr/local/bin/yalla-api --migrate-only`
against the restored database, executes the configured canary suite, and writes
a redacted report only after those steps pass.

## What is NOT in scope

This runbook covers the control-plane database. It does **not** cover:

- Dokploy's own database (`dokploy-postgres`). That is owned by the Dokploy
  operator runbook; restoring Dokploy out from under a healthy Yalla state
  is a recipe for desired-state drift.
- Customer application databases provisioned through Yalla services. Those
  inherit their backup story from the database service's per-engine
  defaults; this story will be revisited under the BE-04xx database
  retention series.
- Object storage of customer environment-variable values. Those live in
  the control-plane database and are covered here transitively.

## Change log

| Date       | Change                          | Owner                |
| ---------- | ------------------------------- | -------------------- |
| 2026-05-16 | Initial runbook (BE-0039).      | Backend Operations   |
