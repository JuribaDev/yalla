# Yalla Control Plane Operations Commands

This directory contains operator-facing commands for production maintenance.
They are versioned with the backend API and worker binaries so schema and
runtime contracts move together.

## Database Migrations

Run database migrations through the API binary's embedded migrator:

```bash
deploy/operations/migrate-database.sh --dry-run
sudo deploy/operations/migrate-database.sh --apply
```

The command loads runtime configuration from `/etc/yalla/control-plane.env`
by default and then executes:

```bash
/usr/local/bin/yalla-api --migrate-only
```

The worker is stopped before schema changes so it cannot claim jobs against a
moving schema:

```bash
sudo systemctl stop yalla-worker
```

After migration, the script starts `yalla-api` and `yalla-worker`, probes
`/healthz` and `/readyz`, and points operators at structured JSON logs:

```bash
journalctl -u yalla-api -u yalla-worker -o json
```

The API process returns stable `yalla.output.v1` / `yalla.error.v1` envelopes
for HTTP health and readiness probes. Migration command logs are structured
JSON diagnostics only and must not contain database URLs, tokens, API keys,
cookies, Dokploy credentials, signing keys, secret keys, or rendered
environment variable values.

Do not paste `/etc/yalla/control-plane.env` into tickets or runbooks. The
dry-run plan prints only redacted `YALLA_*` variable names and command shape.

## Database Backup

Run the control-plane logical backup through the operator-owned backup
toolchain:

```bash
deploy/operations/backup-database.sh --dry-run
sudo deploy/operations/backup-database.sh --apply
```

The command loads `/etc/yalla/control-plane.env` by default, verifies that the
versioned backend binaries exist at `/usr/local/bin/yalla-api` and
`/usr/local/bin/yalla-worker`, and then runs:

```bash
pg_dump --format=custom --no-acl --no-owner --compress=9
```

The dump is written under `YALLA_BACKUP_DIR` using mode `0600` semantics from
`umask 077`; operators must mount that directory on the encrypted backup
volume described in `docs/operations/backup-restore.md`. The command uses
`flock` so two backups cannot run concurrently, writes the
`YALLA_BACKUP_STATUS_FILE` timestamp atomically with `mktemp` and `mv`, and
leaves the previous status file untouched if `pg_dump` fails.

Before and after applying, the script verifies service liveness and probes the
public health surfaces:

```bash
sudo systemctl is-active yalla-api
sudo systemctl is-active yalla-worker
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
curl -fsS http://127.0.0.1:8080/healthz/backup
```

The API process returns stable `yalla.output.v1` / `yalla.error.v1` envelopes
for HTTP health, readiness, and backup probes. Backup command diagnostics are
structured JSON-adjacent operator messages only and must not contain database
URLs, tokens, API keys, cookies, Dokploy credentials, signing keys, secret
keys, backup bucket credentials, or rendered environment variable values. The
dry-run plan prints only redacted `YALLA_*` variable names and command shape.

## Seed Admin

Seed the initial operator user and organization membership through the API
binary's embedded maintenance command:

```bash
deploy/operations/seed-admin.sh --dry-run
sudo deploy/operations/seed-admin.sh --apply
```

The command loads `/etc/yalla/control-plane.env` by default. Operators provide
`YALLA_SEED_ADMIN_EMAIL`, `YALLA_SEED_ADMIN_ORGANIZATION`, and optionally
`YALLA_SEED_ADMIN_ROLE` (`owner`, `admin`, or `member`). It then executes:

```bash
/usr/local/bin/yalla-api --seed-admin
```

Before applying, the script verifies both service units are active:

```bash
sudo systemctl is-active yalla-api
sudo systemctl is-active yalla-worker
```

It also probes `/healthz` and `/readyz`, then points operators at structured
JSON logs:

```bash
journalctl -u yalla-api -u yalla-worker -o json
```

The API process returns stable `yalla.output.v1` / `yalla.error.v1` envelopes
for HTTP health and readiness probes. The seed command writes source-of-truth
rows and an audit event, and logs only stable row IDs, role, and command
status. It must never print database URLs, tokens, API keys, cookies, Dokploy
credentials, signing keys, secret keys, or rendered environment variable
values.

## Backup Command Artifact

The production backup command lives at
`deploy/operations/backup-database.sh` with this runbook. It references the
same deployed backend binaries as the service units (`/usr/local/bin/yalla-api`
and `/usr/local/bin/yalla-worker`) but keeps the backup data plane outside the
Go process: the shell artifact invokes `pg_dump --format=custom --no-acl
--no-owner --compress=9` against the operator-provided Postgres role, writes
the backup file into the operator-managed encrypted backup directory, and
updates `YALLA_BACKUP_STATUS_FILE` only after the dump has succeeded.

The command loads runtime configuration from `/etc/yalla/control-plane.env`
or `YALLA_CONTROL_PLANE_ENV_FILE`. It never checks in or prints database URLs,
signing keys, secret-encryption keys, Dokploy endpoints, Dokploy tokens, API
keys, cookies, backup bucket credentials, or rendered environment values;
`--dry-run` prints only command shape plus redacted `YALLA_*` variable names.
After `--apply`, operators verify the API through `/healthz`, `/readyz`, and
`/healthz/backup`, then inspect structured JSON logs with
`journalctl -u yalla-api -u yalla-worker -o json`.

CI pins the command, runbook, and release gate with
`go test ./internal/release/... -run TestBackupCommand`.
