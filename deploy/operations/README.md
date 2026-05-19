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
