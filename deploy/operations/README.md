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
