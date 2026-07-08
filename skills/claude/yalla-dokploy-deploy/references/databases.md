# Databases: provisioning and wiring

When detection found `db_needs`, prefer the friendly database commands. Each engine has the same three-step flow:

1. **Create** the DB resource (`yalla database create <engine> ...`) → recovers the DB ID by searching after create.
2. **Deploy** the DB (`yalla database deploy <engine> --id ...`, or `--deploy` during create) → spins up the container; returns immediately, status moves to `done` quickly.
3. **Wire** the connection string into the app (`application-saveEnvironment`) → uses the DB's auto-generated `appName` as the in-cluster hostname.

Skip step 3 for compose deploys — the user owns service-to-service hostnames in their compose file.

Raw `yalla --json api call <operationId>` remains the fallback for fields not yet exposed by the friendly create, deploy, update, or backup commands.

## Friendly commands

```sh
yalla database create postgres --environment-id env_123 --name app-postgres --database-name app --database-user app --database-password "$DATABASE_PASSWORD" --deploy
yalla database create mysql    --environment-id env_123 --name app-mysql    --database-name app --database-user app --database-password "$DATABASE_PASSWORD" --root-password "$MYSQL_ROOT_PASSWORD" --deploy
yalla database create mariadb  --environment-id env_123 --name app-mariadb  --database-name app --database-user app --database-password "$DATABASE_PASSWORD" --root-password "$MARIADB_ROOT_PASSWORD" --deploy
yalla database create mongo    --environment-id env_123 --name app-mongo    --database-user app --database-password "$MONGO_PASSWORD" --replica-sets --deploy
yalla database create redis    --environment-id env_123 --name app-redis    --database-password "$REDIS_PASSWORD" --deploy
yalla database deploy postgres --id postgres_123
yalla database update postgres --id postgres_123 --memory-reservation 512M --memory-limit 1G --cpu-reservation 0.25 --cpu-limit 1 --replicas 1
```

Use `--json` for agent workflows when the command output will be parsed. Each engine's `create` returns the new database ID — the friendly command recovers it by re-searching after the create call, so a `{}` response from upstream is not a failure.

Non-obvious flags worth knowing:

- `--root-password` (MySQL / MariaDB only) — sets the engine root password independent of the app user password. If you omit it for MySQL/MariaDB, Dokploy generates a random one you can never read back; pass it explicitly when you want repeatable provisioning.
- `--app-name` — overrides the auto-generated in-cluster hostname (the value other apps reach via Docker Swarm DNS). Default is fine for almost every project; only set this if you need a stable name independent of the DB record name.
- `--server-id` — pins the DB container to a specific Dokploy server in a multi-server cluster. Leave unset for single-server installs.
- `--replica-sets` (Mongo only) — enables MongoDB replica-set mode. Most apps do not need it; turn it on only if the app expects a replica-set connection string.
- `--deploy` on `create` — fuses create + deploy in one step. Skip it if you want to inspect the record before it spins up.

## Schema reminders

| Engine | Op | Required body fields |
|---|---|---|
| Postgres | `postgres-create` | `name`, `databaseName`, `databaseUser`, `databasePassword`, `environmentId` |
| MySQL | `mysql-create` | (same) |
| MariaDB | `mariadb-create` | (same) |
| MongoDB | `mongo-create` | `name`, `databaseUser`, `databasePassword`, `environmentId` (no `databaseName` — Mongo is schemaless) |
| Redis | `redis-create` | `name`, `databasePassword`, `environmentId` (no user/db) |

Optional but useful: `description`, `serverId` (for multi-server clusters; `null` for single-server installs), `dockerImage` via `--image`.

Friendly commands send safe image defaults when `--image` is omitted:

| Engine | Friendly default image |
|---|---|
| Postgres | `postgres:18` |
| MySQL | `mysql:8` |
| MariaDB | `mariadb:11.4` |
| MongoDB | `mongo:8` |
| Redis | `redis:8` |

This avoids broken upstream schema defaults observed during live testing (`mariadb:6`, `mongo:15`). Pass `--image` to pin a different version.

This yalla build and the checked live Dokploy instance do not expose `libsql-*` operations; treat LibSQL as unsupported until the embedded OpenAPI spec includes it.

## Naming convention

Pick names that survive readability after a year:

```
<project>-<engine>           # primary DB for an app:    invoice-app-postgres
<project>-<engine>-<env>     # if separate per env:      invoice-app-postgres-staging
<project>-<engine>-cache     # secondary DB:             invoice-app-redis-cache
```

`databaseName` and `databaseUser` are arbitrary — convention: app-name-snake-case, no dashes (Postgres prefers underscores).

## Generating credentials

The skill should generate a strong password rather than asking the user. 32 random base64 chars from `python3 -c 'import secrets; print(secrets.token_urlsafe(24))'` is fine.

**Surface the password back to the user in the plan output** so they can save it. Never write it to the repo's `.env` — only to their clipboard, the chat, or `.dokploy.yaml.local` (gitignored).

## Connection string templates

After `yalla database deploy <engine>` succeeds, query `<engine>-one` (input `{"query":{"<engine>Id":["<id>"]}}`) and read the `appName` field. Build the connection string:

| Engine | Template |
|---|---|
| Postgres | `postgres://<user>:<pass>@<appName>:5432/<dbName>` |
| MySQL | `mysql://<user>:<pass>@<appName>:3306/<dbName>` |
| MariaDB | `mysql://<user>:<pass>@<appName>:3306/<dbName>` |
| MongoDB | `mongodb://<user>:<pass>@<appName>:27017` |
| Redis | `redis://default:<pass>@<appName>:6379` |

`<appName>` is what Docker swarm will resolve in-cluster — apps in the same Dokploy environment can hit it directly by that hostname.

## Wiring into the app's env

After computing the connection string:

1. Pull the app's current env via `application-one` → `data.body.env` (multi-line string).
2. Strip any local `DATABASE_URL=` line (the project's local dev value is meaningless on Dokploy).
3. Append the new line: `DATABASE_URL=<connection_string>\n`.
4. Send the whole thing back via `application-saveEnvironment`.

Make sure to send `env`, `buildArgs`, AND `buildSecrets` in the new body — `application-saveEnvironment` is replace-not-merge. Use the values from `application-one` for the ones you're not changing.

## Multiple databases

If the project needs more than one (e.g., postgres + redis), repeat the create-deploy-wire cycle per engine. Use distinct env-var names: `DATABASE_URL` for the primary, `REDIS_URL` for the cache, `MONGO_URL` for separate Mongo, etc. Match what the project's code reads.

## Idempotency / re-runs

`*-create` errors with `E_INVALID_INPUT` if the name is already taken in the same environment. On rerun:

1. List existing DBs in the env via `<engine>-byProjectId` (filter by environmentId).
2. If a DB with the planned name already exists, skip create + deploy.
3. Pull its connection string and wire it again (idempotent — `application-saveEnvironment` overwrites).

If the user explicitly wants a fresh DB, ask first ("delete `<existing>` first?") and only proceed on a clear yes — DB deletes are unrecoverable.

## Backup / production hardening

Don't auto-enable external-network exposure — that is install-specific. For backups, prefer the friendly backup commands when the user asks for scheduled or manual DB backups.

Friendly backup commands support Postgres, MySQL, MariaDB, and MongoDB. Redis is not supported by Dokploy's backup API in this spec.

```sh
yalla database backup create postgres \
  --id postgres_123 \
  --destination-id dst_123 \
  --database app \
  --prefix backups/app/ \
  --schedule "0 2 * * *" \
  --keep-latest 7

yalla database backup run postgres --backup-id backup_123
yalla database backup update postgres --backup-id backup_123 --schedule "0 4 * * *" --keep-latest 14 --enabled
yalla database backup get --backup-id backup_123
yalla database backup list-files --destination-id dst_123 --prefix backups/app/   # browse a destination
yalla database backup list-files --backup-id backup_123                            # files for one backup
yalla database backup delete --backup-id backup_123
```

`backup update` accepts `--enabled` or `--disabled` (mutually exclusive) to pause/resume a schedule without deleting the backup record. `--service-name` lets MongoDB replica-set deployments target a specific service inside the swarm.

Use `--json` for agent workflows. Some Dokploy versions return `{}` from raw `backup-create`; the friendly command recovers `backup_id` from the database record's `backups` array via `<engine>-one` and falls back to `user-getBackups`. Treat a missing `backup_id` from the friendly command as a real failure and inspect the typed error hint instead of asking the user to copy an ID from the portal.

### Where `--destination-id` comes from

Destinations are S3-compatible buckets (or local paths) registered at the **organization** level, not per-database. There is no friendly `yalla destination …` wrapper yet — list and create them through the raw API:

```sh
yalla --json api call destination-all --input '{}'                             # see what already exists
yalla --json api call destination-create --input destination.json              # body: {name, provider, accessKey, secretAccessKey, bucket, endpoint, region}
```

Reuse one destination across many backups — that is the design. Only create a new destination when the user asks for an isolated bucket or a different storage backend.

After deploy, point the user at:

- `<engine>-saveExternalPort` — to expose the DB outside the swarm (for migrations from local).
- `yalla database backup create` — for scheduled DB backups to S3/local destinations.

These are post-deploy followups; mention them in the report rather than the plan.
