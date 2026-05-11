# Databases: provisioning and wiring

When detection found `db_needs`, this is the recipe. Each engine has the same three-step flow:

1. **Create** the DB resource (`<engine>-create`) → returns the DB ID after re-listing.
2. **Deploy** the DB (`<engine>-deploy`) → spins up the container; returns immediately, status moves to `done` quickly.
3. **Wire** the connection string into the app (`application-saveEnvironment`) → uses the DB's auto-generated `appName` as the in-cluster hostname.

Skip step 3 for compose deploys — the user owns service-to-service hostnames in their compose file.

## Schema reminders

| Engine | Op | Required body fields |
|---|---|---|
| Postgres | `postgres-create` | `name`, `databaseName`, `databaseUser`, `databasePassword`, `environmentId` |
| MySQL | `mysql-create` | (same) |
| MariaDB | `mariadb-create` | (same) |
| MongoDB | `mongo-create` | `name`, `databaseUser`, `databasePassword`, `environmentId` (no `databaseName` — Mongo is schemaless) |
| Redis | `redis-create` | `name`, `databasePassword`, `environmentId` (no user/db) |
| LibSQL | `libsql-create` | `name`, `environmentId` (token-based, no user/password) |

Optional but useful: `description`, `serverId` (for multi-server clusters; `null` for single-server installs), `dockerImage` (override the default image — pin a major version like `postgres:16-alpine`).

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

After `<engine>-deploy` succeeds, query `<engine>-one` (input `{"query":{"<engine>Id":["<id>"]}}`) and read the `appName` field. Build the connection string:

| Engine | Template |
|---|---|
| Postgres | `postgres://<user>:<pass>@<appName>:5432/<dbName>` |
| MySQL | `mysql://<user>:<pass>@<appName>:3306/<dbName>` |
| MariaDB | `mysql://<user>:<pass>@<appName>:3306/<dbName>` |
| MongoDB | `mongodb://<user>:<pass>@<appName>:27017` |
| Redis | `redis://default:<pass>@<appName>:6379` |
| LibSQL | `libsql://<appName>:8080` (auth token via env var separately) |

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

Don't auto-enable backups, replication, or external-network exposure — those are install-specific decisions. After deploy, point the user at:

- `<engine>-saveExternalPort` — to expose the DB outside the swarm (for migrations from local).
- `backup-create` — for scheduled DB backups to S3/local.

These are post-deploy followups; mention them in the report rather than the plan.
