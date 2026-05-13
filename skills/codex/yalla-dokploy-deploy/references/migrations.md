# Migrations and pre-deploy hooks

Read this when the app needs to run a schema migration, seed step, or any code **before traffic** on each deploy — typically `prisma migrate deploy`, `python manage.py migrate`, `bundle exec rails db:migrate`, `alembic upgrade head`, or similar.

The goal: **the migration runs every deploy, but only once, and only when the new code is ready to serve traffic if the migration succeeds.**

## Three mechanisms Dokploy supports

In rough order of preference:

### 1. Heroku-style `release:` line in Procfile  *(preferred for any Heroku-buildpacks app)*

When `buildType: "heroku_buildpacks"`, the Procfile's `release:` line runs on every deploy after the build completes but before any web/worker process starts. If it fails, the deploy aborts and the previous version stays live.

```Procfile
release: python manage.py migrate --noinput
web: gunicorn config.wsgi --bind 0.0.0.0:$PORT
```

Skill behaviour:
- Detection should look for `Procfile` containing a `release:` line.
- If present AND `buildType: "heroku_buildpacks"` is being used, the migration is **handled automatically** — no extra yalla calls needed.
- The plan should call out: "Migrations run via the Procfile `release:` step before traffic on every deploy."
- Post-deploy verification can scrape `application-readAppMonitoring` for `Running release command` and the migration's exit code to surface migration failures.

This is the cleanest mechanism because:
- It runs **in the same image** as the web process (no version skew between migrate-runner and web).
- Migration failure aborts the deploy automatically.
- No yalla-side machinery — Dokploy's buildpack runner does the work.

### 2. Custom start command via `application-update.command`  *(works for any buildType)*

For non-Heroku buildtypes (Dockerfile, Nixpacks, Railpack), there's no built-in release phase. The simplest substitute is to **chain** migrate + serve in the container's start command:

```sh
# Dockerfile CMD or nixpacks Procfile equivalent
sh -c "python manage.py migrate --noinput && gunicorn config.wsgi --bind 0.0.0.0:$PORT"
```

This works but has caveats:
- The migration runs on **every container start**, including auto-restarts. Idempotent migrations (Django, Rails, Alembic, Prisma) tolerate this fine. Non-idempotent seed scripts will run repeatedly — guard them.
- If you have **replicas > 1**, all replicas race the migration. Set `--lock` (Django) or use advisory locks in your migrate tool.
- Failure crashes the container; Dokploy will retry per its restart policy.

Skill should propose this when:
- `buildType` is not `heroku_buildpacks`
- The project has a clear migration command in its conventions (Prisma's `migrate deploy`, Django's `manage.py migrate`, etc.)
- There's no Procfile to repurpose

The yalla call is `application-update` with the `command` field set; the rest of the app config stays untouched.

### 3. One-shot pre-deploy via `application-execShellCommand`  *(for run-once / out-of-band tasks)*

For migrations the user explicitly does **not** want chained into every container start — e.g., expensive data backfills, one-off seed-after-promotion — Dokploy supports executing a command in the latest deployed container via `application-execShellCommand`.

Pattern:
1. Deploy the new image **without** chaining migrate.
2. Wait for status `done`.
3. Run the migration as a one-shot: `application-execShellCommand` with body `{applicationId, command: "python manage.py migrate --noinput"}`.
4. Verify exit code 0.

The trade-off: the new web/worker processes are already serving traffic against the **old** schema during the gap between deploy and migrate. Only works for backward-compatible migrations (additive columns, etc.) — never for column drops or rename refactors.

Skill should treat this as the **exception, not the default**. Surface it only when the user asks for a backfill or explicitly opts out of release-phase migrations.

## Detection rules (extends `detect.md`)

| Signal in the project | → Migration approach |
|---|---|
| `Procfile` has a `release:` line and a `web:` line | mechanism 1 (Heroku release) |
| `prisma/schema.prisma` exists (any flavour) | mechanism 2 by default (`prisma migrate deploy && <start>`); ask user before mechanism 1 (forces heroku_buildpacks) |
| `manage.py` (Django) + no Procfile | mechanism 2 (`python manage.py migrate --noinput && <start>`) |
| `bin/rails` or `Rakefile` with `db:migrate` task | mechanism 2 |
| `alembic.ini` (SQLAlchemy/Alembic) | mechanism 2 (`alembic upgrade head && <start>`) |
| `migrations/` dir + custom tool | mechanism 2 — ask the user for the migrate command |
| No migration signals | no migration step required |

Always surface the chosen mechanism in the plan: "Migrations: `prisma migrate deploy` chained into the start command (mechanism 2). Runs on every container start."

## State-file extension

Record the migration mechanism so future deploys are consistent:

```yaml
# .dokploy.yaml (iteration-2)
migrations:
  mechanism: release | start-chain | one-shot
  command: "python manage.py migrate --noinput"
  detected_from: "Procfile release: line" | "prisma/schema.prisma" | "user-supplied"
```

Subsequent deploys/redeploys re-use the same mechanism without re-asking.

## Verification

After deploy:
1. Status poll as usual (`application-one`).
2. If `applicationStatus == done`, scrape `application-readAppMonitoring` and grep for the migration's success marker (`Running release command`, `Migrating:`, `OK`, `applied`).
3. If `applicationStatus == error`, pull the same logs and surface the migration's stderr — that's almost always why a previously-working app failed to deploy after a schema change.

A successful deploy with a silent migration step is suspicious; verify the migration actually ran rather than no-oped.

## Failure modes

| Symptom | Likely cause | Fix |
|---|---|---|
| `relation "X" does not exist` after deploy | Migration didn't run (mechanism 2 with replicas racing) | Switch to mechanism 1 or single-replica deploy |
| `column "Y" cannot be cast automatically` | Non-backward-compatible migration with mechanism 3 (one-shot after deploy) | Use mechanism 1 or 2 so migration finishes before traffic |
| Deploy succeeds but app still serves old schema | Restart policy isn't picking up the new image | Force a redeploy or verify image ref |
| Migration succeeds locally, fails on Dokploy | Different Postgres version, missing extension | Pin DB image in `postgres-create.dockerImage`, install required extensions explicitly |

## Anti-patterns

- **Running `migrate` in a CI step before pushing the image** — the migration runs against the old code's database, which is whatever DB CI points at, not necessarily prod. Use mechanism 1 or 2 instead.
- **Wrapping `migrate` in `|| true`** — silently absorbing migration failures hides the most important class of deploy failure.
- **Running expensive backfills in `release:`** — release-phase commands block the deploy. Use mechanism 3 + a feature flag for the new code, then run the backfill afterwards.
