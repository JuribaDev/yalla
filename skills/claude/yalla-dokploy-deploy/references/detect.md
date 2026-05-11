# Detection: deciding what the project needs

Read this *before* scanning the working directory. The scan informs every downstream decision; getting it wrong here means asking the user the same questions twenty times.

The detection has three jobs: pick a **build type**, identify the **source** (local repo with a remote, or an existing image reference), and identify **what databases** the app expects to talk to. Then surface every guess as part of the plan.

You can either run the bundled `scripts/detect_stack.py` (preferred — emits one JSON blob) or do the inspection yourself with file reads. The rules below describe what the script is doing, so they're equivalent.

## Shape: single app vs compose

Decide first because it changes everything else.

| Signal | → | shape |
|---|---|---|
| `docker-compose.yml` or `docker-compose.yaml` at repo root | → | `compose` |
| `compose.yml` / `compose.yaml` (modern Docker spelling) | → | `compose` |
| Anything else | → | `single` |

If both a compose file and a Dockerfile exist, that's still `compose` — the compose file is the source of truth, the Dockerfile is a build input it references.

## Build type (single-app shape only)

These rules apply to single-app projects. Compose stacks skip build-type entirely; the compose file already knows.

Check in this order — the first match wins:

1. **`Dockerfile` (or `Dockerfile.<x>`) at repo root** → `dockerfile`
   - Field config: `dockerfile = "./Dockerfile"`, `dockerContextPath = "."`, `dockerBuildStage = null` (or last stage if multi-stage).
   - If multiple Dockerfiles exist, ask the user.
2. **`railpack.json` or `railpack.toml`** → `railpack`
   - Field config: `railpackVersion = "latest"`.
3. **`Procfile` + (`requirements.txt` | `package.json` | `Gemfile` | etc.)** → `heroku_buildpacks`
   - Field config: `herokuVersion = "heroku-22"` (default; stable, broadly compatible).
4. **`project.toml` with `[[io.buildpacks.group]]`** → `paketo_buildpacks`
   - No extra fields; Paketo discovers everything from the project.toml.
5. **`package.json` / `requirements.txt` / `pyproject.toml` / `go.mod` / `Cargo.toml` / `Gemfile`** without any of the above → `nixpacks`
   - Nixpacks is the most forgiving auto-builder. Default for "modern app, no Dockerfile."
6. **Static web build** — only `index.html` at root, OR a `dist/` / `build/` / `public/` / `out/` directory with html assets, no language manifest → `static`
   - Field config: `publishDirectory` = the dir name (defaults to `.`); `isStaticSpa = true` only if a SPA marker is present (`vite.config.*`, `next.config.*` with `output: "export"`, `react-scripts` build, etc.).

If no rule matches, ask the user.

## Source: where the code comes from

Two options. Pick by inspection:

### Image (pre-built docker image)

Use when:
- the user explicitly says "deploy this image", `nginx:alpine`, `ghcr.io/...`, `<registry>/<image>:tag`
- there's no git remote and no Dockerfile (so we can't build, only pull)

Body for `application-saveDockerProvider`:
```json
{
  "applicationId": "...",
  "dockerImage": "nginx:alpine",
  "username": null,
  "password": null,
  "registryUrl": null
}
```
For private registries, the user must supply credentials — ask before guessing.

### Git (remote repo)

Use when:
- `.git/config` resolves an `origin` URL
- the URL is reachable (https + public, or ssh + key on the Dokploy server)

Get the remote with:
```sh
git -C <project> remote get-url origin
git -C <project> rev-parse --abbrev-ref HEAD     # branch name
```

Default to `application-saveGitProvider` (the generic provider). It works for any git URL — public https, public ssh, or ssh with a Dokploy-side SSH key — and doesn't require Dokploy ↔ GitHub OAuth setup.

Body:
```json
{
  "applicationId": "...",
  "customGitUrl": "https://github.com/owner/repo.git",
  "customGitBranch": "main",
  "customGitBuildPath": "/",
  "watchPaths": [],
  "customGitSSHKeyId": null
}
```

If the user's Dokploy has a configured GitHub App and the URL is on `github.com`, switching to `application-saveGithubProvider` enables push-triggered redeploys. Only do this if the user confirms the GitHub App is wired up — otherwise the call needs a `githubId` we don't have.

## Database needs

Scan files for hints. Surface every match as a candidate; let the user accept or reject.

**Critical rule first**: detecting a connection string is **not** the same as wanting Dokploy to provision the database. The skill must distinguish:

- **Local / in-cluster URL** → the user expects Dokploy to run the database → provision it (`<engine>-create` + `-deploy`, wire the connection string).
- **External / managed URL** (RDS, Neon, Supabase, Render, Aiven, public FQDN, any host the user clearly does not want Dokploy to own) → the user wants their app to reach an existing database → **do NOT provision**. Pass the URL through verbatim in `application-saveEnvironment`.

Use the host-classifier rules in `_External vs in-cluster`_ below before adding any DB to `db_needs.provision`.

| Signal | → | engine |
|---|---|---|
| `DATABASE_URL=postgres://` or `postgresql://` in any `.env*` file | → | `postgres` |
| `DATABASE_URL=mysql://` | → | `mysql` |
| `DATABASE_URL=mongodb://` or `MONGO_URL` env | → | `mongo` |
| `REDIS_URL=` env | → | `redis` |
| `prisma/schema.prisma` with `provider = "postgresql"` (or `mysql`, `mongodb`) | → | matching engine |
| Python deps: `psycopg`, `psycopg2`, `asyncpg`, `sqlalchemy[postgresql]` | → | `postgres` |
| Python deps: `pymysql`, `mysqlclient`, `sqlalchemy[mysql]` | → | `mysql` |
| Python deps: `pymongo`, `motor` | → | `mongo` |
| Python deps: `redis`, `aioredis` | → | `redis` |
| Node deps: `pg`, `postgres`, `@vercel/postgres`, `drizzle-orm` w/ pg | → | `postgres` |
| Node deps: `mysql2`, `mysql` | → | `mysql` |
| Node deps: `mongodb`, `mongoose` | → | `mongo` |
| Node deps: `redis`, `ioredis` | → | `redis` |
| Go: `pgx`, `lib/pq` | → | `postgres` |
| Go: `go-redis/redis` | → | `redis` |

Don't auto-add a database the user didn't reference. False positives are worse than false negatives — a missed DB triggers a clean error at runtime, an unwanted DB silently provisions infra.

### External vs in-cluster — when to provision a database

Parse the host out of every detected connection string and classify it. The rules in order:

| Host pattern | Classification |
|---|---|
| `localhost`, `127.0.0.1`, `::1`, `0.0.0.0` | **local-dev** — almost always a placeholder; ask user if they meant a Dokploy-managed DB. |
| Bare hostname with no dots (`db`, `postgres`, `redis`) | **in-cluster** — Docker-Swarm-resolvable service name → assume Dokploy-managed → provision. |
| Hostname ending in `.local`, `.internal`, `.cluster.local`, `.svc.cluster.local` | **in-cluster** → provision. |
| Hostname matching a known managed-DB suffix | **external** → skip provision. The current list: `*.rds.amazonaws.com`, `*.neon.tech`, `*.supabase.co`, `*.supabase.com`, `*.aivencloud.com`, `*.render.com`, `*.railway.app`, `*.planetscale.com`, `*.cockroachlabs.cloud`, `*.fly.dev`, `*.azure.com`, `*.cloud.google.com`, `*.googleapis.com`, `*.mongodb.net` (Atlas), `*.redislabs.com`, `*.upstash.io`. |
| Any other public FQDN (`mydb.example.com`) | **external** → skip provision. |
| RFC1918 IP (`10.*.*.*`, `192.168.*.*`, `172.16-31.*.*`) | **ambiguous** — could be a private external service or in-cluster IP; ask user. |
| Public IP | **external** → skip provision. |

For every connection string, emit one of:

```yaml
db_needs:
  - engine: postgres
    classification: in-cluster
    signal: DATABASE_URL=postgres://db:5432/...
    provision: true       # → calls postgres-create + postgres-deploy
  - engine: postgres
    classification: external
    signal: DATABASE_URL=postgres://prod-db.cluster-xyz.us-east-1.rds.amazonaws.com:5432/...
    provision: false      # → URL passes through as-is
    host: prod-db.cluster-xyz.us-east-1.rds.amazonaws.com
```

The plan must explicitly state the classification for each detected DB ("Provisioning: yes — postgres-create / postgres-deploy" OR "External — pass-through to RDS, no provisioning"). Ambiguous classifications (RFC1918, unrecognised pattern) require user confirmation before execution.

After a successful first deploy, persist the decision so future runs don't re-classify:

```yaml
# .dokploy.yaml (iteration-2)
external_databases:
  - env_var: DATABASE_URL
    host: prod-db.cluster-xyz.us-east-1.rds.amazonaws.com
    engine: postgres
```

## Env vars

Inspect every `.env*` at the repo root (`.env`, `.env.local`, `.env.example`, `.env.staging`, `.env.production`). Parse `KEY=value` pairs.

Categorise each:

- **secret**: keys with names matching `_SECRET`, `_KEY`, `_TOKEN`, `_PASSWORD`, `PRIVATE_KEY`, `STRIPE_*_SECRET`, `OPENAI_API_KEY`, etc. Routes to `application-saveEnvironment.buildSecrets` (Dokploy injects them at build time, not visible in the runtime env).
- **build arg**: keys matching `BUILD_*`, `NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*`. Routes to `buildArgs`.
- **runtime**: everything else. Routes to `env`.

Drop keys whose values are obviously placeholders: `your-key-here`, `change-me`, empty string, `xxx`, etc. Surface them in the plan as "needs value".

Rebind known DB connection strings — if the project will get a Dokploy-provisioned DB, replace the local `DATABASE_URL` with the placeholder `${DATABASE_URL_FROM_DOKPLOY}` and resolve it after the DB is created (see `references/databases.md`).

## State file (existing deployment?)

Before creating anything, look for `.dokploy.yaml` at the repo root. If present, read:

```yaml
project_id: <id>
environments:
  production: <envId>
  staging:    <envId>
applications:
  app: <applicationId>
domain_pattern: "{project}-{env}.example.com"
```

If the file exists, **default to redeploy** (`application-redeploy`) for the existing app/env, not a fresh `application-create`. Show the user what they have and ask whether they want to update or recreate.

## What to surface in the plan

After detection, the user's plan view should include every guess and its source. Example:

```
Detected:
  shape:       single app          (no docker-compose.yml present)
  build type:  nixpacks            (package.json present, no Dockerfile)
  source:      git                 (origin = git@github.com:owner/repo.git)
  branch:      main                (current branch)
  databases:   postgres            (from prisma/schema.prisma + DATABASE_URL=postgres://)
  env vars:    14 total            (3 build args, 9 runtime, 2 secrets)
  state file:  .dokploy.yaml       (NOT FOUND — fresh deploy)
```

Make it easy for the user to override any line.
