---
name: yalla-dokploy-deploy
description: Deploy and manage apps on yalla — the user's CLI for Dokploy. Use this skill whenever the user wants to ship, deploy, launch, redeploy, promote staging→prod, rollback to a previous image/commit, stop, start, restart, or tear down a project; upload a pre-built artifact / drop a zip / ship a local dist/ or build/ folder onto Dokploy; configure a domain (Let's Encrypt, custom cert, custom path); provision a database (postgres/mysql/mongo/redis) or pass-through an external one (RDS/Neon/Supabase); run schema migrations; scale replicas + resource limits; attach persistent volumes; wire deploy notifications (Slack/Discord/email); set up PR preview deployments; or schedule cron jobs. Trigger words include: "deploy", "ship", "launch", "make it live", "redeploy", "promote", "roll back", "stop the app", "restart the app", "tear down", "add a database", "set up yalla", "yalla deploy", ".yalla.yaml", "drop this zip", "upload my build", "ship this dist folder", "I already built it locally". Also trigger on Arabic / Arabizi: "انشر", "اعمل deploy", "ارجع", "وقف", "ركّب", "خليه يطلع للناس", "يلا deploy", "اعمل redeploy", "ارفع الـ zip", "ارفع البيلد", "اعمل drop". If the user is in a code project and wants to publish, change, observe, or revert a running service, this is the right skill — even if they don't say the word "yalla". Skip only for deploys targeting other platforms (Vercel, Railway, Render, Fly, DigitalOcean App Platform), local Docker debugging that doesn't include a deploy, CI/CD pipeline authoring (GitHub Actions, GitLab CI), or general infrastructure cost comparisons.
---

# Yalla → Dokploy deploy

End-to-end deploy automation. Inspect the project, plan the deploy, get user confirmation, run the canonical lifecycle through `yalla api call`, verify the result is actually serving traffic.

The skill assumes `yalla` is installed and authenticated. If it isn't, see "Pre-flight" below — give the user the exact two-line setup and stop.

## When to do what

This skill covers **nine intents**. Each maps to a different workflow:

| User intent | Workflow | Reference |
|---|---|---|
| Fresh deploy (most common) | detect → plan → confirm → execute → verify → report | this file + `lifecycle.md` |
| Drop a pre-built artifact (zip) onto an app | (project+env+app if missing) → saveBuildType → `application-dropDeployment` (multipart) → verify | `drop-deploy.md` |
| Redeploy existing project | read state file → application-redeploy → verify | `lifecycle.md` § State file |
| Promote staging → production | mirror source/buildType, apply target-env vars, deploy in target env | `promotion.md` |
| Rollback to previous version | swap source pointer to previous image/commit → application-redeploy | `rollback.md` |
| Stop / start / restart | application-stop / application-start / application-reload | `operations.md` |
| Tear down (remove everything) | project-remove (cascades) | `lifecycle.md` § Failure handling |
| Read logs / status | application-readAppMonitoring / application-one | `operations.md` |
| Add a database to an existing app | `<engine>-create` → `<engine>-deploy` → application-saveEnvironment | `databases.md` |

**Detect the user's intent first** by reading the prompt plus the state file:

- Words like "deploy", "ship", "launch", "make it live" + no state file → **fresh deploy**
- "Drop this zip", "upload my build", "ship this dist/ folder", "I built it locally already", or a path to a `.zip` / pre-built artifact in the prompt → **drop-deploy** (`references/drop-deploy.md`). Also pick drop when the user has a `dist/` / `build/` / `out/` folder but no Dockerfile and no reachable git origin Dokploy could clone.
- Same words + state file present → **redeploy** (unless the user names a new target env, then → promote)
- "Promote", "ship to prod", "move staging to production" → **promotion**
- "Roll back", "revert the deploy", "undo last deploy", "previous version" → **rollback** (a drop-deploy app has no server-side rollback — see `drop-deploy.md`)
- "Stop", "pause", "shut down (without removing)" → **stop**
- "Start", "resume", "bring it back up" → **start**
- "Restart", "reload", "pick up env change" → **reload**
- "Tear down", "remove everything", "delete the deployment" → **tear-down**
- "Logs", "what's running", "why is it broken" → **status / logs**

When ambiguous, ask. The wrong workflow is destructive — `project-remove` can't be undone, a rollback against the wrong env wipes traffic.

## The fresh-deploy flow

The flow is always:

1. **Pre-flight** — verify `yalla` works and the user is authenticated.
2. **Detect** — read the project to figure out the build type, source, db needs, env vars, and whether it's single-app or compose.
3. **Plan** — show the user a concise plan with everything that will be created. Include the exact `yalla` calls.
4. **Confirm** — the user approves with a clear yes. Don't run mutations otherwise.
5. **Execute** — run the lifecycle in order. Stop on first failure and report.
6. **Verify** — poll status until `done`/`error`, curl the live URL, surface result.
7. **Report** — give the user the live URL, the project/env/app IDs, and how to redeploy or tear down.

Each step is detailed below. For per-build-type config and per-resource API shapes, follow the pointers into `references/`.

## Pre-flight

Run these checks before anything else:

```sh
yalla --version            # binary exists and runs
yalla --json auth status   # ready: true (token + base_url present)
```

If `yalla` isn't on PATH or `ready: false`, **stop and emit setup instructions** rather than trying to fix it implicitly:

> Tell the user: "I need `yalla` set up first. The simplest path:
> ```sh
> # 1. Build (one-time, requires Go 1.24+)
> cd /path/to/yalla-claude && go build -o ~/.local/bin/yalla ./cmd/yalla
>
> # 2. Persist your Dokploy URL (not secret)
> yalla config set base_url https://your-dokploy.example.com
>
> # 3. Store the API token in Keychain (macOS)
> security add-generic-password -s yalla -a "$USER" -w 'YOUR_TOKEN' -U
> ```
> Plus add a `yalla()` shell wrapper that pulls from Keychain — see `references/preflight.md`."

Once auth status is good, capture the resolved `organization` from `yalla --json api call user-get` (the user record carries an `activeOrganizationId`). All subsequent creates land under that org by default.

## Detect

Inspect the working directory to fill out a `DeployPlan`. The detection rules live in `references/detect.md` — read that file before scanning. The plan has these fields, in this order:

```
project_name        # default: basename of cwd, normalised (lowercase, dashes)
shape               # "single" | "compose"
build_type          # dockerfile | nixpacks | railpack | heroku_buildpacks | paketo_buildpacks | static
source              # git | image | drop          (drop = pre-built zip, see drop-deploy.md)
source_config       # git/image: URL+branch / image ref. drop: {zip_path, drop_build_path}
env_vars            # parsed from local .env*; secrets vs build-args
db_needs            # [] | [{engine: postgres|mysql|mongo|mariadb|redis, reason: "DATABASE_URL=postgres://..."}]
environments        # ["production", "staging"]  (skill always sets up both)
target_env          # which env this run deploys to (default: staging unless user says prod)
domain              # auto-named: {project}-{env}.{base-host}  (override via user input)
```

The detection logic is heuristic — surface every assumption in the plan and let the user correct any of it before execution. Never silently guess and execute. See `references/detect.md` for the rules.

## Plan

Render a compact, scannable plan to the user. The required fields:

```
PLAN — deploy <project_name> to <target_env>

Project       <project_name> (will be created in org <org_id>)
Environments  production + staging (creating staging if missing)
Source        <source>: <source_config>
Build type    <build_type> (detected from <reason>)
Env vars      <count> from .env  (X build args, Y runtime, Z secrets)
Databases     <none | postgres named '<project>-db' | …>
Domain        https://<project>-<target_env>.<base-host>  (Let's Encrypt)
Verify        poll application-one until status=done; HTTP probe domain (expect 2xx)

Yalla calls in order:
  1. project-create
  2. environment-create (staging)
  3. application-create
  4. application-saveGitProvider | application-saveDockerProvider
  5. application-saveBuildType
  6. application-saveEnvironment
  ...
```

End with: **"Proceed? (yes / edit <field>)"** Wait for explicit approval.

If the user says "edit X", re-render the plan with the change and ask again.

## Execute

Run the canonical sequence. The full ordered API-call recipe — including what to do if a step fails midway — is in `references/lifecycle.md`. Read it before executing.

Quick mental model:

- **Single app**: project → envs → app → source → buildType → env vars → (DB if needed) → domain → deploy
- **Compose**: project → envs → compose → composeFile → env vars → (no provisioned DBs; user owns them in compose) → domain → deploy

Every mutation goes through `yalla --json --no-input api call <op> --input <json>`. Capture the `--json` envelope and inspect `.data.body` for the returned IDs.

A few non-obvious bits the references cover:

- POST mutations often return `{}` — re-list (`project-all`, `project-one`) to recover the new ID.
- Build types take **every** field in the schema; pass `null` for the ones that don't apply to your chosen type. See `references/build-types.md` for the per-type body templates.
- DB connection strings need the DB's `appName` (auto-generated), recoverable via `<engine>-one`. See `references/databases.md`.
- Env vars use a multi-line `KEY=value\n…` string under `application-saveEnvironment.env`. See `references/sources.md` for parsing.

## Verify

Don't declare success on `application-deploy` returning 200 — that just queues a build. Verification is a two-step check:

1. **Status poll**: `application-one` (or `compose-one`) every 3s until `applicationStatus ∈ {done, error}` or 5 minutes elapse. Show the user the status transitions.
2. **HTTP probe**: once status is `done`, `curl -s -o /dev/null -w "%{http_code}"` the domain. Expect 2xx, 3xx, or 401/403 (a healthy app behind auth still counts as "live"). 5xx or connection refused = unhealthy; surface logs via `application-readAppMonitoring`.

Verification details (timeouts, retry policy, what "healthy" means for static sites) live in `references/verification.md`.

## Report

End the run with three things:

```
✅ <project>-<env> is live
   URL:           https://<project>-<env>.<base-host>
   Project ID:    <projectId>
   App ID:        <applicationId>
   Final status:  done (Xs)

To redeploy:        yalla api call application-redeploy --input ...
To tear down:       yalla api call project-remove --input ...
To watch logs:      yalla api call application-readAppMonitoring --input ...
```

Save the IDs into `.dokploy.yaml` at the repo root if it doesn't exist (so future skill invocations can find the project without listing every time). The exact format is in `references/lifecycle.md` under "State file".

## Failure handling

If any mutation returns a non-2xx exit code:
- **E_AUTH (4)**: token expired or wrong. Tell user to re-store via Keychain.
- **E_INVALID_INPUT (2)**: the body shape was wrong. Re-fetch `yalla --json schema get <op>` and adjust. Don't keep retrying with the same body.
- **E_NOT_FOUND (5)**: an upstream resource (org, env, app) doesn't exist. Refetch the parent and retry once.
- **E_NETWORK / E_TIMEOUT**: surface to user, don't auto-retry mutations.

For partial deploys (project created, app failed), offer a "rollback?" (run `project-remove` to clean up) so the user isn't left with orphaned resources.

## References — read these as needed

| File | When to read |
|---|---|
| `references/preflight.md` | If `yalla --version` fails or `auth status` is not ready, or user asks how to install yalla. |
| `references/detect.md` | Always before scanning a project. The detection heuristics + decision tree + external-DB host classifier. |
| `references/build-types.md` | Before calling `application-saveBuildType` — minimal-correct body per build type. |
| `references/sources.md` | Before configuring source — git provider vs docker image vs drop, env-var parsing rules. |
| `references/drop-deploy.md` | When `source == drop` (pre-built artifact / zip upload). Covers the `application-dropDeployment` multipart shape, `dropBuildPath` semantics, redeploy/rollback caveats, and the dry-run safety guarantee. |
| `references/databases.md` | If `db_needs` is non-empty — DB creation + connection-string wiring. |
| `references/lifecycle.md` | Before executing fresh deploys — full call order, idempotency rules, state file. |
| `references/verification.md` | After deploy — polling + HTTP probe + log retrieval. |
| `references/promotion.md` | When the user wants to ship code from one env (e.g. staging) into another (e.g. prod) without recreating the project. |
| `references/migrations.md` | When the project needs to run schema migrations / pre-deploy hooks (Procfile `release:`, Prisma, Django, Alembic, etc.). |
| `references/rollback.md` | When the user wants to revert to a previous image/commit because the latest deploy broke. |
| `references/operations.md` | For stop / start / restart / logs / status — day-2 ops that don't redeploy. |
| `references/notifications.md` | When the user wants Slack/Discord/email/Telegram alerts on deploy events. Notifications are org-scoped, event-boolean-gated — non-obvious. |
| `references/mounts.md` | When the app needs persistent storage (named volume, bind mount, or file mount). Op is plural `mounts-create`. |
| `references/preview-deployments.md` | When the user wants per-PR ephemeral preview envs (`<project>-pr-<num>.preview.host`). Requires GitHub App + wildcard DNS. |
| `references/scaling.md` | When the user wants replicas > 1, memory/CPU limits, multi-server placement, or custom health checks. Single op: `application-update`. |
| `references/scheduled-jobs.md` | When the deploy target is a cron job / periodic task, not a long-running web service. Carrier app + `schedule-create` pattern. |

## Style

- Show concrete `yalla` commands the user could re-run themselves. Don't hide the calls.
- Capture the resolved IDs in the chat for traceability — even if you also persist them.
- Be honest about heuristics. "I detected Nixpacks because there's a `package.json` and no Dockerfile" is better than "I'm using Nixpacks."
- Never persist the Dokploy token to repo files. The state file (`.dokploy.yaml`) holds IDs and base URL only.
