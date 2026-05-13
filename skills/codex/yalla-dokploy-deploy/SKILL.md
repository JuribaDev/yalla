---
name: yalla-dokploy-deploy
description: Use when deploying, redeploying, promoting, rolling back, operating, scaling, or tearing down Dokploy projects through yalla; provisioning, scaling, wiring, or backing up databases; configuring domains, env vars, migrations, volumes, notifications, preview deployments, scheduled jobs, or pre-built artifact uploads.
---

# Yalla → Dokploy deploy

End-to-end deploy automation. Inspect the project, plan the deploy, get user confirmation, run the canonical lifecycle through `yalla api call`, verify the result is actually serving traffic.

The skill assumes `yalla` is installed and authenticated. If it isn't, see "Pre-flight" below — give the user the setup snippet and stop.

## Codex Notes

- Use this skill from the repo workspace; resolve reference paths relative to this `SKILL.md`.
- Prefer friendly commands (`yalla database ...`, `yalla auth ...`) before raw `yalla api call` when they cover the requested workflow.
- Keep long operations transparent with short progress updates. For destructive or externally visible actions, show the exact command and get explicit confirmation unless the user already gave clear approval.
- Never write API tokens or generated DB passwords to tracked files. If state must be persisted, use `.dokploy.yaml` for non-secret IDs and `.dokploy.yaml.local` for local-only secret notes.

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
| Tear down (remove everything) | `yalla teardown project --project <name>` (safe cascade, default; `--no-cascade` falls back to raw `project-remove`) | `composite-verbs.md` + `lifecycle.md` § Failure handling |
| Read logs / status | application-readAppMonitoring / application-one | `operations.md` |
| Add/scale/back up a database for an app | `yalla database create/deploy/update/backup ...` → application-saveEnvironment | `databases.md` |

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
> cd /path/to/yalla-repo && go build -o ~/.local/bin/yalla ./cmd/yalla
>
> # 2. Store and verify the Dokploy URL + token
> yalla auth login --url https://your-dokploy.example.com
>
> # Agent/CI-safe alternative:
> printf '%s' "$YALLA_TOKEN" | yalla auth login --url https://your-dokploy.example.com --token-stdin --json
> ```
> This stores the URL in yalla config and the token in the OS credential store by default; see `references/preflight.md`."

Once auth status is good, capture the resolved `organization` from `yalla --json auth whoami` or `yalla --json api call user-get` (the user record carries an `activeOrganizationId`). All subsequent creates land under that org by default.

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

Reach for the composite verbs first — they collapse the ordered API-call list into a single command and stay idempotent under `--get-or-create`. The full surface lives in `references/composite-verbs.md`; the highlights:

- `yalla deploy compose --project <p> --env <e> --compose-file <path> --get-or-create --dry-run` — full compose deploy in one command. Always do `--dry-run` first; it prints the ordered operations it would run so the user can sanity-check before mutating.
- `yalla teardown project --project <p>` — safe cascade teardown that catches orphans Dokploy itself misses.
- `yalla wait compose --id <id> --status done` / `yalla wait url --url <url>` / `yalla wait orphans --app-name <name> --count 0` — replace bespoke polling loops with a single command that returns `E_TIMEOUT` on failure.
- `yalla rescue orphans --app-name <name>` — recover after a stuck or half-deployed stack.
- `yalla audit tail --lines 50` — see exactly what yalla mutated, with the typed envelope per call. Use this when the user asks "what did you change?" or when a deploy went sideways and you need to know what state it left behind.

For single-app deploys (no composite verb yet) and edges the composite commands don't cover, follow the full ordered recipe in `references/lifecycle.md`.

Quick mental model when composite verbs don't apply:

- **Single app**: project → envs → app → source → buildType → env vars → (DB if needed) → domain → deploy
- **Compose** (manual fallback only — prefer `yalla deploy compose`): project → envs → compose → composeFile → env vars → (no provisioned DBs; user owns them in compose) → domain → deploy

Raw mutations have two equivalent forms — `--input <file>` (or `--input -` for stdin) and `--data '<inline-json>'` for short bodies. The `--data` form auto-wraps a bare object as the request body, so you don't have to write `{"body":{...}}` by hand. Capture the `--json` envelope per step and inspect `.data.body` for returned IDs; also check `.data.warnings[]` — a non-fatal `APPNAME_MUTATED` warning means Dokploy renamed your service and the in-cluster hostnames you planned for will not resolve. Re-run with `--strict-appname` to make that fail loud.

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

yalla returns stable typed error codes. Branch on the `code` field of the error doc, not just the exit-code integer:

- **E_AUTH**: token expired or wrong. Tell the user to run `yalla auth login --url <url>` again, or pipe a fresh token with `--token-stdin`.
- **E_INVALID_INPUT**: the body shape was wrong. Re-fetch `yalla --json schema get <op>` and adjust. Don't keep retrying with the same body.
- **E_NOT_FOUND**: an upstream resource (org, env, app) doesn't exist. Refetch the parent and retry once.
- **E_CONFLICT**: name already exists in the same scope. Re-run with `--get-or-create` (raw `api call` or `yalla deploy compose`) to adopt the existing record instead of failing.
- **E_FORBIDDEN**: token is valid but lacks permission for this org/resource. Don't retry — surface to the user.
- **E_ORPHAN**: a previous run left Docker resources Dokploy can no longer see. Run `yalla rescue orphans --app-name <name>`, then `yalla wait orphans --app-name <name> --count 0`, then retry.
- **E_UPSTREAM_BUG**: a known Dokploy bug fired (catalogued in `internal/dokploy/known_issues.yaml`). The error doc carries a `workaround` field — follow it. Don't loop on the same call.
- **E_RATE_LIMITED**: back off; resume after the suggested delay.
- **E_NO_INPUT_REQUIRED**: you passed `--no-input` but the operation needs a body. Provide `--input` or `--data`.
- **E_UNSUPPORTED**: this Dokploy build doesn't expose the operation. Don't loop — tell the user.
- **E_NETWORK / E_TIMEOUT**: surface to user, don't auto-retry mutations.

Non-fatal warnings (HTTP 2xx with a `warnings[]` entry in the envelope):

- **APPNAME_MUTATED**: Dokploy renamed your service after `compose-create`. Either accept the new `appName` and re-wire env vars to it, or retry with `--strict-appname` to make this fail loud.

For partial deploys (project created, app/compose failed), prefer `yalla teardown project --project <name> --dry-run` to preview cleanup, then re-run without `--dry-run`. That command catches orphans the raw `project-remove` leaves behind.

When you can't tell what yalla actually changed, run `yalla audit tail --lines 50` — it shows the exact ordered mutations with operation IDs, request IDs, and response codes.

## References — read these as needed

| File | When to read |
|---|---|
| `references/composite-verbs.md` | Before executing — composite commands (`yalla deploy compose`, `yalla teardown project`, `yalla wait *`, `yalla rescue orphans`, `yalla audit tail`) plus the `--data` / `--get-or-create` / `--strict-appname` ergonomics on raw `api call`. Read this any time you would otherwise hand-orchestrate `yalla api call` steps. |
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
