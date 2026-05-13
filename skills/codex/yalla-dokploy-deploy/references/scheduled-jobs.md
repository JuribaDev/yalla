# Scheduled jobs: cron, nightly batches, periodic tasks

Use this when the user wants to deploy a **periodic task**, not a long-running web service. Examples: nightly DB cleanup, hourly cache warmer, daily report generator, weekly billing job.

## How Dokploy models scheduled jobs

A scheduled job is **a schedule attached to an application's image**. You still need an application (carrier) to produce the image; the schedule just declares "run this command in that container's environment at this cron expression."

That means the deploy flow is **two-phase**:
1. **Carrier application**: a normal `application-create` + source + buildType + (one-time) `application-deploy`. This produces the image. **No domain**, **no replicas**, **no health check** — the container's job is to be the build artifact, not to serve traffic.
2. **Schedule**: `schedule-create` referencing the carrier app's ID + the cron expression + the command to run.

The carrier deploys once. The schedule runs the configured command in a fresh ephemeral container every fire.

## Op family

| Op | Purpose |
|---|---|
| `schedule-create` | Create a schedule on an application or compose service |
| `schedule-update` | Modify cron, command, enabled, timezone |
| `schedule-list` | List all schedules in the org |
| `schedule-one` | Read a schedule's config + last-run status |
| `schedule-runManually` | Trigger a one-shot run outside the schedule (smoke test) |
| `schedule-delete` | Remove a schedule (does NOT remove the carrier app) |

## `schedule-create` body

```json
{
  "body": {
    "name": "nightly-cleanup",
    "cronExpression": "30 2 * * *",
    "shellType": "bash",
    "command": "node cleanup.js",
    "scheduleType": "application",
    "applicationId": "<carrier-app-id>",
    "appName": "<carrier-app-name>",
    "enabled": true,
    "timezone": "UTC",
    "description": "Delete records older than 90 days"
  }
}
```

Fields:
- `cronExpression`: standard 5-field cron (`min hr dom mon dow`). Use `crontab.guru` to validate; explain the schedule to the user in plain English in the plan.
- `shellType`: `"bash"` or `"sh"`. Bash for anything beyond trivial; sh for alpine-based images without bash installed.
- `command`: the shell command run inside the carrier's container. The image's `WORKDIR` + env are inherited; the command runs as `${shellType} -c "<command>"`.
- `scheduleType`: `"application"` for apps, `"compose"` for compose services (then use `composeId` instead of `applicationId`, and `serviceName` for which service in the compose to run).
- `appName`: the carrier's auto-generated swarm service name (recoverable via `application-one`).
- `enabled`: `true` to start the schedule immediately; `false` to create it paused.
- `timezone`: explicit timezone for the cron interpretation. Default `"UTC"` — always set this; relying on host timezone breaks the moment the Dokploy server is migrated.

## Order of operations

```
1. project-create (or reuse existing)
2. environment-create (production / staging — even if there's no domain, the env scopes resources)
3. application-create  ← the carrier
4. application-save<Source>Provider
5. application-saveBuildType
6. application-saveEnvironment  ← env vars the cron command will need (DATABASE_URL, etc.)
7. application-deploy  ← one-time build; poll until `done`
   (NO domain-create — this is a scheduled job, not a web service)
8. schedule-create  ← attach the cron
9. schedule-runManually  ← smoke test the command once before letting cron fire
```

For the verification, after step 8:
- `schedule-list` to confirm the schedule shows up.
- `schedule-runManually` to test-fire the command immediately. Then `application-readAppMonitoring` to confirm the command actually executed.

## What the lifecycle skips

Compared to a web-service deploy:
- ❌ `domain-create` — there's no public endpoint to attach.
- ❌ HTTP probe in verification — see `verification.md` § "When status is `done` but the app has no public endpoint."
- ❌ Replicas — schedules run a single container per fire; `replicas` on the carrier is irrelevant for the schedule itself.
- ❌ Health-check — the carrier never "serves"; it just exists as a build target.

The skill should explicitly call these out in the plan so users don't expect a URL.

## Multiple schedules per app

You can attach multiple schedules to the same carrier app — different cron + different command per schedule. Useful when one image has multiple periodic tasks (a CLI tool with subcommands):

```yaml
# .dokploy.yaml
schedules:
  - name: nightly-cleanup
    id: SCHED-1
    cron: "30 2 * * *"
    command: "node cleanup.js"
  - name: hourly-cache-warm
    id: SCHED-2
    cron: "0 * * * *"
    command: "node warm-cache.js"
```

Each schedule fires independently; collisions (two cron fires overlap) result in two concurrent containers — usually fine, but for non-idempotent jobs the user should add their own locking.

## Cron expression sanity

Common patterns and what to write:
- "Every night at 2:30 UTC" → `30 2 * * *`
- "Every hour at :00" → `0 * * * *`
- "Every 15 minutes" → `*/15 * * * *`
- "Every weekday at 9:00" → `0 9 * * 1-5`
- "First day of every month at midnight" → `0 0 1 * *`

The plan should always include a plain-English translation:

> "Schedule: `30 2 * * *` → every day at 02:30 UTC."

Schedules with seconds-resolution (`* * * * * *` six-field) are NOT supported — Dokploy's cron parser is standard 5-field.

## Updating, pausing, deleting

```sh
# Pause without deleting (don't fire any more, keep the config)
yalla --json --no-input api call schedule-update --input <(echo "{\"body\":{\"scheduleId\":\"$SCHED_ID\",\"enabled\":false}}")

# Change cron expression
yalla --json --no-input api call schedule-update --input <(echo "{\"body\":{\"scheduleId\":\"$SCHED_ID\",\"cronExpression\":\"0 4 * * *\"}}")

# Delete schedule (keeps the carrier app)
yalla --json --no-input api call schedule-delete --input <(echo "{\"body\":{\"scheduleId\":\"$SCHED_ID\"}}")
```

To delete BOTH the schedule and its carrier, run `schedule-delete` first, then `application-delete`.

## Tear-down ordering

When tearing down a project with schedules:

```
1. schedule-list and grep for the project's app IDs
2. schedule-delete each schedule
3. project-remove (cascades to apps + envs + domains + DBs)
```

If you skip step 2, `project-remove` succeeds, but the schedules become orphans — they reference a deleted app ID, fail to fire, and accumulate as zombie records. Always clean up schedules before `project-remove`.

## When to use compose-shape vs single-shape

For a single periodic job → single-app carrier (most common).

For a project that has both a long-running web service AND periodic tasks that share the image → still single-app: one application, one image, one schedule per task, all referencing the same carrier. Don't split web + worker into a compose stack just because there's a schedule.

For a compose stack with periodic tasks running on a specific compose service → `schedule-create` with `scheduleType: "compose"`, `composeId`, `serviceName`. Same shape, different parent.

## Anti-patterns

- **Treating schedules as a long-running daemon**: `cronExpression: "* * * * *"` (every minute) is technically valid but signals the user really wants a long-running process. Probably they should `application-deploy` a normal app instead.
- **Forgetting `timezone`**: cron interpretations drift with daylight saving when timezone is left blank. Always set it.
- **Putting secrets in `command`**: the command string is stored in plaintext and visible in `schedule-one`. Put secrets in `application-saveEnvironment` and reference them via env vars: `command: "node cleanup.js"` (the script reads `$API_KEY`).
- **Multiple schedules with overlapping cron expressions and non-idempotent commands**: at 02:00 UTC, both fire, two containers race the same operation. Either staggered cron (`30 2 * * *` and `45 2 * * *`) or a host-side lockfile.
