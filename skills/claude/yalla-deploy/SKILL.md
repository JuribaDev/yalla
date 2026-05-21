---
name: yalla-deploy
description: Use when deploying, redeploying, promoting, rolling back, operating, scaling, backing up, restoring, or tearing down applications and services through yalla; configuring projects, environments, services, build settings, domains, env vars, migrations, volumes, notifications, preview deployments, scheduled jobs, databases, or pre-built artifact uploads.
---

# Yalla deploy

End-to-end Yalla deployment automation. Inspect the project, plan the deployment,
get user confirmation, run first-class `yalla` commands, verify the result is
actually serving traffic, and report the stable Yalla resource IDs.

The skill assumes `yalla` is installed and authenticated against the Yalla API.
If it is not ready, follow "Pre-flight" and stop after giving setup instructions.

## Intent map

| User intent | Workflow | Reference |
|---|---|---|
| Fresh deploy | detect -> plan -> confirm -> project -> environment -> service -> build config -> deploy -> verify -> report | `lifecycle.md` |
| Static site deploy | service create/set build config with `--build-type static` -> deploy -> verify | `build-types.md` + `lifecycle.md` |
| Dockerfile deploy | service create/set build config with `--build-type dockerfile` -> deploy -> verify | `build-types.md` + `sources.md` |
| Compose deploy | service create with `--kind compose --build-type compose` -> deploy -> verify | `lifecycle.md` |
| Image deploy | service create/set build config with `--build-type image` -> deploy -> verify | `sources.md` |
| Redeploy existing service | read `.yalla.yaml` -> `yalla service deploy --wait` -> verify | `lifecycle.md` |
| Promote staging to production | mirror build config and source into the target environment -> deploy target service -> verify | `promotion.md` |
| Rollback | set previous image/tag/commit in the Yalla build config -> deploy -> verify | `rollback.md` |
| Stop / start / restart / logs | use Yalla service operation/status/log commands when available; otherwise stop and report the missing command | `operations.md` |
| Tear down | `yalla project delete --project-id <id> --wait` after explicit confirmation | `lifecycle.md` |
| Database backup or restore | `yalla database backup run --wait` or `yalla database backup restore --wait` | `databases.md` |

## Pre-flight

```sh
yalla --version
yalla --json auth status
yalla --json auth whoami
```

If `yalla` is missing or `ready` is false, stop and tell the user:

```sh
cd /path/to/yalla-repo && /opt/homebrew/bin/go build -o ~/.local/bin/yalla ./cmd/yalla
printf '%s' "$YALLA_TOKEN" | yalla auth login --url https://your-yalla-api.example.com --token-stdin --json
yalla --json auth status
```

Never write tokens, generated passwords, or secret notes to tracked files.

## Plan

Read the relevant reference, inspect the repo and `.yalla.yaml`, then show a
reviewable plan with assumptions, stable IDs, and exact commands:

```text
Yalla commands in order:
  1. yalla project create --project-id <project_id> --name <project_name> --json
  2. yalla environment create --environment-id <environment_id> --project-id <project_id> --name <environment_name> --json
  3. yalla service create --service-id <service_id> --environment-id <environment_id> --name <service_name> --kind <application|compose> --build-type <static|dockerfile|compose|image> ... --json
  4. yalla service deploy --service-id <service_id> --wait --json
  5. yalla database backup run --service-id <database_service_id> --backup-id <backup_id> --wait --json
```

Ask `Proceed?` before mutations unless the current user request already gives
clear approval. Ask again for destructive work.

## Execute and verify

Prefer first-class Yalla commands. Use `yalla service build set` when build
configuration changes, then `yalla service deploy --wait --json`. For backup and
restore, use the wait-enabled database backup commands.

```sh
yalla service deploy --service-id <service_id> --wait --timeout 10m --json
yalla wait job --job-id <job_id> --json
curl -fsS https://<host>/healthz
```

Raw `yalla api call ...` belongs only in a clearly marked unsupported edge when
a public Yalla command is unavailable and the user approves follow-up work.

## Report

```text
Yalla deployment complete
URL:            https://<host>
Project ID:     <project_id>
Environment ID: <environment_id>
Service ID:     <service_id>
Final job:      <job_id> succeeded

Redeploy:       yalla service deploy --service-id <service_id> --wait --json
Tear down:      yalla project delete --project-id <project_id> --wait --json
Backup:         yalla database backup run --service-id <database_service_id> --backup-id <backup_id> --wait --json
```

Persist non-secret IDs in `.yalla.yaml`; use `.yalla.yaml.local` only for
untracked local notes.

## References

- `preflight.md`: install/auth setup.
- `detect.md`: repo inspection and build-type choice.
- `build-types.md`: static, dockerfile, compose, and image build config.
- `sources.md`: git, image, and artifact source handling.
- `databases.md`: database create, backup, and restore.
- `lifecycle.md`: fresh deploy, redeploy, state file, teardown.
- `verification.md`: wait, job, and HTTP checks.
- `promotion.md`, `rollback.md`, `operations.md`: day-2 workflows.
- `migrations.md`, `mounts.md`, `notifications.md`, `preview-deployments.md`,
  `scaling.md`, `scheduled-jobs.md`: unsupported-edge rule and requirements.
