# Promotion: shipping the same code to a different environment

Use this when the user has a deployed staging (or any) environment and wants the **same code** in a different environment with **different env vars**. The classic case: "promote staging to prod."

## What promotion is and isn't

Promotion **reuses**:
- The same `project_id`
- The same source (git URL + branch OR docker image ref)
- The same `buildType` (with its per-type config)
- The build that staging already produced (Dokploy will rebuild from the same commit, but the inputs match)

Promotion **does not reuse**:
- The same `application` — each environment has its own app instance with its own runtime state
- The same env vars — most apps need different `DATABASE_URL`, `NODE_ENV`, `SENTRY_ENV`, secrets per env
- The same domain — `api-staging.example.com` → `api.example.com` (or whatever)

If the user wants to redeploy the same env they already have, that's a **redeploy**, not a promotion — see `lifecycle.md` § "State file" and use `application-redeploy`.

## Pre-conditions

Promotion only makes sense when the state file confirms the source env exists:

```yaml
# .dokploy.yaml (iteration-1 schema)
project_id: PROJ-…
environments:
  staging: ENV-STG-…
  production: ENV-PROD-…
applications:
  app: APP-STG-…           # only the source env has an app today
```

If `.dokploy.yaml` is missing or doesn't have the source app, this is a fresh deploy, not a promotion.

## State-file schema extension (iteration-2)

To support multiple environments at once, the state file evolves to:

```yaml
schema: yalla.dokploy.v2
project_id: PROJ-…
project_name: …
environments:
  production: ENV-PROD-…
  staging: ENV-STG-…
applications:
  staging: APP-STG-…              # per-environment app IDs
  production: APP-PROD-…          # may be empty before first promotion
domains:
  staging: api-staging.example.com
  production: api.example.com
source:                            # shared across envs; promotion reuses
  provider: git                    # or docker
  url: https://github.com/owner/repo.git
  branch: main
build_type: nixpacks               # shared; rebuilt per env
last_deploy_per_env:
  staging:    { at: 2026-05-09T…, status: done }
  production: { at: 2026-05-11T…, status: done }
```

Skill operations stay backward-compatible: if a state file uses `applications.app` (iteration-1 schema), treat it as `applications.<source_env>` and migrate the YAML on save.

## Promotion workflow

Source env = where the working code lives today (usually staging). Target env = where the code is going (usually production).

```
1. Pre-flight + read state
2. Refetch state from Dokploy (`project-one`) to confirm the source app + target env exist
3. If applications.<target_env> already exists in state, this is a REDEPLOY, not a promotion → bail to lifecycle.md § Redeploy
4. Read source app config via `application-one` (input: applicationId = applications.<source_env>)
   - Capture: source provider type + URL/image, buildType + per-type config, current env, current buildArgs, current buildSecrets
5. Compose target-env vars
   - Start from local .env.<target_env> if it exists (e.g. .env.production)
   - Otherwise prompt the user for the per-env divergence (DATABASE_URL, NODE_ENV, etc.)
   - Keep all other vars from the source app's env unless overridden
6. Create the target app
   - application-create (name = <project>, environmentId = <target_env_id>)
7. Mirror the source config
   - application-save<Source>Provider with the SAME url/branch/image (NOT a new URL)
   - application-saveBuildType with the SAME buildType + config
   - application-saveEnvironment with the TARGET-env-specific env/buildArgs/buildSecrets
8. (Optional) Provision target-env-specific databases
   - If db_needs has external URLs → skip (per detect.md external-db rule)
   - Otherwise: <engine>-create + <engine>-deploy for target env, then re-call application-saveEnvironment to wire connection strings
9. Domain
   - Default: `<project>.<base-host>` for production, `<project>-<env>.<base-host>` for others
   - Override via user input
10. Deploy
    - application-deploy on the target app
11. Verify (same two-phase: status poll + HTTP probe)
12. Persist
    - Update .dokploy.yaml: applications.<target_env> = <new-id>, domains.<target_env> = <host>, last_deploy_per_env.<target_env> = {…}
```

## Worked example: staging → production, two divergent env vars

State file says staging is live. User wants prod with `NODE_ENV=production`, real DB URL, and Sentry env switched.

```sh
# Read source app to capture provider + buildType
SRC_APP_ID="APP-STG-CCC"
TGT_ENV_ID="ENV-PROD-AAA"
yalla --json api call application-one --input <(echo "{\"query\":{\"applicationId\":[\"$SRC_APP_ID\"]}}") > /tmp/src.json

# Extract reusable pieces (manual or jq)
SRC_GIT_URL=$(jq -r '.data.body.customGitUrl // .data.body.repository' /tmp/src.json)
SRC_BRANCH=$(jq -r '.data.body.customGitBranch // .data.body.branch' /tmp/src.json)
SRC_BUILDTYPE=$(jq -r '.data.body.buildType' /tmp/src.json)

# Create the target app
yalla --json --no-input api call application-create --input <(echo "{\"body\":{\"name\":\"$PROJECT\",\"environmentId\":\"$TGT_ENV_ID\"}}")
TGT_APP_ID=$(yalla --json api call project-one --input <(echo "{\"query\":{\"projectId\":[\"$PROJ_ID\"]}}") | jq -r ".data.body.environments[] | select(.environmentId==\"$TGT_ENV_ID\") | .applications[] | select(.name==\"$PROJECT\") | .applicationId")

# Mirror source: same git, same buildType
yalla --json --no-input api call application-saveGitProvider --input <(echo "{\"body\":{\"applicationId\":\"$TGT_APP_ID\",\"customGitUrl\":\"$SRC_GIT_URL\",\"customGitBranch\":\"$SRC_BRANCH\",\"customGitBuildPath\":\"/\",\"watchPaths\":[],\"customGitSSHKeyId\":null,\"enableSubmodules\":false}}")

yalla --json --no-input api call application-saveBuildType --input <(echo "{\"body\":{\"applicationId\":\"$TGT_APP_ID\",\"buildType\":\"$SRC_BUILDTYPE\",\"dockerfile\":null,\"dockerContextPath\":null,\"dockerBuildStage\":null,\"herokuVersion\":null,\"railpackVersion\":null,\"publishDirectory\":null,\"isStaticSpa\":null}}")

# Apply prod-specific env (read .env.production locally and concatenate)
ENV_BLOB=$(cat .env.production | grep -v '^#' | grep '=')
yalla --json --no-input api call application-saveEnvironment --input <(jq -n --arg appId "$TGT_APP_ID" --arg env "$ENV_BLOB" '{body:{applicationId:$appId,env:$env,buildArgs:"",buildSecrets:"",createEnvFile:true}}')

# Domain + deploy + verify
yalla --json --no-input api call domain-create --input <(echo "{\"body\":{\"host\":\"$PROJECT.$BASE_HOST\",\"path\":\"/\",\"port\":3000,\"https\":true,\"applicationId\":\"$TGT_APP_ID\",\"certificateType\":\"letsencrypt\",\"customCertResolver\":null,\"composeId\":null,\"serviceName\":null,\"domainType\":null,\"previewDeploymentId\":null,\"internalPath\":null,\"stripPath\":false}}")
yalla --json --no-input api call application-deploy --input <(echo "{\"body\":{\"applicationId\":\"$TGT_APP_ID\",\"title\":\"yalla-skill: promote staging→production\"}}")
```

## Promotion mistakes to avoid

- **Don't touch the source app.** The whole point is the source keeps running while the target gets created. Never call `application-redeploy` / `application-delete` / `application-stop` on the source mid-promotion.
- **Don't reuse the source's `applicationId` for the target.** Each env has its own resource. Wiring one app to two envs is unsupported by the schema.
- **Don't copy the source env vars verbatim into prod.** The whole reason for separate envs is divergent secrets/URLs. If `.env.production` doesn't exist locally, surface that and ask before proceeding.
- **Don't auto-provision a fresh DB on every promotion.** If the user's prod app already uses RDS/Supabase (external host in `DATABASE_URL`), the target-env DB creation must be skipped — see `detect.md` § External managed databases.

## Rollback after a bad promotion

If the target deploy fails, the source env is still healthy — no rollback needed there. Two options for the target:

1. **Tear down the target app**: `application-delete` with the target `applicationId`. Keep the env, project, and source app intact. State file: clear `applications.<target_env>` and `domains.<target_env>`.
2. **Leave it and fix forward**: usually the cleaner option — `application-redeploy` after fixing the code or env.

Either way, don't `project-remove` — that wipes the source env too.
