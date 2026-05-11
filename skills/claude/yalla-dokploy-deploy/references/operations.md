# Operations: stop / start / restart / logs / status

Day-2 ops that touch an existing deploy without redeploying. These are the verbs the skill needs when the user says **"the app is misbehaving"**, **"pause it"**, **"restart"**, **"show me logs"**, or **"what's running right now?"**.

## When to use this file

The skill's main workflow is **deploy-shaped** — create, configure, ship, verify. This file is for the **inverse and the in-between** — stopping, starting, restarting, inspecting. Read this when:
- The user wants to pause an app temporarily (debugging, cost control, maintenance window).
- The user wants to read logs from a running app.
- The user wants to restart without changing any config.
- The user asks "what's the status?" of an existing deploy.

## State-file prerequisite

All ops here need the existing `applicationId` (or `composeId`). Resolve via:
1. `.dokploy.yaml` if present (the happy path).
2. `project-all` + `project-one` walk to find the matching app by name — slower but always works.

If no state file AND no matching project, this is a setup error, not an operation. Surface "I don't see this project on Dokploy" rather than guessing.

## The ops

### `application-stop` — pause without removing

Stops the running container, **keeps every piece of config intact** (env vars, domains, databases, build config, source). The next `application-start` resumes from the same image.

Body: `{"applicationId": "<id>"}`

Use cases:
- Maintenance window: stop traffic, do something, start back up.
- Cost control: pause idle staging/preview envs overnight.
- Incident response: stop a misbehaving app while keeping evidence for forensics.

NOT a destructive op — domains, env vars, databases, and the configured source all remain. `application-start` is the inverse.

Verification: `application-one` should show `applicationStatus: idle` after a successful stop.

### `application-start` — resume after stop

Starts the configured app using the last-deployed image. **Doesn't rebuild** — it brings the same container back. For "stop, change something, redeploy" workflows, use `application-deploy` after configuration changes instead.

Body: `{"applicationId": "<id>"}`

Verification: `application-one` should show `applicationStatus: running` then `done`.

### `application-reload` — restart without stop/start dance

Restarts the running container in-place. Equivalent to `docker service update --force` against the swarm service. Useful for picking up an env-var change without a full rebuild.

Body: `{"applicationId": "<id>"}`

Caveats:
- Reload doesn't pick up source changes; only image changes (which require a rebuild via `application-deploy`) and env-var changes (via `application-saveEnvironment` immediately before reload) take effect.
- For multi-replica services, reload rolls all replicas, briefly impacting capacity. Sticky-session apps may see disconnects.

### `application-readAppMonitoring` — fetch logs

Streams container logs. Useful when:
- A deploy ended in `error` status — read the build/start output.
- A running app is misbehaving — tail the runtime logs.
- The user asks "what happened?" or "why is this failing?"

Body via `query`:
```json
{"query": {"applicationId": ["<id>"]}}
```

Returns log lines; the response can be large. The skill should consume it via context-mode rather than reading the full payload into chat. Tail the last N lines and surface to the user.

### `application-one` — current status / config

The universal read. Returns everything about the app: status, current source pointer, build type, env vars (REDACTED), domains, attached resources.

Body via `query`:
```json
{"query": {"applicationId": ["<id>"]}}
```

Skill uses this for:
- Polling deploy status (see `verification.md`).
- Capturing source config before promotion (see `promotion.md`).
- Confirming the current image before rollback (see `rollback.md`).

## Compose equivalents

For compose stacks, the corresponding ops are:
- `compose-stop` / `compose-start` / `compose-deploy` (no separate reload — redeploy is the only refresh path)
- `compose-readComposeMonitoring` for logs
- `compose-one` for status + config

## Decision tree

```
User wants to ...
├── ... pause an app temporarily          → application-stop
├── ... resume a paused app               → application-start
├── ... pick up an env-var change         → application-saveEnvironment + application-reload
├── ... pick up a code change             → application-deploy or application-redeploy (lifecycle.md)
├── ... read recent logs                  → application-readAppMonitoring
├── ... see what version is live          → application-one (read .dockerImage / .customGitUrl)
├── ... revert to a previous version      → rollback.md
├── ... promote staging code to prod      → promotion.md
└── ... permanently remove                → project-remove (lifecycle.md § tear-down)
```

## Patterns

### "Drain & maintenance"

User wants to pull an app offline for a few minutes, do something manual (DB surgery, edge-case investigation), and restart.

```sh
# Drain
yalla --json --no-input api call application-stop --input <(echo "{\"body\":{\"applicationId\":\"$APP_ID\"}}")
# Verify
yalla --json api call application-one --input <(echo "{\"query\":{\"applicationId\":[\"$APP_ID\"]}}") | jq '.data.body.applicationStatus'   # idle

# ... do the work ...

# Resume
yalla --json --no-input api call application-start --input <(echo "{\"body\":{\"applicationId\":\"$APP_ID\"}}")
```

### "Hot env-var update"

User changes a feature flag, doesn't want a full rebuild.

```sh
# Pull current env, append/replace the line, push back
yalla --json api call application-one --input <(echo "{\"query\":{\"applicationId\":[\"$APP_ID\"]}}") > /tmp/app.json
CURRENT_ENV=$(jq -r '.data.body.env' /tmp/app.json)
NEW_ENV=$(printf "%s\nFEATURE_X=true" "$(echo "$CURRENT_ENV" | grep -v '^FEATURE_X=')")

yalla --json --no-input api call application-saveEnvironment --input <(jq -n --arg id "$APP_ID" --arg env "$NEW_ENV" '{body:{applicationId:$id,env:$env,buildArgs:(jq -r ".data.body.buildArgs"),buildSecrets:(jq -r ".data.body.buildSecrets"),createEnvFile:true}}')
yalla --json --no-input api call application-reload --input <(echo "{\"body\":{\"applicationId\":\"$APP_ID\"}}")
```

### "Tail logs for the last incident"

```sh
yalla --json api call application-readAppMonitoring --input <(echo "{\"query\":{\"applicationId\":[\"$APP_ID\"]}}") \
  > /tmp/logs.json
jq -r '.data.body | split("\n") | .[-200:] | join("\n")' /tmp/logs.json
```

## Anti-patterns

- **`application-delete` for "stop"**: deletes the app config too. The user almost never wants that.
- **`application-saveEnvironment` followed by `application-deploy`** when the user only changed an env var: triggers a full rebuild. `application-reload` is the cheap path.
- **Polling `application-readAppMonitoring` in a tight loop**: streams the whole log buffer every call. Tail-only.
- **Reading logs as the FIRST diagnostic step**: usually `application-one`'s `applicationStatus` + the last deploy's exit-code answers the question. Logs are slower and noisier.
