# Composite verbs and AI-first ergonomics

Read this any time you would otherwise hand-orchestrate a chain of `yalla api call` steps. The composite verbs were added precisely so a language model can do one well-named call instead of stitching together six raw ones. Raw `api call` is still there for unsupported edges — this file also covers the new `--data`, `--get-or-create`, and `--strict-appname` flags that make raw calls less fiddly when you do need them.

## When to use composite vs raw

| Intent | Composite verb | When to fall back to raw `api call` |
|---|---|---|
| Compose deploy (whole stack) | `yalla deploy compose` | Single-app deploys (no composite yet); compose features the verb does not expose; tweaking one piece of an already-deployed compose stack. |
| Tear down everything | `yalla teardown project` | Almost never. The composite default is the safe path; pass `--no-cascade` only if you want the exact raw `project-remove` behaviour and accept orphaned containers. |
| Wait for state | `yalla wait compose` / `yalla wait url` / `yalla wait orphans` | When you need a custom predicate that none of the three covers. |
| Clean up a stuck stack | `yalla rescue orphans` | When orphans live on a host yalla can't reach over the Dokploy API; pass `--ssh` for the fallback. |
| Inspect what yalla did | `yalla audit tail` | Use the composite. The audit log is the single source of truth for mutations this CLI made. |

## `yalla deploy compose`

End-to-end compose deploy in one command — creates project/env/compose if missing, uploads the compose file, applies env file and domain bindings, deploys, and waits for `done`.

```sh
# Plan first; do not mutate
yalla --json deploy compose \
  --project app \
  --env staging \
  --compose-file docker-compose.yml \
  --env-file .env.staging \
  --domain "app-staging.example.com:web:3000" \
  --get-or-create \
  --dry-run

# Live
yalla --json deploy compose \
  --project app \
  --env staging \
  --compose-file docker-compose.yml \
  --env-file .env.staging \
  --domain "app-staging.example.com:web:3000" \
  --get-or-create
```

Flag reference:

- `--project` (required) — project name. If it doesn't exist, it's created.
- `--env` (required) — environment name. Created if missing.
- `--compose-file` (required) — path to the docker-compose YAML.
- `--env-file` — optional env file applied as runtime env.
- `--domain host:service:port` (repeatable) — domain bindings; each maps a public host to a compose service + port.
- `--get-or-create` — when set, exact-name matches at every level (project, env, compose) are reused instead of triggering `E_CONFLICT`. This is the right default for repeat runs and CI.
- `--dry-run` — print the planned ordered operations without sending any mutation. **Always do this first** so the user can sanity-check before any side-effect.
- `--timeout` — overall budget (default 5m). Returns `E_TIMEOUT` if the deploy doesn't reach `done` in time.

The dry-run output is ordered exactly like the live execution, so the user can paste it into a change log as a record of what's about to happen.

## `yalla teardown project`

Safe cascade teardown. Removes the project, every environment, every app/compose, every database, every domain, **and** the orphan Docker containers that vanilla `project-remove` leaves behind on the swarm.

```sh
# Preview only
yalla --json teardown project --project app --dry-run

# Live
yalla --json teardown project --project app

# Match raw upstream behaviour (NOT recommended — leaves orphans on the host)
yalla --json teardown project --project app --no-cascade
```

If the user explicitly says "I just want `project-remove`'s behaviour", honour that with `--no-cascade` and warn them what they're trading away. Otherwise default to the cascade.

## `yalla wait` family

Three primitives that return when the predicate is met or `E_TIMEOUT` when it isn't. Use these instead of writing your own poll-and-sleep loop — they share the same audit + retry + timeout semantics as the rest of yalla.

```sh
# Wait for a compose status (most common after deploy)
yalla --json wait compose --id compose_123 --status done --timeout 300s

# Wait for an HTTP response class on a domain
yalla --json wait url --url https://app-staging.example.com --status-class 2xx --timeout 120s

# Wait for orphan containers under an appName to drain (most common during teardown)
yalla --json wait orphans --app-name app-staging --count 0 --timeout 60s
```

Notes:

- `wait compose` defaults to `--status done`. Use `error` to wait for a known-bad terminal state during diagnostics.
- `wait url` defaults to `2xx`. Use `4xx` or `5xx` when you want to wait until a specific HTTP class is *no longer* observed (with `--status-class !5xx`-style flips if available in future versions).
- `wait orphans` defaults to `--count 0`. The point is to confirm a teardown actually drained.

## `yalla rescue orphans`

Manual cleanup when a previous deploy or teardown left orphan containers — `wait orphans` returned timeout, or `E_ORPHAN` came back from another call.

```sh
# Default: remove orphans via the Dokploy API
yalla --json rescue orphans --app-name app-staging

# Fallback: if Dokploy can't reach the host, generate (or run) the SSH cleanup command
yalla --json rescue orphans --app-name app-staging --ssh user@host
yalla --json rescue orphans --app-name app-staging --ssh user@host --execute-ssh
```

`--ssh user@host` without `--execute-ssh` *prints* the shell command you (or the user) would run; with `--execute-ssh` yalla runs it for you. Default to print-only so the user sees what will happen before it happens — only auto-execute if the user explicitly said so.

## `yalla audit tail`

Inspect what yalla mutated. Every `api call` and every composite verb appends a typed record to the audit log; tailing it reveals the exact ordered mutations including operation IDs, request IDs, response codes, and `idempotent_result` markers (`created` vs `reused` for `--get-or-create` paths).

```sh
yalla --json audit tail --lines 50
```

Use this any time the user asks "what did you change?" or when a deploy went sideways and you need to know what state it left. It's also the right tool to recover from "I lost the IDs from the last run" — they're all in the audit log.

## Raw `api call` ergonomics

Three flags landed alongside the composite verbs that make raw calls less painful when you do need them.

### `--data` — inline JSON instead of a file

```sh
# Old way: write a file, then pass its path
yalla --json api call environment-create --input <(echo '{"body":{"name":"staging","projectId":"proj_123"}}')

# New way: pass JSON on the command line
yalla --json api call environment-create --data '{"name":"staging","projectId":"proj_123"}'
```

`--data` and `--input` are mutually exclusive — pass one or the other. `--data` is the right choice for short bodies that fit on one line; `--input` is better for multi-line / generated JSON. Both still accept `-` to mean stdin.

### Body auto-wrap

The new request decoder treats a top-level JSON object as the request *body* unless you include the canonical envelope keys (`body`, `query`, `headers`, `path_params`, etc.). That means you can drop the `{"body":...}` wrapper for almost every mutation:

```sh
# Both of these are now equivalent:
yalla --json api call environment-create --data '{"body":{"name":"staging","projectId":"proj_123"}}'
yalla --json api call environment-create --data '{"name":"staging","projectId":"proj_123"}'
```

Stick with the explicit envelope only when you need a non-body envelope key (e.g. `query` for list-with-filter ops).

### `--get-or-create`

For create operations that support idempotent lookup (currently: most `*-create` ops), `--get-or-create` returns the existing exact-name match instead of failing with `E_CONFLICT`. The response envelope sets `idempotent_result` to `"created"` or `"reused"` so you can branch on it.

```sh
yalla --json api call project-create --data '{"name":"app"}' --get-or-create
# → {"data": {..., "idempotent_result": "reused"}, "warnings": []}
```

Use this on every re-run of a deploy — it keeps the workflow idempotent without you having to list-then-conditional-create.

### `--strict-appname`

`compose-create` accepts an `appName` field but Dokploy may silently rename it (collision avoidance, sanitization). The default behaviour is to emit a non-fatal `APPNAME_MUTATED` warning in the response envelope. Pass `--strict-appname` to upgrade that warning to a hard failure (`E_INVALID_INPUT`) — use it when downstream env wiring assumes a specific in-cluster hostname.

```sh
yalla --json api call compose-create --data '{"name":"app","appName":"app","environmentId":"env_123"}' --strict-appname
```

## Known issues catalog

`internal/dokploy/known_issues.yaml` enumerates upstream Dokploy bugs yalla recognises. When a raw call hits one of these, the error code is `E_UPSTREAM_BUG` (not the generic `E_SERVER`) and the error doc carries a `workaround` field with the exact recovery action. Follow the workaround; do not loop on the same call hoping it stops failing.

Example entry: `compose-stop` returning `spawn /bin/sh ENOENT` (HTTP 500) is classified as `upstream_bug` with workaround "Use docker-compose-down by appName, then retry cleanup." `yalla teardown project` already does that automatically; raw callers need to do it explicitly.
