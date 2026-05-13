# Verification: actually confirming the deploy works

`application-deploy` returning HTTP 200 means **the deploy was queued**, not that it succeeded. Real verification has two phases.

## Prefer the wait primitives

When you just need to wait until a condition is true, use the `yalla wait` family instead of writing a sleep-poll loop:

```sh
yalla --json wait compose --id compose_123 --status done --timeout 300s
yalla --json wait url --url https://<host>/ --status-class 2xx --timeout 120s
yalla --json wait orphans --app-name <appName> --count 0 --timeout 60s
```

Each returns `E_TIMEOUT` if the predicate doesn't hold within the budget, with the last observed state on the error envelope. They share yalla's audit log, retry, and JSON envelope so a human can replay what happened later. See `composite-verbs.md` § wait.

The two-phase verification model below still applies — `yalla wait compose` then `yalla wait url` is its composite expression. Use the manual phases below when you need a predicate the wait primitives don't cover (e.g. probing a specific JSON field on a `/healthz` response).

---


## Phase 1: status poll

Loop on `application-one` (or `compose-one`) until the status terminates:

```sh
yalla --json api call application-one --input <(echo '{"query":{"applicationId":["<id>"]}}')
```

Read `data.body.applicationStatus`. The full state machine:

| Status | Meaning | Action |
|---|---|---|
| `idle` | Not yet running. After a fresh deploy it should leave this state within seconds; if it stays here past ~30s, the deploy probably never enqueued. | Wait, then poll again |
| `running` | Container running but build/health-check still in progress | Keep polling |
| `done` | Final success — build succeeded, container healthy | Move to phase 2 |
| `error` | Final failure | Surface logs, abort verification |

For compose: `compose-one` returns `data.body.composeStatus` with the same enum.

### Polling interval + timeout

- 3-second interval is gentle on the API and shows visible status changes.
- 5 minutes (100 polls) is the default cap. Most deploys finish in 30-90s; a long Docker build can take 3+ minutes; anything past 5 minutes is almost always a hung build.
- On every status transition, print to the user (e.g., `idle → running → done (47s)`).

### When status is `error`

Pull the build logs:

```sh
yalla --json api call application-readAppMonitoring --input <(echo '{"query":{"applicationId":["<id>"]}}')
```

(The endpoint streams; if it's heavy, just grab the last N lines.) Surface the tail to the user with a clear "build failed" header. Don't try to interpret — let the user read the actual error.

Common error categories to recognise (and how the skill should react):

| Symptom in logs | Likely cause | What the skill suggests |
|---|---|---|
| `git: not a valid Git repository` / 403/404 on clone | Source URL wrong or private without key | Re-check `application-saveGitProvider` body; confirm SSH key |
| `npm ERR! / pip ERROR` mid-build | Build dependency issue in the project | Show logs; stop, don't retry |
| `manifest unknown` / `pull access denied` | Pre-built image source wrong or private | Re-check `application-saveDockerProvider` body; confirm registry creds |
| `dial tcp ... connect: connection refused` from the app | App tried to talk to a DB that isn't ready yet | Order of operations issue — DB deploy + readiness must precede app deploy |
| `Permission denied / EACCES` | Container running as wrong user | Project-side fix |
| OOM kill | Resource limits | Project-side or Dokploy-side fix |

## Phase 2: HTTP probe

After status `done`, confirm the public endpoint actually responds.

```sh
DOMAIN="https://<host-from-domain-create>"
curl -sS -o /dev/null -w "%{http_code}" --max-time 10 "$DOMAIN"
```

- HTTP `2xx` → live ✓
- HTTP `301`/`302` → redirect, count as live (often http→https or trailing-slash)
- HTTP `401` / `403` → app is up, just behind auth. Live ✓ (note it in the report).
- HTTP `404` → reachable but no route at `/`. Probably live but the home route isn't `/` — try the project's known health endpoint, or accept it.
- HTTP `5xx` → unhealthy. Phase 1 said `done` but the app is crashing. Pull `application-readAppMonitoring` and surface.
- Connection refused / timeout → DNS or Traefik routing issue. Check that the domain's DNS A/AAAA records actually point at the Dokploy server.

### Let's Encrypt cold-start lag

For brand-new domains the first probe can fail with TLS handshake errors while Let's Encrypt issues the cert. Accept up to 60 seconds of `curl` failures after status=done before declaring TLS broken. Retry every 5 seconds with `--max-time 5`.

If the user requested `certificateType: "none"` (no Let's Encrypt), probe `http://` instead.

## Reporting

Final message:

```
✅ deployed cleanly
   project        my-app
   environment    staging
   app id         abcDEF...
   build          47s (idle → running → done)
   probe          200 OK in 312ms
   url            https://my-app-staging.apps.example.com
```

For partial success (status=done but probe fails):

```
⚠️ deployed but not reachable
   build          succeeded (status=done in 47s)
   probe          connection refused on https://my-app-staging.apps.example.com
   likely cause   DNS wildcard not pointing at Dokploy server
   yalla call:    yalla api call domain-byApplicationId --input <(echo '{"query":{"applicationId":["<id>"]}}')
```

For build failure:

```
❌ build failed
   final status   error after 38s
   logs (tail):
     ┌────────────────────────────────────────
     │ npm ERR! Missing required arg: --token
     │ npm ERR! See npm-help...
     └────────────────────────────────────────
   to retry:      yalla api call application-redeploy --input ...
```

## Health-check vs probe

This skill uses an external HTTP probe for verification — the only signal that matters at the user's level. Dokploy also supports per-app health-check configuration (start command, interval, retries) via `application-update`. The skill does not configure those by default; mention them in the report as a hardening step.
