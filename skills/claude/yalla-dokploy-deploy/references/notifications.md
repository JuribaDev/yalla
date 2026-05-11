# Notifications: Slack / Discord / email / Telegram on deploy events

Wire Dokploy to send a webhook (or email) when a deploy succeeds, fails, or hits a build error. Use this when the user mentions "notify me on deploy", "Slack on failure", "email when X breaks", or wants any post-event alerting.

## The non-obvious design choice

Dokploy's notification model is **organization-scoped**, not project- or application-scoped. There is **no per-project attach op** — `notification-createSlack` (or `createDiscord` / `createEmail` / `createTelegram`) creates a notification record under the active organization, and the *event booleans* on that record decide which events trigger it.

That means:
- A single Slack notification with `appDeploy=true` will fire for **every app deploy across the entire organization**, not just one project.
- To send different channels per project, create separate notification records with the project name in the channel, and use the event booleans to scope coverage.

If the user wants "only fire when project X deploys", that scoping is a feature gap — surface it and propose either: (1) one notification covering everything + downstream Slack channel filtering, or (2) creating multiple notifications with the same webhook but different channel selectors per project.

## Op family

Provider-specific creation ops (no generic `notification-create`):

| Provider | Create op | Test op |
|---|---|---|
| Slack | `notification-createSlack` | `notification-testSlackConnection` |
| Discord | `notification-createDiscord` | `notification-testDiscordConnection` |
| Email | `notification-createEmail` | `notification-testEmailConnection` |
| Telegram | `notification-createTelegram` | `notification-testTelegramConnection` |
| Gotify | `notification-createGotify` | `notification-testGotifyConnection` |

Per-provider updates: `notification-updateSlack`, `-updateDiscord`, etc. Removal: `notification-remove`. Listing: `notification-all`, `notification-one`.

## Body for `notification-createSlack`

```json
{
  "body": {
    "name": "production-deploys",
    "webhookUrl": "https://hooks.slack.com/services/T0/B0/SECRET",
    "channel": "#deploys",

    "appDeploy": true,
    "appBuildError": true,
    "databaseBackup": false,
    "dokployRestart": false,
    "dockerCleanup": false,
    "serverThreshold": false,
    "newRelease": false
  }
}
```

All 7 event booleans are **required** (no nullable defaults). Set the ones you want, set the rest to `false` explicitly.

Event meanings:
- `appDeploy` — application or compose deploy succeeded
- `appBuildError` — build failed mid-deploy
- `databaseBackup` — scheduled DB backup ran (success or failure)
- `dokployRestart` — Dokploy itself restarted (rare; only when you care about platform uptime)
- `dockerCleanup` — scheduled `docker system prune` ran
- `serverThreshold` — server-level CPU/memory/disk crossed configured threshold
- `newRelease` — a new Dokploy release was published

The `name` is a free-text label that helps in the Dokploy UI; it doesn't affect routing.

## Body for `notification-createEmail`

```json
{
  "body": {
    "name": "ops-team",
    "smtpServer": "smtp.example.com",
    "smtpPort": 587,
    "username": "alerts@example.com",
    "password": "<smtp-password>",
    "fromAddress": "alerts@example.com",
    "toAddress": "ops@example.com",

    "appDeploy": true,
    "appBuildError": true,
    "databaseBackup": false,
    "dokployRestart": false,
    "dockerCleanup": false,
    "serverThreshold": false,
    "newRelease": false
  }
}
```

`password` is the SMTP password — never paste in chat; read from Keychain / env var at execute time, same as other secrets (see `sources.md` § Private registry credentials).

## Recovering the notification ID

`notification-create*` returns `{}` on success — recover the ID by listing:

```sh
yalla --json api call notification-all 2>/dev/null | jq -r '.data.body[] | select(.name == "production-deploys") | .notificationId'
```

Persist the ID in `.dokploy.yaml` so future runs don't re-list:

```yaml
notifications:
  production-deploys:
    id: NOTIF-…
    provider: slack
    events: [appDeploy, appBuildError]
```

## When to test-before-create

The skill should call `notification-testSlackConnection` (with the same webhook URL) **before** the create call — a bad webhook surfaces immediately, and you don't end up with a half-configured notification record. The test op returns 200 only when the webhook responds.

```sh
yalla --json api call notification-testSlackConnection --input <(jq -n --arg url "$WEBHOOK" '{body:{webhookUrl:$url,channel:"#deploys"}}')
```

If the test 401s or 404s, stop and tell the user the webhook is invalid before any mutation.

## Ordering in the deploy lifecycle

Notifications can be wired **before or after** the first deploy — they're independent of the project/app. Best practice:

1. Test the webhook first.
2. Create the notification before deploying so the first deploy itself fires the appDeploy event.
3. Update `.dokploy.yaml` with the notification ID.

If you wire after the first deploy, that deploy's "success" event doesn't get sent (notification record didn't exist yet). Subsequent deploys will fire correctly.

## What this skill does NOT do

- Slack channel routing per project — there's no Dokploy API for that. The user gets all org-wide deploys in one channel unless they configure multiple notifications.
- Per-environment filtering (e.g., "only notify on prod deploys") — same story; the booleans are org-wide.
- Custom message templating — Dokploy controls the message body.

If the user wants any of these, surface as Dokploy product gaps and propose a sidecar (a webhook receiver that filters and re-emits) rather than pretending the skill can do it.
