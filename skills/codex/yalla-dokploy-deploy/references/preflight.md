# Preflight: getting `yalla` set up

Read this when `yalla --version` fails, when `yalla --json auth status` returns `ready: false`, or when the user asks how to install yalla in the first place.

The skill never silently installs or logs into `yalla` for the user — too many side effects (PATH, credential store, config files). The skill's job is to give them a copy-pasteable two-minute setup and stop.

## What the skill needs

1. `yalla` binary on PATH (or runnable as `./bin/yalla` from a known repo path)
2. `base_url` resolvable (config file, env var, or `--base-url` flag)
3. A token resolvable (OS credential store from `yalla auth login`, `YALLA_TOKEN`, config file, or `--token`)

`yalla --json auth status` is the single-source-of-truth check — if it prints `ready: true`, you're good.

## Setup snippet to give the user

When auth is not ready, emit this verbatim:

```sh
# 1. Build (one-time, requires Go 1.24+; clone the yalla repo first if missing)
cd /path/to/yalla-repo && go build -o ~/.local/bin/yalla ./cmd/yalla

# 2. Store and verify the Dokploy URL + API token
yalla auth login --url https://your-dokploy.example.com

# Agent/CI-safe alternative: read the token from stdin, not shell history
printf '%s' "$YALLA_TOKEN" | yalla auth login --url https://your-dokploy.example.com --token-stdin --json

# 3. Verify
yalla --json auth status
yalla --json auth whoami
```

`yalla auth login` is the secure default: it writes the URL to the yalla config file and stores the token in the host OS credential store. It verifies credentials by default and rolls back the stored token if verification fails.

If the host has no usable credential store, use `--store config` as an explicit fallback. Warn the user that this writes the token to the yalla config file:

```sh
printf '%s' "$YALLA_TOKEN" | yalla auth login --url https://your-dokploy.example.com --token-stdin --store config --json
```

## What "ready: true" looks like

```json
{
  "schema_version": "yalla.output.v1",
  "data": {
    "base_url": {"set": true, "source": "file", "value": "https://dokploy.example.com"},
    "token":    {"set": true, "source": "credential_store"},
    "ready":    true,
    ...
  }
}
```

The `source` fields tell you where the value came from: `flag` > `env` > `credential_store` > `file` > `default`.

## Health probe (optional, network)

For deeper confidence, also run:

```sh
yalla --json auth whoami
```

This makes a real authenticated GET to Dokploy. Success means transport is fine. Failure modes:

- HTTP 401 → token is wrong or revoked. Ask the user to rotate via Dokploy Settings → API Keys, then re-run `yalla auth login --url <url>`.
- E_NETWORK → DNS or TLS problem with `base_url`. Ask the user to confirm the URL is reachable in a browser.
- E_TIMEOUT → server slow/unreachable, but the right host. Retry once.

If `auth whoami` succeeds, the org for new resources comes from `data.active_organization_id`. If you use raw `user-get` instead, read `data.body.activeOrganizationId`.
