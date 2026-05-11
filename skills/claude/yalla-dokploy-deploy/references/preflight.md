# Preflight: getting `yalla` set up

Read this when `yalla --version` fails, when `yalla --json auth status` returns `ready: false`, or when the user asks how to install yalla in the first place.

The skill never silently installs `yalla` for the user — too many side effects (PATH, Keychain, ~/.zshrc). The skill's job is to give them a copy-pasteable two-minute setup and stop.

## What the skill needs

1. `yalla` binary on PATH (or runnable as `./bin/yalla` from a known repo path)
2. `base_url` resolvable (config file, env var, or `--base-url` flag)
3. A token resolvable (`YALLA_TOKEN` env var, config file, or a wrapper that injects from Keychain)

`yalla --json auth status` is the single-source-of-truth check — if it prints `ready: true`, you're good.

## Setup snippet to give the user

When auth is not ready, emit this verbatim:

```sh
# 1. Build (one-time, requires Go 1.24+; clone the yalla repo first if missing)
cd /path/to/yalla-repo && go build -o ~/.local/bin/yalla ./cmd/yalla

# 2. Persist the Dokploy URL (not secret)
yalla config set base_url https://your-dokploy.example.com

# 3. Store the API token securely in macOS Keychain
security add-generic-password -s yalla -a "$USER" -w 'PASTE_TOKEN_HERE' -U

# 4. Add a yalla() wrapper to ~/.zshrc that pulls from Keychain only when invoked
cat >> ~/.zshrc <<'ZSHRC'

# >>> yalla CLI wrapper (managed) >>>
yalla() {
  if [[ -z "${YALLA_TOKEN:-}" ]]; then
    local _yalla_key
    _yalla_key=$(security find-generic-password -s yalla -a "$USER" -w 2>/dev/null)
    if [[ -z "$_yalla_key" ]]; then
      print -u2 "yalla: no token in Keychain. Store one with:"
      print -u2 "  security add-generic-password -s yalla -a \"\$USER\" -w '<TOKEN>' -U"
      return 1
    fi
    YALLA_TOKEN="$_yalla_key" command yalla "$@"
  else
    command yalla "$@"
  fi
}
# <<< yalla CLI wrapper (managed) <<<
ZSHRC

# 5. Reload zsh and verify
exec zsh
yalla --json auth status
```

The wrapper is the secure-default: the token is decrypted from the OS keychain at the moment of each invocation, never written to disk by yalla, never persisted in shell env or history.

For Linux, swap step 3-4 for `pass` or `secret-tool`; the principle is the same.

## What "ready: true" looks like

```json
{
  "schema_version": "yalla.output.v1",
  "data": {
    "base_url": {"set": true, "source": "file", "value": "https://dokploy.example.com"},
    "token":    {"set": true, "source": "env"},
    "ready":    true,
    ...
  }
}
```

The `source` fields tell you where the value came from: `flag` > `env` > `file` > `default`.

## Health probe (optional, network)

For deeper confidence, also run:

```sh
yalla --json api call user-get
```

This makes a real authenticated GET to Dokploy. Success means transport is fine. Failure modes:

- HTTP 401 → token is wrong or revoked. Ask the user to rotate via Dokploy Settings → API Keys, then re-run step 3.
- E_NETWORK → DNS or TLS problem with `base_url`. Ask the user to confirm the URL is reachable in a browser.
- E_TIMEOUT → server slow/unreachable, but the right host. Retry once.

If `user-get` succeeds, the org for the new resources comes from `data.body.activeOrganizationId` — capture and use it.
