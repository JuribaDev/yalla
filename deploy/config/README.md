# Yalla Control Plane Config Examples

This directory contains the canonical production environment example for the
Yalla Control Plane API and worker binaries:

- `deploy/config/control-plane.env.example`
- `/usr/local/bin/yalla-api`
- `/usr/local/bin/yalla-worker`

Install the rendered file outside the repository as `root:yalla` with mode
`0640`:

```bash
sudo install -d -o root -g yalla -m 0750 /etc/yalla
sudo install -o root -g yalla -m 0640 \
  deploy/config/control-plane.env.example \
  /etc/yalla/control-plane.env
sudoedit /etc/yalla/control-plane.env
```

Replace every `<redacted:...>` placeholder from the operator secret manager.
Do not commit `/etc/yalla/control-plane.env`, paste rendered values into
tickets, or print them in dry-run output. Database URLs, signing keys, secret
keys, API keys, cookies, and the Dokploy service token are runtime-only
credentials.

`yalla-api` exposes `GET /healthz` for process liveness and `GET /readyz` for
dependency readiness. Health and readiness probes render stable
`yalla.output.v1` or `yalla.error.v1` envelopes. `yalla-worker` has no HTTP
listener; observe it through process liveness, durable job state, worker
metrics, dead-letter alerts, and structured JSON logs.

Both binaries write structured JSON diagnostics only. Logs, errors, audit
metadata, and dry-run output must redact tokens, cookies, API keys, database
URLs, Dokploy tokens, and rendered environment variable values.

Verification is static and does not require production secrets:

```bash
go test ./internal/release/... -run TestConfigExamplesArtifact
```
