# Yalla Control Plane systemd Artifact

This directory contains a production baseline for running `yalla-api` and
`yalla-worker` on a single Linux node with systemd. The units assume the
binaries are installed at `/usr/local/bin/yalla-api` and
`/usr/local/bin/yalla-worker`, and that a local or reachable PostgreSQL service
is available before the API and worker start.

## Runtime Inputs

Create a dedicated service account and runtime directories:

```bash
sudo useradd --system --home /var/lib/yalla --shell /usr/sbin/nologin yalla
sudo install -d -o yalla -g yalla -m 0750 /var/lib/yalla
sudo install -d -o root -g yalla -m 0750 /etc/yalla
```

Install the example environment file and replace every `<redacted:...>`
placeholder from your secret manager:

```bash
sudo install -o root -g yalla -m 0640 \
  deploy/systemd/control-plane.env.example \
  /etc/yalla/control-plane.env
sudoedit /etc/yalla/control-plane.env
```

Do not commit `/etc/yalla/control-plane.env` or paste rendered values into
issues, logs, audit metadata, or runbooks. Database URLs, signing keys, secret
keys, and the Dokploy service token are runtime-only credentials.

Install the units:

```bash
sudo install -o root -g root -m 0644 deploy/systemd/yalla-api.service /etc/systemd/system/yalla-api.service
sudo install -o root -g root -m 0644 deploy/systemd/yalla-worker.service /etc/systemd/system/yalla-worker.service
sudo systemctl daemon-reload
```

## Verification

Render a local dry-run plan without starting services:

```bash
systemd-analyze verify deploy/systemd/yalla-api.service deploy/systemd/yalla-worker.service
systemctl cat yalla-api yalla-worker
```

The release static gate also parses the checked-in files:

```bash
go test ./internal/release/... -run TestSystemdArtifact
```

## Start And Health

Start the API first, then the worker:

```bash
sudo systemctl enable --now yalla-api
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
sudo systemctl enable --now yalla-worker
```

`yalla-api` listens on `127.0.0.1:8080` by default so a local reverse proxy can
terminate TLS and forward traffic over loopback. `GET /healthz` is process
liveness; `GET /readyz` returns 200 only when startup dependency gates are
ready and otherwise returns a stable `yalla.error.v1` envelope.

`yalla-worker` has no HTTP listener. Its health model is process liveness,
durable `provisioning_jobs` state, worker queue metrics, dead-letter alerts,
and structured startup/error logs.

## Logs And Rollback

Both services write structured JSON logs to journald:

```bash
journalctl -u yalla-api -o json --since -15m
journalctl -u yalla-worker -o json --since -15m
```

Logs are diagnostics only. The service logging layer redacts tokens, cookies,
API keys, database URLs, Dokploy tokens, and rendered environment variable
values.

To stop or roll back a bad deployment:

```bash
sudo systemctl stop yalla-worker
sudo systemctl stop yalla-api
sudo install -o root -g root -m 0755 /path/to/known-good/yalla-api /usr/local/bin/yalla-api
sudo install -o root -g root -m 0755 /path/to/known-good/yalla-worker /usr/local/bin/yalla-worker
sudo systemctl start yalla-api
sudo systemctl start yalla-worker
```
