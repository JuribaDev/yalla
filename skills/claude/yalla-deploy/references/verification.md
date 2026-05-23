# Verification

Do not report success until fresh verification evidence exists.

## Deploy wait

```sh
yalla service deploy --service-id svc_app_web --wait --timeout 10m --json
yalla wait job --job-id job_123 --json
curl -fsS https://app.example.com/healthz
```

This CLI build exposes `yalla wait job` and `yalla wait deployment`; it has no
standalone job-inspection command. Use wait-enabled commands for completion. If
a workflow lacks direct inspection in the current manifest, document that
limitation and rely on the wait-enabled command that queued the work.

## HTTP probe

Use `curl -fsS` for explicit health endpoints. For apps without a health path,
probe the root URL and treat 2xx, 3xx, 401, and 403 as evidence that the service
is reachable. Treat 5xx, DNS failures, connection refusal, and timeouts as
failed verification.

## Backup and restore

```sh
yalla database backup run --service-id svc_app_db --backup-id sbkp_daily --wait --json
yalla database backup restore --service-id svc_app_db --backup-id sbkp_daily --wait --json
```

For restore, verify the service starts and the app-level smoke test still passes.
