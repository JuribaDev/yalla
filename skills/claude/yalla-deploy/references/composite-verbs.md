# Composite commands

Use composite Yalla commands only when they are present in `yalla --json
manifest`. They are convenience workflows over public Yalla resources and do
not replace the resource model.

## Compose deploy

```sh
yalla deploy compose --project-id proj_app --environment-id env_app_prod \
  --service-id svc_app_stack --compose-file docker-compose.yml --wait --json
```

If the command is unavailable in the current manifest, use the first-class
sequence from `lifecycle.md`: project, environment, service with `--kind compose
--build-type compose`, then `yalla service deploy --wait`.

## Teardown

Prefer first-class project deletion for the public contract:

```sh
yalla project delete --project-id proj_app --wait --json
```

If `yalla teardown project` is available, it may be used as an operator-friendly
wrapper after the same explicit destructive confirmation:

```sh
yalla teardown project --project-id proj_app --wait --json
```

## Waiting

```sh
yalla wait deployment --service-id svc_app_web --timeout 10m --json
yalla wait job --job-id job_123 --timeout 10m --json
yalla wait url --url https://app.example.com/healthz --timeout 2m --json
```

Report unavailable wait commands as a CLI surface gap instead of falling back to
private operations.
