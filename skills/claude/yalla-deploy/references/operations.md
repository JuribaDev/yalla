# Operations

Use the public service commands that are present in the manifest.

## Status

```sh
yalla service get --service-id svc_app_web --json
yalla service list --environment-id env_app_prod --json
```

## Redeploy

```sh
yalla service deploy --service-id svc_app_web --wait --json
```

## Stop, start, restart, and logs

Check `yalla --json manifest` first. If no first-class Yalla command exists for
the requested operation, do not invent a private API operation. State the missing
Yalla command, stop before mutation, and ask the user whether they want a
follow-up implementation task.

For logs, use the public Yalla log command if present. If it is not present,
report that log retrieval is unavailable in this CLI build.
