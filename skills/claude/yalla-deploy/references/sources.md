# Sources

Use the public Yalla source model.

| Source | Yalla build type | Primary command |
|---|---|---|
| Static build from git | `static` | `yalla service create ... --build-type static` |
| Dockerfile from git | `dockerfile` | `yalla service create ... --build-type dockerfile` |
| Compose file from git | `compose` | `yalla service create ... --kind compose --build-type compose` |
| Pre-built image | `image` | `yalla service create ... --build-type image --image ...` |

## Git source

Capture repo URL, branch, optional commit, context, and build file:

```sh
yalla service build set --service-id svc_app_web --build-type dockerfile \
  --repo https://github.com/acme/app --branch main \
  --context . --dockerfile Dockerfile --port 3000 --json
```

## Image source

```sh
yalla service build set --service-id svc_worker --build-type image \
  --image ghcr.io/acme/worker:latest --port 8080 --json
```

Use secret references for private registries.
