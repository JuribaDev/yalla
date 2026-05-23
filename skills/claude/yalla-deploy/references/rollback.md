# Rollback

Rollback changes the service build configuration to a previously known image,
tag, branch, or commit, then deploys and verifies.

## Image rollback

```sh
yalla service build set --service-id svc_app_web --build-type image \
  --image ghcr.io/acme/app:v1.2.2 --port 3000 --json
yalla service deploy --service-id svc_app_web --wait --json
```

## Git rollback

```sh
yalla service build set --service-id svc_app_web --build-type dockerfile \
  --repo https://github.com/acme/app --branch main --commit abc1234 \
  --context . --dockerfile Dockerfile --port 3000 --json
yalla service deploy --service-id svc_app_web --wait --json
```

Confirm the rollback target before mutation. After deploy, run the same
verification as a forward deploy.
