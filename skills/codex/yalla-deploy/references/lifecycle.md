# Lifecycle

The canonical fresh deploy creates a project, environment, service, build
configuration, then deploys and verifies.

## Fresh deploy sequence

```sh
yalla project create --project-id proj_app --name app --json
yalla environment create --environment-id env_app_prod --project-id proj_app --name production --json
yalla service create --service-id svc_app_web --environment-id env_app_prod --name web --kind application --build-type dockerfile --repo https://github.com/acme/app --branch main --context . --dockerfile Dockerfile --port 3000 --json
yalla service deploy --service-id svc_app_web --wait --json
```

If the service exists, use `yalla service get` and `yalla service build set`
before deploying again. Do not recreate resources only to redeploy.

## State file

Write non-secret IDs to `.yalla.yaml`:

```yaml
schema: yalla.deploy.v1
project_id: proj_app
project_name: app
environments:
  production:
    environment_id: env_app_prod
    services:
      web: svc_app_web
last_deploy:
  environment: production
  service: web
  source: https://github.com/acme/app
  ref: main
```

Use `.yalla.yaml.local` only for untracked local notes. Never write tokens,
passwords, generated database credentials, or registry credentials to either
tracked files or chat output.

## Redeploy

```sh
yalla service deploy --service-id svc_app_web --wait --json
```

## Tear down

Deletion is destructive. Require explicit confirmation that names the project or
project ID:

```sh
yalla project delete --project-id proj_app --wait --json
```
