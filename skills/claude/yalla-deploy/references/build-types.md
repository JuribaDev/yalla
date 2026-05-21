# Build types

Use `yalla service build set` to make build configuration explicit and
repeatable. Prefer setting build config before every deploy when the source,
branch, image, output directory, port, or compose file changed.

## Static site

```sh
yalla service build set --service-id svc_web --build-type static \
  --repo https://github.com/acme/web --branch main \
  --build-command "npm run build" --output-dir dist --json
```

Use this for Vite, Astro, SvelteKit static export, Next static export, and
similar build-output directories. Confirm the output directory contains the
entry HTML and static assets before deploy.

## Dockerfile

```sh
yalla service build set --service-id svc_api --build-type dockerfile \
  --repo https://github.com/acme/api --branch main \
  --context . --dockerfile Dockerfile --port 8080 --json
```

Use this when the repo has a Dockerfile or the user explicitly wants container
build semantics. Prefer the exposed port from the Dockerfile when present.

## Compose

```sh
yalla service build set --service-id svc_stack --build-type compose \
  --repo https://github.com/acme/stack --branch main \
  --compose-file docker-compose.yml --json
```

Use this for multi-service stacks owned by one service resource.

## Pre-built image

```sh
yalla service build set --service-id svc_worker --build-type image \
  --image ghcr.io/acme/worker:latest --port 8080 \
  --registry-secret-ref sec_registry --json
```

Never paste registry passwords into tracked files or chat output. Use an
existing Yalla secret reference when private registry credentials are needed.
