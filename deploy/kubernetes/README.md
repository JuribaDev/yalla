# Yalla Control Plane Kubernetes Artifact

This directory contains the production baseline manifest for running
`yalla-api` and `yalla-worker` on Kubernetes. The manifest is intentionally
plain YAML so operators can review it, run a dry-run plan, and layer their
own ingress, external secret controller, image tags, and namespace policy.

## Runtime Inputs

The manifest does not check in a Kubernetes `Secret`. Create
`yalla-control-plane-secrets` out of band through your secret manager or a
one-off operator command before applying the workloads:

```bash
kubectl -n yalla-control-plane create secret generic yalla-control-plane-secrets \
  --from-literal=YALLA_DATABASE_URL='<redacted>' \
  --from-literal=YALLA_SIGNING_KEYS='<redacted>' \
  --from-literal=YALLA_SECRET_KEYS='<redacted>' \
  --from-literal=YALLA_DOKPLOY_BASE_URL='<redacted>' \
  --from-literal=YALLA_DOKPLOY_TOKEN='<redacted>' \
  --from-literal=YALLA_INTERNAL_WORKER_TOKEN='<redacted>' \
  --from-literal=YALLA_RATE_LIMIT_REDIS_URL='<redacted>' \
  --dry-run=client -o yaml
```

Do not commit the rendered Secret. The checked-in Deployment binds those
keys by `secretKeyRef` at runtime so database URLs, signing material,
secret-encryption keys, Dokploy credentials, internal worker callback tokens,
and the Redis rate-limit DSN are never baked into images or files.

Production and staging use Redis-backed rate limiting so every `yalla-api`
replica shares the same org, API-key, and IP buckets. The checked-in
ConfigMap sets `YALLA_RATE_LIMIT_BACKEND=redis`; supply
`YALLA_RATE_LIMIT_REDIS_URL` through the Secret or explicitly disable the
limiter only for an approved incident.

## Production Rollout

The source tree uses `0.0.0-dev` image tags as placeholders only. Release
manifests are rendered with immutable image digests, and manual Kustomize
rollouts should pin the same way:

```bash
cd deploy/kubernetes
kustomize edit set image ghcr.io/juribadev/yalla-api=ghcr.io/juribadev/yalla-api@sha256:<api-digest>
kustomize edit set image ghcr.io/juribadev/yalla-worker=ghcr.io/juribadev/yalla-worker@sha256:<worker-digest>
cd ../..
kubectl apply --server-side -k deploy/kubernetes
kubectl -n yalla-control-plane rollout status deploy/yalla-api
kubectl -n yalla-control-plane rollout status deploy/yalla-worker
```

Use the `dist/yalla-control-plane-<tag>.yaml` artifact from a release when you
do not need local overlays. It contains the same baseline manifest with the
API and worker images replaced by the signed release digests.

## Verification

Render the artifact locally without contacting a cluster:

```bash
kubectl kustomize deploy/kubernetes
```

Validate against a reachable cluster API before rollout:

```bash
kubectl apply --dry-run=server -f deploy/kubernetes/yalla-control-plane.yaml
```

The release static gate also parses this manifest:

```bash
go test ./internal/release/... -run TestKubernetesArtifact
```

## Health And Logs

`yalla-api` exposes `GET /healthz` for liveness and `GET /readyz` for
dependency readiness on port `8080`. The worker has no HTTP listener; its
health signal is process liveness, durable `provisioning_jobs` state, worker
queue metrics, and structured startup/error logs.

Both workloads write structured JSON logs to stdout. Logs must be collected
as diagnostics only; tokens, cookies, API keys, database URLs, Dokploy
tokens, and rendered environment variable values are redacted by the service
logging layer.
