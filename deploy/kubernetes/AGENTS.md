# deploy/kubernetes

This directory contains the production Kubernetes baseline for the
control-plane API and worker.

- Do not check in Kubernetes `Secret` objects or rendered secret values.
  Workloads should reference the operator-created
  `yalla-control-plane-secrets` object with `secretKeyRef`.
- Keep `yalla-api` and `yalla-worker` as separate workloads referencing
  the dedicated API and worker images. The worker has no HTTP listener.
- Preserve least-privilege pod defaults: non-root UID/GID 65532,
  `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, dropped
  `ALL` capabilities, `RuntimeDefault` seccomp, and disabled service
  account token automounting.
- When the artifact changes, update `deploy/kubernetes/README.md`,
  `SECURITY.md`, `.github/workflows/ci.yml`, `scripts/verify.sh`, and the
  static release gate in `internal/release/kubernetes_artifact_static_test.go`
  together.
