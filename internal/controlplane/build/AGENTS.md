# internal/controlplane/build

Verification leaf for operations artefacts (Dockerfile, .dockerignore, future
compose / k8s manifests, deploy scripts). The package itself ships no
production code — its tests read the repo-tracked artefacts at the repository
root and assert the properties an operations audit would check.

## Conventions

- One test file per artefact, named after the artefact
  (`api_dockerfile_test.go`, `worker_dockerfile_test.go`, …).
- Tests live in the `_test` external package so the verification surface has
  no production-code dependency and stays decoupled from controlplane
  internals.
- Tests locate the artefact via `repoRoot(t)`, which walks up from the test's
  working directory until it finds `go.mod`. Do not hard-code relative paths.
- Assertions name the property they pin (multi-stage build, non-root user,
  pinned base images, EXPOSE matching the production listen address,
  no baked secrets, …) so a failing test points at the operations regression,
  not the test's own internals.
- When adding a new operations artefact (a worker Dockerfile, a Helm chart, a
  systemd unit), add the matching verification test in this package and keep
  the assertions structurally parallel — operators read the test names to
  understand what guarantees the artefact carries.
