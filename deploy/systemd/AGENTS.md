# deploy/systemd

This directory contains the single-node systemd baseline for the control-plane
API and worker.

- Keep `yalla-api` and `yalla-worker` as separate units that execute
  `/usr/local/bin/yalla-api` and `/usr/local/bin/yalla-worker`.
- Do not put secret values in unit files or examples. Units should load runtime
  credentials from `/etc/yalla/control-plane.env`, and examples should use only
  redacted placeholders.
- Preserve least-privilege systemd hardening: non-root `User=yalla`,
  `NoNewPrivileges=true`, strict filesystem protection, empty capability sets,
  address-family restrictions, private temp/devices, and explicit journald
  logging.
- When this artifact changes, update `deploy/systemd/README.md`, `SECURITY.md`,
  `.github/workflows/ci.yml`, `scripts/verify.sh`, and
  `internal/release/systemd_artifact_static_test.go` together.
