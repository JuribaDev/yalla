# deploy/operations

Production operations commands live here. Keep scripts deterministic, dry-run
capable, and safe to inspect in CI.

- Never bake or echo rendered secrets. Load runtime values from an operator
  managed env file and print only redacted variable names in dry-run output.
- Commands that touch the database schema should run through
  `/usr/local/bin/yalla-api --migrate-only` so the embedded migration ladder
  matches the deployed backend version.
- Commands that seed or mutate control-plane source-of-truth data should run
  through a narrow `yalla-api` maintenance flag (for example `--seed-admin`),
  not through ad hoc `psql` snippets, so validation, transactions, audit, and
  structured logs stay in the backend binary.
- Pause `yalla-worker` before schema-changing operations and verify API
  `/healthz` plus `/readyz` before declaring the maintenance step complete.
