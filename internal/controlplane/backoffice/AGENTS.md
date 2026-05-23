# internal/controlplane/backoffice

Backoffice packages validate and project admin-owned runtime configuration
before it is published.

- Keep validators deterministic and side-effect free except for explicit
  repository/read ports used for existence checks or impact simulation.
- Dry-run responses are public contracts: use stable `kind`, `code`, `field`,
  `message`, and impact fields, and never echo submitted secret values.
- Treat blocking errors as part of a successful dry-run result when the request
  shape is valid. Reserve typed API errors for malformed requests, missing
  referenced database rows, and dependency failures.
- Runtime configuration consumers should use `RuntimeConfigCache` over a
  `RuntimeConfigLoader`. Snapshots are immutable, carry config set/version
  identifiers plus revision tokens, preserve the last known good payload after
  reload failures, and emit stale/reload alerts without exposing payload
  contents.
