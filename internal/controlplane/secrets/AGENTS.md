# secrets package

This package defines the at-rest secret-protection abstraction the Yalla
Control Plane uses for any source-of-truth column that stores customer-
supplied secret values (organization, project, environment, and service
environment variables; later: backup-target credentials, webhook signing
secrets, deployment-config secrets).

## What lives here

- `Provider` interface — Seal/Open contract. New providers MUST implement
  this surface and MUST follow the contracts documented on the interface:
  authenticated encryption, self-describing storage, no plaintext logging,
  no key material in errors, concurrency safety.
- `AESGCM` — production-grade AES-256-GCM envelope-encryption provider.
  ProviderID is `"aesgcm-v1"`. KeyID is the SHA-256 prefix of the master
  key, so the id is deterministic, non-secret, and short enough for audit
  metadata.
- `Plaintext` — passthrough provider. ProviderID is `"plaintext-v1"`.
  Restricted to local/test profiles by cmd/yalla-api/main.go; production
  wiring refuses to build it.
- Typed errors: `ErrInvalidCiphertext`, `ErrUnknownKey`,
  `ErrUnsupportedProvider`. All are value-free.

## What does NOT live here

- The store-layer columns and the migration that adds them. Those live
  with the table they protect (e.g. organization_variables migration
  0028).
- The HTTP wire shape. Secret values are still redacted to
  `output.Sentinel` at the HTTP projection chokepoint — encryption-at-rest
  is a defence-in-depth layer, not a substitute for the wire-level
  redaction policy.
- Audit-metadata redaction. The audit Auditor's regex-based scrub still
  runs on every audit row regardless of encryption status.

## Reusable knowledge

- Persist (provider_id, key_id, ciphertext) alongside the secret-bearing
  row. A single `provider_id` column + a single `key_id` column lets a
  future provider migration coexist with the current one.
- For Postgres, a CHECK constraint pins the invariant `is_secret =>
  (ciphertext NOT NULL AND provider_id NOT NULL AND key_id NOT NULL AND
  plain_value = '')`. The plain-value column stays `NOT NULL` (so the
  column has a single representation across both states) and is forced
  to `''` for secret rows.
- The store layer (not the repository) is the right seam to call Seal.
  Reasons: (1) Seal is a side-effecting call that depends on a runtime
  Provider, not a Tx; (2) calling Seal before opening the transaction
  shortens the SQL critical section; (3) the repository stays SQL-only.
- For internal-only read paths that legitimately need the plaintext (the
  Dokploy provisioning renderer, future variable-inheritance resolver),
  expose a `Reveal(ctx, provider, organizationID) ([]Var, error)` method
  next to the `List(...)` method, NEVER a wire-facing endpoint.
- Wire-level redaction stays the chokepoint. The HTTP projection MUST
  continue to substitute `output.Sentinel` for every secret value — even
  if the ciphertext column were accidentally exposed, the projection
  drops it. Defence in depth.

## Key rotation

The BE-0351 story owns the rotation procedure. The provider already
exposes everything the rotation job needs: `KeyIDs()` enumerates the
accepted set, `ActiveKeyID()` names the seal target, and rows that name
a retired key id can be re-sealed by Open-then-Seal under the new active
key. Do not implement rotation here — implement it in a dedicated
worker.
