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

### Threat model

Master-key compromise is a "when, not if" event for any long-lived
encryption system: a backup tape is taken offsite, an HSM is decommissioned,
a former operator's offline copy is presumed leaked, or the algorithm
itself ages out of guidance (AES-256-GCM has a per-key birthday bound near
2^32 messages before nonce-collision probability becomes non-trivial). The
mitigation that has to be in place BEFORE any of these events is the
ability to:

1. introduce a NEW master key without invalidating ciphertext sealed under
   any existing key (so the rotation does not require a synchronous re-
   encryption of every row before any Seal can complete),
2. flip which key is ACTIVE (so every NEW Seal lands under the new key)
   without changing the on-disk format,
3. enumerate the rows that still reference a retired key id (so an
   operator can run a re-seal worker over a bounded backlog instead of a
   full-table scan), and
4. eventually drop the retired key from the accepted set — at which point
   any ciphertext still naming the retired id surfaces as a typed
   `ErrUnknownKey` rather than a silent plaintext recovery, which is the
   operator signal that a row was missed.

### Provider surface that supports rotation

The `AESGCM` provider already exposes the four surface methods the
rotation procedure depends on, AND `(provider_id, key_id, ciphertext)` is
the on-disk tuple persisted per secret-bearing row:

- `NewAESGCM([k_new, k_old, ...])` — first key is active for Seal;
  every key in the slice is accepted for Open. The constructor rejects
  duplicates so a misconfiguration that silently reduces the accepted
  set is caught at startup.
- `ActiveKeyID()` — names the key id every subsequent Seal will reference.
  An operator can read this from a structured log line at boot
  (`AESGCM.LogValue` exposes `active_key_id`) and confirm the rotation
  took effect without sealing a probe value.
- `KeyIDs()` — enumerates the accepted set in configured order
  (`KeyIDs()[0] == ActiveKeyID()`). The rotation worker compares this
  list against the distinct `(secret_provider, secret_key_id)` pairs
  recorded in each `*_variables` table to find re-seal candidates.
- `Open(ciphertext, key_id)` — accepts ANY id currently in the set, not
  only the active one. This is the load-bearing invariant for the
  rotation window: a row sealed under the previous active key continues
  to decrypt while the rotation worker chips away at the backlog. Removing
  the previous active key from `NewAESGCM(...)` BEFORE the backlog is
  cleared is the mistake the typed `ErrUnknownKey` exists to catch.

### Routing index (store layer)

Each `*_variables` migration that adds the encryption-at-rest columns
also creates a partial index named
`<table>_secret_routing_idx ON <table> (secret_provider, secret_key_id) WHERE is_secret = true`.
The index is the rotation worker's lookup surface: a
`SELECT id FROM <table> WHERE is_secret = true AND secret_provider = $1 AND secret_key_id = $2 LIMIT N`
query touches only rows that still reference the retired
`(provider, key)` pair, so the worker never needs a full-table scan and
the backlog drains in bounded chunks that interleave with normal write
traffic.

A static analyzer
(`internal/controlplane/store/migrate/secret_routing_idx_static_test.go`)
parses every `*_variables_encrypted_secrets.up.sql` from the embedded
migration FS and asserts the routing index is present with the
documented shape — dropping the index from a migration breaks the
rotation worker's only sub-linear lookup, so the trap fires at build
time.

### Runbook (operator)

1. Generate a fresh 32-byte master key off-host and load it into the
   configured key source.
2. Restart every process (API + worker) with the key list ordered
   `[k_new, k_old, ...]`. Confirm the startup log records
   `active_key_id = <id of k_new>`. From this moment, every new Seal
   uses `k_new`; existing ciphertext continues to Open under `k_old`.
3. Run the re-seal worker against each `*_variables` table:
   `SELECT id FROM <table> WHERE is_secret = true AND secret_key_id = <id of k_old>`,
   `Open(secret_ciphertext, secret_key_id)`, `Seal(plaintext)`,
   `UPDATE <table> SET secret_provider = $1, secret_key_id = $2, secret_ciphertext = $3 WHERE id = $4`.
   The unit of work runs per row in its own transaction so a worker
   crash never half-rotates a row, and the
   `is_secret => ciphertext columns populated` CHECK constraint blocks
   any UPDATE that would produce an inconsistent row.
4. When the routing-index lookup returns zero rows for every variable
   table, restart with `[k_new]` only. Any `Open` call that still names
   `k_old` from this point returns `ErrUnknownKey` — that is the typed
   operator signal that step 3 missed a row (an audit-trail or
   migration import that bypassed the rotation worker), not a silent
   plaintext exposure.

### Verification tests pinning the rotation contract

Three tests in this package and one in the migrations directory pin the
rotation contract so a future refactor that quietly removes the
capability fails the build:

- `key_rotation_static_test.go::TestAESGCMRotationSurfaceIsExported` —
  parses `aesgcm.go` and asserts the four surface methods (`NewAESGCM`,
  `ActiveKeyID`, `KeyIDs`, `Open`) exist with the documented shape, AND
  asserts `Open` enumerates the configured `keys` slice (not a single
  active key) so the multi-key accept window is structurally present.
- `key_rotation_test.go::TestAESGCMRotationLifecycle` — drives the full
  three-phase rotation lifecycle end-to-end on a real provider and
  asserts plaintext survives the rotation, new Seals reference the new
  key id, and the post-retirement Open of a missed row surfaces
  `ErrUnknownKey`.
- `key_rotation_test.go::TestAESGCMRotationDoesNotLeak` — drives the
  same lifecycle but checks the structured-log boundary
  (`AESGCM.LogValue`, `AESGCM.String`) for every provider configuration
  along the way and asserts no key material, no plaintext, and no
  ciphertext leaks through any of those redacted views.
- `internal/controlplane/store/migrate/secret_routing_idx_static_test.go::TestVariableMigrationsHaveSecretRoutingIndex` —
  parses each variable encryption migration and pins the routing index
  shape the rotation worker depends on.

Do not build the rotation worker in this package — it is an operational
concern coupled to the store layer and the variable tables, and lives
in its own future story. This package only owns the cryptographic
primitives and the rotation contract.
