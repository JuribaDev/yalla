// Package secrets defines the at-rest secret-protection contract the
// Yalla Control Plane uses to seal customer-supplied secret values before
// they reach the source-of-truth database, and to open the sealed
// ciphertext on the rare internal code paths that legitimately need the
// plaintext (today, the future Dokploy provisioning renderer).
//
// The package exposes a narrow Provider interface and two concrete
// implementations:
//
//   - AESGCM, an envelope-encryption provider that authenticates every
//     ciphertext with AES-256-GCM, supports multiple master keys (the
//     first key is active for Seal; every key is accepted for Open), and
//     mints a stable, content-derived KeyID so a future key-rotation
//     story can identify which rows still reference a retired key.
//
//   - Plaintext, a passthrough provider that performs no encryption. It
//     is restricted to the local and test profiles — production wiring
//     refuses to build it — and exists so unit tests and local
//     development can exercise the at-rest seam without a real key
//     material.
//
// Design contracts:
//
//   - Authenticated encryption. Seal MUST return a ciphertext that Open
//     can detect a single-byte mutation in. A tampered ciphertext is
//     never silently returned as plaintext.
//
//   - Self-describing storage. Callers persist (provider_id, key_id,
//     ciphertext) alongside the row that carries the secret. A future
//     migration to a different provider can coexist with the current
//     one because the persisted tuple names which provider can open
//     which row.
//
//   - No plaintext logging. Implementations MUST NOT log the plaintext
//     or the ciphertext value through any structured log, error message,
//     or panic stack trace. Provider errors are typed and value-free.
//
//   - No key material in errors. A failed Seal or Open never echoes any
//     of: the plaintext, the ciphertext, the master key bytes, the key
//     id, or the nonce. The classification of the failure is the only
//     observable.
//
//   - Concurrency. Provider implementations are safe for concurrent use
//     so the unit-of-work transaction inside the store layer can Seal
//     once per Replace item without serialising through a global lock.
//
// The interface is deliberately the same width every variable scope
// (organization, project, environment, service) needs, so a single
// provider configured at process startup covers every variables table.
package secrets
