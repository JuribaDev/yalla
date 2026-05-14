# internal/controlplane/auth

Credential primitives for the backend: API key generation, hashing, and
verification. This package owns the *crypto and value types*; persistence of
keys lives in `internal/controlplane/store` (`api_keys`, `APIKeyRepository`).
`store` does **not** import `auth` — it only ever stores the opaque `Prefix`
and `SecretHash` strings `auth.Generate` produces.

## Token contract (public, stable)

- A token has the shape `<namespace><prefix-random><separator><secret>` —
  `yk_` + base32 random + `_` + base32 secret. The namespace, separator,
  alphabet, and entropy budgets are a compatibility contract: changing them
  invalidates every stored key and every credential in the wild.
- `Generate` returns a `GeneratedKey`: the one-time plaintext `Token`, plus the
  `Prefix` (public, safe to store/log) and `SecretHash` (the only
  representation of the secret that is ever persisted).
- `ParseToken` splits and validates a token; a malformed token is
  `ErrMalformedToken` and the bad input is never echoed. `VerifySecret` is a
  **constant-time** hash comparison — never compare hashes with `==`.

## Redaction

- `Token` is a credential type: `String`, `GoString`, `LogValue`, and
  `MarshalJSON` all yield `output.Sentinel`, so it cannot leak through `fmt`,
  `slog`, or JSON. The plaintext is reachable **only** via the explicit
  `Reveal()` method — call it exactly once, at the point the token is handed to
  its owner, and never log the result.
- Tests assert the redaction contract with `testutil.AssertRedactedValue` over
  the full plaintext token *and* the bare secret body.

## Hashing choice

- API key secrets carry 192 bits of entropy, so a **fast unsalted SHA-256** is
  correct here — slow/salted password hashes defend low-entropy human secrets,
  which is not this threat model. The hash is deterministic so a key is found
  by its public prefix, never by hashing a guess. Do not "upgrade" this to
  bcrypt/argon2 without changing the threat model.
