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

## Session token contract (public, stable)

- `session.go` mints/verifies **human** session tokens as compact HS256 JWTs:
  `<header>.<payload>.<signature>`, base64url segments, with a *fixed* header
  constant (`sessionTokenHeader`). An incoming token must match that header
  byte-for-byte, so `"alg":"none"` and algorithm-downgrade tokens never reach
  signature verification.
- Claims: registered `iss/aud/sub/iat/exp` plus Yalla claims `org`, `role`,
  `rver` (the role/revocation version). `MintSession` signs with the active
  signing key; `VerifySession` accepts **any** key in `SigningKeys` (index 0
  active, rest for rotation) via a constant-time `hmac.Equal`.
- `VerifySession` checks in a fixed order — structure → signature → issuer →
  audience → expiry → revocation — and returns sentinel errors
  (`ErrMalformedToken`, `ErrTokenSignature`, `ErrTokenIssuer`,
  `ErrTokenAudience`, `ErrTokenExpired`, `ErrTokenRevoked`,
  `ErrUnknownSubject`). No error ever echoes the token or a signing key.
- **Revocation is version-based, not a denylist.** The token embeds `rver`;
  `VerifySession` rejects it unless it equals the *current* version returned by
  the injected `CurrentRoleVersion(userID, orgID)` lookup. `ok == false` from
  that lookup is the not-found case (`ErrUnknownSubject`). Bumping the counter
  (role change, forced sign-out) invalidates every outstanding token at once.
- `VerifySession` does **no I/O** — the only lookup is the injected
  `CurrentRoleVersion` func, so the store wiring lands in the BE-0020 auth
  middleware, not here. `SessionClaims.Principal()` returns a `policy.Principal`
  — the *same* internal identity shape the API-key path resolves to.
- `SessionToken` is a credential type with the identical redaction contract as
  `Token` (`String/GoString/LogValue/MarshalJSON` → `output.Sentinel`, plaintext
  only via `Reveal()`).
