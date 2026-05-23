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

## API key rotation (BE-0352)

- **Threat model.** A long-lived API key in source control, in an exported
  shell history, or in a CI log is a permanent credential leak until it is
  rotated. The mitigation is `POST
  /v1/organizations/{org_id}/api-keys/{key_id}/rotate`, which atomically
  swaps the row's credential body so that every subsequent authentication
  attempt with the OLD token fails as cleanly as one against a non-existent
  key. The cryptographic-primitive layer that makes this work is the same
  surface that mints a new credential at create time: `auth.Generate`
  produces fresh `Prefix` and `SecretHash` values; the store layer writes
  both onto the row in one UPDATE; the handler returns the one-time
  plaintext `Token` in the response body and nowhere else.
- **Atomicity is load-bearing.** The credential body is `(Prefix,
  SecretHash)` — a pair, not two independent fields. Rotation MUST replace
  both in the same statement: `store.APIKeyRepository.RotateCredential` runs
  `UPDATE api_keys SET prefix = $3, secret_hash = $4 WHERE organization_id =
  $1 AND id = $2`. A regression that swaps only one (e.g. updates `prefix`
  but leaves `secret_hash` stale) breaks one of two ways: if the prefix
  changes but the hash does not, the old secret keeps verifying against the
  new prefix and the leaked credential survives the "rotation"; if the hash
  changes but the prefix does not, the new token's prefix lookup misses the
  row and every authentication attempt with either credential fails. Either
  failure is silent at the handler boundary because the response shape is
  unchanged. The static-analysis sealing trap that pins this invariant
  lives in `internal/controlplane/store/api_key_rotation_static_test.go`.
- **Lifecycle conflicts surface as typed `apierr.Conflict`.** A revoked or
  expired key is permanently out of authentication service: the row stays
  in the table for audit-trail continuity, but no plaintext credential
  body can re-activate it. `store.APIKeyService.Rotate` reads the current
  row inside the same transaction it would UPDATE, checks `IsRevoked()` and
  `IsExpired(now)`, and returns `apierr.Conflict("api key is revoked")` or
  `apierr.Conflict("api key is expired")` before any credential primitive
  is persisted. The caller learns to mint a new key through `Create`
  instead of trying to revive a dead row.
- **Audit metadata carries only public identifiers.** The audit event for
  a successful rotation is a closed-set map: `organization_id` (the target
  tenant) and `rotated_prefix` (the public lookup id the row now serves).
  The secret hash, the plaintext token, the old prefix, and the actor's
  bearer credential are never carried in the metadata — only the
  identifiers a future investigator needs to correlate the event with the
  rest of the audit trail. The static analyzer enforces the closed-set
  invariant directly on the AST of `apikeyservice.go`.
- **The plaintext escape hatch is greppable.** The one-time plaintext
  Token of the new credential body is exposed exactly once, in the JSON
  body of the rotate response, via the `auth.Token.Reveal()` method. Every
  standard rendering of `auth.Token` (fmt `%v/%+v/%#v`, `slog`,
  `json.Marshal`) emits `output.Sentinel` instead. The runtime test
  `internal/controlplane/auth/api_key_rotation_test.go` drives the full
  rotation lifecycle of the credential primitives — old vs. new key —
  and asserts that every redaction projection survives across both keys,
  that the old secret cannot verify against the new hash (and vice
  versa), and that `Generate` keeps producing unique prefix+hash pairs at
  scale.
- **The OLD credential becomes unusable the moment the row is committed.**
  There is no grace period and no dual-active window. Yalla's prefix-keyed
  authentication path looks the row up by its current prefix only, so
  every subsequent authentication attempt with the old token misses
  through the same uniform invalid-credentials path that a non-existent
  key produces (see `Authenticator.Authenticate`'s
  `ErrInvalidCredentials` contract above). A grace-window design would
  require a denylist for the old hash plus a recovery window during which
  a leaked credential is still active — exactly the property rotation
  exists to remove.
- **Out of scope here.** The cross-tenant 404 invariant is enforced by
  `APIKeyService.Rotate`'s in-transaction `Get(...)` against the named
  tenant. The policy boundary that gates the rotate endpoint behind
  `CapManage` (no support cross-tenant exception, unlike `CapRead`) is
  pinned by `api_keys_rotate_policy_test.go`. The response envelope,
  redaction in logs, and dependency-cause-no-leak invariants are pinned
  by the BE-0092 contract test family. This AGENTS.md section is the
  threat-model documentation that points future readers at those pins.

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

## Request authenticator (`authenticator.go`)

- `Authenticator.Authenticate(ctx, bearerToken)` is the decision layer behind
  the HTTP auth middleware: it resolves any of the three bearer schemes — API
  key (`yk_...`), human session JWT, internal worker secret — to one
  `Identity{Principal, Method}`. The thin HTTP wrapper lives in `httpapi`
  (`RequireAuth` / `RequireInternalWorker`).
- **Uniform invalid-credentials contract.** Every invalid-credential cause —
  malformed token, unknown API key prefix, wrong secret, revoked/expired key,
  bad signature, expired/revoked/unknown-subject session — collapses to the
  single `ErrInvalidCredentials` sentinel. Never add a path that returns a more
  specific error for a bad credential: that is how a "does this prefix exist?"
  oracle leaks. A missing credential is `ErrNoCredentials`. A genuine datastore
  failure is propagated **unchanged** (a typed `*yerr.Error`), never disguised
  as `ErrInvalidCredentials`, so the middleware renders it as a 5xx, not a 401.
- The Authenticator depends on the narrow `CredentialStore` port and its
  `APIKeyRecord` / `ServiceAccountRecord` DTOs, so `auth` never imports
  `store`; the production adapter is `store.CredentialReader`. Unit tests use a
  fake `CredentialStore` and need no database.
- API-key principals carry **no** `Role` and **no** `Grants` here — resolving
  an API key's authority from its stored scopes is a later story, so an API-key
  principal can perform only `CapSelf` actions until a scoped grant lands
  (deny-by-default). Session principals get their role from the verified token
  claim. The internal worker principal is role-less and org-less by design.
- `SessionIssuer` / `SessionAudience` are the stable iss/aud contract values —
  `MintSession` callers must use exactly these. Session revocation is wired
  through `CredentialStore.OrganizationRoleVersion`, which feeds
  `VerifySession`'s `CurrentRoleVersion` hook.
