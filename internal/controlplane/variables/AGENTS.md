# variables package

Resolves a single service's effective environment-variable set across
the four hierarchy scopes (organization -> project -> environment ->
service) under the Dokploy-compatible precedence
**service > environment > project > organization**.

## What lives here

- `Resolver` — the pure, stateless merge engine. Constructed with a
  `secrets.Provider` so it can `Open` sealed rows during resolution.
  Safe for concurrent use.
- `ScopedVariable` — the scope-agnostic input shape. Carries the at-rest
  seal tuple (`SecretProvider`, `SecretKeyID`, `SecretCiphertext`) plus
  the source-of-truth row id used for explain output.
- `Resolved` / `Rendered` — the internal-only consumer view. Carries
  verbatim plaintext values. MUST be redacted before reaching a
  customer wire (use `Resolved.Explain()`).
- `Explained` / `ExplainedVariable` — the customer-facing projection.
  Every value is `output.Sentinel`; the override chain is preserved.
- `Options.AllowSecretDowngrade` — the opt-in that lets a non-secret
  variable at a higher scope override a secret at a lower scope. The
  zero value rejects.

## What does NOT live here

- No I/O. The resolver does not import `store` and does not accept a
  context. The caller is responsible for fetching each scope's
  variables (typically through the per-scope `*Reader` adapters in
  `internal/controlplane/store`) inside a single short-lived read
  transaction, and for converting the store types into `ScopedVariable`
  values before invoking `Resolve`.
- No HTTP wire shape. The httpapi handler that surfaces the resolved
  set is responsible for wrapping `Explained` in a `yalla.output.v1`
  envelope and for emitting the audit event recording an opt-in
  secret downgrade.
- No Dokploy provisioning. The Dokploy renderer
  (`internal/controlplane/dokploy/renderer.go`) consumes the merged
  view through a different validation pass focused on tier/role
  invariants; the two paths are intentionally separate so a variable
  resolver bug cannot mis-render a service spec and vice versa.

## Contracts

1. **Precedence**: service > environment > project > organization. A
   variable at a higher scope completely replaces the value (not the
   chain) of the same key at any lower scope.
2. **Provenance**: `Resolved.Contributions[key]` lists every scope
   that contributed a value for `key`, in ascending precedence order.
   The last entry is the winner. `Rendered.Source` and
   `Rendered.SourceID` mirror the winning entry for convenience.
3. **Secret downgrade**: a non-secret variable at a higher scope
   overriding a secret at a lower scope is rejected as
   `apierr.InvalidInput` with a stable field path unless
   `Options.AllowSecretDowngrade` is set. Callers wiring the opt-in
   MUST emit an audit event recording the override.
4. **Secret upgrade**: a secret variable at a higher scope overriding
   a non-secret at a lower scope is always allowed.
5. **Validation**: names must match `^[A-Za-z_][A-Za-z0-9_]*$`. A
   scope cannot define the same key twice. All violations across all
   scopes are returned in one `apierr.InvalidInput` so the customer
   can fix every problem in one round trip. Field paths follow
   `<scope>.variables[<index>].key` and never echo the rejected value.
6. **Server-side failures**: a sealed row whose `SecretProvider` does
   not match the resolver's provider, an `Open` that fails with
   `secrets.ErrUnknownKey` / wrapped `ErrInvalidCiphertext`, or a
   resolver constructed with a nil/empty-id provider surfaces as
   `apierr.Internal`. None of these paths echo plaintext or ciphertext.
7. **Redaction**: `Resolved.LogValue`, `Rendered.LogValue`, and
   `ScopedVariable.LogValue` redact value and ciphertext at the slog
   boundary. `Explained` redacts every value to `output.Sentinel`.
   Tests prove no error message, JSON-marshalled `Explained`, or slog
   line contains the source plaintext or ciphertext.

## When adding a new field

- Updating `ScopedVariable` with a new field that carries secret
  material? Update `ScopedVariable.LogValue` in the same edit to
  redact it. A stray slog capture must never leak the new field.
- Updating `Rendered`? Same rule. Also extend `ExplainedVariable` if
  the field is part of the customer-facing projection — and confirm
  the value passes through `output.Sentinel`, never verbatim.
- Adding a new precedence rule? The merge order is encoded in one
  table at the top of `Resolver.Resolve`. Update it there and add a
  golden scenario to `TestResolveGoldenScenarios`.

## Tests

- `TestResolvePrecedence*` pins each precedence step.
- `TestResolveSecretDowngrade*` pins the downgrade default and opt-in.
- `TestResolveGoldenScenarios` exercises four realistic shapes
  (production, staging, preview, service-specific-overrides). Add a
  new scenario when you change the merge semantics — do not edit the
  existing ones.
- `TestResolved*LogValue*` and `TestExplain*` pin the redaction
  invariants. These tests will catch any drift that surfaces secret
  bytes through slog or the customer-facing JSON projection.
- The package has no Postgres integration test of its own: the
  per-scope `*Reader` integration tests in `internal/controlplane/store`
  prove the tenant-scoping invariants of the inputs handed to this
  package, and the resolver is pure with no persistence to test.
