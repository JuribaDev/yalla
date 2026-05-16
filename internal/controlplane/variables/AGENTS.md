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

## Env-var redaction verification (BE-0360)

Two complementary tests pin the package's redaction contract as a
build-time invariant. See the matching `SECURITY.md` section
"Environment Variable Redaction" for the threat-model documentation.

- `env_var_redaction_static_test.go` is the static AST analyzer half. It
  walks every non-test `.go` file in the package directory and enforces
  three structural rules:
  1. `(ScopedVariable).LogValue`, `(Rendered).LogValue`,
     `(Resolved).LogValue` MUST reference `output.Sentinel` AND MUST NOT
     emit a `<receiver>.Value` or `<receiver>.SecretCiphertext` selector.
     The receiver-name tie prevents false positives from unrelated
     `<other>.Value` accesses inside the method body.
  2. Every `ExplainedVariable{...}` composite literal in package source
     MUST set the `Value:` field to `output.Sentinel` exactly. An
     omitted `Value:` field is also rejected — the field is mandatory
     so the redaction is explicit and grep-able.
  3. No call to `fmt.Sprint*` / `fmt.Errorf` / `errors.New` /
     `apierr.Internal` / `apierr.InvalidInput` / `apierr.NotFound` /
     `apierr.Conflict`, and no `apierr.FieldViolation{Reason: …,
     Field: …}` composite literal, may carry a `.Value` /
     `.SecretCiphertext` selector or a local identifier named
     `plaintext` (the resolver's conventional name for bytes recovered
     through `secrets.Provider.Open`).

  The analyzer ships with `TestRedactionStaticAnalyzerDetectsRegressions`
  — a self-check that parses synthetic bad and good source snippets and
  asserts each rule fires (or stays silent) as expected. The synthetic
  source lives in the test file as Go string literals so the bad code
  never lives on disk and cannot be accidentally compiled or shipped.
  Adding a new redaction-bearing type extends `redactingTypes`; adding a
  new forbidden selector extends `forbiddenFieldNames`; adding a new
  error-forming helper extends `errorFormingFuncs`. Each extension is a
  one-line edit.

- `env_var_redaction_test.go` is the runtime evidence half. Five
  table-driven tests pin the no-leak invariant for the slog and the
  customer-facing JSON projection across a hostile-value seed corpus
  (long values, invalid UTF-8, control characters, regex metacharacters,
  JSON-escape sequences, the `output.Sentinel` literal itself). Two
  Go fuzz targets (`FuzzRedactionScopedVariableLogValue`,
  `FuzzRedactionExplain`) widen the corpus coverage; CI runs the seed
  corpus only, `-fuzz` is operator-opt-in. The marker-bracket pattern
  (`FUZZENVMARKERLMN`) borrowed from the BE-0359 log-redaction fuzz
  suite is the leak detector — every fuzz-supplied value is wrapped
  with the marker so a leak surfaces independently of the bytes the
  value happens to carry.

When adding a new field that carries secret material, the same two-test
pair stays load-bearing: extend the static analyzer's
`forbiddenFieldNames` AND the runtime test's seed bracketing in the
same edit. A drift that updates one but not the other is a regression
the runtime tests catch on the next push.
