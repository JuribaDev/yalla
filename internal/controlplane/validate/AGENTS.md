# validate — request validation toolkit

`internal/controlplane/validate` is the single place handlers and services
validate untrusted request input. It is pure: no I/O, no Postgres, no knowledge
of feature flags or quota.

## Conventions

- **Collector pattern.** Build a `validate.New()` Collector, call validators
  against it (each takes `c *Collector, field string, ...`), then return
  `c.Err()` — nil or one `apierr.InvalidInput` carrying every violation. Never
  short-circuit on the first bad field.
- **Never echo the submitted value.** A `FieldViolation.Reason` carries only
  classification text (bounds, "must not be blank"). Reasons may interpolate
  bounds/counts via `Addf`, never input. This is what lets a secret env var be
  rejected without its value reaching a log/error. Add a "never echoes the
  value" test for any new validator.
- **Policy-dependent rules are options, not lookups.** `Domain` takes
  `DomainOptions{AllowWildcard}`; the caller resolves the feature flag + quota
  and passes the bool. Keep the package free of config/quota imports.
- **Field paths.** Dotted (`build.dockerfile_path`), indexed for slices
  (`env[0].name`), and a distinct segment for sensitive sub-lists
  (`env.secret[0]`).
- **Fuzz every string validator.** Seed `fuzzSeeds` covers long strings,
  invalid UTF-8, path traversal, control chars. A fuzz target asserts no panic
  and re-derives the accept invariants — mirror that for new validators.
- `DecodeJSON` is the strict JSON body decoder: size-capped, unknown-field- and
  trailing-data-rejecting, and every failure is a body-free `apierr.Invalid`.

## JSON parser hardening invariants (BE-0346)

`DecodeJSON` is the single canonical decoder every mutating HTTP handler
funnels through (BE-0345 already rejects any handler that bypasses it). The
function's body MUST keep four AST-shaped hardenings — losing any one of
them re-opens a real attack surface:

1. `json.NewDecoder(&limitedReader{...})` — the reader is wrapped in the
   explicit byte-cap reader BEFORE the decoder sees it (OOM/slow-loris
   defence).
2. `<dec>.DisallowUnknownFields()` — rejects extra keys (mass-assignment /
   schema-confusion / hidden-field smuggling defence).
3. `<dec>.More()` — after `Decode`, asserts the stream is exhausted (JSON
   smuggling defence; a body like `{"a":1}{"b":2}` lets a proxy/WAF see
   one value while the API acts on another).
4. `decodeError(...)` — every failure flows through this fixed-message
   renderer; raw `encoding/json` errors that quote the submitted bytes
   never reach the response (secret-leak / body-echo defence).

The static analyser `TestDecodeJSONKeepsAllHardenings`
(`json_static_test.go`) parses `json.go`, locates `DecodeJSON`, and emits
a build-time failure listing each hardening that is missing; the companion
`TestDecodeJSONHardeningStaticAnalyzerDetectsRegressions` synthesises
known-bad and known-good DecodeJSON variants to prove the analyser fires
on the bad shapes and stays silent on the good one. The runtime backstop
lives in `internal/controlplane/httpapi/json_hardening_test.go` and proves
the hardenings hold end-to-end through `NewHandler` (unknown field,
trailing data, malformed JSON, wrong-typed field, auth-before-decode).

When changing `DecodeJSON`, run the validate package tests AND the httpapi
package tests. The hardenings are not optional and not negotiable: if a
caller cannot live with one of them, add a NEW typed decoder beside
`DecodeJSON` (and a new analyser companion that pins its hardenings) —
never weaken the canonical one.
