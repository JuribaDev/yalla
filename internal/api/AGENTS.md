# internal/api

Owns the runtime registry of Dokploy OpenAPI operations and the schema
extraction surface used by `yalla api`, `yalla schema`, and (US-0007)
`yalla manifest`.

## Conventions

- The registry source-of-truth is `data/openapi.json`, embedded into the
  binary via `//go:embed`. Updating the spec is a public-API change: bump
  `EmbeddedSpecSHA256`, the matching pin in `ralph/prd.json`, and let
  `registry_test.go` lock the new digest plus operation count + IDs.
- Schemas are preserved as `json.RawMessage`. Do **not** re-model OpenAPI
  schema fragments into Go structs — yalla's contract is to surface the
  schema verbatim so agents can feed it into their own validators.
- `Operation` is an immutable value type. Methods on `*Registry` return
  copies (`Operations()`, `Get()`) so callers cannot mutate the registry
  in place. Concurrent reads are safe.
- `Default()` is the production accessor — it parses `EmbeddedSpec` once
  and panics on parse failure (a panic here is a build-time bug, not a
  runtime one). Tests that exercise alternate specs use `Load()` directly.
- Status keys in `Response.Status` are kept as strings so OpenAPI's
  `"default"` survives alongside numeric codes; sorting is numeric-aware
  via `statusLess`.
- Operations are exposed in **operationId-sorted** order. Any code that
  relies on path/method order is wrong — use `Operation.Path` /
  `Operation.Method` if you need it.
- A registry parse failure is a typed Go error, not a `*errors.Error`.
  CLI callers wrap it with `errors.Newf(errors.CodeInternal, ...)` because
  a parse failure means the embedded spec drifted from the registry code,
  which is an internal problem.
- The registry rejects multi-tag operations (Dokploy never uses more
  than one). Lifting that restriction requires a `Tags []string` field
  and updating every consumer at once.
