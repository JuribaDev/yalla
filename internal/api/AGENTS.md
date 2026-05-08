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

## HTTP client (US-0006)

- `client.go` is the single execution surface for Dokploy HTTP calls.
  Construct via `NewClient(ClientConfig)` once per command invocation;
  the returned `*Client` is immutable and safe for concurrent reads.
- The client never imports `internal/config` or `internal/cli`. Keep it
  that way — circular imports are easier to avoid than to untangle. The
  CLI layer builds `ClientConfig` from `*config.Config` and renders any
  returned `*yerr.Error` through `internal/output.Renderer` so the secret
  redactor runs uniformly.
- `Client.Do` returns `(*Result, error)` with a strict contract:
  transport-level failures map to typed `*yerr.Error` (`CodeTimeout`,
  `CodeCanceled`, `CodeNetwork`); any completed HTTP response — including
  4xx/5xx — comes back as `(*Result, nil)` so the caller picks the policy.
  Use `Result.AsError()` to opt into the canonical status-to-code mapping
  (the same mapping the raw API executor will adopt in US-0005).
- Retries are only applied when `Request.Idempotent` is true AND
  `ClientConfig.MaxRetries > 0`. The retry triggers are conservative:
  network/timeout errors and HTTP 502/503/504. 500 is treated as
  deterministic and never retried automatically.
- The bearer token is forwarded as `Authorization: Bearer <token>` and
  never appears in any error message we construct. A caller-supplied
  `Authorization` header on `Request.Headers` always wins over the
  token-derived default — that is how curated commands hit non-Dokploy
  endpoints with a different scheme without instantiating a second client.
- Observability headers (`X-Request-Id`, `X-Trace-Id`, `X-Correlation-Id`,
  `Traceparent`) are captured into `Result.RequestID` / `Result.TraceID`
  using the first non-empty value. Adding new header aliases means
  appending to `firstHeader(...)` in `client.go` and updating the test.
- Tests live in `client_test.go` and **must** use either `httptest.Server`
  or a stub `http.RoundTripper` — never a live Dokploy endpoint. Set
  `RetryBase: 0` in tests so the backoff loop runs without sleeping.
- Backoff sleeps are `time.NewTimer`-based and watch the request context
  so a `<-ctx.Done()` during retry returns `CodeCanceled` rather than
  waiting out the timer. Keep this behaviour: agents script around it.
