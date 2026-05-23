# internal/api

Owns the generic HTTP/OpenAPI registry helpers used by the CLI. The current
backend-only CLI loads the Yalla Control Plane `/openapi.json` document at
runtime for `yalla api`, `yalla schema`, and manifest API coverage. The
checked-in `data/openapi.json` remains a legacy Dokploy fixture for registry
and compatibility tests; it is not the public normal-user CLI contract.

## Conventions

- `data/openapi.json` is embedded via `//go:embed` for local registry tests
  and legacy compatibility seams. Updating it is still a public compatibility
  change for that fixture: bump `EmbeddedSpecSHA256`, the matching pin in
  `ralph/prd.json`, and let `registry_test.go` lock the new digest plus
  operation count + IDs.
- Schemas are preserved as `json.RawMessage`. Do **not** re-model OpenAPI
  schema fragments into Go structs — yalla's contract is to surface the
  schema verbatim so agents can feed it into their own validators.
- `Operation` is an immutable value type. Methods on `*Registry` return
  copies (`Operations()`, `Get()`) so callers cannot mutate the registry
  in place. Concurrent reads are safe.
- `Default()` parses `EmbeddedSpec` once and panics on parse failure (a panic
  here is a build-time bug, not a runtime one). Production backend-only CLI
  discovery should prefer `Load()` on the live `/openapi.json` bytes fetched by
  `internal/cli/yalla_backend_client.go`.
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

## HTTP client

- `client.go` is the generic execution surface for Yalla backend calls and
  legacy Dokploy fixture tests.
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
- For Yalla backend calls, use `AuthSchemeBearer` so the token is forwarded as
  `Authorization: Bearer <token>` and never appears in any error message this
  package constructs. `AuthSchemeAPIKeyHeader` remains available for legacy
  Dokploy fixture coverage that expects `x-api-key`.
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

## Multipart bodies (`multipart.go`)

- `Request.Body` is contractually pre-serialised bytes — `internal/api`
  never reaches into the file system and never spawns a multipart writer on
  the wire side. Multipart encoding helpers are retained for compatibility and
  deterministic tests; normal backend-only product commands send JSON through
  `yallaJSONRequest`.
- `IsMultipartFormData(ct)` is the canonical detector. Use it instead of
  hand-rolling a `strings.HasPrefix("multipart/form-data")` check so the
  case/whitespace/parameter handling stays in one place.
- Deterministic mode: an empty boundary tells `BuildMultipart` to let
  `mime/multipart` pick a random one (live wire). A non-empty boundary
  is passed through `multipart.Writer.SetBoundary`, which validates it
  and returns an error rather than producing a malformed envelope.
  `DefaultDryRunMultipartBoundary` is the single literal `yalla api call
  --dry-run` uses; do not derive a new constant in tests, reference this
  one so a future change to the dry-run boundary only edits one place.
- Field ordering is alphabetical by name across the scalar+file
  namespace so the encoded bytes are reproducible for a given boundary.
  Tests that assert byte-equality of dry-run envelopes rely on this.
- File parts default to `application/octet-stream` when `ContentType`
  is empty so binaries never get mislabelled as `text/plain` by an
  intermediary. Filename defaults to FieldName when empty so the part
  still has a stable identifier on the wire.
- `BuildMultipart` rejects empty / duplicate field names with a typed
  Go error; the CLI wraps that into `CodeInvalidInput` so an agent sees
  a stable exit code and a hint pointing back at the input shape.
