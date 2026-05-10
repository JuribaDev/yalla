package api

// HTTP client for the Dokploy API.
//
// The client is the single execution surface used by every yalla command
// that has to actually talk to Dokploy: the raw API executor (US-0005), the
// future curated commands (US-0012), and any contract test that prefers a
// real HTTP round-trip over a mocked registry.
//
// The package boundary is deliberate:
//
//   - The client never imports `internal/config` or `internal/cli`. It is a
//     plain Go type that takes a fully-resolved [ClientConfig] and returns a
//     fully-resolved [Result]. The CLI layer is responsible for constructing
//     the config from `*config.Config` and for rendering errors through the
//     output Renderer.
//   - The client never logs and never calls a renderer. It returns rich
//     typed errors and a [Result] so callers stay in control of stdout /
//     stderr. The token, query string, headers, and body never appear in a
//     [yerr.Error] message we construct here, so the output redactor's
//     defence-in-depth pass cannot find a leak from this package.
//   - The client maps transport-level failures (DNS, TLS, dial, timeout,
//     cancel) to typed [yerr.Error] values directly. HTTP responses with
//     a non-2xx status are NOT auto-converted: the caller decides whether
//     a 4xx is fatal (raw API call) or expected (probe). Use
//     [Result.AsError] to opt into the canonical mapping.

import (
	"bytes"
	"context"
	stderrors "errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Defaults applied when [ClientConfig] leaves a field zero. The values are
// part of the public contract — the CLI's documented behavior assumes these
// numbers.
const (
	// DefaultTimeout caps a single HTTP attempt (connect + headers + body).
	// Dokploy's slowest deploy operations stream progress on stderr from the
	// server side; the request itself returns quickly. 30s is generous for
	// any single round trip while still failing fast for unreachable hosts.
	DefaultTimeout = 30 * time.Second

	// DefaultMaxRetries is the number of retries (NOT total attempts) used
	// for idempotent requests on transient failures. With the default the
	// client makes at most three attempts (1 + 2).
	DefaultMaxRetries = 2

	// DefaultRetryBase is the first backoff interval; subsequent retries
	// double this value up to a small cap.
	DefaultRetryBase = 200 * time.Millisecond

	// MaxBackoff caps a single retry sleep so a runaway exponential cannot
	// stretch a request past its context deadline by more than this.
	MaxBackoff = 5 * time.Second
)

// Header names treated specially by the client. Defined as constants so the
// httptest tests, retry policy, and error path all agree on the casing.
const (
	HeaderAuthorization = "Authorization"
	HeaderUserAgent     = "User-Agent"
	HeaderContentType   = "Content-Type"
	HeaderAccept        = "Accept"
	HeaderRequestID     = "X-Request-Id"
	HeaderTraceID       = "X-Trace-Id"
	HeaderCorrelationID = "X-Correlation-Id"

	// ContentTypeJSON is the canonical media type for Dokploy request and
	// response bodies. Other media types are accepted on the response path
	// (the body is captured verbatim) but never produced by the client.
	ContentTypeJSON = "application/json"

	// DefaultAPIKeyHeader is the wire header used by [AuthSchemeAPIKeyHeader]
	// when [ClientConfig.AuthHeaderName] is empty. Dokploy's OpenAPI spec
	// declares this exact casing (`x-api-key`) and the production server
	// rejects requests that use Bearer in its place, so the constant is
	// part of the public contract.
	DefaultAPIKeyHeader = "x-api-key"
)

// AuthScheme controls how [ClientConfig.Token] is attached to outgoing
// requests. The value is meant to be derived from the OpenAPI security
// scheme so a future spec drop that switches Dokploy to a different
// transport (Basic, OAuth2, signed headers) can be supported by adding a
// constant here without touching every CLI call site.
//
// String forms are part of the public contract — tests may match on
// them. New schemes should be added as additional constants rather than
// repurposing existing values.
type AuthScheme string

// AuthScheme values. The zero value is treated as [AuthSchemeBearer] so
// pre-existing tests and any caller that has not been updated keep their
// previous behavior; production callers should pass an explicit scheme
// resolved from the OpenAPI document.
const (
	// AuthSchemeUnspecified preserves the legacy default. Equivalent to
	// [AuthSchemeBearer] at runtime.
	AuthSchemeUnspecified AuthScheme = ""

	// AuthSchemeBearer sends `Authorization: Bearer <token>`. Used when
	// the OpenAPI spec declares an HTTP-bearer security scheme.
	AuthSchemeBearer AuthScheme = "bearer"

	// AuthSchemeAPIKeyHeader sends a single header carrying the raw
	// token (no scheme prefix). The header name defaults to
	// [DefaultAPIKeyHeader]; override via [ClientConfig.AuthHeaderName]
	// when the spec declares a custom name.
	AuthSchemeAPIKeyHeader AuthScheme = "apiKeyHeader"
)

// ClientConfig is the resolved input to [NewClient]. The CLI layer builds it
// from `*config.Config`; tests build it inline. Zero fields take their
// [Default*] values.
type ClientConfig struct {
	// BaseURL is the Dokploy installation URL. Must include scheme and host
	// (e.g. https://dokploy.example.com); a path prefix is allowed and is
	// preserved when joining with the per-request Path.
	BaseURL string

	// Token is the API token forwarded to Dokploy. Its placement on the
	// wire is controlled by [ClientConfig.AuthScheme]:
	//   - [AuthSchemeBearer]         → `Authorization: Bearer <token>`
	//   - [AuthSchemeAPIKeyHeader]   → `<AuthHeaderName>: <token>`
	// An empty Token disables auth entirely so unauthenticated probes
	// stay possible. The value is never embedded in client-produced error
	// messages; the output redactor scrubs it as a defence-in-depth.
	Token string

	// AuthScheme controls how Token is attached. Empty falls back to
	// [AuthSchemeBearer] so existing tests and any caller that has not
	// been updated keep their previous behavior.
	AuthScheme AuthScheme

	// AuthHeaderName overrides the header name when AuthScheme is
	// [AuthSchemeAPIKeyHeader]. Empty falls back to [DefaultAPIKeyHeader].
	// Ignored for any other scheme.
	AuthHeaderName string

	// BasePathPrefix is prepended to the per-request Path when the
	// caller-supplied BaseURL has no path component. Use the path
	// component of the OpenAPI `servers[0].url` (e.g. "/api") so a user
	// who pastes only their host into YALLA_BASE_URL still hits the API
	// router instead of the upstream SPA. An explicit BaseURL path
	// (anything other than "" or "/") wins so reverse-proxied installs
	// (e.g. `https://example.com/dokploy/api`) continue to work without
	// extra configuration.
	BasePathPrefix string

	// UserAgent is forwarded as the User-Agent header. Callers should pass
	// `"yalla/<version>"` to keep the CLI traceable in Dokploy access logs.
	UserAgent string

	// Timeout caps a single HTTP attempt. Zero falls back to [DefaultTimeout].
	// A negative value disables the per-attempt timeout — used by tests that
	// drive a context.WithDeadline themselves.
	Timeout time.Duration

	// MaxRetries bounds the number of retries (extra attempts) the client
	// makes for idempotent requests on transient failures. Zero disables
	// retries; a negative value is clamped to zero.
	MaxRetries int

	// RetryBase is the first retry's sleep. Subsequent retries double up to
	// [MaxBackoff]. Setting this to zero disables sleeping between retries
	// — useful for tests that still want the retry loop to run.
	RetryBase time.Duration

	// Transport overrides the http.RoundTripper. Used by tests with
	// httptest.Server-backed clients and by future tracing wrappers.
	Transport http.RoundTripper
}

// Client is the immutable, concurrency-safe Dokploy HTTP client. Construct
// once per command invocation via [NewClient] and pass the pointer down.
type Client struct {
	baseURL        *url.URL
	token          string
	authScheme     AuthScheme
	authHeaderName string
	userAgent      string
	httpClient     *http.Client
	maxRetries     int
	retryBase      time.Duration
}

// NewClient validates the config and returns a ready-to-use client. A bad
// base URL surfaces here as a [yerr.Error] with [yerr.CodeConfig] so the
// caller can render it the same way as any other config failure.
func NewClient(cfg ClientConfig) (*Client, error) {
	base := strings.TrimSpace(cfg.BaseURL)
	if base == "" {
		return nil, yerr.New(yerr.CodeConfig, "no Dokploy base URL configured").
			WithHint("set YALLA_BASE_URL, pass --base-url, or run `yalla config set base_url https://dokploy.example.com`")
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, yerr.New(yerr.CodeConfig, "invalid Dokploy base URL").Wrap(err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, yerr.New(yerr.CodeConfig, "Dokploy base URL must use http or https").
			WithHintf("got scheme %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, yerr.New(yerr.CodeConfig, "Dokploy base URL is missing a host")
	}

	// Apply the spec-derived path prefix only when the user-supplied URL
	// has no path of its own. A non-trivial Path (anything beyond "/")
	// is the user's explicit intent — typically a reverse-proxied
	// install — and must not be overwritten by the default.
	if prefix := strings.TrimSpace(cfg.BasePathPrefix); prefix != "" && (u.Path == "" || u.Path == "/") {
		if !strings.HasPrefix(prefix, "/") {
			prefix = "/" + prefix
		}
		u.Path = strings.TrimSuffix(prefix, "/")
	}

	// Resolve the auth scheme. The zero value maps to Bearer for
	// backward compatibility with tests and pre-existing callers; named
	// schemes pass through verbatim so an unknown value would surface
	// (the doOnce switch falls back to Bearer for unknown schemes too,
	// so unknown is a no-op rather than a panic).
	scheme := cfg.AuthScheme
	if scheme == AuthSchemeUnspecified {
		scheme = AuthSchemeBearer
	}
	authHeader := strings.TrimSpace(cfg.AuthHeaderName)
	if scheme == AuthSchemeAPIKeyHeader && authHeader == "" {
		authHeader = DefaultAPIKeyHeader
	}

	timeout := cfg.Timeout
	switch {
	case timeout == 0:
		timeout = DefaultTimeout
	case timeout < 0:
		timeout = 0
	}

	httpClient := &http.Client{
		Timeout:   timeout,
		Transport: cfg.Transport,
	}

	ua := strings.TrimSpace(cfg.UserAgent)
	if ua == "" {
		ua = "yalla/dev"
	}

	retries := cfg.MaxRetries
	if retries < 0 {
		retries = 0
	}
	retryBase := cfg.RetryBase
	if retryBase < 0 {
		retryBase = 0
	}

	return &Client{
		baseURL:        u,
		token:          strings.TrimSpace(cfg.Token),
		authScheme:     scheme,
		authHeaderName: authHeader,
		userAgent:      ua,
		httpClient:     httpClient,
		maxRetries:     retries,
		retryBase:      retryBase,
	}, nil
}

// HasToken reports whether the client carries a non-empty token.
// Useful for callers that want to short-circuit before issuing a request
// against an authenticated endpoint.
func (c *Client) HasToken() bool { return c != nil && c.token != "" }

// AuthHeaderName returns the wire header that will carry the token for
// the current scheme: "Authorization" for [AuthSchemeBearer], the
// configured API-key name (defaulting to [DefaultAPIKeyHeader]) for
// [AuthSchemeAPIKeyHeader]. Used by the dry-run renderer to know which
// header to scrub. Returns "" for a nil client.
func (c *Client) AuthHeaderName() string {
	if c == nil {
		return ""
	}
	switch c.authScheme {
	case AuthSchemeAPIKeyHeader:
		if c.authHeaderName != "" {
			return c.authHeaderName
		}
		return DefaultAPIKeyHeader
	default:
		return HeaderAuthorization
	}
}

// AuthHeaderValue returns the literal value the client would attach to
// the wire request for the given token under the current scheme. The
// dry-run renderer never calls this with the real token (it substitutes
// the redaction sentinel first), so the function never leaks secrets on
// its own. Returns "" for a nil client.
func (c *Client) AuthHeaderValue(token string) string {
	if c == nil {
		return ""
	}
	switch c.authScheme {
	case AuthSchemeAPIKeyHeader:
		return token
	default:
		return "Bearer " + token
	}
}

// BaseURL returns the resolved base URL string. Stable across the client's
// lifetime; safe to use in diagnostic output (no token component).
func (c *Client) BaseURL() string {
	if c == nil || c.baseURL == nil {
		return ""
	}
	return c.baseURL.String()
}

// UserAgent returns the configured User-Agent.
func (c *Client) UserAgent() string {
	if c == nil {
		return ""
	}
	return c.userAgent
}

// Request describes a single HTTP request. Zero values are valid for every
// optional field. Callers serialise their own bodies (typically JSON via
// [json.Marshal]) so the client stays media-type agnostic on the request
// side.
type Request struct {
	// Method is the HTTP verb. Required. Case-insensitive on input;
	// upper-cased before being sent.
	Method string

	// Path is the path component appended to [Client.BaseURL]. A leading
	// slash is added if missing. Use a fully-qualified URL (with scheme)
	// to bypass BaseURL — this is how curated commands hit non-Dokploy
	// endpoints (e.g. an OAuth provider) without a second client.
	Path string

	// Query is the request query string. May be nil. Values are appended to
	// any query already present in BaseURL/Path so a caller-supplied path
	// like "/foo?x=1" combines cleanly with Query["y"]=["2"].
	Query url.Values

	// Headers are merged after the request is built so callers can override
	// any default the client would otherwise set. Pass a custom
	// Authorization header here to bypass the Token-derived default.
	Headers http.Header

	// Body is the pre-serialised request body. Empty body sends no body.
	Body []byte

	// ContentType is the request body media type. Defaults to
	// application/json when Body is non-empty and the field is empty.
	ContentType string

	// Idempotent opts the request into the retry policy. The client never
	// retries an Idempotent==false request, even on a transport timeout,
	// because Dokploy's POST-shaped operation surface includes mutating
	// calls (deploy, restart, delete) that must not double-fire.
	Idempotent bool
}

// Result captures everything the caller needs from a completed HTTP
// transaction: status, body, headers, and the metadata fields agents care
// about (request id, trace id, attempts, duration).
type Result struct {
	// Status is the numeric HTTP status code (e.g. 200, 401, 503).
	Status int
	// StatusText is the full status line ("200 OK"), as returned by net/http.
	StatusText string

	// Headers is a clone of the response headers. Safe to mutate.
	Headers http.Header

	// Body is the full response body. Captured even for non-2xx responses
	// so the caller can surface the server's error envelope. Limited only
	// by what Dokploy itself writes; yalla does not impose an upper bound.
	Body []byte

	// ContentType is the response Content-Type header (verbatim, including
	// any `; charset=utf-8` suffix).
	ContentType string

	// RequestID and TraceID are extracted from common observability headers
	// so agents can quote them when reporting upstream failures. Empty when
	// Dokploy did not emit the header.
	RequestID string
	TraceID   string

	// Duration is the wall-clock time spent on the (final) attempt only.
	Duration time.Duration

	// Attempts counts how many HTTP round-trips were made (including
	// retries). Always >= 1 for a returned Result.
	Attempts int
}

// Success reports whether the status code is in the 2xx range.
func (r *Result) Success() bool {
	return r != nil && r.Status >= 200 && r.Status < 300
}

// AsError maps a non-2xx status to a typed [yerr.Error]. 2xx returns nil so
// callers can write `if err := result.AsError(); err != nil { ... }`. The
// returned error's hint includes a truncated, single-line excerpt of the
// response body so agents can distinguish failure modes without a second
// round trip.
func (r *Result) AsError() *yerr.Error {
	if r == nil {
		return yerr.New(yerr.CodeInternal, "nil HTTP result")
	}
	if r.Success() {
		return nil
	}
	code := classifyStatus(r.Status)
	msg := fmt.Sprintf("Dokploy API responded with HTTP %d %s", r.Status, http.StatusText(r.Status))
	e := yerr.New(code, msg)
	if hint := bodyHint(r.Body); hint != "" {
		e = e.WithHint(hint)
	}
	return e
}

// classifyStatus is the canonical HTTP-status to [yerr.Code] map. Keep it in
// sync with the table documented in `internal/errors`. New status families
// (e.g. 451 Unavailable For Legal Reasons) should be added explicitly rather
// than absorbed by the default branch.
func classifyStatus(status int) yerr.Code {
	switch {
	case status >= 200 && status < 300:
		return ""
	case status == http.StatusBadRequest, status == http.StatusUnprocessableEntity:
		return yerr.CodeInvalidInput
	case status == http.StatusUnauthorized:
		return yerr.CodeAuth
	case status == http.StatusForbidden:
		return yerr.CodeForbidden
	case status == http.StatusNotFound:
		return yerr.CodeNotFound
	case status == http.StatusConflict, status == http.StatusPreconditionFailed:
		return yerr.CodeConflict
	case status == http.StatusTooManyRequests:
		return yerr.CodeRateLimited
	case status >= 500 && status < 600:
		return yerr.CodeServer
	default:
		// 4xx values we don't classify above (e.g. 405, 415, 418) are caller
		// errors that don't fit a more specific code; surface them as
		// invalid input so scripts get exit code 2.
		if status >= 400 && status < 500 {
			return yerr.CodeInvalidInput
		}
		return yerr.CodeServer
	}
}

// bodyHint trims the response body to a single-line excerpt suitable for an
// error hint. Caller-side renderers always run the result through the
// output redactor before printing.
func bodyHint(body []byte) string {
	s := strings.TrimSpace(string(body))
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	const maxLen = 256
	if len(s) > maxLen {
		s = s[:maxLen] + "…"
	}
	return "response body: " + s
}

// Do performs the request. The contract is:
//
//   - On a transport-level failure (timeout, cancel, DNS, TCP, TLS), the
//     return is `(nil, *yerr.Error)` with one of [yerr.CodeTimeout],
//     [yerr.CodeCanceled], or [yerr.CodeNetwork].
//   - On any completed HTTP transaction (any status code), the return is
//     `(*Result, nil)` and the caller decides what counts as a failure.
//   - When [Request.Idempotent] is true and [ClientConfig.MaxRetries] is
//     positive, retriable transport failures and 502/503/504 responses
//     trigger a bounded exponential-backoff retry. A non-idempotent request
//     is never retried, even on a network timeout.
//
// Cancelling ctx during a backoff sleep returns the [yerr.CodeCanceled]
// error from the most recent attempt rather than waiting out the timer.
func (c *Client) Do(ctx context.Context, req *Request) (*Result, error) {
	if c == nil {
		return nil, yerr.New(yerr.CodeInternal, "nil HTTP client")
	}
	if req == nil {
		return nil, yerr.New(yerr.CodeInternal, "nil HTTP request")
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		return nil, yerr.New(yerr.CodeInternal, "request missing method")
	}
	if req.Path == "" {
		return nil, yerr.New(yerr.CodeInternal, "request missing path")
	}

	target, err := c.resolvePath(req.Path)
	if err != nil {
		return nil, yerr.New(yerr.CodeInternal, "invalid request path").Wrap(err)
	}
	if len(req.Query) > 0 {
		merged := target.Query()
		for k, vs := range req.Query {
			for _, v := range vs {
				merged.Add(k, v)
			}
		}
		target.RawQuery = merged.Encode()
	}

	maxAttempts := 1
	if req.Idempotent {
		maxAttempts = 1 + c.maxRetries
	}

	var lastTransportErr *yerr.Error
	var lastResult *Result

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			if cancelled := ctxToTypedError(err); cancelled != nil {
				return nil, cancelled
			}
		}

		start := time.Now()
		result, doErr := c.doOnce(ctx, method, target, req)
		duration := time.Since(start)

		if doErr != nil {
			typed := transportToTypedError(doErr)
			lastTransportErr = typed
			if attempt+1 < maxAttempts && shouldRetryTransportError(typed) {
				if !c.backoff(ctx, attempt) {
					// Context cancelled during backoff. Surface that, not
					// the transport error, because the cancel is the
					// proximate cause of the abort.
					return nil, yerr.New(yerr.CodeCanceled, "request canceled during retry backoff").Wrap(ctx.Err())
				}
				continue
			}
			return nil, typed
		}

		result.Duration = duration
		result.Attempts = attempt + 1
		lastResult = result

		if attempt+1 < maxAttempts && shouldRetryStatus(result.Status) {
			if !c.backoff(ctx, attempt) {
				return result, nil
			}
			continue
		}
		return result, nil
	}

	// Loop exited without a return. This is unreachable in practice (the
	// final iteration always returns) but is defensive: prefer the last
	// result if any, otherwise the last transport error.
	if lastResult != nil {
		return lastResult, nil
	}
	if lastTransportErr != nil {
		return nil, lastTransportErr
	}
	return nil, yerr.New(yerr.CodeNetwork, "request exceeded retry budget without a response")
}

// resolvePath joins Path against the client's base URL. An absolute URL in
// Path bypasses the base entirely, which is the documented escape hatch for
// non-Dokploy endpoints.
func (c *Client) resolvePath(path string) (*url.URL, error) {
	rel, err := url.Parse(path)
	if err != nil {
		return nil, err
	}
	if rel.IsAbs() {
		return rel, nil
	}
	merged := *c.baseURL
	rp := rel.Path
	if rp != "" && !strings.HasPrefix(rp, "/") {
		rp = "/" + rp
	}
	switch {
	case merged.Path == "" || merged.Path == "/":
		merged.Path = rp
	default:
		merged.Path = strings.TrimSuffix(merged.Path, "/") + rp
	}
	merged.RawQuery = rel.RawQuery
	merged.Fragment = rel.Fragment
	return &merged, nil
}

// doOnce builds and sends a single HTTP attempt. The caller owns the retry
// loop; doOnce never retries.
func (c *Client) doOnce(ctx context.Context, method string, target *url.URL, req *Request) (*Result, error) {
	var body io.Reader
	if len(req.Body) > 0 {
		body = bytes.NewReader(req.Body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, target.String(), body)
	if err != nil {
		return nil, err
	}

	// Caller headers first so client defaults can fill the gaps without
	// ever overwriting an explicit caller value (Authorization, etc.).
	if req.Headers != nil {
		for k, vs := range req.Headers {
			for _, v := range vs {
				httpReq.Header.Add(k, v)
			}
		}
	}
	if len(req.Body) > 0 && httpReq.Header.Get(HeaderContentType) == "" {
		ct := req.ContentType
		if ct == "" {
			ct = ContentTypeJSON
		}
		httpReq.Header.Set(HeaderContentType, ct)
	}
	// Auth header. Caller-supplied headers always win (the loop above
	// already populated them) so an explicit Authorization or x-api-key
	// in req.Headers bypasses both branches.
	if c.token != "" {
		switch c.authScheme {
		case AuthSchemeAPIKeyHeader:
			h := c.authHeaderName
			if h == "" {
				h = DefaultAPIKeyHeader
			}
			if httpReq.Header.Get(h) == "" {
				httpReq.Header.Set(h, c.token)
			}
		default: // AuthSchemeBearer / AuthSchemeUnspecified
			if httpReq.Header.Get(HeaderAuthorization) == "" {
				httpReq.Header.Set(HeaderAuthorization, "Bearer "+c.token)
			}
		}
	}
	if c.userAgent != "" && httpReq.Header.Get(HeaderUserAgent) == "" {
		httpReq.Header.Set(HeaderUserAgent, c.userAgent)
	}
	if httpReq.Header.Get(HeaderAccept) == "" {
		httpReq.Header.Set(HeaderAccept, ContentTypeJSON)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	payload, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return nil, readErr
	}

	return &Result{
		Status:      resp.StatusCode,
		StatusText:  resp.Status,
		Headers:     resp.Header.Clone(),
		Body:        payload,
		ContentType: resp.Header.Get(HeaderContentType),
		RequestID:   firstHeader(resp.Header, HeaderRequestID, "X-Request-ID", "Request-Id"),
		TraceID:     firstHeader(resp.Header, HeaderTraceID, HeaderCorrelationID, "Traceparent"),
	}, nil
}

// firstHeader returns the first non-empty value among the supplied header
// names. Comparison is case-insensitive (delegated to http.Header.Get).
func firstHeader(h http.Header, names ...string) string {
	for _, n := range names {
		if v := h.Get(n); v != "" {
			return v
		}
	}
	return ""
}

// backoff sleeps for the attempt's exponential interval, returning false
// when ctx is canceled (so the caller can short-circuit). When [retryBase]
// is zero the function is a no-op — used by tests to keep the retry loop
// fast while still exercising the attempt counter.
func (c *Client) backoff(ctx context.Context, attempt int) bool {
	if c.retryBase <= 0 {
		return ctx.Err() == nil
	}
	d := time.Duration(float64(c.retryBase) * math.Pow(2, float64(attempt)))
	if d > MaxBackoff {
		d = MaxBackoff
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// ctxToTypedError converts a context error into the typed equivalent. Used
// when the loop notices a cancellation between attempts.
func ctxToTypedError(err error) *yerr.Error {
	switch {
	case err == nil:
		return nil
	case stderrors.Is(err, context.Canceled):
		return yerr.New(yerr.CodeCanceled, "request canceled").Wrap(err)
	case stderrors.Is(err, context.DeadlineExceeded):
		return yerr.New(yerr.CodeTimeout, "request deadline exceeded").Wrap(err)
	default:
		return yerr.New(yerr.CodeNetwork, err.Error()).Wrap(err)
	}
}

// transportToTypedError classifies a transport-level error returned by
// http.Client.Do or io.ReadAll. The distinction between timeout, cancel,
// and network is observable to scripts (different exit codes), so the
// classifier is conservative: anything that is not unambiguously a timeout
// or a cancel becomes [yerr.CodeNetwork].
func transportToTypedError(err error) *yerr.Error {
	if err == nil {
		return nil
	}
	if stderrors.Is(err, context.Canceled) {
		return yerr.New(yerr.CodeCanceled, "request canceled").Wrap(err)
	}
	if stderrors.Is(err, context.DeadlineExceeded) {
		return yerr.New(yerr.CodeTimeout, "request deadline exceeded").Wrap(err)
	}
	var netErr net.Error
	if stderrors.As(err, &netErr) && netErr.Timeout() {
		return yerr.New(yerr.CodeTimeout, "network timeout contacting Dokploy").Wrap(err)
	}
	// url.Error.Error() embeds the request URL but not the body or headers,
	// so the message is safe to surface; the output redactor still scrubs
	// any ?token=… parameter as defence in depth.
	return yerr.New(yerr.CodeNetwork, "network error contacting Dokploy: "+err.Error()).Wrap(err)
}

// shouldRetryTransportError reports whether a transport-level failure is
// safe to retry. CodeCanceled is never retried (the caller asked us to
// stop); CodeTimeout and CodeNetwork are.
func shouldRetryTransportError(e *yerr.Error) bool {
	if e == nil {
		return false
	}
	switch e.Code {
	case yerr.CodeTimeout, yerr.CodeNetwork:
		return true
	default:
		return false
	}
}

// shouldRetryStatus reports whether an HTTP status is worth retrying. Only
// the upstream/gateway 5xx codes qualify: 500 may indicate a deterministic
// server bug and 501 is permanent, so neither is retried automatically.
func shouldRetryStatus(status int) bool {
	switch status {
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}
