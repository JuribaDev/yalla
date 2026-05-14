package dokploy

import (
	"bytes"
	"context"
	stderrors "errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// Defaults applied by New when the corresponding Config field is left zero.
const (
	defaultTimeout        = 30 * time.Second
	defaultMaxRetries     = 2
	defaultRetryBaseDelay = 200 * time.Millisecond
	defaultRetryMaxDelay  = 5 * time.Second
)

// maxResponseBody bounds how much of a Dokploy response body the client reads.
// Dokploy resource payloads are small; the bound only guards against a
// pathological or hostile upstream.
const maxResponseBody = 1 << 20

// Config configures a Client. Only BaseURL and Token are required; every other
// field has a safe default applied by New.
type Config struct {
	// BaseURL is the absolute base URL of the Dokploy API (http or https). It
	// is required.
	BaseURL string
	// Token is the Dokploy bearer token. It is required, is stored only inside
	// the Client, and is never exposed by any Client method. Handlers must
	// never receive it.
	Token string
	// HTTPClient is the underlying transport. When nil a default *http.Client
	// is used. The client applies its own per-request timeout regardless, so a
	// supplied client need not set Timeout.
	HTTPClient *http.Client
	// Timeout bounds each individual HTTP attempt. Defaults to 30s.
	Timeout time.Duration
	// MaxRetries is the number of additional attempts made for idempotent
	// (GET, DELETE) requests that fail transiently. A negative value disables
	// retries; zero selects the default of 2. Non-idempotent requests (POST)
	// are never retried.
	MaxRetries int
	// RetryBaseDelay is the first backoff delay; it doubles each attempt up to
	// RetryMaxDelay. Defaults to 200ms.
	RetryBaseDelay time.Duration
	// RetryMaxDelay caps the backoff delay. Defaults to 5s.
	RetryMaxDelay time.Duration
	// Logger receives retry diagnostics. When nil, diagnostics are discarded.
	Logger *slog.Logger
}

// Client is the typed wrapper around the private Dokploy provisioning backend.
// It exposes Yalla provisioning intents (ensure project, deploy service, read
// logs, remove service, ...) rather than raw Dokploy operations, injects the
// Dokploy bearer token into every request without ever exposing it, propagates
// request correlation, applies per-request timeouts, retries only idempotent
// operations, and maps every failure onto the catalogued apierr taxonomy with
// secrets redacted.
//
// A Client is safe for concurrent use. Construct one with New.
type Client struct {
	baseURL        string
	token          string
	httpClient     *http.Client
	timeout        time.Duration
	maxRetries     int
	retryBaseDelay time.Duration
	retryMaxDelay  time.Duration
	logger         *slog.Logger
	redactor       *output.Redactor
}

// New validates cfg and returns a ready Client. Configuration failures are
// typed yerr.CodeConfig errors and never echo the token.
func New(cfg Config) (*Client, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if base == "" {
		return nil, yerr.New(yerr.CodeConfig, "dokploy: base URL is required")
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return nil, yerr.New(yerr.CodeConfig, "dokploy: base URL is not a valid absolute URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, yerr.New(yerr.CodeConfig, "dokploy: base URL scheme must be http or https")
	}

	token := strings.TrimSpace(cfg.Token)
	if token == "" {
		return nil, yerr.New(yerr.CodeConfig, "dokploy: API token is required")
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{}
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	maxRetries := cfg.MaxRetries
	switch {
	case maxRetries < 0:
		maxRetries = 0
	case maxRetries == 0:
		maxRetries = defaultMaxRetries
	}

	retryBaseDelay := cfg.RetryBaseDelay
	if retryBaseDelay <= 0 {
		retryBaseDelay = defaultRetryBaseDelay
	}
	retryMaxDelay := cfg.RetryMaxDelay
	if retryMaxDelay <= 0 {
		retryMaxDelay = defaultRetryMaxDelay
	}
	if retryMaxDelay < retryBaseDelay {
		retryMaxDelay = retryBaseDelay
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	return &Client{
		baseURL:        base,
		token:          token,
		httpClient:     httpClient,
		timeout:        timeout,
		maxRetries:     maxRetries,
		retryBaseDelay: retryBaseDelay,
		retryMaxDelay:  retryMaxDelay,
		logger:         logger,
		// Seed the redactor with the bearer token so it is scrubbed from any
		// error built from upstream response data; the built-in patterns scrub
		// Authorization headers and token query params even when the literal
		// value is unknown.
		redactor: output.NewRedactor(token),
	}, nil
}

// LogValue renders the Client for structured logging with the token redacted,
// so a Client value can be logged without leaking the credential.
func (c *Client) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("base_url", c.baseURL),
		slog.String("token", output.Sentinel),
	)
}

// get issues a GET and decodes the response into dst. GET is idempotent, so it
// is retried on transient failures.
func (c *Client) get(ctx context.Context, path string, dst any) error {
	return c.do(ctx, http.MethodGet, path, nil, dst)
}

// post issues a POST and decodes the response into dst. POST is not idempotent
// and is never retried.
func (c *Client) post(ctx context.Context, path string, body, dst any) error {
	return c.do(ctx, http.MethodPost, path, body, dst)
}

// del issues a DELETE. DELETE is idempotent, so it is retried on transient
// failures.
func (c *Client) del(ctx context.Context, path string) error {
	return c.do(ctx, http.MethodDelete, path, nil, nil)
}

// do runs an HTTP request, retrying only idempotent methods (GET, DELETE) on
// transient, catalogued-retryable failures. Non-idempotent methods get exactly
// one attempt so a retry can never duplicate a provisioning side effect.
func (c *Client) do(ctx context.Context, method, path string, body, dst any) error {
	var encoded []byte
	if body != nil {
		b, err := encodeBody(body)
		if err != nil {
			return apierr.Internal(err)
		}
		encoded = b
	}

	retryable := method == http.MethodGet || method == http.MethodDelete
	attempts := 1
	if retryable {
		attempts += c.maxRetries
	}

	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return c.contextError(err)
		}
		if attempt > 0 {
			if err := sleep(ctx, c.retryDelay(attempt-1)); err != nil {
				return c.contextError(err)
			}
			c.logger.WarnContext(ctx, "retrying dokploy request",
				"method", method, "path", path, "attempt", attempt, "error", lastErr)
		}

		err := c.attempt(ctx, method, path, encoded, dst)
		if err == nil {
			return nil
		}
		lastErr = err
		if !retryable || !apierr.Retryable(err) {
			return err
		}
	}
	return lastErr
}

// attempt performs a single HTTP round trip. It applies the per-request
// timeout, injects the bearer token and correlation headers, and maps the
// outcome onto the apierr taxonomy.
func (c *Client) attempt(ctx context.Context, method, path string, body []byte, dst any) error {
	reqCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(reqCtx, method, c.baseURL+path, reader)
	if err != nil {
		return apierr.Internal(fmt.Errorf("build dokploy request: %w", err))
	}

	// The bearer token is injected here and nowhere else; it never reaches a
	// handler or an error message.
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if corr := telemetry.FromContext(ctx); corr.RequestID != "" {
		req.Header.Set(telemetry.HeaderRequestID, corr.RequestID)
		req.Header.Set(telemetry.HeaderCorrelationID, corr.CorrelationID)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return c.transportError(err)
	}
	defer func() { _ = resp.Body.Close() }()

	payload, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if dst == nil || len(payload) == 0 {
			return nil
		}
		if err := decodeBody(payload, dst); err != nil {
			return apierr.DokployUnavailable(c.redact(
				fmt.Errorf("decode dokploy response for %s %s: %w", method, path, err)))
		}
		return nil
	}
	return c.statusError(method, path, resp.StatusCode, payload)
}

// transportError classifies a transport-level failure (the request never
// produced an HTTP response) into the apierr taxonomy.
func (c *Client) transportError(err error) error {
	if stderrors.Is(err, context.DeadlineExceeded) {
		return apierr.Timeout(apierr.DependencyDokploy, c.redact(err))
	}
	var netErr net.Error
	if stderrors.As(err, &netErr) && netErr.Timeout() {
		return apierr.Timeout(apierr.DependencyDokploy, c.redact(err))
	}
	return apierr.DokployUnavailable(c.redact(err))
}

// contextError maps a cancelled or expired request context onto the taxonomy.
func (c *Client) contextError(err error) error {
	if stderrors.Is(err, context.DeadlineExceeded) {
		return apierr.Timeout(apierr.DependencyDokploy, c.redact(err))
	}
	return apierr.DokployUnavailable(c.redact(err))
}

// statusError maps a non-2xx Dokploy response onto the apierr taxonomy. The
// response body is preserved (redacted) only as the wrapped cause for
// server-side logging; it never reaches a client-facing Message.
func (c *Client) statusError(method, path string, status int, payload []byte) error {
	detail := c.redact(fmt.Errorf("dokploy %s %s returned status %d: %s",
		method, path, status, strings.TrimSpace(string(payload))))

	switch status {
	case http.StatusBadRequest:
		return apierr.Invalid("the Dokploy provisioning request was rejected").Wrap(detail)
	case http.StatusUnauthorized, http.StatusForbidden:
		// The Dokploy backend rejected Yalla's own credentials. This is an
		// internal Yalla misconfiguration the customer cannot act on and that
		// a retry will not fix, so it is a non-retryable internal error.
		return apierr.Internal(detail)
	case http.StatusNotFound:
		return apierr.NotFound("dokploy resource", "").Wrap(detail)
	case http.StatusConflict:
		return apierr.Conflict("the Dokploy resource already exists").Wrap(detail)
	case http.StatusTooManyRequests:
		return apierr.DokployUnavailable(detail)
	default:
		return apierr.DokployUnavailable(detail)
	}
}

// redact returns an error whose message has every known secret scrubbed. The
// errors.Is/As chain is intentionally flattened: the result is only ever used
// as the wrapped, log-only cause of a catalogued apierr error.
func (c *Client) redact(err error) error {
	if err == nil {
		return nil
	}
	return stderrors.New(c.redactor.Redact(err.Error()))
}

// retryDelay returns the backoff delay before retry number attempt (0-based):
// retryBaseDelay doubled attempt times, capped at retryMaxDelay.
func (c *Client) retryDelay(attempt int) time.Duration {
	d := c.retryBaseDelay
	for i := 0; i < attempt && d < c.retryMaxDelay; i++ {
		d *= 2
	}
	if d > c.retryMaxDelay {
		d = c.retryMaxDelay
	}
	return d
}

// sleep waits for d or until ctx is done, whichever comes first.
func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
