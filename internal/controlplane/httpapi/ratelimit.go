package httpapi

import (
	"log/slog"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/ratelimit"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
)

// RateLimiter is the narrow port the rate-limit middleware depends on.
// *ratelimit.Limiter satisfies it in production; tests supply a fake so
// the middleware contract — bucket selection, internal-worker exemption,
// 429 envelope shape, no-secret logging — is verifiable without a real
// token-bucket implementation.
type RateLimiter interface {
	Check(req ratelimit.Request) ratelimit.Decision
}

// RateLimit builds the middleware that enforces inbound request quotas
// against the supplied limiter. It is wired inside RequireAuth so the
// resolved principal (organization id, API key id, auth method) is on the
// request context when the limiter decides — that is what lets the gate
// bill the org and key buckets for an authenticated request while
// falling back to the IP bucket for a public endpoint. The HTTP method
// selects the read- or write-side spec: GET / HEAD / OPTIONS pull from
// the read budget, everything else from the write budget.
//
// A nil limiter installs a no-op wrapper so the construction path is
// uniform for tests and embedders that exercise the routing surface
// without enforcing any cap.
//
// Two cross-cutting guarantees are non-negotiable on this path:
//
//   - The internal-worker credential scheme is unconditionally exempt.
//     The httpapi auth gates stamp the auth method on the request context
//     via withAuthMethod; this middleware reads it back through
//     AuthMethodFromContext and sets ratelimit.Request.Exempt before the
//     limiter even sees the request, so internal callbacks are never
//     throttled by the customer-facing rate limit.
//   - A 429 response carries the stable yalla.error.v1 envelope built by
//     apierr.RateLimited and the integer Retry-After response header.
//     The limiter's Decision.Bucket names the bucket dimension only
//     (BucketOrg / BucketKey / BucketIP); the bucket identity (a tenant's
//     org id, an API key id, a client IP) is never echoed to the wire or
//     to the structured log record.
//
// The optional logger receives one structured WARN record per denial so
// operators can correlate a throttling incident with the request path,
// the bucket dimension, and the retry-after instruction. The record
// inherits the request_id / correlation_id attached by telemetry.Correlate
// and carries no secret-shaped value.
func RateLimit(limiter RateLimiter, logger *slog.Logger) func(http.Handler) http.Handler {
	if limiter == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			req := ratelimit.Request{
				IP:    ClientIP(r),
				Write: isMutatingMethod(r.Method),
			}
			if method, ok := AuthMethodFromContext(r.Context()); ok && method == auth.MethodInternalWorker {
				req.Exempt = true
			}
			if p, ok := policy.PrincipalFromContext(r.Context()); ok {
				req.OrgID = p.OrganizationID
				req.KeyID = p.ID
			}

			decision := limiter.Check(req)
			if decision.Allowed {
				next.ServeHTTP(w, r)
				return
			}

			retrySeconds := int64(math.Ceil(decision.Retry.Seconds()))
			if retrySeconds < 1 {
				retrySeconds = 1
			}
			w.Header().Set("Retry-After", strconv.FormatInt(retrySeconds, 10))
			if logger != nil {
				attrs := []any{
					slog.String("bucket", decision.Bucket),
					slog.Int64("retry_after_seconds", retrySeconds),
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path),
				}
				// telemetry.LogAttrs splats request_id / correlation_id
				// into the record so operators can pivot from a 429 log
				// line straight to the inbound HTTP record.
				attrs = append(attrs, telemetry.LogAttrs(r.Context())...)
				logger.LogAttrs(r.Context(), slog.LevelWarn, "rate limit exceeded", toLogAttrs(attrs)...)
			}
			apienvelope.WriteError(w, requestID(r),
				apierr.RateLimited(decision.Bucket, time.Duration(retrySeconds)*time.Second))
		})
	}
}

// ClientIP resolves the client IP for a request. Trusted reverse-proxy
// headers (X-Forwarded-For, X-Real-IP) win when present so the limiter
// can distinguish callers behind a load balancer; without them the gate
// falls back to the request's RemoteAddr. An empty result is acceptable
// — the limiter skips the IP bucket entirely when no identity is
// available rather than billing every anonymous caller to a shared empty
// bucket.
//
// The header parsing trims the comma-separated list to the first hop so
// a forged tail value cannot push the real client identity out of the
// bucket key.
func ClientIP(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		if i := strings.Index(v, ","); i >= 0 {
			return strings.TrimSpace(v[:i])
		}
		return strings.TrimSpace(v)
	}
	if v := r.Header.Get("X-Real-IP"); v != "" {
		return strings.TrimSpace(v)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// isMutatingMethod reports whether an HTTP method is state-changing so
// the limiter can pick the write-side spec. GET / HEAD / OPTIONS are the
// only methods the API serves that read state without mutating it; every
// other method (POST / PUT / PATCH / DELETE, plus any future RFC-7231
// extension) consumes from the write budget.
func isMutatingMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

// toLogAttrs adapts a slog-style []any value list into the typed
// slog.Attr slice that *slog.Logger.LogAttrs expects. It skips entries
// that are not already slog.Attrs (the telemetry.LogAttrs output is
// already typed), so the result is always safe to splat.
func toLogAttrs(in []any) []slog.Attr {
	out := make([]slog.Attr, 0, len(in))
	for _, v := range in {
		if a, ok := v.(slog.Attr); ok {
			out = append(out, a)
		}
	}
	return out
}
