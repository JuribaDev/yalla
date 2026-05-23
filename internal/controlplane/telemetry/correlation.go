// Package telemetry owns logs, metrics, traces, and request correlation for
// the Yalla Control Plane backend.
//
// Correlation is the foundation the rest of the observability surface builds
// on: every request carries a request_id (unique to that one HTTP request) and
// a correlation_id (shared across every request, log line, audit record,
// provisioning job, and Dokploy call that belongs to the same logical
// workflow). The IDs travel on the request context so any layer — handler,
// repository, queue, provisioner — can read them without threading an extra
// argument through every signature.
//
// The wire contract is stable and public:
//
//   - Inbound: a caller may supply X-Request-Id and/or X-Correlation-Id. A
//     supplied value is honoured only when it passes SafeID; an unsafe value
//     (control characters, header-injection payloads, oversized blobs) is
//     discarded and a fresh value is generated instead.
//   - Outbound: the resolved request_id and correlation_id are echoed back as
//     X-Request-Id and X-Correlation-Id response headers, and surface in every
//     yalla.output.v1 / yalla.error.v1 envelope as request_id.
package telemetry

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"log/slog"
	"net/http"
	"time"
)

// Stable HTTP header names for request correlation. These are part of the
// public API contract: agents, CI, and the CLI may set them on outbound
// requests and read them from responses. Changing them is a breaking change.
const (
	// HeaderRequestID carries the per-request identifier.
	HeaderRequestID = "X-Request-Id"
	// HeaderCorrelationID carries the cross-request workflow identifier.
	HeaderCorrelationID = "X-Correlation-Id"
)

// maxIDLen bounds the length of an inbound correlation identifier. It is
// generous enough for UUIDs, ULIDs, and our own 32-hex-character IDs while
// small enough that a hostile caller cannot use the header to bloat logs,
// audit metadata, or job rows.
const maxIDLen = 128

// ctxKey is an unexported context-key type so correlation values cannot
// collide with keys set by other packages.
type ctxKey int

const (
	correlationKey ctxKey = iota
)

// Correlation carries the identifiers that tie a single request — and every
// log line, audit record, provisioning job, and Dokploy call it spawns —
// together. The zero value means "no correlation in context yet".
type Correlation struct {
	// RequestID is unique to one HTTP request.
	RequestID string
	// CorrelationID is shared across every request and job in the same
	// logical workflow. When a caller does not supply one it defaults to the
	// request_id, so a single request is always its own correlation root.
	CorrelationID string
}

// NewRequestID returns a fresh, collision-resistant request identifier as a
// 32-character lowercase hex string. The character set is intentionally a
// strict subset of SafeID, so a generated ID always round-trips cleanly
// through headers, logs, JSON envelopes, and database columns.
func NewRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand is documented never to fail on supported platforms; if
		// it somehow does, fall back to a nanosecond timestamp so the request
		// still receives a usable, unique-enough identifier rather than an
		// empty string.
		binary.BigEndian.PutUint64(b[:8], uint64(time.Now().UnixNano()))
	}
	return hex.EncodeToString(b[:])
}

// SafeID reports whether s is safe to accept as an inbound correlation
// identifier. A safe ID is 1..maxIDLen characters drawn only from
// [A-Za-z0-9._-]. The restriction is deliberate defence-in-depth: it rejects
// control characters and CR/LF (header- and log-injection payloads), spaces,
// and oversized blobs, so an inbound header value can be placed verbatim into
// response headers, structured logs, audit metadata, and job rows without
// further escaping.
func SafeID(s string) bool {
	if len(s) == 0 || len(s) > maxIDLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return true
}

// WithCorrelation returns a child context carrying c. It is used by the
// Correlate middleware and is also available to non-HTTP entry points (worker
// jobs, internal tasks) that need to seed a correlation context of their own.
func WithCorrelation(ctx context.Context, c Correlation) context.Context {
	return context.WithValue(ctx, correlationKey, c)
}

// FromContext returns the Correlation stored in ctx, or the zero Correlation
// when none is present.
func FromContext(ctx context.Context) Correlation {
	if ctx == nil {
		return Correlation{}
	}
	c, _ := ctx.Value(correlationKey).(Correlation)
	return c
}

// RequestID is a convenience accessor for FromContext(ctx).RequestID.
func RequestID(ctx context.Context) string {
	return FromContext(ctx).RequestID
}

// CorrelationID is a convenience accessor for FromContext(ctx).CorrelationID.
func CorrelationID(ctx context.Context) string {
	return FromContext(ctx).CorrelationID
}

// LogAttrs returns the correlation identifiers in ctx as slog attributes,
// ready to splat into a log call or logger.With. It returns an empty slice
// when ctx carries no correlation, so callers never emit empty-valued fields.
func LogAttrs(ctx context.Context) []any {
	c := FromContext(ctx)
	if c.RequestID == "" && c.CorrelationID == "" {
		return nil
	}
	return []any{
		slog.String("request_id", c.RequestID),
		slog.String("correlation_id", c.CorrelationID),
	}
}

// Correlate is the HTTP middleware that resolves request correlation for every
// inbound request. It honours a caller-supplied X-Request-Id / X-Correlation-Id
// only when the value passes SafeID, generates a fresh request_id otherwise,
// defaults a missing correlation_id to the request_id, stores the resolved
// Correlation on the request context, and echoes both IDs back as response
// headers before delegating to next.
//
// It is the outermost middleware in the stack: every downstream handler,
// logging middleware, and error renderer can rely on the correlation context
// already being present.
func Correlate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get(HeaderRequestID)
		if !SafeID(requestID) {
			// Missing or unsafe (e.g. a CR/LF header-injection payload):
			// discard it and mint a trusted value instead.
			requestID = NewRequestID()
		}

		correlationID := r.Header.Get(HeaderCorrelationID)
		if !SafeID(correlationID) {
			// A standalone request is its own correlation root.
			correlationID = requestID
		}

		c := Correlation{RequestID: requestID, CorrelationID: correlationID}

		// Echo the resolved IDs so clients and proxies can record them even
		// for responses that never reach a handler (panics, timeouts). The
		// values are SafeID-clean, so they cannot inject extra headers.
		w.Header().Set(HeaderRequestID, requestID)
		w.Header().Set(HeaderCorrelationID, correlationID)

		next.ServeHTTP(w, r.WithContext(WithCorrelation(r.Context(), c)))
	})
}
