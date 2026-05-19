package telemetry

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/JuribaDev/yalla/internal/output"
)

// requestFields holds log attributes that only become known partway through
// request handling. The organization and principal are resolved by the auth
// and policy layers, which run well after the logging middleware has started
// the request clock, so the middleware seeds an empty, mutable holder onto the
// request context; downstream layers enrich it through SetOrgID /
// SetPrincipalID; the middleware reads it back when it emits the final
// per-request log record.
type requestFields struct {
	mu           sync.Mutex
	orgID        string
	principalID  string
	resourceKind string
	resourceID   string
	jobID        string
	errorCode    string
}

// fieldsKey is an unexported context-key type so the logging holder cannot
// collide with values set by other packages.
type fieldsKey struct{}

// withRequestFields returns a child context carrying a fresh, empty
// requestFields holder. RequestLogging seeds it for every request.
func withRequestFields(ctx context.Context) context.Context {
	return context.WithValue(ctx, fieldsKey{}, &requestFields{})
}

func fieldsFromContext(ctx context.Context) *requestFields {
	if ctx == nil {
		return nil
	}
	f, _ := ctx.Value(fieldsKey{}).(*requestFields)
	return f
}

// SetOrgID records the resolved organization id for the current request so
// the per-request log record includes it. It is a no-op when ctx carries no
// logging holder (for example a non-HTTP code path), so callers never need to
// guard the call. It is safe for concurrent use.
func SetOrgID(ctx context.Context, orgID string) {
	if f := fieldsFromContext(ctx); f != nil {
		f.mu.Lock()
		f.orgID = orgID
		f.mu.Unlock()
	}
}

// SetPrincipalID records the authenticated principal id for the current
// request. It has the same no-op and concurrency semantics as SetOrgID.
func SetPrincipalID(ctx context.Context, principalID string) {
	if f := fieldsFromContext(ctx); f != nil {
		f.mu.Lock()
		f.principalID = principalID
		f.mu.Unlock()
	}
}

// SetResource records the tenant-scoped resource that the current request is
// operating on. Callers should pass only stable resource kind names and IDs
// already authorized or resolved by the control plane; blank values are
// omitted from the final log record.
func SetResource(ctx context.Context, kind, id string) {
	if f := fieldsFromContext(ctx); f != nil {
		f.mu.Lock()
		f.resourceKind = kind
		f.resourceID = id
		f.mu.Unlock()
	}
}

// SetJobID records the durable job associated with the current request, when a
// request enqueues or observes one.
func SetJobID(ctx context.Context, jobID string) {
	if f := fieldsFromContext(ctx); f != nil {
		f.mu.Lock()
		f.jobID = jobID
		f.mu.Unlock()
	}
}

// RecordErrorCode lets envelope renderers attach the stable public error code
// to the request log without exposing response bodies or importing telemetry.
func (s *statusRecorder) RecordErrorCode(code string) {
	if s == nil {
		return
	}
	if f := fieldsFromContext(s.ctx); f != nil {
		f.mu.Lock()
		f.errorCode = code
		f.mu.Unlock()
	}
}

func (f *requestFields) snapshot() (orgID, principalID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.orgID, f.principalID
}

func (f *requestFields) logSnapshot() (orgID, principalID, resourceKind, resourceID, jobID, errorCode string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.orgID, f.principalID, f.resourceKind, f.resourceID, f.jobID, f.errorCode
}

// logRedactor scrubs well-known secret transport patterns (Authorization
// headers, token-bearing query parameters) from any string before it reaches
// a log record. It carries no registered literal secrets — it is a structural
// backstop, so even a request target that smuggles ?token=... into the URL is
// logged redacted.
var logRedactor = output.NewRedactor()

// statusRecorder wraps an http.ResponseWriter to capture the response status
// code and the number of body bytes written, so the logging middleware can
// report them after the handler returns.
type statusRecorder struct {
	http.ResponseWriter
	ctx    context.Context
	status int
	bytes  int
	wrote  bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wrote {
		s.status = code
		s.wrote = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wrote {
		s.status = http.StatusOK
		s.wrote = true
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err
}

// RequestLogging is the HTTP middleware that emits exactly one structured log
// record per request, after the handler has run. Each record carries the
// request_id and correlation_id (resolved by Correlate, which must wrap this
// middleware), the HTTP method, the matched route, the response status, the
// latency, the response size, and — once the auth and policy layers have
// resolved them — the organization and principal ids.
//
// The middleware never logs request or response headers or bodies, so
// Authorization headers, cookies, API keys, and secret variable values cannot
// leak into the log stream. The one caller-controlled string it does record —
// the request target — is passed through a redactor so a token smuggled into
// the URL query is scrubbed too.
//
// The log level of the per-request record reflects the outcome: 5xx responses
// log at error, 4xx at warn, everything else at info. The logger's own level
// threshold — configured from YALLA_LOG_LEVEL with no code change required —
// decides which records are actually written.
//
// A nil logger is replaced with one that discards output, so tests and
// embedders that do not care about request logs can pass nil.
func RequestLogging(logger *slog.Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ctx := withRequestFields(r.Context())
			r = r.WithContext(ctx)
			rec := &statusRecorder{ResponseWriter: w, ctx: ctx, status: http.StatusOK}

			next.ServeHTTP(rec, r)

			latency := time.Since(start)

			// r.Pattern is populated in place by http.ServeMux once a route
			// matches; fall back to the raw path for unmatched routes so the
			// record always has a route field.
			route := r.Pattern
			if route == "" {
				route = r.URL.Path
			}

			attrs := []any{
				slog.String("method", r.Method),
				slog.String("route", logRedactor.Redact(route)),
				slog.String("target", logRedactor.Redact(r.URL.RequestURI())),
				slog.Int("status", rec.status),
				slog.String("status_class", statusClass(rec.status)),
				slog.String("outcome", outcome(rec.status)),
				slog.Int64("latency_ms", latency.Milliseconds()),
				slog.Int("bytes", rec.bytes),
			}
			attrs = append(attrs, LogAttrs(ctx)...)
			if f := fieldsFromContext(ctx); f != nil {
				orgID, principalID, resourceKind, resourceID, jobID, errorCode := f.logSnapshot()
				if orgID != "" {
					attrs = append(attrs, slog.String("org_id", orgID))
				}
				if principalID != "" {
					attrs = append(attrs, slog.String("principal_id", principalID))
				}
				if resourceKind != "" {
					attrs = append(attrs, slog.String("resource_kind", resourceKind))
				}
				if resourceID != "" {
					attrs = append(attrs, slog.String("resource_id", resourceID))
				}
				if jobID != "" {
					attrs = append(attrs, slog.String("job_id", jobID))
				}
				if errorCode != "" {
					attrs = append(attrs, slog.String("error_code", errorCode))
				}
			}

			level := slog.LevelInfo
			switch {
			case rec.status >= 500:
				level = slog.LevelError
			case rec.status >= 400:
				level = slog.LevelWarn
			}
			logger.Log(ctx, level, "http request handled", attrs...)
		})
	}
}

func statusClass(status int) string {
	switch status / 100 {
	case 1:
		return "1xx"
	case 2:
		return "2xx"
	case 3:
		return "3xx"
	case 4:
		return "4xx"
	case 5:
		return "5xx"
	default:
		return "unknown"
	}
}

func outcome(status int) string {
	if status >= http.StatusBadRequest {
		return "failure"
	}
	return "success"
}
