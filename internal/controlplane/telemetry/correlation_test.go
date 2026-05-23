package telemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSafeID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"plain alphanumeric", "abc123", true},
		{"hex request id", "0f1e2d3c4b5a69788796a5b4c3d2e1f0", true},
		{"uuid-style with dashes", "550e8400-e29b-41d4-a716-446655440000", true},
		{"dotted and underscored", "svc.api_42-prod", true},
		{"max length boundary", strings.Repeat("a", maxIDLen), true},
		{"empty", "", false},
		{"too long", strings.Repeat("a", maxIDLen+1), false},
		{"contains space", "abc 123", false},
		{"crlf header injection", "abc\r\nX-Evil: 1", false},
		{"newline log injection", "abc\ndef", false},
		{"tab", "abc\tdef", false},
		{"slash", "abc/def", false},
		{"non-ascii", "abcé", false},
		{"null byte", "abc\x00", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := SafeID(tt.in); got != tt.want {
				t.Errorf("SafeID(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestNewRequestIDIsUniqueAndSafe(t *testing.T) {
	t.Parallel()

	const n = 1000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		id := NewRequestID()
		if !SafeID(id) {
			t.Fatalf("NewRequestID() = %q, which is not a SafeID", id)
		}
		if len(id) != 32 {
			t.Fatalf("NewRequestID() length = %d, want 32 (%q)", len(id), id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("NewRequestID() produced a duplicate: %q", id)
		}
		seen[id] = struct{}{}
	}
}

func TestWithCorrelationRoundTrips(t *testing.T) {
	t.Parallel()

	want := Correlation{RequestID: "req-1", CorrelationID: "corr-1"}
	ctx := WithCorrelation(context.Background(), want)

	if got := FromContext(ctx); got != want {
		t.Errorf("FromContext = %+v, want %+v", got, want)
	}
	if got := RequestID(ctx); got != want.RequestID {
		t.Errorf("RequestID = %q, want %q", got, want.RequestID)
	}
	if got := CorrelationID(ctx); got != want.CorrelationID {
		t.Errorf("CorrelationID = %q, want %q", got, want.CorrelationID)
	}
}

func TestFromContextZeroValue(t *testing.T) {
	t.Parallel()

	if got := FromContext(context.Background()); got != (Correlation{}) {
		t.Errorf("FromContext(empty) = %+v, want zero Correlation", got)
	}
	// A nil context must not panic — FromContext guards it explicitly. Use a
	// typed nil variable rather than an untyped nil literal so the guard is
	// exercised without tripping the nil-context lint.
	var nilCtx context.Context
	if got := FromContext(nilCtx); got != (Correlation{}) {
		t.Errorf("FromContext(nil) = %+v, want zero Correlation", got)
	}
}

func TestLogAttrs(t *testing.T) {
	t.Parallel()

	if got := LogAttrs(context.Background()); got != nil {
		t.Errorf("LogAttrs(empty) = %v, want nil", got)
	}

	ctx := WithCorrelation(context.Background(), Correlation{RequestID: "r", CorrelationID: "c"})
	attrs := LogAttrs(ctx)
	if len(attrs) != 2 {
		t.Fatalf("LogAttrs returned %d attrs, want 2", len(attrs))
	}
}

// captureHandler records the correlation it observed on the request context so
// tests can prove the middleware propagated values into downstream handlers.
type captureHandler struct {
	got Correlation
}

func (h *captureHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.got = FromContext(r.Context())
	w.WriteHeader(http.StatusOK)
}

func TestCorrelateGeneratesWhenMissing(t *testing.T) {
	t.Parallel()

	next := &captureHandler{}
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rec := httptest.NewRecorder()

	Correlate(next).ServeHTTP(rec, req)

	if !SafeID(next.got.RequestID) {
		t.Fatalf("generated request_id %q is not safe", next.got.RequestID)
	}
	// A standalone request is its own correlation root.
	if next.got.CorrelationID != next.got.RequestID {
		t.Errorf("correlation_id = %q, want it to default to request_id %q",
			next.got.CorrelationID, next.got.RequestID)
	}
	// The resolved IDs must be echoed on the response headers.
	if got := rec.Header().Get(HeaderRequestID); got != next.got.RequestID {
		t.Errorf("response %s = %q, want %q", HeaderRequestID, got, next.got.RequestID)
	}
	if got := rec.Header().Get(HeaderCorrelationID); got != next.got.CorrelationID {
		t.Errorf("response %s = %q, want %q", HeaderCorrelationID, got, next.got.CorrelationID)
	}
}

func TestCorrelateHonoursSafeInboundHeaders(t *testing.T) {
	t.Parallel()

	next := &captureHandler{}
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set(HeaderRequestID, "inbound-req-1")
	req.Header.Set(HeaderCorrelationID, "inbound-corr-1")
	rec := httptest.NewRecorder()

	Correlate(next).ServeHTTP(rec, req)

	if next.got.RequestID != "inbound-req-1" {
		t.Errorf("request_id = %q, want inbound-req-1", next.got.RequestID)
	}
	if next.got.CorrelationID != "inbound-corr-1" {
		t.Errorf("correlation_id = %q, want inbound-corr-1", next.got.CorrelationID)
	}
	if got := rec.Header().Get(HeaderRequestID); got != "inbound-req-1" {
		t.Errorf("response %s = %q, want inbound-req-1", HeaderRequestID, got)
	}
}

func TestCorrelateDefaultsCorrelationToRequestID(t *testing.T) {
	t.Parallel()

	next := &captureHandler{}
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set(HeaderRequestID, "inbound-req-2")
	// No X-Correlation-Id supplied.
	rec := httptest.NewRecorder()

	Correlate(next).ServeHTTP(rec, req)

	if next.got.CorrelationID != "inbound-req-2" {
		t.Errorf("correlation_id = %q, want it to default to request_id inbound-req-2",
			next.got.CorrelationID)
	}
}

func TestCorrelateRejectsUnsafeInboundHeaders(t *testing.T) {
	t.Parallel()

	next := &captureHandler{}
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	// A header-injection / log-injection payload and an oversized blob must
	// both be discarded in favour of a freshly generated, trusted value.
	req.Header.Set(HeaderRequestID, "evil value with spaces")
	req.Header.Set(HeaderCorrelationID, strings.Repeat("z", maxIDLen+1))
	rec := httptest.NewRecorder()

	Correlate(next).ServeHTTP(rec, req)

	if next.got.RequestID == "evil value with spaces" {
		t.Fatalf("unsafe inbound request_id was accepted: %q", next.got.RequestID)
	}
	if !SafeID(next.got.RequestID) {
		t.Fatalf("fallback request_id %q is not safe", next.got.RequestID)
	}
	if next.got.CorrelationID != next.got.RequestID {
		t.Errorf("unsafe correlation_id should fall back to request_id; got %q want %q",
			next.got.CorrelationID, next.got.RequestID)
	}
	// The unsafe value must never reach the response headers.
	if got := rec.Header().Get(HeaderRequestID); got != next.got.RequestID {
		t.Errorf("response %s = %q, want %q", HeaderRequestID, got, next.got.RequestID)
	}
}
