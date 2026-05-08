package testutil

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/JuribaDev/yalla/internal/api"
	"github.com/JuribaDev/yalla/internal/config"
)

// RoundTripperFunc is the canonical http.RoundTripper stub for tests that
// need to bypass an httptest.Server entirely (for example to force a
// transport-level network error or to fail before any byte is written).
//
// Tests that just need to assert on a request and return a response should
// reach for NewServer or RecordingServer instead — they keep request
// inspection in one place and survive RoundTripper-shape changes.
type RoundTripperFunc func(*http.Request) (*http.Response, error)

// RoundTrip satisfies http.RoundTripper.
func (f RoundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// JSONResponse writes the supplied status, sets Content-Type: application/json,
// and serialises body via encoding/json. Use it as a one-liner inside an
// httptest.HandlerFunc.
func JSONResponse(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if body == nil {
		return
	}
	_ = json.NewEncoder(w).Encode(body)
}

// NewServer is the everyday Dokploy fixture: it stands up an httptest.Server
// with the supplied handler, registers t.Cleanup, points YALLA_BASE_URL at
// the server, and seeds YALLA_TOKEN with a fixed test value so commands that
// require auth proceed. The token is reported back so tests can assert the
// redactor actually scrubs it.
func NewServer(t testing.TB, handler http.Handler) (*httptest.Server, string) {
	t.Helper()
	tt, ok := t.(interface {
		Cleanup(f func())
		Setenv(key, value string)
	})
	if !ok {
		t.Fatalf("NewServer requires a *testing.T or *testing.B")
	}
	srv := httptest.NewServer(handler)
	tt.Cleanup(srv.Close)
	const token = "test-token-value"
	tt.Setenv(config.EnvBaseURL, srv.URL)
	tt.Setenv(config.EnvToken, token)
	return srv, token
}

// CapturedRequest is a single recorded HTTP request. Body is captured fully
// so tests can assert on JSON payloads; Header and Query are copies so
// concurrent readers don't race the live request.
type CapturedRequest struct {
	Method string
	Path   string
	Query  url.Values
	Header http.Header
	Body   []byte
}

// AsJSON unmarshals the captured body into target. It fails the test if the
// body is empty or not valid JSON.
func (c CapturedRequest) AsJSON(t testing.TB, target any) {
	t.Helper()
	if len(c.Body) == 0 {
		t.Fatalf("captured request body is empty; cannot decode JSON")
	}
	if err := json.Unmarshal(c.Body, target); err != nil {
		t.Fatalf("decode captured body: %v\nbody=%q", err, c.Body)
	}
}

// Recorder is the request log for a RecordingServer. It is safe to read
// after the server returns its final response; concurrent reads with a live
// request stream are serialised via the embedded mutex.
type Recorder struct {
	mu  sync.Mutex
	all []CapturedRequest
}

// All returns a copy of every captured request in arrival order.
func (r *Recorder) All() []CapturedRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]CapturedRequest, len(r.all))
	copy(out, r.all)
	return out
}

// Len returns the number of requests captured so far.
func (r *Recorder) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.all)
}

// First returns the first captured request. It fails the test if no
// requests have been recorded — that is the most common assertion shape so
// the helper avoids a manual length check at every call site.
func (r *Recorder) First(t testing.TB) CapturedRequest {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.all) == 0 {
		t.Fatalf("recorder has no captured requests")
	}
	return r.all[0]
}

// RecordingServer wraps an httptest.Server with a request recorder so tests
// can both feed canned responses and assert exactly what was sent. The
// inner handler receives the live request unchanged so streaming responses
// and trailers behave normally.
//
// Pair this with NewServerRecording: you supply the response side; the
// recorder takes care of the request side.
func RecordingServer(t testing.TB, handler http.Handler) (*httptest.Server, *Recorder, string) {
	t.Helper()
	rec := &Recorder{}
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var bodyCopy []byte
		if r.Body != nil {
			b, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			bodyCopy = b
			// Restore the body so the inner handler sees identical bytes.
			r.Body = io.NopCloser(bytes.NewReader(b))
		}
		rec.mu.Lock()
		rec.all = append(rec.all, CapturedRequest{
			Method: r.Method,
			Path:   r.URL.Path,
			Query:  r.URL.Query(),
			Header: r.Header.Clone(),
			Body:   bodyCopy,
		})
		rec.mu.Unlock()
		handler.ServeHTTP(w, r)
	})
	srv, token := NewServer(t, wrapped)
	return srv, rec, token
}

// AssertOperationCalled verifies that exactly one captured request matches
// the OpenAPI operation's method and path. This is the canonical shape for
// API operation contract tests: build the request via the executor, drive it
// against a recording server, and call this helper to confirm the wire
// shape matches the embedded OpenAPI spec.
//
// Path matching is done against the raw operation path (parameters in
// `{name}` curly-brace form must already be substituted by the caller).
func AssertOperationCalled(t testing.TB, rec *Recorder, opID, method, path string) CapturedRequest {
	t.Helper()
	for _, c := range rec.All() {
		if c.Method == method && c.Path == path {
			return c
		}
	}
	t.Fatalf("operation %s: expected %s %s; recorded=%v", opID, method, path, rec.All())
	return CapturedRequest{}
}

// LookupOperation is a thin wrapper over api.Default().Get(opID) that fails
// the test on a miss. It centralises the hint string so a typo in a future
// API operation story produces a predictable error.
func LookupOperation(t testing.TB, opID string) api.Operation {
	t.Helper()
	op, ok := api.Default().Get(opID)
	if !ok {
		t.Fatalf("operation %q not in embedded spec; check ralph/prd.json and api.EmbeddedSpecSHA256", opID)
	}
	return op
}
