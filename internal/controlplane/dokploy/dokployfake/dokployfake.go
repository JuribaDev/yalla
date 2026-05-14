// Package dokployfake provides a deterministic, in-memory HTTP test double for
// the private Dokploy provisioning backend.
//
// Dokploy is real infrastructure that the worker mutates through a typed
// internal client. Exercising provisioning against a live Dokploy server in
// the normal test suite would be slow, non-deterministic, and unsafe, so this
// package serves a faithful but fully in-memory stand-in: it models the
// Organization -> Project -> Environment -> Service hierarchy plus domains,
// deployments, deployment logs, and runtime status, and it answers the HTTP
// operations the provisioning worker needs.
//
// The fake exists so that "normal tests use fake Dokploy fixtures, not a live
// Dokploy server" is structurally true. A live Dokploy smoke test remains a
// separate, opt-in concern and must never run by accident.
//
// # Determinism
//
// Resource IDs are minted from per-kind counters guarded by the server mutex,
// so a fixed sequence of calls always produces the same IDs (org_1, proj_1,
// env_1, ...). Deployments succeed immediately by default; a test that needs an
// in-progress or failed deployment drives it explicitly with
// SetDeploymentStatus. Nothing in the fake depends on wall-clock timing except
// the timeout fault, which a caller asks for on purpose.
//
// # Fault injection
//
// QueueFault arms a FIFO queue of failures. Each incoming request consumes the
// next queued fault, letting a worker test assert retry, backoff, and
// dead-letter behaviour against 400/401/403/404/409/429/500 responses, a slow
// upstream (TimeoutFault), and malformed JSON bodies — all without a real
// Dokploy server.
//
// # Redaction
//
// Every request is recorded for assertions, but the recording is scrubbed
// first: the Authorization / X-Api-Key / X-Auth-Token / Cookie header values
// are replaced with output.Sentinel, and the request body is run through a
// redactor seeded with the server's bearer token. A test can therefore prove
// the worker sent credentials without those credentials ever entering the
// recorded fixture, a log line, or test output.
//
// # Response shape
//
// The fake intentionally mimics Dokploy's own JSON shapes, not Yalla's
// yalla.output.v1 / yalla.error.v1 envelopes: it stands in for the upstream
// provisioning API, which is not a Yalla public surface. Success responses are
// the bare resource JSON; error responses are {"error":{"code","message"}}.
package dokployfake

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/JuribaDev/yalla/internal/output"
)

// DefaultToken is the bearer token a fake server accepts when no WithToken
// option is supplied. It is deliberately long enough for the redactor to treat
// it as a real secret, and it is a fixture value — never a real credential.
const DefaultToken = "dkp_faketoken_0123456789abcdef0123456789"

// maxRecordedBody bounds how much of a request body the fake reads for
// recording. Test payloads are tiny; the bound only guards against a
// pathological caller.
const maxRecordedBody = 1 << 20

// sensitiveHeaders are the request header names whose values are replaced with
// output.Sentinel in every RecordedRequest. They never appear verbatim in a
// recorded fixture.
var sensitiveHeaders = []string{"Authorization", "X-Api-Key", "X-Auth-Token", "Cookie", "Set-Cookie"}

// Server is a deterministic, in-memory HTTP test double for Dokploy. The zero
// value is not usable; construct one with New. A Server is safe for concurrent
// use: every field is guarded by mu.
type Server struct {
	http     *httptest.Server
	token    string
	redactor *output.Redactor
	mux      *http.ServeMux

	mu        sync.Mutex
	requests  []RecordedRequest
	faults    []Fault
	resources resourceStore
}

// Option configures a Server at construction time.
type Option func(*Server)

// WithToken sets the bearer token the fake requires on every request. An empty
// token is ignored so callers can pass through an unset config value safely.
func WithToken(token string) Option {
	return func(s *Server) {
		if strings.TrimSpace(token) != "" {
			s.token = token
		}
	}
}

// New starts a fake Dokploy server and returns it ready to serve. The caller
// owns the returned Server and must call Close when finished, typically with
// defer.
func New(opts ...Option) *Server {
	s := &Server{
		token:     DefaultToken,
		resources: newResourceStore(),
	}
	for _, opt := range opts {
		opt(s)
	}
	// Seed the redactor with the bearer token so it is scrubbed from any
	// recorded body; the redactor's built-in patterns scrub Authorization
	// headers and token query params even when the literal value is unknown.
	s.redactor = output.NewRedactor(s.token)
	s.mux = s.newMux()
	s.http = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

// Close shuts the server down and releases its listener. It is safe to call
// more than once.
func (s *Server) Close() {
	if s.http != nil {
		s.http.Close()
	}
}

// URL is the base URL the fake is listening on, with no trailing slash.
func (s *Server) URL() string { return s.http.URL }

// Token is the bearer token the fake requires on every request. Callers wire
// it into the client under test; it is a fixture value, not a real credential.
func (s *Server) Token() string { return s.token }

// serve is the single entry point for every request. It records the request
// (with credentials redacted), consumes any queued fault, enforces bearer
// auth, and only then dispatches to the resource router.
func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.record(r)

	if fault, ok := s.popFault(); ok {
		s.applyFault(w, r, fault)
		return
	}

	if !s.authorized(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized",
			"a valid Dokploy bearer token is required")
		return
	}

	s.mux.ServeHTTP(w, r)
}

// authorized reports whether r carries the server's bearer token. The compare
// is constant-time so the fake never leaks token length through timing, the
// same discipline the real auth path uses.
func (s *Server) authorized(r *http.Request) bool {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return false
	}
	got := strings.TrimSpace(h[len(prefix):])
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) == 1
}

// record appends a redacted RecordedRequest for r and restores r.Body so the
// downstream handler can still read it.
func (s *Server) record(r *http.Request) {
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(io.LimitReader(r.Body, maxRecordedBody))
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))
	}

	rec := RecordedRequest{
		Method:   r.Method,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
		Headers:  redactHeaders(r.Header),
		Body:     s.redactor.Redact(string(body)),
		At:       time.Now().UTC(),
	}
	if r.Header.Get("Authorization") != "" {
		rec.AuthHeader = output.Sentinel
	}

	s.mu.Lock()
	s.requests = append(s.requests, rec)
	s.mu.Unlock()
}

// redactHeaders returns a copy of h with every sensitive header value replaced
// by output.Sentinel. The original header map is never mutated.
func redactHeaders(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for name, values := range h {
		copied := make([]string, len(values))
		copy(copied, values)
		out[name] = copied
	}
	for _, name := range sensitiveHeaders {
		if values, ok := out[http.CanonicalHeaderKey(name)]; ok {
			for i := range values {
				values[i] = output.Sentinel
			}
		}
	}
	return out
}

// RecordedRequest is one request the fake received, captured with every
// credential already redacted. It is the assertion surface for "the worker
// called Dokploy correctly, and did so without leaking a secret".
type RecordedRequest struct {
	// Method is the HTTP method.
	Method string
	// Path is the request path, without query string.
	Path string
	// RawQuery is the raw query string, if any.
	RawQuery string
	// AuthHeader is output.Sentinel when the request carried an Authorization
	// header, and "" otherwise. The raw token is never stored here.
	AuthHeader string
	// Headers is a copy of the request headers with the Authorization,
	// X-Api-Key, X-Auth-Token, Cookie, and Set-Cookie values redacted.
	Headers http.Header
	// Body is the request body, run through the server's redactor.
	Body string
	// At is when the request was received (UTC).
	At time.Time
}

// Requests returns a copy of every request the fake has received so far, in
// arrival order. The returned slice is owned by the caller.
func (s *Server) Requests() []RecordedRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]RecordedRequest, len(s.requests))
	copy(out, s.requests)
	return out
}

// RequestCount returns how many requests the fake has received.
func (s *Server) RequestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

// Reset clears all recorded requests, queued faults, and provisioned
// resources, returning the fake to its just-constructed state. The bearer
// token is preserved.
func (s *Server) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = nil
	s.faults = nil
	s.resources = newResourceStore()
}

// FaultKind selects which kind of failure an injected Fault produces.
type FaultKind int

const (
	// FaultStatus returns Fault.Status with a Dokploy-style JSON error body.
	FaultStatus FaultKind = iota
	// FaultMalformedJSON returns a body that is not valid JSON, so a client
	// test can exercise its decode-failure path.
	FaultMalformedJSON
	// FaultTimeout sleeps for Fault.Delay (honouring request cancellation)
	// and then returns 504, simulating a slow or unresponsive upstream.
	FaultTimeout
)

// Fault describes a single injected failure. Construct one with StatusFault,
// MalformedJSONFault, or TimeoutFault rather than building it directly.
type Fault struct {
	// Kind selects the failure behaviour.
	Kind FaultKind
	// Status is the HTTP status for FaultStatus, and the status that
	// accompanies the malformed body for FaultMalformedJSON.
	Status int
	// Delay is how long FaultTimeout sleeps before responding. It is also
	// applied as a pre-response delay for the other kinds when non-zero.
	Delay time.Duration
}

// StatusFault returns a Fault that responds with the given HTTP status and a
// Dokploy-style JSON error body. Use it to inject 400, 401, 403, 404, 409,
// 429, or 500 responses.
func StatusFault(status int) Fault {
	return Fault{Kind: FaultStatus, Status: status}
}

// MalformedJSONFault returns a Fault that responds 200 with a body that is not
// valid JSON.
func MalformedJSONFault() Fault {
	return Fault{Kind: FaultMalformedJSON, Status: http.StatusOK}
}

// TimeoutFault returns a Fault that sleeps for d (honouring request
// cancellation) and then responds 504.
func TimeoutFault(d time.Duration) Fault {
	return Fault{Kind: FaultTimeout, Delay: d}
}

// QueueFault arms one or more faults. They are consumed FIFO: the next request
// takes the first queued fault, the request after it the second, and so on.
// Requests that arrive once the queue is empty are served normally.
func (s *Server) QueueFault(faults ...Fault) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults = append(s.faults, faults...)
}

// ClearFaults discards every queued-but-unconsumed fault.
func (s *Server) ClearFaults() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults = nil
}

// popFault removes and returns the next queued fault, if any.
func (s *Server) popFault() (Fault, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.faults) == 0 {
		return Fault{}, false
	}
	fault := s.faults[0]
	s.faults = s.faults[1:]
	return fault, true
}

// applyFault writes the response described by fault. For FaultTimeout (or any
// fault with a Delay) it waits first, abandoning the response if the request
// context is cancelled while it waits.
func (s *Server) applyFault(w http.ResponseWriter, r *http.Request, fault Fault) {
	if fault.Delay > 0 {
		select {
		case <-time.After(fault.Delay):
		case <-r.Context().Done():
			// The caller gave up (deadline or cancellation); there is no
			// point writing a response nobody will read.
			return
		}
	}

	switch fault.Kind {
	case FaultTimeout:
		writeError(w, http.StatusGatewayTimeout, "timeout",
			"the upstream Dokploy request timed out")
	case FaultMalformedJSON:
		status := fault.Status
		if status == 0 {
			status = http.StatusOK
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		// A truncated object: valid JSON start, no valid end.
		_, _ = io.WriteString(w, `{"id":"dep_1","status":`)
	default: // FaultStatus
		status := fault.Status
		if status == 0 {
			status = http.StatusInternalServerError
		}
		writeError(w, status, codeForStatus(status), messageForStatus(status))
	}
}

// writeJSON renders v as the response body with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// errorBody is the fake's Dokploy-style error envelope. It deliberately does
// not use Yalla's yalla.error.v1 envelope: the fake stands in for the upstream
// provisioning API, not a Yalla public surface.
type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// writeError renders a Dokploy-style JSON error response.
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorBody{Error: errorDetail{Code: code, Message: message}})
}

// codeForStatus maps an HTTP status to the fake's stable error code string.
func codeForStatus(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "bad_request"
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusConflict:
		return "conflict"
	case http.StatusTooManyRequests:
		return "rate_limited"
	case http.StatusGatewayTimeout:
		return "timeout"
	default:
		return "internal"
	}
}

// messageForStatus maps an HTTP status to a fixed, non-secret human message.
func messageForStatus(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "the request was rejected by Dokploy"
	case http.StatusUnauthorized:
		return "the Dokploy credentials were rejected"
	case http.StatusForbidden:
		return "the Dokploy credentials are not permitted to perform this action"
	case http.StatusNotFound:
		return "the requested Dokploy resource does not exist"
	case http.StatusConflict:
		return "the Dokploy resource already exists"
	case http.StatusTooManyRequests:
		return "the Dokploy API is rate limiting requests"
	case http.StatusGatewayTimeout:
		return "the upstream Dokploy request timed out"
	default:
		return "Dokploy encountered an internal error"
	}
}
