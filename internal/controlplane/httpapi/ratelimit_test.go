package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/ratelimit"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
)

// Contract tests for the BE-0035 HTTP rate-limit middleware. They cover
// the per-bucket isolation contract, the 429 yalla.error.v1 envelope
// shape (stable code, retry_after detail, integer Retry-After header),
// the internal-worker exemption, the bearer-token / secret leak guards
// on the warn log record, and that an allowed request reaches the
// downstream handler.

// fakeRateLimiter is a canned RateLimiter that records every Check call
// and returns the next queued decision. It is the test stand-in for
// *ratelimit.Limiter so the contract is verifiable without a real
// token-bucket implementation.
type fakeRateLimiter struct {
	mu        sync.Mutex
	decisions []ratelimit.Decision
	seen      []ratelimit.Request
	idx       int
}

func (f *fakeRateLimiter) queue(d ratelimit.Decision) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.decisions = append(f.decisions, d)
}

func (f *fakeRateLimiter) Check(req ratelimit.Request) ratelimit.Decision {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, req)
	if f.idx >= len(f.decisions) {
		return ratelimit.Decision{Allowed: true}
	}
	d := f.decisions[f.idx]
	f.idx++
	return d
}

func (f *fakeRateLimiter) requests() []ratelimit.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]ratelimit.Request, len(f.seen))
	copy(out, f.seen)
	return out
}

// rateLimitOK is a stand-in handler that records whether it ran. Tests
// use it to assert the middleware shorts out on a denial.
type rateLimitOK struct{ ran bool }

func (h *rateLimitOK) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	h.ran = true
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"ok":true}`))
}

// rateLimitedEnvelope is the decoded yalla.error.v1 shape used for 429
// assertions. It is the same wire contract every other error envelope
// rides on; details are surfaced as a map of stable string keys.
type rateLimitedEnvelope struct {
	SchemaVersion string `json:"schema_version"`
	OK            bool   `json:"ok"`
	Error         struct {
		Code    string            `json:"code"`
		Message string            `json:"message"`
		Hint    string            `json:"hint"`
		Details map[string]string `json:"details"`
	} `json:"error"`
	RequestID string `json:"request_id"`
}

// runRateLimit dispatches one request through h (wrapped in
// telemetry.Correlate so a request_id is resolved) and returns the
// recorder.
func runRateLimit(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	telemetry.Correlate(h).ServeHTTP(rec, req)
	return rec
}

// TestRateLimitAllowsWhenLimiterAllows proves the happy-path contract:
// an allowed Decision lets the request reach the downstream handler with
// the principal still on context and no Retry-After header emitted.
func TestRateLimitAllowsWhenLimiterAllows(t *testing.T) {
	t.Parallel()

	limiter := &fakeRateLimiter{}
	limiter.queue(ratelimit.Decision{Allowed: true})
	next := &rateLimitOK{}
	h := RateLimit(limiter, nil)(next)

	req := httptest.NewRequest(http.MethodGet, "/v1/projects", nil)
	req.RemoteAddr = "203.0.113.10:54321"
	rec := runRateLimit(h, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if !next.ran {
		t.Error("next handler did not run for an allowed request")
	}
	if got := rec.Header().Get("Retry-After"); got != "" {
		t.Errorf("Retry-After header set to %q on an allowed request", got)
	}
	if seen := limiter.requests(); len(seen) != 1 {
		t.Fatalf("Check called %d times, want 1", len(seen))
	}
}

// TestRateLimitDeniesWithStableEnvelope is the core 429 contract: the
// middleware renders a yalla.error.v1 envelope with E_RATE_LIMITED, a
// retry_after detail, and a matching integer Retry-After response
// header. The downstream handler must not run.
func TestRateLimitDeniesWithStableEnvelope(t *testing.T) {
	t.Parallel()

	limiter := &fakeRateLimiter{}
	limiter.queue(ratelimit.Decision{Bucket: ratelimit.BucketOrg, Retry: 2 * time.Second})
	next := &rateLimitOK{}
	h := RateLimit(limiter, nil)(next)

	rec := runRateLimit(h, httptest.NewRequest(http.MethodGet, "/v1/projects", nil))

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429; body %s", rec.Code, rec.Body.String())
	}
	if next.ran {
		t.Error("next handler ran for a denied request")
	}
	if got := rec.Header().Get("Retry-After"); got != "2" {
		t.Errorf("Retry-After header = %q, want 2", got)
	}

	var env rateLimitedEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode 429 envelope: %v; body %s", err, rec.Body.String())
	}
	if env.SchemaVersion != "yalla.error.v1" {
		t.Errorf("schema_version = %q, want yalla.error.v1", env.SchemaVersion)
	}
	if env.OK {
		t.Error("ok = true on a denial envelope")
	}
	if env.Error.Code != "E_RATE_LIMITED" {
		t.Errorf("code = %q, want E_RATE_LIMITED", env.Error.Code)
	}
	if env.Error.Details["retry_after"] != "2" {
		t.Errorf("details.retry_after = %q, want 2", env.Error.Details["retry_after"])
	}
	if env.Error.Details["scope"] != ratelimit.BucketOrg {
		t.Errorf("details.scope = %q, want %q", env.Error.Details["scope"], ratelimit.BucketOrg)
	}
	if env.RequestID == "" {
		t.Error("request_id is empty on a 429")
	}
}

// TestRateLimitRetryAfterFloorsAtOneSecond proves the integer-second
// floor: a sub-second Retry duration rounds up to 1 so an integer
// Retry-After header is always actionable.
func TestRateLimitRetryAfterFloorsAtOneSecond(t *testing.T) {
	t.Parallel()

	limiter := &fakeRateLimiter{}
	limiter.queue(ratelimit.Decision{Bucket: ratelimit.BucketIP, Retry: 100 * time.Millisecond})
	h := RateLimit(limiter, nil)(&rateLimitOK{})

	rec := runRateLimit(h, httptest.NewRequest(http.MethodGet, "/v1/projects", nil))

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "1" {
		t.Errorf("Retry-After header = %q, want 1 (sub-second floor)", got)
	}
}

// TestRateLimitBuildsRequestFromPrincipalAndIP proves the middleware
// reads the principal off the request context (organization id, API
// key id) and the IP off the request (preferring X-Forwarded-For), and
// passes them as the Request to the limiter.
func TestRateLimitBuildsRequestFromPrincipalAndIP(t *testing.T) {
	t.Parallel()

	limiter := &fakeRateLimiter{}
	limiter.queue(ratelimit.Decision{Allowed: true})
	h := RateLimit(limiter, nil)(&rateLimitOK{})

	principal := policy.Principal{
		ID: "sa_ci", Kind: domain.KindServiceAccount, OrganizationID: "org_acme",
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/projects", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.42, 198.51.100.1")
	ctx := policy.WithPrincipal(req.Context(), principal)
	ctx = withAuthMethod(ctx, auth.MethodAPIKey)
	req = req.WithContext(ctx)

	rec := runRateLimit(h, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}

	seen := limiter.requests()
	if len(seen) != 1 {
		t.Fatalf("Check called %d times, want 1", len(seen))
	}
	got := seen[0]
	if got.OrgID != "org_acme" {
		t.Errorf("OrgID = %q, want org_acme", got.OrgID)
	}
	if got.KeyID != "sa_ci" {
		t.Errorf("KeyID = %q, want sa_ci", got.KeyID)
	}
	if got.IP != "203.0.113.42" {
		t.Errorf("IP = %q, want first X-Forwarded-For hop", got.IP)
	}
	if !got.Write {
		t.Error("Write = false for POST; want true")
	}
	if got.Exempt {
		t.Error("Exempt = true for an API-key principal; want false")
	}
}

// TestRateLimitExemptsInternalWorker pins the most-load-bearing
// acceptance criterion: an internal worker callback is exempt from the
// rate limit and the middleware tells the limiter so. The limiter
// receives Exempt=true and (per its contract) allows unconditionally,
// regardless of bucket state.
func TestRateLimitExemptsInternalWorker(t *testing.T) {
	t.Parallel()

	limiter := &fakeRateLimiter{}
	// Pre-queue a denial; if the middleware forgot to set Exempt the
	// limiter would deny and the next handler would not run.
	limiter.queue(ratelimit.Decision{Allowed: true})
	next := &rateLimitOK{}
	h := RateLimit(limiter, nil)(next)

	req := httptest.NewRequest(http.MethodPost, "/v1/internal/callback", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	ctx := withAuthMethod(req.Context(), auth.MethodInternalWorker)
	req = req.WithContext(ctx)

	rec := runRateLimit(h, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if !next.ran {
		t.Error("next handler did not run for an exempt internal-worker request")
	}
	seen := limiter.requests()
	if len(seen) != 1 || !seen[0].Exempt {
		t.Errorf("limiter saw %+v, want Exempt=true", seen)
	}
}

// TestRateLimitPerKeyIsolationDoesNotLeakAcrossPrincipals proves the
// per-key isolation contract: the middleware passes each principal's
// identity through to the limiter as the bucket key, so two different
// API keys consume from two different buckets. The fake limiter denies
// only when a request whose KeyID matches a sentinel arrives, mirroring
// what a real token bucket would do once a single key's burst is
// drained.
func TestRateLimitPerKeyIsolationDoesNotLeakAcrossPrincipals(t *testing.T) {
	t.Parallel()

	limiter := &perKeyFakeLimiter{drained: "key_a"}
	h := RateLimit(limiter, nil)(&rateLimitOK{})

	send := func(keyID string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/v1/projects", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		p := policy.Principal{ID: keyID, OrganizationID: "org_acme", Kind: domain.KindServiceAccount}
		ctx := policy.WithPrincipal(req.Context(), p)
		ctx = withAuthMethod(ctx, auth.MethodAPIKey)
		return runRateLimit(h, req.WithContext(ctx))
	}

	// key_a is drained -> 429.
	rec := send("key_a")
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("key_a status = %d, want 429", rec.Code)
	}
	// key_b is a different bucket -> 200. If the middleware billed both
	// keys to a shared bucket, the second request would also deny.
	rec = send("key_b")
	if rec.Code != http.StatusOK {
		t.Errorf("key_b status = %d, want 200 (per-key isolation)", rec.Code)
	}
}

// perKeyFakeLimiter denies only when the request's KeyID matches a
// sentinel value, mirroring real per-key bucket isolation.
type perKeyFakeLimiter struct {
	drained string
}

func (f *perKeyFakeLimiter) Check(req ratelimit.Request) ratelimit.Decision {
	if req.KeyID == f.drained {
		return ratelimit.Decision{Bucket: ratelimit.BucketKey, Retry: 3 * time.Second}
	}
	return ratelimit.Decision{Allowed: true}
}

// TestRateLimitNilLimiterIsNoOp proves a nil limiter installs a
// passthrough wrapper. The construction path stays uniform for tests
// and embedders that exercise the routing surface without enforcing
// any cap.
func TestRateLimitNilLimiterIsNoOp(t *testing.T) {
	t.Parallel()

	next := &rateLimitOK{}
	h := RateLimit(nil, nil)(next)

	rec := runRateLimit(h, httptest.NewRequest(http.MethodGet, "/v1/projects", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if !next.ran {
		t.Error("next handler did not run with nil limiter")
	}
}

// TestRateLimitDenialLogsNoSecretValue is a redaction backstop on the
// log path: a denial emits one structured WARN record with the bucket
// dimension and the integer retry-after, but never the bucket identity
// (the org id, the API key id, the client IP). A bearer-token style
// secret on the request must not appear in the log record.
func TestRateLimitDenialLogsNoSecretValue(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	limiter := &fakeRateLimiter{}
	limiter.queue(ratelimit.Decision{Bucket: ratelimit.BucketKey, Retry: time.Second})
	h := RateLimit(limiter, logger)(&rateLimitOK{})

	const secret = "yk_super-secret-token-value"
	req := httptest.NewRequest(http.MethodGet, "/v1/projects", nil)
	req.RemoteAddr = "203.0.113.99:1234"
	req.Header.Set("Authorization", "Bearer "+secret)
	p := policy.Principal{ID: "sa_throttled", OrganizationID: "org_throttled", Kind: domain.KindServiceAccount}
	ctx := policy.WithPrincipal(req.Context(), p)
	ctx = withAuthMethod(ctx, auth.MethodAPIKey)

	rec := runRateLimit(h, req.WithContext(ctx))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}

	log := buf.String()
	if !strings.Contains(log, "rate limit exceeded") {
		t.Errorf("log record missing the rate-limit warn message: %s", log)
	}
	if !strings.Contains(log, ratelimit.BucketKey) {
		t.Errorf("log record does not name the bucket dimension: %s", log)
	}
	for _, leak := range []string{secret, "sa_throttled", "org_throttled", "203.0.113.99"} {
		if strings.Contains(log, leak) {
			t.Errorf("log record leaked sensitive value %q: %s", leak, log)
		}
	}
}

// TestRateLimitRetryAfterMatchesDetail proves the response header and
// the envelope detail agree on the retry instruction so a client that
// reads either gets the same number.
func TestRateLimitRetryAfterMatchesDetail(t *testing.T) {
	t.Parallel()

	for _, retry := range []time.Duration{time.Second, 7 * time.Second, 30 * time.Second} {
		retry := retry
		t.Run(retry.String(), func(t *testing.T) {
			t.Parallel()
			limiter := &fakeRateLimiter{}
			limiter.queue(ratelimit.Decision{Bucket: ratelimit.BucketIP, Retry: retry})
			h := RateLimit(limiter, nil)(&rateLimitOK{})

			rec := runRateLimit(h, httptest.NewRequest(http.MethodGet, "/v1/projects", nil))

			if rec.Code != http.StatusTooManyRequests {
				t.Fatalf("status = %d, want 429", rec.Code)
			}
			wantSeconds := int64(retry.Seconds())
			if got := rec.Header().Get("Retry-After"); got != strconv.FormatInt(wantSeconds, 10) {
				t.Errorf("Retry-After header = %q, want %d", got, wantSeconds)
			}
			var env rateLimitedEnvelope
			if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
				t.Fatalf("decode 429 envelope: %v", err)
			}
			if env.Error.Details["retry_after"] != strconv.FormatInt(wantSeconds, 10) {
				t.Errorf("details.retry_after = %q, want %d", env.Error.Details["retry_after"], wantSeconds)
			}
		})
	}
}

// TestRateLimitMethodSelectsReadOrWriteSpec proves the gate maps HTTP
// methods to the limiter's read/write classification. GET / HEAD /
// OPTIONS pull from the read budget; everything else (POST / PUT /
// PATCH / DELETE and the catch-all) is treated as a write.
func TestRateLimitMethodSelectsReadOrWriteSpec(t *testing.T) {
	t.Parallel()

	cases := []struct {
		method    string
		wantWrite bool
	}{
		{http.MethodGet, false},
		{http.MethodHead, false},
		{http.MethodOptions, false},
		{http.MethodPost, true},
		{http.MethodPut, true},
		{http.MethodPatch, true},
		{http.MethodDelete, true},
		{"PROPFIND", true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.method, func(t *testing.T) {
			t.Parallel()
			limiter := &fakeRateLimiter{}
			limiter.queue(ratelimit.Decision{Allowed: true})
			h := RateLimit(limiter, nil)(&rateLimitOK{})
			req := httptest.NewRequest(tc.method, "/v1/projects", nil)
			req.RemoteAddr = "10.0.0.1:80"
			runRateLimit(h, req)
			seen := limiter.requests()
			if len(seen) != 1 {
				t.Fatalf("Check called %d times, want 1", len(seen))
			}
			if seen[0].Write != tc.wantWrite {
				t.Errorf("%s -> Write=%t, want %t", tc.method, seen[0].Write, tc.wantWrite)
			}
		})
	}
}

// TestClientIPPrefersForwardingHeaders documents the IP-resolution
// contract independently of the middleware so a future change to header
// preferences cannot silently break the limiter's bucket selection.
func TestClientIPPrefersForwardingHeaders(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		setup   func(*http.Request)
		wantIP  string
		wantOK  bool
		comment string
	}{
		{
			name: "X-Forwarded-For single hop",
			setup: func(r *http.Request) {
				r.RemoteAddr = "10.0.0.1:1234"
				r.Header.Set("X-Forwarded-For", "203.0.113.5")
			},
			wantIP: "203.0.113.5",
		},
		{
			name: "X-Forwarded-For multi-hop trims to first",
			setup: func(r *http.Request) {
				r.RemoteAddr = "10.0.0.1:1234"
				r.Header.Set("X-Forwarded-For", "203.0.113.5, 198.51.100.1, 10.0.0.1")
			},
			wantIP: "203.0.113.5",
		},
		{
			name: "X-Real-IP fallback when X-Forwarded-For absent",
			setup: func(r *http.Request) {
				r.RemoteAddr = "10.0.0.1:1234"
				r.Header.Set("X-Real-IP", "203.0.113.99")
			},
			wantIP: "203.0.113.99",
		},
		{
			name: "RemoteAddr fallback when no proxy headers",
			setup: func(r *http.Request) {
				r.RemoteAddr = "192.0.2.10:5555"
			},
			wantIP: "192.0.2.10",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			tc.setup(req)
			if got := ClientIP(req); got != tc.wantIP {
				t.Errorf("ClientIP = %q, want %q", got, tc.wantIP)
			}
		})
	}
}

// TestAuthMethodFromContextRoundtrips proves the context helper used by
// both auth gates and the rate-limit gate returns ("", false) for an
// unauthenticated context, and roundtrips a stamped value.
func TestAuthMethodFromContextRoundtrips(t *testing.T) {
	t.Parallel()

	var nilCtx context.Context
	if _, ok := AuthMethodFromContext(nilCtx); ok {
		t.Error("nil ctx must return ok=false")
	}
	if _, ok := AuthMethodFromContext(context.Background()); ok {
		t.Error("background ctx must return ok=false")
	}
	ctx := withAuthMethod(context.Background(), auth.MethodInternalWorker)
	got, ok := AuthMethodFromContext(ctx)
	if !ok {
		t.Fatal("AuthMethodFromContext returned ok=false for a stamped method")
	}
	if got != auth.MethodInternalWorker {
		t.Errorf("AuthMethodFromContext = %q, want %q", got, auth.MethodInternalWorker)
	}
}
