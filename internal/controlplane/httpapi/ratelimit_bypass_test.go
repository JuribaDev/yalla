package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/ratelimit"
)

// BE-0363: Security verification — rate-limit bypass resistance (runtime
// evidence half of the two-test pattern).
//
// The structural half lives at
// `internal/release/rate_limit_bypass_resistance_static_test.go` and pins
// the source-tree invariants: the single Exempt=true assignment under
// the auth.MethodInternalWorker guard, the closed Decision.Bucket constant
// set, the canonical 429 emission seam, and the per-route wrap site in
// server.go. This file pins the behavioural half: a hostile client
// cannot manufacture an Exempt=true `ratelimit.Request` by carrying a
// header, a path, an IP, an empty principal, or any other client-controlled
// input the static analyzer cannot reach into.

// bypassMarker is a sentinel string installed into every bypass-shaped
// header / path / principal id below. Each assertion below checks that
// the marker (a) cannot flip Exempt to true on the `ratelimit.Request`
// the middleware constructs, and (b) does not appear in the deny-log
// or in the 429 envelope body. The marker is far longer than any
// realistic header value so a partial-write or truncation regression
// would still surface the leak.
const bypassMarker = "BE0363RATELIMITBYPASSMARKERXYZ"

func TestClientIPIgnoresForwardedHeadersFromUntrustedRemote(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/v1/projects", nil)
	req.RemoteAddr = "198.51.100.10:45678"
	req.Header.Set("X-Forwarded-For", "203.0.113.99")

	resolver := NewTrustedProxyClientIPResolver(nil)
	if got := resolver(req); got != "198.51.100.10" {
		t.Fatalf("resolver = %q, want remote addr when proxy is untrusted", got)
	}
}

func TestClientIPHonoursForwardedHeadersFromTrustedProxy(t *testing.T) {
	t.Parallel()

	prefix := netip.MustParsePrefix("10.42.0.0/16")
	req := httptest.NewRequest(http.MethodGet, "/v1/projects", nil)
	req.RemoteAddr = "10.42.5.7:45678"
	req.Header.Set("X-Forwarded-For", "203.0.113.99, 10.42.5.7")

	resolver := NewTrustedProxyClientIPResolver([]netip.Prefix{prefix})
	if got := resolver(req); got != "203.0.113.99" {
		t.Fatalf("resolver = %q, want first forwarded client IP", got)
	}
}

// TestRateLimitBypassResistanceForgedInternalHeaderDoesNotExempt proves
// the middleware never trusts a client-supplied "internal-worker" claim.
// The attacker shape: a request that carries `X-Yalla-Internal: 1` or any
// similarly-named header. The contract: the limiter sees Exempt=false
// because AuthMethodFromContext was never stamped, and the request is
// deniable like any customer-facing call.
func TestRateLimitBypassResistanceForgedInternalHeaderDoesNotExempt(t *testing.T) {
	t.Parallel()

	limiter := &fakeRateLimiter{}
	// Pre-queue a denial. If the middleware honoured the forged header
	// and flipped Exempt=true, the limiter would short-circuit to
	// Allowed and the test would fail.
	limiter.queue(ratelimit.Decision{Bucket: ratelimit.BucketIP, Retry: 1})
	h := RateLimit(limiter, nil)(&rateLimitOK{})

	req := httptest.NewRequest(http.MethodPost, "/v1/projects", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	// Every header below mimics an attacker's attempt to impersonate
	// the internal-worker exemption path. None of them set the
	// auth-method context value, so the middleware MUST treat the
	// request as customer-facing.
	req.Header.Set("X-Yalla-Internal", "1")
	req.Header.Set("X-Yalla-Auth-Method", string(auth.MethodInternalWorker))
	req.Header.Set("X-Internal-Worker", bypassMarker)
	req.Header.Set("X-Auth-Method", bypassMarker)

	rec := runRateLimit(h, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("forged-header request got status %d, want 429; body %s", rec.Code, rec.Body.String())
	}
	seen := limiter.requests()
	if len(seen) != 1 {
		t.Fatalf("limiter saw %d requests, want 1", len(seen))
	}
	if seen[0].Exempt {
		t.Errorf("limiter saw Exempt=true on a forged-header request: %+v", seen[0])
	}
	if strings.Contains(rec.Body.String(), bypassMarker) {
		t.Errorf("429 body echoed bypassMarker: %s", rec.Body.String())
	}
}

// TestRateLimitBypassResistanceForgedInternalPathDoesNotExempt proves
// the middleware never trusts the request path as a bypass signal. A
// path like `/v1/internal/...` looks "internal" but the limiter MUST
// still bill the appropriate customer bucket because the auth method
// was not stamped to MethodInternalWorker.
func TestRateLimitBypassResistanceForgedInternalPathDoesNotExempt(t *testing.T) {
	t.Parallel()

	limiter := &fakeRateLimiter{}
	limiter.queue(ratelimit.Decision{Bucket: ratelimit.BucketIP, Retry: 1})
	h := RateLimit(limiter, nil)(&rateLimitOK{})

	req := httptest.NewRequest(http.MethodPost, "/v1/internal/callback/"+bypassMarker, nil)
	req.RemoteAddr = "10.0.0.1:1234"

	rec := runRateLimit(h, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("path-bypass request got status %d, want 429; body %s", rec.Code, rec.Body.String())
	}
	seen := limiter.requests()
	if len(seen) != 1 || seen[0].Exempt {
		t.Errorf("limiter saw %+v on a forged-path request, want Exempt=false", seen)
	}
}

// TestRateLimitBypassResistanceInternalWorkerCannotBeForgedFromHeader
// proves that the middleware's auth-method context value is the only
// bypass signal: a request that bypasses RequireAuth and stamps a fake
// method through the public package surface CAN flip Exempt — but only
// if the canonical `withAuthMethod` helper was called, which is itself
// gated by the authenticator. The complementary
// TestAuthMethodFromContextRoundtrips proves the round-trip; this test
// proves the inverse: ANY other channel — header, path, IP, principal
// id — does NOT flip Exempt.
func TestRateLimitBypassResistanceInternalWorkerCannotBeForgedFromHeader(t *testing.T) {
	t.Parallel()

	limiter := &fakeRateLimiter{}
	// Queue two denials so a regression that flipped either request to
	// Exempt would visibly let one through.
	limiter.queue(ratelimit.Decision{Bucket: ratelimit.BucketKey, Retry: 1})
	limiter.queue(ratelimit.Decision{Bucket: ratelimit.BucketKey, Retry: 1})
	h := RateLimit(limiter, nil)(&rateLimitOK{})

	// First leg: a request with a faked method-shaped header value.
	req := httptest.NewRequest(http.MethodPost, "/v1/projects", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer "+bypassMarker)
	p := policy.Principal{ID: bypassMarker, OrganizationID: "org_acme", Kind: domain.KindServiceAccount}
	req = req.WithContext(policy.WithPrincipal(req.Context(), p))
	// NOTE: deliberately NOT calling withAuthMethod(..., MethodInternalWorker)
	// so the middleware's exemption gate sees no method stamp.
	rec := runRateLimit(h, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("first leg: status = %d, want 429", rec.Code)
	}

	// Second leg: same shape but with the auth method stamped to a
	// non-internal value. This proves the middleware checks for the
	// SPECIFIC internal-worker value, not just "any auth method
	// stamp".
	req2 := httptest.NewRequest(http.MethodPost, "/v1/projects", nil)
	req2.RemoteAddr = "10.0.0.1:1234"
	req2 = req2.WithContext(policy.WithPrincipal(req2.Context(), p))
	req2 = req2.WithContext(withAuthMethod(req2.Context(), auth.MethodAPIKey))
	rec2 := runRateLimit(h, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Errorf("second leg: status = %d, want 429", rec2.Code)
	}

	seen := limiter.requests()
	if len(seen) != 2 {
		t.Fatalf("limiter saw %d requests, want 2", len(seen))
	}
	for i, r := range seen {
		if r.Exempt {
			t.Errorf("limiter saw Exempt=true on leg %d: %+v", i, r)
		}
	}
	// Neither response body nor any header value should echo the
	// marker — a regression that surfaced the marker as the bucket
	// identity, the principal id, or the auth-method value would
	// shift cross-tenant data onto the wire.
	body := rec.Body.String() + rec2.Body.String()
	if strings.Contains(body, bypassMarker) {
		t.Errorf("429 body echoed bypassMarker: leg1=%q leg2=%q", rec.Body.String(), rec2.Body.String())
	}
}

// TestRateLimitBypassResistanceClientIPHonoursOnlyFirstHop proves that a
// chained `X-Forwarded-For` value cannot shift the IP bucket identity
// past the first hop. An attacker who tried to push their real IP out
// of the bucket key by appending bogus suffixes — or to ride a victim's
// IP by prepending one — would still see the first comma-separated
// entry win. This is the BE-0035 contract; the assertion here pins the
// bypass-resistance angle.
func TestRateLimitBypassResistanceClientIPHonoursOnlyFirstHop(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		xff     string
		xreal   string
		wantIP  string
		wantNot string
	}{
		{
			name:    "first hop wins over trailing bogus entries",
			xff:     "203.0.113.10, 10.0.0.1, " + bypassMarker,
			wantIP:  "203.0.113.10",
			wantNot: bypassMarker,
		},
		{
			name:    "x-real-ip is used only when X-Forwarded-For is absent",
			xreal:   "198.51.100.7",
			wantIP:  "198.51.100.7",
			wantNot: bypassMarker,
		},
		{
			name:    "no header falls through to RemoteAddr",
			wantIP:  "172.18.0.5",
			wantNot: bypassMarker,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			limiter := &fakeRateLimiter{}
			resolver := NewTrustedProxyClientIPResolver([]netip.Prefix{netip.MustParsePrefix("172.18.0.0/16")})
			h := RateLimitWithClientIPResolver(limiter, nil, resolver)(&rateLimitOK{})
			req := httptest.NewRequest(http.MethodGet, "/v1/projects", nil)
			req.RemoteAddr = "172.18.0.5:1234"
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}
			if tc.xreal != "" {
				req.Header.Set("X-Real-IP", tc.xreal)
			}
			rec := runRateLimit(h, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
			}
			seen := limiter.requests()
			if len(seen) != 1 {
				t.Fatalf("limiter saw %d requests, want 1", len(seen))
			}
			if seen[0].IP != tc.wantIP {
				t.Errorf("Request.IP = %q, want %q", seen[0].IP, tc.wantIP)
			}
			if strings.Contains(seen[0].IP, tc.wantNot) {
				t.Errorf("Request.IP %q contains forbidden substring %q", seen[0].IP, tc.wantNot)
			}
		})
	}
}

// TestRateLimitBypassResistanceConcurrentBurstCannotExceedCap proves that
// N parallel requests against a single per-key bucket cannot all
// succeed when the limiter is wired with a finite burst. This is the
// behavioural contract the production `*ratelimit.Limiter` is supposed
// to provide; the assertion here pins it end-to-end through the HTTP
// middleware so a regression that lost atomicity (e.g. by reading the
// bucket counter outside the mutex) would surface as a flaky
// over-grant. The test uses the production limiter, not a fake.
func TestRateLimitBypassResistanceConcurrentBurstCannotExceedCap(t *testing.T) {
	t.Parallel()

	cfg := ratelimit.Config{
		Key: ratelimit.Specs{
			Read:  ratelimit.Spec{Rate: 1, Burst: 3},
			Write: ratelimit.Spec{Rate: 1, Burst: 3},
		},
	}
	limiter, err := ratelimit.New(cfg)
	if err != nil {
		t.Fatalf("ratelimit.New: %v", err)
	}
	// The per-goroutine handler must be stateless: the shared
	// `rateLimitOK` test helper writes to a `ran` field on every call
	// and would race with itself under -race when called from 20
	// goroutines. A bare ResponseWriter write is enough — the assertion
	// below cares only about the status code, not whether a specific
	// handler instance ran.
	concurrentHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	h := RateLimit(limiter, nil)(concurrentHandler)

	const parallel = 20
	var allowed, denied atomic.Int64
	var wg sync.WaitGroup
	wg.Add(parallel)
	for i := 0; i < parallel; i++ {
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/v1/projects", nil)
			req.RemoteAddr = "10.0.0.1:1234"
			p := policy.Principal{ID: "key_concurrent", OrganizationID: "org_concurrent", Kind: domain.KindServiceAccount}
			req = req.WithContext(policy.WithPrincipal(req.Context(), p))
			req = req.WithContext(withAuthMethod(req.Context(), auth.MethodAPIKey))
			rec := runRateLimit(h, req)
			switch rec.Code {
			case http.StatusOK:
				allowed.Add(1)
			case http.StatusTooManyRequests:
				denied.Add(1)
			default:
				t.Errorf("unexpected status %d; body %s", rec.Code, rec.Body.String())
			}
		}()
	}
	wg.Wait()

	got := allowed.Load()
	if got > int64(cfg.Key.Read.Burst) {
		t.Errorf("allowed=%d, want <= burst=%d (concurrent over-grant)", got, cfg.Key.Read.Burst)
	}
	if got+denied.Load() != parallel {
		t.Errorf("allowed+denied=%d, want %d", got+denied.Load(), parallel)
	}
	if denied.Load() == 0 {
		t.Errorf("denied=0, want > 0 (a burst-of-%d cannot grant all %d parallel requests)", cfg.Key.Read.Burst, parallel)
	}
}

// TestRateLimitBypassResistanceDecisionBucketIsClosedConstantSet pins
// the runtime complement of the static-gate matcher: every Decision
// emitted by `*ratelimit.Limiter.Check` for a denial uses one of the
// closed-set constants `BucketOrg`, `BucketKey`, `BucketIP`. A
// regression that filled the field with a bucket identity would
// surface here as a denial whose `Bucket` string does not match any
// of the three constants.
func TestRateLimitBypassResistanceDecisionBucketIsClosedConstantSet(t *testing.T) {
	t.Parallel()

	cfg := ratelimit.Config{
		Org: ratelimit.Specs{
			Read:  ratelimit.Spec{Rate: 1, Burst: 1},
			Write: ratelimit.Spec{Rate: 1, Burst: 1},
		},
		Key: ratelimit.Specs{
			Read:  ratelimit.Spec{Rate: 1, Burst: 1},
			Write: ratelimit.Spec{Rate: 1, Burst: 1},
		},
		IP: ratelimit.Specs{
			Read:  ratelimit.Spec{Rate: 1, Burst: 1},
			Write: ratelimit.Spec{Rate: 1, Burst: 1},
		},
	}
	limiter, err := ratelimit.New(cfg)
	if err != nil {
		t.Fatalf("ratelimit.New: %v", err)
	}
	allowed := map[string]struct{}{
		ratelimit.BucketOrg: {},
		ratelimit.BucketKey: {},
		ratelimit.BucketIP:  {},
	}
	bypassID := "org_" + bypassMarker
	for _, leg := range []ratelimit.Request{
		{OrgID: bypassID, IP: "10.0.0.1", Write: false},
		{OrgID: bypassID, IP: "10.0.0.1", Write: false},
		{KeyID: "key_" + bypassMarker, IP: "10.0.0.2", Write: false},
		{KeyID: "key_" + bypassMarker, IP: "10.0.0.2", Write: false},
		{IP: "10.0.0.3", Write: false},
		{IP: "10.0.0.3", Write: false},
	} {
		d := limiter.Check(leg)
		if d.Allowed {
			continue
		}
		if _, ok := allowed[d.Bucket]; !ok {
			t.Errorf("Decision.Bucket = %q, want one of {organization, api_key, ip}", d.Bucket)
		}
		if strings.Contains(d.Bucket, bypassMarker) {
			t.Errorf("Decision.Bucket %q leaked the bucket identity", d.Bucket)
		}
	}
}

// TestRateLimitBypassResistanceDenyLogDoesNotEchoBucketIdentity proves
// the WARN log record emitted on a denial carries the bucket DIMENSION
// name only — never the bucket IDENTITY. A regression that splatted
// the principal id, org id, or client IP into the log record would let
// an operator pivot from a 429 record to "which tenant lives here".
func TestRateLimitBypassResistanceDenyLogDoesNotEchoBucketIdentity(t *testing.T) {
	t.Parallel()

	limiter := &fakeRateLimiter{}
	limiter.queue(ratelimit.Decision{Bucket: ratelimit.BucketKey, Retry: 2})

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h := RateLimit(limiter, logger)(&rateLimitOK{})

	req := httptest.NewRequest(http.MethodPost, "/v1/projects/"+bypassMarker, nil)
	req.RemoteAddr = "10.0.0.1:1234"
	p := policy.Principal{
		ID:             "key_" + bypassMarker,
		OrganizationID: "org_" + bypassMarker,
		Kind:           domain.KindServiceAccount,
	}
	req = req.WithContext(policy.WithPrincipal(req.Context(), p))
	req = req.WithContext(withAuthMethod(req.Context(), auth.MethodAPIKey))

	rec := runRateLimit(h, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	logText := buf.String()
	// The log record MUST include the dimension name…
	if !strings.Contains(logText, `"bucket":"`+ratelimit.BucketKey+`"`) {
		t.Errorf("log record missing bucket dimension; got %q", logText)
	}
	// …but MUST NOT include the bucket identity (any prefix of the
	// marker would still trip this check).
	if strings.Contains(logText, bypassMarker) {
		// The path attribute is allowed to contain the marker (the
		// request URL is a public surface) — but the log record's
		// bucket/principal/key slots must not. We assert the marker
		// appears at most once in the entire record (in the `path`
		// attribute) so a regression that splatted the principal id
		// into a bucket-shaped field would surface.
		count := strings.Count(logText, bypassMarker)
		if count > 1 {
			t.Errorf("log record echoed bypassMarker %d times; want <= 1 (path only); record=%q", count, logText)
		}
	}
}

// TestRateLimitBypassResistanceEnvelopeBodyHidesBucketIdentity proves
// the 429 wire envelope body carries only the closed-set dimension
// name in `details["scope"]` and never the bucket identity. The
// rendered body is the public surface a cross-tenant attacker would
// observe; an identity leak here is the most direct bypass-adjacent
// data-exposure regression.
func TestRateLimitBypassResistanceEnvelopeBodyHidesBucketIdentity(t *testing.T) {
	t.Parallel()

	limiter := &fakeRateLimiter{}
	limiter.queue(ratelimit.Decision{Bucket: ratelimit.BucketOrg, Retry: 5})
	h := RateLimit(limiter, nil)(&rateLimitOK{})

	req := httptest.NewRequest(http.MethodPost, "/v1/projects/"+bypassMarker, nil)
	req.RemoteAddr = "10.0.0.1:1234"
	p := policy.Principal{
		ID:             "key_" + bypassMarker,
		OrganizationID: "org_" + bypassMarker,
		Kind:           domain.KindServiceAccount,
	}
	req = req.WithContext(policy.WithPrincipal(req.Context(), p))
	req = req.WithContext(withAuthMethod(req.Context(), auth.MethodAPIKey))

	rec := runRateLimit(h, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	var env rateLimitedEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode envelope: %v; body=%s", err, rec.Body.String())
	}
	if env.Error.Code == "" || !strings.Contains(env.Error.Code, "RATE_LIMIT") {
		t.Errorf("envelope code = %q, want a stable rate-limit code", env.Error.Code)
	}
	// The scope detail MUST be the dimension name, not the identity.
	scope := env.Error.Details["scope"]
	if scope != ratelimit.BucketOrg {
		t.Errorf("details.scope = %q, want %q (dimension name, not identity)", scope, ratelimit.BucketOrg)
	}
	// And the raw body bytes MUST NOT echo the bucket identity (org
	// id or principal id). The body is the cross-tenant attacker's
	// view; an identity here would directly enumerate live tenants.
	if strings.Contains(rec.Body.String(), bypassMarker) {
		t.Errorf("envelope body echoed bypassMarker (bucket identity leak): %s", rec.Body.String())
	}
}

// TestRateLimitBypassResistanceEmptyContextStillBillsIPBucket proves
// the middleware does NOT skip the limiter entirely when the request
// context carries no principal and no auth method — i.e. the bypass
// channel "send an anonymous request to skip the gate" does not exist.
// Without a principal, the IP bucket alone applies; the limiter still
// gets a chance to deny.
func TestRateLimitBypassResistanceEmptyContextStillBillsIPBucket(t *testing.T) {
	t.Parallel()

	limiter := &fakeRateLimiter{}
	// Pre-queue a denial. If the middleware short-circuited to Allowed
	// because the context was empty, the limiter would never be
	// consulted and `next.ran` would be true.
	limiter.queue(ratelimit.Decision{Bucket: ratelimit.BucketIP, Retry: 1})
	next := &rateLimitOK{}
	h := RateLimit(limiter, nil)(next)

	req := httptest.NewRequest(http.MethodPost, "/v1/projects", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	// Intentionally no principal, no auth method, no headers.
	req = req.WithContext(context.Background())
	// Re-attach RemoteAddr lost via WithContext.
	req.RemoteAddr = "10.0.0.1:1234"

	rec := runRateLimit(h, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 (empty-context request must still consult limiter)", rec.Code)
	}
	if next.ran {
		t.Error("next handler ran on an empty-context request despite a queued denial")
	}
	seen := limiter.requests()
	if len(seen) != 1 {
		t.Fatalf("limiter saw %d requests, want 1", len(seen))
	}
	if seen[0].Exempt {
		t.Errorf("limiter saw Exempt=true on an empty-context request: %+v", seen[0])
	}
	if seen[0].OrgID != "" || seen[0].KeyID != "" {
		t.Errorf("limiter saw principal slots populated on an empty-context request: %+v", seen[0])
	}
	if seen[0].IP == "" {
		t.Errorf("limiter saw empty IP on an empty-context request: %+v", seen[0])
	}
}
