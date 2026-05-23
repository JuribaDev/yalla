package httpapi

import (
	stderrors "errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
)

// CORS policy — runtime defense (BE-0347).
//
// These integration-style handler tests prove that no production route
// in the package emits an `Access-Control-*` response header for any
// request shape — neither for a benign same-origin GET, a preflight
// OPTIONS with attacker-style request headers, a 401 from a missing
// credential, nor a 404 from an unmatched path. The companion static
// analyser in `cors_static_test.go` is the regression backstop and
// rejects any future production source that names a CORS header
// literal; this file proves the same invariant end-to-end through the
// real `NewHandler` route table.
//
// The threat model is the Yalla control-plane API serving an
// authenticated cross-origin call from an attacker-loaded browser
// script: without `Access-Control-Allow-Origin` in the response, the
// browser's same-origin policy refuses to surface the response body to
// the script — and for a credentialed request, refuses to send the
// request body at all. Yalla's API surface today is consumed by
// non-browser callers (CLI, agents, CI) authenticated by Bearer tokens
// or session cookies, so the "deny by default" stance is both safe and
// load-bearing. A future browser surface will be wired through one
// explicit middleware seam — never per-handler.
//
// Every test below asserts the SAME load-bearing property: no response
// header begins with the case-insensitive `Access-Control-` prefix.
// The `assertNoCORSHeaders` helper centralises the assertion so a
// regression that emits one CORS header on one route fails one test
// with a clear diagnostic.

// TestCORSPublicRoutesEmitNoApprovalHeaders proves the public-surface
// routes (`/healthz`, `/version`, `/readyz`, `/healthz/backup`,
// `/openapi.json`) respond with no `Access-Control-*` header — even
// when the request carries an `Origin` header that a permissive CORS
// middleware would reflect. The same property is asserted on the
// production routes wired through `newTestHandler`, which uses the
// same `NewHandler` constructor `cmd/yalla-api` calls at startup, so
// the test exercises the real route table rather than a per-handler
// fake.
func TestCORSPublicRoutesEmitNoApprovalHeaders(t *testing.T) {
	t.Parallel()
	handler := newTestHandler(runtime.BuildInfo{
		Version: "1.2.3",
		Commit:  "abc123",
		Date:    "2026-05-16T00:00:00Z",
	}, runtime.NewReadiness(), nil, nil)

	paths := []string{
		"/healthz",
		"/version",
		"/readyz",
		"/healthz/backup",
		"/openapi.json",
	}
	for _, path := range paths {
		path := path
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			for _, origin := range []string{"", "https://evil.example"} {
				origin := origin
				t.Run("origin="+origin, func(t *testing.T) {
					t.Parallel()
					req := httptest.NewRequest(http.MethodGet, path, nil)
					if origin != "" {
						req.Header.Set("Origin", origin)
					}
					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, req)
					assertNoCORSHeaders(t, rec)
				})
			}
		})
	}
}

// TestCORSPreflightOptionsReceivesNoApproval simulates a browser
// preflight: an `OPTIONS` request with `Origin`, `Access-Control-
// Request-Method`, and `Access-Control-Request-Headers` request
// headers, sent to a path that legitimately accepts a credentialed
// `POST`. The response must NOT carry `Access-Control-Allow-Origin`,
// `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`, or
// `Access-Control-Allow-Credentials`. With no approval, the browser
// fails the preflight and the unsafe request never reaches the
// server.
//
// We do not assert a specific status code because Go's
// method-scoped `ServeMux` returns 405 for a path-with-registered-
// methods and 404 for a path-without-any-registered-route; both are
// acceptable. The load-bearing assertion is the header absence.
// Routes with no body (`OPTIONS /missing`) and routes with a
// registered POST (`OPTIONS /v1/organizations`) are both tested.
func TestCORSPreflightOptionsReceivesNoApproval(t *testing.T) {
	t.Parallel()
	handler := newTestHandler(runtime.BuildInfo{}, runtime.NewReadiness(), nil, nil)

	paths := []string{
		"/v1/organizations",
		"/healthz",
		"/missing-deliberately",
	}
	for _, path := range paths {
		path := path
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodOptions, path, nil)
			req.Header.Set("Origin", "https://evil.example")
			req.Header.Set("Access-Control-Request-Method", "POST")
			req.Header.Set("Access-Control-Request-Headers", "Authorization, Content-Type")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			assertNoCORSHeaders(t, rec)
		})
	}
}

// TestCORSOriginHeaderDoesNotInfluenceResponse pins the determinism
// invariant: two GETs to the same public path return the same
// response headers (modulo per-request identifiers and the system
// `Date` header) regardless of whether the request carries an
// `Origin` header. A regression that reflected `Origin` into
// `Access-Control-Allow-Origin` would visibly diverge the two header
// sets, even if it returned the same body. The body is not asserted
// to be byte-identical because the `request_id` field is necessarily
// per-request.
func TestCORSOriginHeaderDoesNotInfluenceResponse(t *testing.T) {
	t.Parallel()
	handler := newTestHandler(runtime.BuildInfo{
		Version: "1.2.3",
	}, runtime.NewReadiness(), nil, nil)

	do := func(origin string) http.Header {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Result().Header.Clone()
	}

	bare := do("")
	withOrigin := do("https://evil.example")

	if got := headerKeySet(bare); !equalKeys(got, headerKeySet(withOrigin)) {
		t.Fatalf("response header key sets differ for Origin vs no-Origin:\nbare       = %v\nwithOrigin = %v",
			got, headerKeySet(withOrigin))
	}
	for _, key := range headerKeySet(bare) {
		if strings.EqualFold(key, "Date") || strings.EqualFold(key, "X-Request-Id") || strings.EqualFold(key, "X-Correlation-Id") {
			// Date and per-request identifiers necessarily differ
			// between two requests; everything else must match.
			continue
		}
		if got, want := withOrigin.Values(key), bare.Values(key); !equalStrings(got, want) {
			t.Errorf("header %q differs with Origin: got %v, want %v (regression: Origin header influences the response)",
				key, got, want)
		}
	}
	assertNoCORSHeaders(t, &recorderShim{headers: bare})
	assertNoCORSHeaders(t, &recorderShim{headers: withOrigin})
}

// TestCORSUnauthenticatedRequestHasNoApproval proves the auth gate is
// not weakened by the CORS stance: a credentialed cross-origin POST
// without a valid token returns a 401 `E_AUTH` envelope with no
// `Access-Control-*` response header. A regression that emitted
// `Access-Control-Allow-Origin: *` on the 401 would let a browser
// script learn that the API rejects its credentials — a
// reconnaissance vector — and would also turn the 401 into a
// readable error for the attacker's page.
//
// We drive this through `createOrganizationHandlerFor` rather than
// `newTestHandler` because the per-handler helper accepts a zero
// `auth.Identity`, which the fake authenticator rejects as
// unauthenticated — the cleanest way to drive the 401 path through
// real auth middleware.
func TestCORSUnauthenticatedRequestHasNoApproval(t *testing.T) {
	t.Parallel()

	creator := fakeOrganizationCreator{
		err: stderrors.New("creator must not be called for an unauthenticated request"),
	}
	handler := createOrganizationHandlerFor(auth.Identity{}, nil, creator)

	req := httptest.NewRequest(http.MethodPost, "/v1/organizations",
		strings.NewReader(`{"slug":"acme","display_name":"Acme"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	assertNoCORSHeaders(t, rec)
}

// TestCORSAuthenticatedRequestHasNoApproval proves the authenticated
// happy-path is not weakened by the CORS stance: a successful POST
// (201 yalla.output.v1) with an `Origin` request header returns no
// `Access-Control-*` response header. A regression that emitted
// approval on a successful response would let a same-script that
// already has the credentials read the result of every authorised
// mutation — the worst-case CORS outcome.
func TestCORSAuthenticatedRequestHasNoApproval(t *testing.T) {
	t.Parallel()
	handler := createOrganizationHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, fakeOrganizationCreator{})

	req := httptest.NewRequest(http.MethodPost, "/v1/organizations",
		strings.NewReader(`{"slug":"acme","display_name":"Acme"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer a-valid-session-token")
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	assertNoCORSHeaders(t, rec)
}

// TestCORSNotFoundEnvelopeHasNoApprovalHeaders proves the 404 surface
// (every unmatched path, served through `notFoundRecorder` as a
// stable `yalla.error.v1` envelope) carries no `Access-Control-*`
// header even when the request carries an attacker-style `Origin`.
// A regression that added approval to the 404 path would let a
// browser script enumerate the API's route table by probing missing
// paths and reading the discriminating error.
func TestCORSNotFoundEnvelopeHasNoApprovalHeaders(t *testing.T) {
	t.Parallel()
	handler := newTestHandler(runtime.BuildInfo{}, runtime.NewReadiness(), nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/this-route-does-not-exist", nil)
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	assertNoCORSHeaders(t, rec)
}

// corsHeaderHolder is the narrow interface assertNoCORSHeaders needs —
// either an `*httptest.ResponseRecorder` (the common case) or a
// `recorderShim` that adapts a cloned header for the deterministic-
// response test above. Keeping the helper interface-typed lets the
// determinism test re-use the same assertion logic without recording
// every response twice.
type corsHeaderHolder interface{ Header() http.Header }

// recorderShim adapts an `http.Header` (cloned from a recorder) into
// the `corsHeaderHolder` surface, so `TestCORSOriginHeaderDoesNotInfluenceResponse`
// can run `assertNoCORSHeaders` over two already-captured header maps
// without replaying the requests.
type recorderShim struct{ headers http.Header }

func (s *recorderShim) Header() http.Header { return s.headers }

// assertNoCORSHeaders fails the test if any header in the response
// begins with the case-insensitive `Access-Control-` prefix. The
// failure message names the offending header so a regression is
// immediately diagnosable. This is the load-bearing assertion the
// entire suite shares: a single CORS header on a single route is a
// policy regression.
func assertNoCORSHeaders(t *testing.T, holder corsHeaderHolder) {
	t.Helper()
	headers := holder.Header()
	var leaked []string
	for key, values := range headers {
		if strings.HasPrefix(strings.ToLower(key), "access-control-") {
			leaked = append(leaked, key+": "+strings.Join(values, ", "))
		}
	}
	if len(leaked) > 0 {
		sort.Strings(leaked)
		t.Errorf("response carries CORS approval header(s) — regression of the CORS stance:\n  %s",
			strings.Join(leaked, "\n  "))
	}
}

// headerKeySet returns a sorted list of header names present in h. The
// case-insensitive header map preserves canonical names (`Content-
// Type`, not `content-type`), so direct sort+string compare suffices.
func headerKeySet(h http.Header) []string {
	out := make([]string, 0, len(h))
	for k := range h {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// equalKeys compares two sorted string slices for set equality.
func equalKeys(a, b []string) bool { return equalStrings(a, b) }

// equalStrings is the literal element-wise compare for two string
// slices already in matching order.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
