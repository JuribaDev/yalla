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
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// CSRF stance for browser sessions — runtime defense (BE-0348).
//
// The static analyzer (`csrf_static_test.go`) proves the package has
// no source-level cookie surface. These runtime tests prove the same
// invariant through `NewHandler` end-to-end — a stronger statement,
// because the static analyzer cannot see what a third-party
// middleware in the standard library or an injected logger might
// emit, but `httptest.ResponseRecorder.Header()` shows exactly what
// the wire would carry. Together the two tests pin the load-bearing
// CSRF defence: no response on any route carries a `Set-Cookie`
// header, no `Cookie` request header authenticates a caller, and no
// cookie value ever ends up reflected in an error envelope.
//
// Each test below asserts the SAME load-bearing property: no
// response header matches the case-insensitive `Set-Cookie` or
// `Set-Cookie2` literal. The `assertNoSetCookie` helper centralises
// the assertion so a regression that issues a session cookie on one
// route fails one test with a clear diagnostic.

// cookieSentinel is the value planted in the request `Cookie` header
// by every test below. It is unguessable enough that a substring
// search in the response body is a sound redaction backstop: an
// envelope that echoes the cookie value is a redaction regression,
// and the substring search names it.
const cookieSentinel = "session=yalla-csrf-sentinel-9f3c2a7e-do-not-echo"

// TestCSRFPublicRoutesIssueNoSetCookie proves every public-surface
// route (`/healthz`, `/version`, `/readyz`, `/healthz/backup`,
// `/openapi.json`) responds with no `Set-Cookie` header — even when
// the request carries a `Cookie` header that a permissive
// "remember-me" middleware might reflect into a refresh `Set-Cookie`.
// The same property is asserted on the production routes wired
// through `newTestHandler`, which uses the same `NewHandler`
// constructor `cmd/yalla-api` calls at startup, so the test
// exercises the real route table rather than a per-handler fake.
func TestCSRFPublicRoutesIssueNoSetCookie(t *testing.T) {
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
			for _, cookie := range []string{"", cookieSentinel} {
				cookie := cookie
				name := "no-cookie"
				if cookie != "" {
					name = "with-cookie"
				}
				t.Run(name, func(t *testing.T) {
					t.Parallel()
					req := httptest.NewRequest(http.MethodGet, path, nil)
					if cookie != "" {
						req.Header.Set("Cookie", cookie)
					}
					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, req)
					assertNoSetCookie(t, rec)
					assertNoCookieEchoInBody(t, rec)
				})
			}
		})
	}
}

// TestCSRFNotFoundEnvelopeIssuesNoSetCookie proves the 404 surface
// (every unmatched path, served through the package-level
// not-found recorder as a stable `yalla.error.v1` envelope) carries
// no `Set-Cookie` header even when the request planted an attacker-
// style `Cookie` header. A regression that issued a fresh session
// cookie on the 404 path would let an attacker browser store a
// Yalla-issued cookie by probing missing paths from a credentialed
// page — a session-fixation primitive that has no business existing
// on a non-cookie surface.
func TestCSRFNotFoundEnvelopeIssuesNoSetCookie(t *testing.T) {
	t.Parallel()
	handler := newTestHandler(runtime.BuildInfo{}, runtime.NewReadiness(), nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/this-route-does-not-exist", nil)
	req.Header.Set("Cookie", cookieSentinel)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	assertNoSetCookie(t, rec)
	assertNoCookieEchoInBody(t, rec)
}

// TestCSRFUnauthenticatedRequestIssuesNoSetCookie proves the 401
// surface (auth middleware rejection) carries no `Set-Cookie` header
// even when the request planted an attacker-style `Cookie` header.
// The companion invariant is that the `Cookie` header is NOT honored
// as a credential: a request with only a `Cookie: session=...`
// header and no `Authorization: Bearer ...` header is unauthenticated
// — the auth middleware reads `Authorization` only (see
// `middleware.go::bearerToken`). A regression that taught the
// middleware to fall back to a session cookie would let a browser
// script forge a credentialed request riding an ambient cookie, the
// canonical CSRF primitive this stance refuses.
//
// We drive this through `createOrganizationHandlerFor` rather than
// `newTestHandler` because the per-handler helper accepts a zero
// `auth.Identity`, which the fake authenticator rejects as
// unauthenticated — the cleanest way to drive the 401 path through
// real auth middleware.
func TestCSRFUnauthenticatedRequestIssuesNoSetCookie(t *testing.T) {
	t.Parallel()
	creator := fakeOrganizationCreator{
		err: stderrors.New("creator must not be called for an unauthenticated request"),
	}
	handler := createOrganizationHandlerFor(auth.Identity{}, nil, creator)

	req := httptest.NewRequest(http.MethodPost, "/v1/organizations",
		strings.NewReader(`{"slug":"acme","display_name":"Acme"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", cookieSentinel)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_AUTH")
	if env.SchemaVersion != "yalla.error.v1" {
		t.Errorf("schema_version = %q, want yalla.error.v1", env.SchemaVersion)
	}
	if env.RequestID == "" {
		t.Errorf("request_id is empty, want a generated id")
	}
	assertNoSetCookie(t, rec)
	assertNoCookieEchoInBody(t, rec)
}

// TestCSRFCookieHeaderDoesNotAuthenticate is the companion to
// TestCSRFUnauthenticatedRequestIssuesNoSetCookie: it pins the
// invariant that swapping the JWT into the `Cookie` header does not
// authenticate the caller, even when the cookie value is well-formed
// and would be a valid bearer token in the `Authorization` header.
// A regression that taught the middleware to read the JWT from a
// `session`-named cookie would silently transform the API into a
// cookie-credential surface — and would simultaneously activate
// every CSRF primitive against it.
//
// The test plants the JWT in BOTH the cookie name and a
// distinctive sentinel value, so a regression that decoded the
// cookie and forwarded the principal would 201 the request (and the
// assertion fails closed). The fakeAuthenticator is configured to
// return a valid identity ONLY for the exact bearer-token string —
// not for the cookie-encoded equivalent — which would cause the
// fake to be invoked and return success had the middleware switched
// to cookie-mode.
func TestCSRFCookieHeaderDoesNotAuthenticate(t *testing.T) {
	t.Parallel()
	creator := fakeOrganizationCreator{
		err: stderrors.New("creator must not be called when only a Cookie credential is supplied"),
	}
	handler := createOrganizationHandlerFor(auth.Identity{}, nil, creator)

	// Three cookie shapes a permissive middleware might learn to read.
	// Each must be rejected as unauthenticated.
	cases := []struct {
		name   string
		cookie string
	}{
		{
			name:   "session=jwt",
			cookie: "session=a-valid-session-token",
		},
		{
			name:   "authorization=Bearer jwt",
			cookie: "authorization=Bearer a-valid-session-token",
		},
		{
			name:   "yalla_session=jwt; csrf_token=abc",
			cookie: "yalla_session=a-valid-session-token; csrf_token=abc",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodPost, "/v1/organizations",
				strings.NewReader(`{"slug":"acme","display_name":"Acme"}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Cookie", tc.cookie)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 (cookie credentials must not authenticate); body %s",
					rec.Code, rec.Body.String())
			}
			decodeError(t, rec, "E_AUTH")
			assertNoSetCookie(t, rec)
		})
	}
}

// TestCSRFAuthenticatedSuccessIssuesNoSetCookie proves the happy
// path (201) carries no `Set-Cookie` header. A regression that
// issued a session cookie alongside a successful API-key-authenticated
// mutation would silently grant a browser-readable ambient credential
// to any client — including a CLI or CI runner that has no use for
// it, and a future browser surface that has no cookie-store
// guarantees. The body assertion additionally proves the cookie
// sentinel never round-trips into the response envelope, so a logging
// regression that inadvertently captured the request `Cookie` value
// into a response field also fails this test.
func TestCSRFAuthenticatedSuccessIssuesNoSetCookie(t *testing.T) {
	t.Parallel()
	creator := fakeOrganizationCreator{org: store.Organization{
		ID:          "org_new",
		Slug:        "acme",
		DisplayName: "Acme, Inc.",
	}}
	handler := createOrganizationHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	req := httptest.NewRequest(http.MethodPost, "/v1/organizations",
		strings.NewReader(`{"slug":"acme","display_name":"Acme, Inc."}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer a-valid-session-token")
	req.Header.Set("Cookie", cookieSentinel)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	assertNoSetCookie(t, rec)
	assertNoCookieEchoInBody(t, rec)
}

// TestCSRFValidationFailureIssuesNoSetCookie proves the 400
// validation-error surface carries no `Set-Cookie` header. The
// envelope is `yalla.error.v1` E_INVALID_INPUT (malformed JSON
// rejected by the decoder), and the cookie sentinel must not be
// reflected into the error message — body-echo of a `Cookie` header
// value into an error envelope would be both a redaction regression
// and a CSRF-adjacent information leak (it would tell an attacker
// page which cookies the server inspected).
func TestCSRFValidationFailureIssuesNoSetCookie(t *testing.T) {
	t.Parallel()
	creator := fakeOrganizationCreator{
		err: stderrors.New("creator must not be called for invalid input"),
	}
	handler := createOrganizationHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	req := httptest.NewRequest(http.MethodPost, "/v1/organizations",
		strings.NewReader(`{"slug":`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer a-valid-session-token")
	req.Header.Set("Cookie", cookieSentinel)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INVALID_INPUT")
	assertNoSetCookie(t, rec)
	assertNoCookieEchoInBody(t, rec)
}

// TestCSRFCookieHeaderDoesNotInfluencePublicResponse pins the
// determinism invariant: two GETs to the same public path return the
// same response headers (modulo per-request identifiers and the
// system `Date` header) regardless of whether the request carries a
// `Cookie` header. A regression that reflected the request cookie
// into a refresh `Set-Cookie` would visibly diverge the two header
// sets, even if it returned the same body.
func TestCSRFCookieHeaderDoesNotInfluencePublicResponse(t *testing.T) {
	t.Parallel()
	handler := newTestHandler(runtime.BuildInfo{Version: "1.2.3"}, runtime.NewReadiness(), nil, nil)

	do := func(cookie string) http.Header {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		if cookie != "" {
			req.Header.Set("Cookie", cookie)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Result().Header.Clone()
	}

	bare := do("")
	withCookie := do(cookieSentinel)

	if got := headerKeySet(bare); !equalKeys(got, headerKeySet(withCookie)) {
		t.Fatalf("response header key sets differ for Cookie vs no-Cookie:\nbare       = %v\nwithCookie = %v",
			got, headerKeySet(withCookie))
	}
	assertNoSetCookie(t, &recorderShim{headers: bare})
	assertNoSetCookie(t, &recorderShim{headers: withCookie})
}

// assertNoSetCookie fails the test if any response header matches
// the case-insensitive `Set-Cookie` or `Set-Cookie2` literal — the
// only HTTP response headers that issue a browser-stored cookie. The
// failure message names the offending header so a regression is
// immediately diagnosable. This is the load-bearing assertion the
// entire suite shares: a single `Set-Cookie` on a single route is a
// CSRF-stance regression.
//
// The helper reuses the `corsHeaderHolder` interface declared in
// `cors_test.go` (`{ Header() http.Header }`) so the determinism
// test can pass a cloned header without re-running the request.
func assertNoSetCookie(t *testing.T, holder corsHeaderHolder) {
	t.Helper()
	headers := holder.Header()
	var leaked []string
	for key, values := range headers {
		lower := strings.ToLower(key)
		if lower == "set-cookie" || lower == "set-cookie2" {
			leaked = append(leaked, key+": "+strings.Join(values, ", "))
		}
	}
	if len(leaked) > 0 {
		sort.Strings(leaked)
		t.Errorf("response carries Set-Cookie header(s) — the Yalla control-plane API is "+
			"a non-cookie surface by design (no ambient browser credentials, no CSRF "+
			"primitive); see AGENTS.md \"CSRF stance\" for the threat model. Leaked: %s",
			strings.Join(leaked, "; "))
	}
}

// assertNoCookieEchoInBody fails the test if the cookie sentinel
// appears anywhere in the response body. The sentinel is a
// distinctive opaque string (`cookieSentinel`); a substring match is
// sound because the sentinel cannot appear by coincidence in any
// production envelope. The check is a redaction backstop: a logging
// regression that captured the request `Cookie` header into a
// response field — or an error message that echoed the body it could
// not parse — would surface as a sentinel hit here.
func assertNoCookieEchoInBody(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	body := rec.Body.String()
	if strings.Contains(body, cookieSentinel) {
		t.Errorf("response body echoes the request Cookie sentinel %q — the "+
			"Cookie header must NOT be reflected into the response envelope "+
			"(redaction backstop). Body: %s", cookieSentinel, body)
	}
	// The bare sentinel value (without the `session=` prefix) is the
	// raw cookie payload an attacker page would care about exfiltrating.
	const bareValue = "yalla-csrf-sentinel-9f3c2a7e-do-not-echo"
	if strings.Contains(body, bareValue) {
		t.Errorf("response body echoes the bare Cookie payload %q. Body: %s",
			bareValue, body)
	}
}
