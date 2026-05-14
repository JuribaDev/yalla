package httpapi

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
)

// Contract tests for the BE-0020 HTTP authorization middleware. They cover the
// four credential paths (API key, session, internal worker, anonymous public),
// the stable status/code/envelope contract for missing, invalid, and
// unauthorized requests, the separation of a dependency failure from a 401,
// cross-tenant resource resolution, and that the resolved principal reaches
// the handler context. They use a fake Authenticator and the real policy
// engine; no database is required.

// fakeAuthenticator is a canned auth.Authenticator for middleware tests.
type fakeAuthenticator struct {
	identity auth.Identity
	err      error
}

func (f fakeAuthenticator) Authenticate(context.Context, string) (auth.Identity, error) {
	return f.identity, f.err
}

// errorEnvelope is the decoded shape of a yalla.error.v1 response body.
type errorEnvelope struct {
	SchemaVersion string `json:"schema_version"`
	OK            bool   `json:"ok"`
	RequestID     string `json:"request_id"`
	Error         struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// run dispatches one request through h (already wrapped in telemetry.Correlate
// so a request_id is resolved) and returns the recorder.
func run(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	telemetry.Correlate(h).ServeHTTP(rec, req)
	return rec
}

// decodeError decodes rec's body as a yalla.error.v1 envelope and asserts the
// stable error contract: error schema version, ok:false, a non-empty
// request_id, and the expected code.
func decodeError(t *testing.T, rec *httptest.ResponseRecorder, wantCode string) errorEnvelope {
	t.Helper()
	var env errorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode error envelope: %v; body %s", err, rec.Body.String())
	}
	if env.SchemaVersion != "yalla.error.v1" {
		t.Errorf("schema_version = %q, want yalla.error.v1", env.SchemaVersion)
	}
	if env.OK {
		t.Error("ok = true, want false for an error envelope")
	}
	if env.RequestID == "" {
		t.Error("request_id is empty, want the correlated request id")
	}
	if env.Error.Code != wantCode {
		t.Errorf("error.code = %q, want %q", env.Error.Code, wantCode)
	}
	return env
}

// okHandler records that it ran and captures the principal on its context.
type okHandler struct {
	ran       bool
	principal policy.Principal
}

func (h *okHandler) ServeHTTP(_ http.ResponseWriter, r *http.Request) {
	h.ran = true
	h.principal, _ = policy.PrincipalFromContext(r.Context())
}

func bearerReq(token string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/v1/projects", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

func TestRequireAuthMissingCredentials(t *testing.T) {
	t.Parallel()
	next := &okHandler{}
	h := RequireAuth(fakeAuthenticator{}, policy.NewEngine(), policy.ActionProjectRead, nil)(next)

	rec := run(h, httptest.NewRequest(http.MethodGet, "/v1/projects", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_AUTH")
	if env.Error.Message != "authentication is required" {
		t.Errorf("message = %q, want %q", env.Error.Message, "authentication is required")
	}
	if next.ran {
		t.Error("next handler ran for an unauthenticated request")
	}
}

func TestRequireAuthInvalidCredentials(t *testing.T) {
	t.Parallel()
	next := &okHandler{}
	a := fakeAuthenticator{err: auth.ErrInvalidCredentials}
	h := RequireAuth(a, policy.NewEngine(), policy.ActionProjectRead, nil)(next)

	rec := run(h, bearerReq("yk_whatever"))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_AUTH")
	// The message is fixed and generic — it must not reveal which check failed
	// or whether a key prefix exists.
	if env.Error.Message != "the supplied credentials are invalid" {
		t.Errorf("message = %q, want the generic invalid-credentials message", env.Error.Message)
	}
	if next.ran {
		t.Error("next handler ran for an invalid-credential request")
	}
}

func TestRequireAuthDependencyFailureIsNot401(t *testing.T) {
	t.Parallel()
	next := &okHandler{}
	a := fakeAuthenticator{err: apierr.StoreUnavailable(stderrors.New("connection refused"))}
	h := RequireAuth(a, policy.NewEngine(), policy.ActionProjectRead, nil)(next)

	rec := run(h, bearerReq("yk_whatever"))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_UNAVAILABLE")
	if next.ran {
		t.Error("next handler ran despite a dependency failure")
	}
}

func TestRequireAuthAuthorizedRunsHandler(t *testing.T) {
	t.Parallel()
	next := &okHandler{}
	principal := policy.Principal{
		ID: "usr_ada", Kind: domain.KindUser, OrganizationID: "org_acme", Role: policy.RoleOwner,
	}
	a := fakeAuthenticator{identity: auth.Identity{Principal: principal, Method: auth.MethodSession}}
	h := RequireAuth(a, policy.NewEngine(), policy.ActionProjectRead, nil)(next)

	rec := run(h, bearerReq("a-valid-session-token"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if !next.ran {
		t.Fatal("next handler did not run for an authorized request")
	}
	if next.principal.ID != "usr_ada" || next.principal.OrganizationID != "org_acme" {
		t.Errorf("principal on context = %+v, want the authenticated principal", next.principal)
	}
}

func TestRequireAuthUnauthorizedIsForbidden(t *testing.T) {
	t.Parallel()
	next := &okHandler{}
	// A viewer may read but never create a project.
	principal := policy.Principal{
		ID: "usr_v", Kind: domain.KindUser, OrganizationID: "org_acme", Role: policy.RoleViewer,
	}
	a := fakeAuthenticator{identity: auth.Identity{Principal: principal, Method: auth.MethodSession}}
	h := RequireAuth(a, policy.NewEngine(), policy.ActionProjectCreate, nil)(next)

	rec := run(h, bearerReq("a-valid-session-token"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	// The message carries the stable policy reason code.
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedNoCapability)) {
		t.Errorf("message = %q, want it to name the stable deny reason", env.Error.Message)
	}
	if next.ran {
		t.Error("next handler ran for an unauthorized request")
	}
}

func TestRequireAuthResourceResolverEnforcesTenantBoundary(t *testing.T) {
	t.Parallel()
	next := &okHandler{}
	// The principal owns org_acme, but the route targets a resource in
	// org_other: the resolver makes that a cross-tenant 403, not a silent
	// allow against the principal's home organization.
	principal := policy.Principal{
		ID: "usr_ada", Kind: domain.KindUser, OrganizationID: "org_acme", Role: policy.RoleOwner,
	}
	a := fakeAuthenticator{identity: auth.Identity{Principal: principal, Method: auth.MethodSession}}
	resolver := func(*http.Request) policy.Resource {
		return policy.Resource{Kind: domain.KindProject, Scope: policy.Scope{OrganizationID: "org_other"}}
	}
	h := RequireAuth(a, policy.NewEngine(), policy.ActionProjectRead, resolver)(next)

	rec := run(h, bearerReq("a-valid-session-token"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("message = %q, want it to name the cross-tenant deny reason", env.Error.Message)
	}
	if next.ran {
		t.Error("next handler ran for a cross-tenant request")
	}
}

// TestRequireAuthAPIKeyPrincipal exercises the API-key credential path: an
// API-key principal carries no role, so the policy engine allows it only self
// actions and denies everything else — deny-by-default until scoped grants
// land.
func TestRequireAuthAPIKeyPrincipal(t *testing.T) {
	t.Parallel()
	principal := policy.Principal{
		ID: "sa_ci", Kind: domain.KindServiceAccount, OrganizationID: "org_acme",
	}
	a := fakeAuthenticator{identity: auth.Identity{Principal: principal, Method: auth.MethodAPIKey}}

	// A self action is allowed for any authenticated principal.
	selfNext := &okHandler{}
	selfH := RequireAuth(a, policy.NewEngine(), policy.ActionAuthMe, nil)(selfNext)
	if rec := run(selfH, bearerReq("yk_valid")); rec.Code != http.StatusOK {
		t.Fatalf("auth.me status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if !selfNext.ran {
		t.Error("next handler did not run for an allowed self action")
	}

	// A tenant action is denied: the role-less API-key principal has no
	// capability for it.
	tenantNext := &okHandler{}
	tenantH := RequireAuth(a, policy.NewEngine(), policy.ActionProjectCreate, nil)(tenantNext)
	if rec := run(tenantH, bearerReq("yk_valid")); rec.Code != http.StatusForbidden {
		t.Fatalf("project.create status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	if tenantNext.ran {
		t.Error("next handler ran for a denied tenant action")
	}
}

func TestRequireInternalWorker(t *testing.T) {
	t.Parallel()

	t.Run("admits the internal worker", func(t *testing.T) {
		t.Parallel()
		next := &okHandler{}
		identity := auth.Identity{
			Principal: policy.Principal{ID: auth.InternalWorkerPrincipalID},
			Method:    auth.MethodInternalWorker,
		}
		h := RequireInternalWorker(fakeAuthenticator{identity: identity})(next)

		rec := run(h, bearerReq("internal-worker-secret"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
		}
		if !next.ran {
			t.Fatal("next handler did not run for the internal worker")
		}
		if next.principal.ID != auth.InternalWorkerPrincipalID {
			t.Errorf("principal on context = %+v, want the internal worker principal", next.principal)
		}
	})

	t.Run("rejects a customer credential with 403", func(t *testing.T) {
		t.Parallel()
		next := &okHandler{}
		identity := auth.Identity{
			Principal: policy.Principal{ID: "usr_ada", OrganizationID: "org_acme", Role: policy.RoleOwner},
			Method:    auth.MethodSession,
		}
		h := RequireInternalWorker(fakeAuthenticator{identity: identity})(next)

		rec := run(h, bearerReq("a-valid-session-token"))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
		}
		decodeError(t, rec, "E_FORBIDDEN")
		if next.ran {
			t.Error("next handler ran for a non-worker credential")
		}
	})

	t.Run("rejects a missing credential with 401", func(t *testing.T) {
		t.Parallel()
		next := &okHandler{}
		h := RequireInternalWorker(fakeAuthenticator{})(next)

		rec := run(h, httptest.NewRequest(http.MethodGet, "/internal/jobs", nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
		}
		decodeError(t, rec, "E_AUTH")
		if next.ran {
			t.Error("next handler ran for a missing credential")
		}
	})
}

func TestBearerToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		header    string
		wantToken string
		wantErr   bool
	}{
		{"valid bearer", "Bearer yk_abc123", "yk_abc123", false},
		{"scheme is case-insensitive", "bEaReR yk_abc123", "yk_abc123", false},
		{"surrounding whitespace trimmed", "Bearer    yk_abc123  ", "yk_abc123", false},
		{"missing header", "", "", true},
		{"non-bearer scheme", "Basic dXNlcjpwYXNz", "", true},
		{"bearer with empty token", "Bearer    ", "", true},
		{"bare token without scheme", "yk_abc123", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			token, err := bearerToken(req)
			if tt.wantErr {
				if !stderrors.Is(err, auth.ErrNoCredentials) {
					t.Errorf("error = %v, want auth.ErrNoCredentials", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if token != tt.wantToken {
				t.Errorf("token = %q, want %q", token, tt.wantToken)
			}
		})
	}
}

// TestPublicRoutesNeedNoCredential confirms the anonymous path: the bootstrap
// public routes are served by NewHandler with no auth middleware at all, so a
// request with no Authorization header still succeeds. This is the "anonymous
// public endpoints" leg of the BE-0020 acceptance criteria.
func TestPublicRoutesNeedNoCredential(t *testing.T) {
	t.Parallel()
	handler := NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil)
	for _, path := range []string{"/healthz", "/version", "/openapi.json"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s without credentials: status = %d, want 200", path, rec.Code)
		}
	}
}
