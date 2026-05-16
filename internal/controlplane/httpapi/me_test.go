package httpapi

import (
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

// Contract, authorization, and tenant-isolation coverage for GET /v1/me
// (BE-0040). The endpoint reports the authenticated principal's own identity;
// it touches no database, so the tests drive it through NewHandler with a fake
// Authenticator and the real policy engine — the same wiring a request hits in
// production, minus the credential store.

// meSuccessEnvelope is the decoded shape of the GET /v1/me success envelope.
type meSuccessEnvelope struct {
	SchemaVersion string    `json:"schema_version"`
	OK            bool      `json:"ok"`
	RequestID     string    `json:"request_id"`
	Data          mePayload `json:"data"`
}

// meHandlerFor builds the full NewHandler surface with an Authenticator that
// resolves every credential to id. It is the production request path: the
// /v1/me route is wrapped in RequireAuth for action auth.me.
func meHandlerFor(id auth.Identity, authErr error) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(), fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{}, fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{}, fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{}, fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{}, fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeBreakGlassController{}, nil, nil)
}

// getMe issues GET /v1/me against handler, optionally with a bearer token.
func getMe(handler http.Handler, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeMe(t *testing.T, rec *httptest.ResponseRecorder) meSuccessEnvelope {
	t.Helper()
	var env meSuccessEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode success envelope: %v; body %s", err, rec.Body.String())
	}
	if env.SchemaVersion != "yalla.output.v1" {
		t.Errorf("schema_version = %q, want yalla.output.v1", env.SchemaVersion)
	}
	if !env.OK {
		t.Errorf("ok = false, want true")
	}
	if env.RequestID == "" {
		t.Errorf("request_id is empty, want a generated id")
	}
	return env
}

// TestMeReturnsPrincipalIdentity is the happy path: an authenticated principal
// with an organization role and a scoped grant receives its own identity in a
// stable yalla.output.v1 envelope.
func TestMeReturnsPrincipalIdentity(t *testing.T) {
	t.Parallel()

	principal := policy.Principal{
		ID:             "usr_ada",
		Kind:           domain.KindUser,
		OrganizationID: "org_acme",
		Role:           policy.RoleOwner,
		Grants: []policy.Grant{{
			Role: policy.RoleDeveloper,
			Scope: policy.Scope{
				OrganizationID: "org_acme",
				ProjectID:      "proj_web",
			},
		}},
	}
	handler := meHandlerFor(auth.Identity{Principal: principal, Method: auth.MethodSession}, nil)

	rec := getMe(handler, "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q, want application/json", got)
	}

	env := decodeMe(t, rec)
	if env.Data.PrincipalID != "usr_ada" {
		t.Errorf("principal_id = %q, want usr_ada", env.Data.PrincipalID)
	}
	if env.Data.Kind != string(domain.KindUser) {
		t.Errorf("kind = %q, want %q", env.Data.Kind, domain.KindUser)
	}
	if env.Data.OrganizationID != "org_acme" {
		t.Errorf("organization_id = %q, want org_acme", env.Data.OrganizationID)
	}
	if env.Data.Role != string(policy.RoleOwner) {
		t.Errorf("role = %q, want owner", env.Data.Role)
	}
	if env.Data.Disabled {
		t.Errorf("disabled = true, want false")
	}
	if len(env.Data.Grants) != 1 {
		t.Fatalf("grants = %+v, want exactly one", env.Data.Grants)
	}
	g := env.Data.Grants[0]
	if g.Role != string(policy.RoleDeveloper) || g.OrganizationID != "org_acme" || g.ProjectID != "proj_web" {
		t.Errorf("grant = %+v, want developer @ org_acme/proj_web", g)
	}
	if g.EnvironmentID != "" || g.ServiceID != "" {
		t.Errorf("grant carries deeper scope ids %+v, want them omitted", g)
	}
}

// TestMeServiceAccountPrincipalAndEmptyGrants proves a role-less service-account
// principal is reported with kind "sa" and that the grants field is always an
// empty array on the wire, never null.
func TestMeServiceAccountPrincipalAndEmptyGrants(t *testing.T) {
	t.Parallel()

	principal := policy.Principal{
		ID:             "sa_ci",
		Kind:           domain.KindServiceAccount,
		OrganizationID: "org_acme",
	}
	handler := meHandlerFor(auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil)

	rec := getMe(handler, "yk_valid")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"grants":[]`) {
		t.Errorf("body %s does not render grants as [], want a non-null empty array", rec.Body.String())
	}

	env := decodeMe(t, rec)
	if env.Data.Kind != string(domain.KindServiceAccount) {
		t.Errorf("kind = %q, want %q", env.Data.Kind, domain.KindServiceAccount)
	}
	if env.Data.Role != "" {
		t.Errorf("role = %q, want empty for a role-less service account", env.Data.Role)
	}
	if env.Data.Grants == nil {
		t.Errorf("grants decoded as nil, want a non-nil empty slice")
	}
}

// TestMeUnauthenticated proves a request with no credential is a stable
// 401 E_AUTH and never reaches the handler.
func TestMeUnauthenticated(t *testing.T) {
	t.Parallel()

	handler := meHandlerFor(auth.Identity{}, nil)
	rec := getMe(handler, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_AUTH")
	if env.Error.Message != "authentication is required" {
		t.Errorf("message = %q, want %q", env.Error.Message, "authentication is required")
	}
}

// TestMeInvalidCredentials proves an unverifiable credential is a stable
// 401 E_AUTH — identical to the missing-credential contract, so the response
// never reveals whether the credential was recognised.
func TestMeInvalidCredentials(t *testing.T) {
	t.Parallel()

	handler := meHandlerFor(auth.Identity{}, auth.ErrInvalidCredentials)
	rec := getMe(handler, "yk_bogus")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_AUTH")
}

// TestMeDisabledPrincipalIsForbidden is the authorization-failure path: a
// principal whose access has been revoked authenticates but is denied action
// auth.me, so the endpoint is 403 E_FORBIDDEN and never serves an identity.
func TestMeDisabledPrincipalIsForbidden(t *testing.T) {
	t.Parallel()

	principal := policy.Principal{
		ID:             "usr_revoked",
		Kind:           domain.KindUser,
		OrganizationID: "org_acme",
		Role:           policy.RoleOwner,
		Disabled:       true,
	}
	handler := meHandlerFor(auth.Identity{Principal: principal, Method: auth.MethodSession}, nil)

	rec := getMe(handler, "a-revoked-session-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
	}
}

// TestMeDependencyFailureIsNot401 proves a credential-store outage surfaces as
// its own typed 5xx, never disguised as an authentication denial.
func TestMeDependencyFailureIsNot401(t *testing.T) {
	t.Parallel()

	handler := meHandlerFor(auth.Identity{}, apierr.StoreUnavailable(stderrors.New("connection refused")))
	rec := getMe(handler, "yk_valid")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_UNAVAILABLE")
}

// TestMePropagatesRequestID proves the resolved request_id reaches both the
// response envelope and the echoed response header.
func TestMePropagatesRequestID(t *testing.T) {
	t.Parallel()

	principal := policy.Principal{
		ID: "usr_ada", Kind: domain.KindUser, OrganizationID: "org_acme", Role: policy.RoleViewer,
	}
	handler := meHandlerFor(auth.Identity{Principal: principal, Method: auth.MethodSession}, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	req.Header.Set("Authorization", "Bearer a-valid-session-token")
	req.Header.Set(telemetry.HeaderRequestID, "caller-supplied-id")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeMe(t, rec)
	if env.RequestID != "caller-supplied-id" {
		t.Errorf("envelope request_id = %q, want caller-supplied-id", env.RequestID)
	}
	if got := rec.Header().Get(telemetry.HeaderRequestID); got != "caller-supplied-id" {
		t.Errorf("response header request_id = %q, want caller-supplied-id", got)
	}
}

// TestMeIsDocumentedInOpenAPI proves the served route is also a documented
// route: GET /v1/me appears in the OpenAPI document requiring the API-key
// security scheme and naming its policy action through the x-required-action
// extension, so agents can discover the authorization contract.
func TestMeIsDocumentedInOpenAPI(t *testing.T) {
	t.Parallel()

	handler := meHandlerFor(auth.Identity{}, nil)
	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}

	var doc struct {
		Paths map[string]map[string]struct {
			OperationID    string                `json:"operationId"`
			Security       []map[string][]string `json:"security"`
			RequiredAction string                `json:"x-required-action"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode openapi document: %v", err)
	}
	op, ok := doc.Paths["/v1/me"]["get"]
	if !ok {
		t.Fatalf("openapi document does not describe GET /v1/me")
	}
	if op.OperationID != "getMe" {
		t.Errorf("operationId = %q, want getMe", op.OperationID)
	}
	if op.RequiredAction != string(policy.ActionAuthMe) {
		t.Errorf("x-required-action = %q, want %q", op.RequiredAction, policy.ActionAuthMe)
	}
	if len(op.Security) != 1 {
		t.Fatalf("security = %+v, want exactly one requirement", op.Security)
	}
	if _, ok := op.Security[0]["ApiKeyAuth"]; !ok {
		t.Errorf("security = %+v, want it to require the ApiKeyAuth scheme", op.Security)
	}
}

// TestMeHandlerWithoutPrincipalIsInternal proves the defensive path: if the
// handler is ever reached without RequireAuth having placed a principal on the
// context, it reports a typed internal error rather than serving an identity
// built from a zero principal.
func TestMeHandlerWithoutPrincipalIsInternal(t *testing.T) {
	t.Parallel()

	rec := run(meHandler(), httptest.NewRequest(http.MethodGet, "/v1/me", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INTERNAL")
}

// TestPrincipalPayloadMapping is a focused unit test of the principal->wire
// projection: kinds and roles are stringified, grant scopes are flattened, and
// an empty grant list yields a non-nil slice.
func TestPrincipalPayloadMapping(t *testing.T) {
	t.Parallel()

	got := principalPayload(policy.Principal{
		ID:             "usr_ada",
		Kind:           domain.KindUser,
		OrganizationID: "org_acme",
		Role:           policy.RoleAdmin,
		Grants: []policy.Grant{{
			Role: policy.RoleDeveloper,
			Scope: policy.Scope{
				OrganizationID: "org_acme",
				ProjectID:      "proj_web",
				EnvironmentID:  "env_prod",
				ServiceID:      "svc_api",
			},
		}},
	})
	if got.PrincipalID != "usr_ada" || got.Kind != "usr" || got.OrganizationID != "org_acme" {
		t.Errorf("identity fields = %+v, want usr_ada/usr/org_acme", got)
	}
	if got.Role != "admin" {
		t.Errorf("role = %q, want admin", got.Role)
	}
	if len(got.Grants) != 1 {
		t.Fatalf("grants = %+v, want one", got.Grants)
	}
	want := meGrant{
		Role: "developer", OrganizationID: "org_acme",
		ProjectID: "proj_web", EnvironmentID: "env_prod", ServiceID: "svc_api",
	}
	if got.Grants[0] != want {
		t.Errorf("grant = %+v, want %+v", got.Grants[0], want)
	}

	empty := principalPayload(policy.Principal{ID: "usr_x", Kind: domain.KindUser})
	if empty.Grants == nil {
		t.Errorf("grants = nil, want a non-nil empty slice")
	}
}
