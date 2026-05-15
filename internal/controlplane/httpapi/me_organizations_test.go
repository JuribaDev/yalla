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
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
)

// Contract, authorization, and tenant-isolation coverage for
// GET /v1/me/organizations (BE-0043). The endpoint lists the organizations the
// authenticated principal can see; it touches no database, so the tests drive
// it through NewHandler with a fake Authenticator and the real policy engine —
// the same wiring a request hits in production, minus the credential store.

// meOrganizationsSuccessEnvelope is the decoded shape of the
// GET /v1/me/organizations success envelope.
type meOrganizationsSuccessEnvelope struct {
	SchemaVersion string                 `json:"schema_version"`
	OK            bool                   `json:"ok"`
	RequestID     string                 `json:"request_id"`
	Data          meOrganizationsPayload `json:"data"`
}

// getMeOrganizations issues GET /v1/me/organizations against handler,
// optionally with a bearer token.
func getMeOrganizations(handler http.Handler, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v1/me/organizations", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeMeOrganizations(t *testing.T, rec *httptest.ResponseRecorder) meOrganizationsSuccessEnvelope {
	t.Helper()
	var env meOrganizationsSuccessEnvelope
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

// TestMeOrganizationsReturnsHomeOrganization is the happy path: an
// authenticated principal with an organization role and a scoped grant receives
// its home organization — and only that organization — in a stable
// yalla.output.v1 envelope, with its role and grant echoed verbatim.
func TestMeOrganizationsReturnsHomeOrganization(t *testing.T) {
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

	rec := getMeOrganizations(handler, "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q, want application/json", got)
	}

	env := decodeMeOrganizations(t, rec)
	if len(env.Data.Organizations) != 1 {
		t.Fatalf("organizations = %+v, want exactly the principal's home org", env.Data.Organizations)
	}
	org := env.Data.Organizations[0]
	if org.OrganizationID != "org_acme" {
		t.Errorf("organization_id = %q, want org_acme", org.OrganizationID)
	}
	if org.Role != string(policy.RoleOwner) {
		t.Errorf("role = %q, want owner", org.Role)
	}
	if len(org.Grants) != 1 {
		t.Fatalf("grants = %+v, want exactly one", org.Grants)
	}
	g := org.Grants[0]
	if g.Role != string(policy.RoleDeveloper) || g.OrganizationID != "org_acme" || g.ProjectID != "proj_web" {
		t.Errorf("grant = %+v, want developer @ org_acme/proj_web", g)
	}
	if g.EnvironmentID != "" || g.ServiceID != "" {
		t.Errorf("grant carries deeper scope ids %+v, want them omitted", g)
	}
}

// TestMeOrganizationsServiceAccountAndEmptyGrants proves a role-less
// service-account principal is reported with its home org, no role, and a
// grants field that is always an empty array on the wire, never null.
func TestMeOrganizationsServiceAccountAndEmptyGrants(t *testing.T) {
	t.Parallel()

	principal := policy.Principal{
		ID:             "sa_ci",
		Kind:           domain.KindServiceAccount,
		OrganizationID: "org_acme",
	}
	handler := meHandlerFor(auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil)

	rec := getMeOrganizations(handler, "yk_valid")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"grants":[]`) {
		t.Errorf("body %s does not render grants as [], want a non-null empty array", rec.Body.String())
	}

	env := decodeMeOrganizations(t, rec)
	if len(env.Data.Organizations) != 1 {
		t.Fatalf("organizations = %+v, want exactly one", env.Data.Organizations)
	}
	org := env.Data.Organizations[0]
	if org.Role != "" {
		t.Errorf("role = %q, want empty for a role-less service account", org.Role)
	}
	if org.Grants == nil {
		t.Errorf("grants decoded as nil, want a non-nil empty slice")
	}
}

// TestMeOrganizationsUnauthenticated proves a request with no credential is a
// stable 401 E_AUTH and never reaches the handler.
func TestMeOrganizationsUnauthenticated(t *testing.T) {
	t.Parallel()

	handler := meHandlerFor(auth.Identity{}, nil)
	rec := getMeOrganizations(handler, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_AUTH")
	if env.Error.Message != "authentication is required" {
		t.Errorf("message = %q, want %q", env.Error.Message, "authentication is required")
	}
}

// TestMeOrganizationsInvalidCredentials proves an unverifiable credential is a
// stable 401 E_AUTH — identical to the missing-credential contract, so the
// response never reveals whether the credential was recognised.
func TestMeOrganizationsInvalidCredentials(t *testing.T) {
	t.Parallel()

	handler := meHandlerFor(auth.Identity{}, auth.ErrInvalidCredentials)
	rec := getMeOrganizations(handler, "yk_bogus")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_AUTH")
}

// TestMeOrganizationsDisabledPrincipalIsForbidden is the authorization-failure
// path: a principal whose access has been revoked authenticates but is denied
// action auth.orgs, so the endpoint is 403 E_FORBIDDEN and never lists an
// organization.
func TestMeOrganizationsDisabledPrincipalIsForbidden(t *testing.T) {
	t.Parallel()

	principal := policy.Principal{
		ID:             "usr_revoked",
		Kind:           domain.KindUser,
		OrganizationID: "org_acme",
		Role:           policy.RoleOwner,
		Disabled:       true,
	}
	handler := meHandlerFor(auth.Identity{Principal: principal, Method: auth.MethodSession}, nil)

	rec := getMeOrganizations(handler, "a-revoked-session-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
	}
	if strings.Contains(rec.Body.String(), "org_acme") {
		t.Errorf("error body %s leaked the principal's organization id", rec.Body.String())
	}
}

// TestMeOrganizationsDependencyFailureIsNot401 proves a credential-store outage
// surfaces as its own typed 5xx, never disguised as an authentication denial.
func TestMeOrganizationsDependencyFailureIsNot401(t *testing.T) {
	t.Parallel()

	handler := meHandlerFor(auth.Identity{}, apierr.StoreUnavailable(stderrors.New("connection refused")))
	rec := getMeOrganizations(handler, "yk_valid")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_UNAVAILABLE")
}

// TestMeOrganizationsPropagatesRequestID proves the resolved request_id reaches
// both the response envelope and the echoed response header.
func TestMeOrganizationsPropagatesRequestID(t *testing.T) {
	t.Parallel()

	principal := policy.Principal{
		ID: "usr_ada", Kind: domain.KindUser, OrganizationID: "org_acme", Role: policy.RoleViewer,
	}
	handler := meHandlerFor(auth.Identity{Principal: principal, Method: auth.MethodSession}, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/me/organizations", nil)
	req.Header.Set("Authorization", "Bearer a-valid-session-token")
	req.Header.Set(telemetry.HeaderRequestID, "caller-supplied-id")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeMeOrganizations(t, rec)
	if env.RequestID != "caller-supplied-id" {
		t.Errorf("envelope request_id = %q, want caller-supplied-id", env.RequestID)
	}
	if got := rec.Header().Get(telemetry.HeaderRequestID); got != "caller-supplied-id" {
		t.Errorf("response header request_id = %q, want caller-supplied-id", got)
	}
}

// TestMeOrganizationsIsTenantIsolated proves the endpoint reports the caller's
// own organization and nothing else: a principal in org_intruder never sees
// another tenant's identifiers, and a grant that somehow references a foreign
// organization is dropped rather than surfaced as a visible tenant.
func TestMeOrganizationsIsTenantIsolated(t *testing.T) {
	t.Parallel()

	const (
		ownOrg    = "org_intruder"
		victimOrg = "org_victim"
	)

	principal := policy.Principal{
		ID:             "usr_intruder",
		Kind:           domain.KindUser,
		OrganizationID: ownOrg,
		Role:           policy.RoleOwner,
		Grants: []policy.Grant{
			{Role: policy.RoleDeveloper, Scope: policy.Scope{OrganizationID: ownOrg, ProjectID: "proj_own"}},
			// A defensively-included grant that points at another tenant. The
			// payload builder must confine grants to the home organization, so
			// this must never appear in the response.
			{Role: policy.RoleOwner, Scope: policy.Scope{OrganizationID: victimOrg, ProjectID: "proj_victim"}},
		},
	}
	handler := meHandlerFor(auth.Identity{Principal: principal, Method: auth.MethodSession}, nil)

	rec := getMeOrganizations(handler, "a-valid-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeMeOrganizations(t, rec)
	if len(env.Data.Organizations) != 1 {
		t.Fatalf("organizations = %+v, want exactly the caller's own org", env.Data.Organizations)
	}
	if env.Data.Organizations[0].OrganizationID != ownOrg {
		t.Errorf("organization_id = %q, want the caller's own org %q",
			env.Data.Organizations[0].OrganizationID, ownOrg)
	}
	if len(env.Data.Organizations[0].Grants) != 1 {
		t.Fatalf("grants = %+v, want only the home-org grant", env.Data.Organizations[0].Grants)
	}
	if body := rec.Body.String(); strings.Contains(body, victimOrg) || strings.Contains(body, "proj_victim") {
		t.Errorf("response %s leaked another tenant's identifiers", body)
	}
}

// TestMeOrganizationsIsDocumentedInOpenAPI proves the served route is also a
// documented route: GET /v1/me/organizations appears in the OpenAPI document
// requiring the API-key security scheme and naming its policy action through
// the x-required-action extension, so agents can discover the authorization
// contract.
func TestMeOrganizationsIsDocumentedInOpenAPI(t *testing.T) {
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
	op, ok := doc.Paths["/v1/me/organizations"]["get"]
	if !ok {
		t.Fatalf("openapi document does not describe GET /v1/me/organizations")
	}
	if op.OperationID != "getMeOrganizations" {
		t.Errorf("operationId = %q, want getMeOrganizations", op.OperationID)
	}
	if op.RequiredAction != string(policy.ActionAuthOrgs) {
		t.Errorf("x-required-action = %q, want %q", op.RequiredAction, policy.ActionAuthOrgs)
	}
	if len(op.Security) != 1 {
		t.Fatalf("security = %+v, want exactly one requirement", op.Security)
	}
	if _, ok := op.Security[0]["ApiKeyAuth"]; !ok {
		t.Errorf("security = %+v, want it to require the ApiKeyAuth scheme", op.Security)
	}
}

// TestMeOrganizationsHandlerWithoutPrincipalIsInternal proves the defensive
// path: if the handler is ever reached without RequireAuth having placed a
// principal on the context, it reports a typed internal error rather than
// serving an empty organization list built from a zero principal.
func TestMeOrganizationsHandlerWithoutPrincipalIsInternal(t *testing.T) {
	t.Parallel()

	rec := run(meOrganizationsHandler(), httptest.NewRequest(http.MethodGet, "/v1/me/organizations", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INTERNAL")
}

// TestPrincipalOrganizationsPayloadMapping is a focused unit test of the
// principal->wire projection: the home organization is emitted with the
// principal's role, grants confined to the home org are flattened, foreign
// grants are dropped, and an empty grant list yields a non-nil slice. A
// principal with no home organization yields an empty (non-nil) list.
func TestPrincipalOrganizationsPayloadMapping(t *testing.T) {
	t.Parallel()

	got := principalOrganizationsPayload(policy.Principal{
		ID:             "usr_ada",
		Kind:           domain.KindUser,
		OrganizationID: "org_acme",
		Role:           policy.RoleAdmin,
		Grants: []policy.Grant{
			{
				Role: policy.RoleDeveloper,
				Scope: policy.Scope{
					OrganizationID: "org_acme",
					ProjectID:      "proj_web",
					EnvironmentID:  "env_prod",
					ServiceID:      "svc_api",
				},
			},
			{Role: policy.RoleOwner, Scope: policy.Scope{OrganizationID: "org_other", ProjectID: "proj_x"}},
		},
	})
	if len(got.Organizations) != 1 {
		t.Fatalf("organizations = %+v, want exactly the home org", got.Organizations)
	}
	org := got.Organizations[0]
	if org.OrganizationID != "org_acme" || org.Role != "admin" {
		t.Errorf("org identity = %+v, want org_acme/admin", org)
	}
	if len(org.Grants) != 1 {
		t.Fatalf("grants = %+v, want only the home-org grant (the foreign grant dropped)", org.Grants)
	}
	want := meGrant{
		Role: "developer", OrganizationID: "org_acme",
		ProjectID: "proj_web", EnvironmentID: "env_prod", ServiceID: "svc_api",
	}
	if org.Grants[0] != want {
		t.Errorf("grant = %+v, want %+v", org.Grants[0], want)
	}

	empty := principalOrganizationsPayload(policy.Principal{ID: "usr_x", Kind: domain.KindUser, OrganizationID: "org_x"})
	if empty.Organizations[0].Grants == nil {
		t.Errorf("grants = nil, want a non-nil empty slice")
	}

	noOrg := principalOrganizationsPayload(policy.Principal{ID: "usr_y", Kind: domain.KindUser})
	if noOrg.Organizations == nil {
		t.Errorf("organizations = nil, want a non-nil empty slice")
	}
	if len(noOrg.Organizations) != 0 {
		t.Errorf("organizations = %+v, want empty for a principal with no home org", noOrg.Organizations)
	}
}
