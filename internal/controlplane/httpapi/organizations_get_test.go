package httpapi

import (
	"encoding/json"
	stderrors "errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
)

// Contract, authorization, and tenant-isolation coverage for GET
// /v1/organizations/{org_id} (BE-0052). The endpoint returns the single
// organization named by the {org_id} path parameter, read through the
// OrganizationReader port; the tests drive it through NewHandler with a fake
// Authenticator, the real policy engine, and a fake reader — the same wiring a
// request hits in production, minus the database. The store-backed reader has
// its own isolated-Postgres integration coverage in store/organization_test.go.
//
// This endpoint has no request body and no query parameters: its only input is
// the {org_id} path parameter, an opaque identifier. There is therefore no
// syntactic request to reject — a malformed or unknown id surfaces as the
// typed NotFound the reader produces, or, for an id outside the principal's
// tenant, as the deterministic 403 the policy engine returns through
// organizationIDResolver. Those two paths are the "validation" and
// "authorization" coverage for this story.

// getOrganizationSuccessEnvelope is the decoded shape of the GET
// /v1/organizations/{org_id} success envelope.
type getOrganizationSuccessEnvelope struct {
	SchemaVersion string                 `json:"schema_version"`
	OK            bool                   `json:"ok"`
	RequestID     string                 `json:"request_id"`
	Data          getOrganizationPayload `json:"data"`
}

// getOrganizationByID issues GET /v1/organizations/{orgID} against handler,
// optionally with a bearer token.
func getOrganizationByID(handler http.Handler, orgID, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v1/organizations/"+orgID, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeGetOrganization(t *testing.T, rec *httptest.ResponseRecorder) getOrganizationSuccessEnvelope {
	t.Helper()
	var env getOrganizationSuccessEnvelope
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

// TestGetOrganizationReturnsRequestedOrganization is the happy path: an
// authenticated principal requesting its own organization receives it in a
// stable yalla.output.v1 envelope, with every source-of-truth field projected
// onto the wire shape.
func TestGetOrganizationReturnsRequestedOrganization(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 6, 7, 8, 0, time.UTC)
	reader := fakeOrganizationReader{org: store.Organization{
		ID:          "org_acme",
		Slug:        "acme",
		DisplayName: "Acme, Inc.",
		CreatedAt:   created,
		UpdatedAt:   updated,
	}}
	handler := organizationsHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleViewer)}, nil, reader)

	rec := getOrganizationByID(handler, "org_acme", "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeGetOrganization(t, rec)
	got := env.Data.Organization
	want := organizationResource{
		OrganizationID: "org_acme",
		Slug:           "acme",
		DisplayName:    "Acme, Inc.",
		CreatedAt:      created.Format(time.RFC3339Nano),
		UpdatedAt:      updated.Format(time.RFC3339Nano),
	}
	if got != want {
		t.Errorf("organization = %+v, want %+v", got, want)
	}
}

// TestGetOrganizationScopesReadToPathParameter proves the handler reads exactly
// the organization named by the {org_id} path parameter — the path id is the
// sole input that selects the row.
func TestGetOrganizationScopesReadToPathParameter(t *testing.T) {
	t.Parallel()

	var gotID string
	reader := fakeOrganizationReader{
		org:   store.Organization{ID: "org_acme", Slug: "acme", DisplayName: "Acme"},
		gotID: &gotID,
	}
	handler := organizationsHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner)}, nil, reader)

	rec := getOrganizationByID(handler, "org_acme", "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if gotID != "org_acme" {
		t.Errorf("reader received organization id %q, want org_acme", gotID)
	}
}

// TestGetOrganizationCrossTenantIsForbidden proves a principal requesting an
// organization outside its own tenant is denied with a deterministic 403
// E_FORBIDDEN carrying the stable cross-tenant reason — and the reader is never
// reached, so a cross-tenant id can never reveal another tenant's data or even
// whether that organization exists.
func TestGetOrganizationCrossTenantIsForbidden(t *testing.T) {
	t.Parallel()

	var gotID string
	reader := fakeOrganizationReader{
		org:   store.Organization{ID: "org_victim", Slug: "victim", DisplayName: "Victim"},
		gotID: &gotID,
	}
	handler := organizationsHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_mallory", "org_attacker", policy.RoleOwner)}, nil, reader)

	rec := getOrganizationByID(handler, "org_victim", "a-valid-session-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedCrossTenant)
	}
	if gotID != "" {
		t.Errorf("reader was reached with id %q for a cross-tenant request; it must never run", gotID)
	}
	if strings.Contains(env.Error.Message, "org_victim") {
		t.Errorf("error message %q echoes the cross-tenant organization id", env.Error.Message)
	}
}

// TestGetOrganizationSupportReadsAnotherTenant proves the one deliberate
// cross-tenant exception: a support principal performing a read is allowed to
// retrieve an organization outside its home tenant, exactly as the policy
// matrix specifies.
func TestGetOrganizationSupportReadsAnotherTenant(t *testing.T) {
	t.Parallel()

	var gotID string
	reader := fakeOrganizationReader{
		org:   store.Organization{ID: "org_customer", Slug: "customer", DisplayName: "Customer"},
		gotID: &gotID,
	}
	handler := organizationsHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_support", "org_yalla", policy.RoleSupport)}, nil, reader)

	rec := getOrganizationByID(handler, "org_customer", "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeGetOrganization(t, rec)
	if env.Data.Organization.OrganizationID != "org_customer" {
		t.Errorf("organization id = %q, want org_customer", env.Data.Organization.OrganizationID)
	}
	if gotID != "org_customer" {
		t.Errorf("reader received id %q, want org_customer", gotID)
	}
}

// TestGetOrganizationNotFound proves an {org_id} the principal is authorized to
// read but that has no row in the source-of-truth database is the typed 404 the
// reader produces, never disguised as an empty success.
func TestGetOrganizationNotFound(t *testing.T) {
	t.Parallel()

	reader := fakeOrganizationReader{err: apierr.NotFound("organization", "org_acme")}
	handler := organizationsHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleViewer)}, nil, reader)

	rec := getOrganizationByID(handler, "org_acme", "a-valid-session-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_NOT_FOUND")
}

// TestGetOrganizationRequiresAuthentication proves a request with no credential
// is a stable 401 E_AUTH and never reaches the reader.
func TestGetOrganizationRequiresAuthentication(t *testing.T) {
	t.Parallel()

	handler := organizationsHandlerFor(auth.Identity{}, nil,
		fakeOrganizationReader{err: stderrors.New("reader must not be called")})

	rec := getOrganizationByID(handler, "org_acme", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_AUTH")
	if env.Error.Message != "authentication is required" {
		t.Errorf("message = %q, want %q", env.Error.Message, "authentication is required")
	}
}

// TestGetOrganizationInvalidCredentials proves an unverifiable credential is a
// stable 401 E_AUTH — identical to the missing-credential contract.
func TestGetOrganizationInvalidCredentials(t *testing.T) {
	t.Parallel()

	handler := organizationsHandlerFor(auth.Identity{}, auth.ErrInvalidCredentials,
		fakeOrganizationReader{err: stderrors.New("reader must not be called")})

	rec := getOrganizationByID(handler, "org_acme", "a-bogus-token")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_AUTH")
	if env.Error.Message != "the supplied credentials are invalid" {
		t.Errorf("message = %q, want %q", env.Error.Message, "the supplied credentials are invalid")
	}
}

// TestGetOrganizationDisabledPrincipal proves a revoked or expired credential
// surfaces as a disabled principal and is denied with a 403 E_FORBIDDEN
// carrying the stable reason — and the reader is never reached.
func TestGetOrganizationDisabledPrincipal(t *testing.T) {
	t.Parallel()

	disabled := orgPrincipal("usr_ada", "org_acme", policy.RoleOwner)
	disabled.Disabled = true
	handler := organizationsHandlerFor(auth.Identity{Principal: disabled}, nil,
		fakeOrganizationReader{err: stderrors.New("reader must not be called")})

	rec := getOrganizationByID(handler, "org_acme", "a-revoked-session-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
	}
}

// TestGetOrganizationReaderUnavailable proves a datastore outage surfaces as
// its own typed 5xx, never disguised as a not-found.
func TestGetOrganizationReaderUnavailable(t *testing.T) {
	t.Parallel()

	reader := fakeOrganizationReader{err: apierr.StoreUnavailable(stderrors.New("connection refused"))}
	handler := organizationsHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleViewer)}, nil, reader)

	rec := getOrganizationByID(handler, "org_acme", "a-valid-session-token")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_UNAVAILABLE")
	if strings.Contains(env.Error.Message, "connection refused") {
		t.Errorf("error message %q leaks the wrapped datastore cause", env.Error.Message)
	}
}

// TestGetOrganizationPropagatesRequestID proves the resolved request_id reaches
// both the response envelope and the echoed response header.
func TestGetOrganizationPropagatesRequestID(t *testing.T) {
	t.Parallel()

	reader := fakeOrganizationReader{org: store.Organization{ID: "org_acme", Slug: "acme", DisplayName: "Acme"}}
	handler := organizationsHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleViewer)}, nil, reader)

	req := httptest.NewRequest(http.MethodGet, "/v1/organizations/org_acme", nil)
	req.Header.Set("Authorization", "Bearer a-valid-session-token")
	req.Header.Set(telemetry.HeaderRequestID, "caller-supplied-id")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeGetOrganization(t, rec)
	if env.RequestID != "caller-supplied-id" {
		t.Errorf("envelope request_id = %q, want caller-supplied-id", env.RequestID)
	}
	if got := rec.Header().Get(telemetry.HeaderRequestID); got != "caller-supplied-id" {
		t.Errorf("response header request_id = %q, want caller-supplied-id", got)
	}
}

// TestGetOrganizationHandlerWithoutPrincipalIsInternal proves the defensive
// path: if the handler is ever reached without RequireAuth having placed a
// principal on the context, it reports a typed internal error rather than
// reading an organization for a zero principal.
func TestGetOrganizationHandlerWithoutPrincipalIsInternal(t *testing.T) {
	t.Parallel()

	rec := run(getOrganizationHandler(fakeOrganizationReader{}),
		httptest.NewRequest(http.MethodGet, "/v1/organizations/org_acme", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INTERNAL")
}

// TestGetOrganizationHandlerWithNilReaderIsInternal proves a route registered
// without an organization reader is a wiring error reported as a typed internal
// failure — never a misleading response.
func TestGetOrganizationHandlerWithNilReaderIsInternal(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/v1/organizations/org_acme", nil)
	req = req.WithContext(policy.WithPrincipal(req.Context(),
		orgPrincipal("usr_ada", "org_acme", policy.RoleViewer)))
	rec := run(getOrganizationHandler(nil), req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INTERNAL")
}

// TestGetOrganizationIsDocumentedInOpenAPI proves the served route is also a
// documented route: GET /v1/organizations/{org_id} appears in the OpenAPI
// document requiring the API-key security scheme, naming its policy action
// through the x-required-action extension, and declaring the {org_id} path
// parameter.
func TestGetOrganizationIsDocumentedInOpenAPI(t *testing.T) {
	t.Parallel()

	handler := organizationsHandlerFor(auth.Identity{}, nil, fakeOrganizationReader{})
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
			Parameters     []struct {
				Name     string `json:"name"`
				In       string `json:"in"`
				Required bool   `json:"required"`
			} `json:"parameters"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode openapi document: %v", err)
	}
	op, ok := doc.Paths["/v1/organizations/{org_id}"]["get"]
	if !ok {
		t.Fatalf("openapi document does not describe GET /v1/organizations/{org_id}")
	}
	if op.OperationID != "getOrganization" {
		t.Errorf("operationId = %q, want getOrganization", op.OperationID)
	}
	if op.RequiredAction != string(policy.ActionOrganizationRead) {
		t.Errorf("x-required-action = %q, want %q", op.RequiredAction, policy.ActionOrganizationRead)
	}
	if len(op.Security) != 1 || len(op.Security[0]) != 1 {
		t.Errorf("security = %+v, want it to require the ApiKeyAuth scheme", op.Security)
	}
	if len(op.Parameters) != 1 {
		t.Fatalf("parameters = %+v, want exactly one path parameter", op.Parameters)
	}
	p := op.Parameters[0]
	if p.Name != "org_id" || p.In != "path" || !p.Required {
		t.Errorf("path parameter = %+v, want {Name:org_id In:path Required:true}", p)
	}
}
