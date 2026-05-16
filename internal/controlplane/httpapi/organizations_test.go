package httpapi

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
)

// Contract, authorization, and tenant-isolation coverage for GET
// /v1/organizations (BE-0046). The endpoint lists the organizations visible to
// the authenticated principal, reading them through the OrganizationReader
// port; the tests drive it through NewHandler with a fake Authenticator, the
// real policy engine, and a fake reader — the same wiring a request hits in
// production, minus the database. The store-backed reader has its own
// isolated-Postgres integration coverage in store/organization_test.go.

// fakeOrganizationReader is a canned OrganizationReader for httpapi tests. The
// zero value returns a zero organization and no error, which is all the tests
// that never reach the handler (the public-surface and /v1/me suites) need;
// organization tests set org/err and read gotID back to prove the read is
// scoped to the principal's own home organization.
type fakeOrganizationReader struct {
	org   store.Organization
	err   error
	gotID *string
}

func (f fakeOrganizationReader) GetOrganization(_ context.Context, organizationID string) (store.Organization, error) {
	if f.gotID != nil {
		*f.gotID = organizationID
	}
	return f.org, f.err
}

// organizationsSuccessEnvelope is the decoded shape of the GET
// /v1/organizations success envelope.
type organizationsSuccessEnvelope struct {
	SchemaVersion string               `json:"schema_version"`
	OK            bool                 `json:"ok"`
	RequestID     string               `json:"request_id"`
	Data          organizationsPayload `json:"data"`
}

// organizationsHandlerFor builds the full NewHandler surface with an
// Authenticator that resolves every credential to id and the given
// OrganizationReader. It is the production request path: the /v1/organizations
// route is wrapped in RequireAuth for action organization.read.
func organizationsHandlerFor(id auth.Identity, authErr error, reader OrganizationReader) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(), reader, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{}, fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{}, fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{}, fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{}, fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
}

// getOrganizations issues GET /v1/organizations against handler, optionally
// with a bearer token.
func getOrganizations(handler http.Handler, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v1/organizations", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeOrganizations(t *testing.T, rec *httptest.ResponseRecorder) organizationsSuccessEnvelope {
	t.Helper()
	var env organizationsSuccessEnvelope
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

// orgPrincipal builds an authenticated user principal in org with role.
func orgPrincipal(id, org string, role policy.Role) policy.Principal {
	return policy.Principal{ID: id, Kind: domain.KindUser, OrganizationID: org, Role: role}
}

// TestOrganizationsReturnsVisibleOrganizations is the happy path: an
// authenticated principal receives its home organization in a stable
// yalla.output.v1 envelope, with every source-of-truth field projected onto
// the wire shape.
func TestOrganizationsReturnsVisibleOrganizations(t *testing.T) {
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
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleViewer), Method: auth.MethodSession},
		nil, reader)

	rec := getOrganizations(handler, "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q, want application/json", got)
	}

	env := decodeOrganizations(t, rec)
	if len(env.Data.Organizations) != 1 {
		t.Fatalf("organizations = %+v, want exactly the caller's home org", env.Data.Organizations)
	}
	got := env.Data.Organizations[0]
	if got.OrganizationID != "org_acme" || got.Slug != "acme" || got.DisplayName != "Acme, Inc." {
		t.Errorf("organization = %+v, want id/slug/name from the stored row", got)
	}
	if got.CreatedAt != created.Format(time.RFC3339Nano) {
		t.Errorf("created_at = %q, want %q", got.CreatedAt, created.Format(time.RFC3339Nano))
	}
	if got.UpdatedAt != updated.Format(time.RFC3339Nano) {
		t.Errorf("updated_at = %q, want %q", got.UpdatedAt, updated.Format(time.RFC3339Nano))
	}
}

// TestOrganizationsReadsOnlyTheCallersHomeOrganization proves the tenant
// boundary is structural: the handler reads exactly the principal's own
// OrganizationID and nothing the caller could influence, and the response never
// carries another tenant's identifiers.
func TestOrganizationsReadsOnlyTheCallersHomeOrganization(t *testing.T) {
	t.Parallel()

	var requested string
	reader := fakeOrganizationReader{
		org:   store.Organization{ID: "org_acme", Slug: "acme", DisplayName: "Acme"},
		gotID: &requested,
	}
	handler := organizationsHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, reader)

	rec := getOrganizations(handler, "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if requested != "org_acme" {
		t.Errorf("reader was asked for organization %q, want the principal's own home org org_acme", requested)
	}
	if body := rec.Body.String(); strings.Contains(body, "org_intruder") || strings.Contains(body, "org_victim") {
		t.Errorf("response %s carries an organization id the principal does not own", body)
	}
}

// TestOrganizationsUnauthenticated proves a request with no credential is a
// stable 401 E_AUTH and never reaches the handler — the reader is never called.
func TestOrganizationsUnauthenticated(t *testing.T) {
	t.Parallel()

	handler := organizationsHandlerFor(auth.Identity{}, nil, fakeOrganizationReader{err: stderrors.New("reader must not be called")})
	rec := getOrganizations(handler, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_AUTH")
	if env.Error.Message != "authentication is required" {
		t.Errorf("message = %q, want %q", env.Error.Message, "authentication is required")
	}
}

// TestOrganizationsInvalidCredentials proves an unverifiable credential is a
// stable 401 E_AUTH — identical to the missing-credential contract.
func TestOrganizationsInvalidCredentials(t *testing.T) {
	t.Parallel()

	handler := organizationsHandlerFor(auth.Identity{}, auth.ErrInvalidCredentials, fakeOrganizationReader{})
	rec := getOrganizations(handler, "yk_bogus")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_AUTH")
}

// TestOrganizationsDisabledPrincipalIsForbidden is the authorization-failure
// path: a principal whose access has been revoked authenticates but is denied
// action organization.read, so the endpoint is 403 E_FORBIDDEN and the reader
// is never reached.
func TestOrganizationsDisabledPrincipalIsForbidden(t *testing.T) {
	t.Parallel()

	principal := orgPrincipal("usr_revoked", "org_acme", policy.RoleOwner)
	principal.Disabled = true
	handler := organizationsHandlerFor(
		auth.Identity{Principal: principal, Method: auth.MethodSession},
		nil, fakeOrganizationReader{err: stderrors.New("reader must not be called")})

	rec := getOrganizations(handler, "a-revoked-session-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
	}
}

// TestOrganizationsHomeOrganizationNotFound proves a home organization with no
// row in the source-of-truth database is the typed 404 the reader produces,
// never disguised as an empty success.
func TestOrganizationsHomeOrganizationNotFound(t *testing.T) {
	t.Parallel()

	reader := fakeOrganizationReader{err: apierr.NotFound("organization", "org_acme")}
	handler := organizationsHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleViewer), Method: auth.MethodSession},
		nil, reader)

	rec := getOrganizations(handler, "a-valid-session-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_NOT_FOUND")
}

// TestOrganizationsDependencyFailureIsTyped5xx proves a reader-store outage
// surfaces as its own typed 5xx, never disguised as a not-found or an empty
// success.
func TestOrganizationsDependencyFailureIsTyped5xx(t *testing.T) {
	t.Parallel()

	reader := fakeOrganizationReader{err: apierr.StoreUnavailable(stderrors.New("connection refused"))}
	handler := organizationsHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleViewer), Method: auth.MethodSession},
		nil, reader)

	rec := getOrganizations(handler, "a-valid-session-token")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_UNAVAILABLE")
}

// TestOrganizationsPropagatesRequestID proves the resolved request_id reaches
// both the response envelope and the echoed response header.
func TestOrganizationsPropagatesRequestID(t *testing.T) {
	t.Parallel()

	reader := fakeOrganizationReader{org: store.Organization{ID: "org_acme", Slug: "acme", DisplayName: "Acme"}}
	handler := organizationsHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleViewer), Method: auth.MethodSession},
		nil, reader)

	req := httptest.NewRequest(http.MethodGet, "/v1/organizations", nil)
	req.Header.Set("Authorization", "Bearer a-valid-session-token")
	req.Header.Set(telemetry.HeaderRequestID, "caller-supplied-id")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeOrganizations(t, rec)
	if env.RequestID != "caller-supplied-id" {
		t.Errorf("envelope request_id = %q, want caller-supplied-id", env.RequestID)
	}
	if got := rec.Header().Get(telemetry.HeaderRequestID); got != "caller-supplied-id" {
		t.Errorf("response header request_id = %q, want caller-supplied-id", got)
	}
}

// TestOrganizationsIsDocumentedInOpenAPI proves the served route is also a
// documented route: GET /v1/organizations appears in the OpenAPI document
// requiring the API-key security scheme and naming its policy action through
// the x-required-action extension.
func TestOrganizationsIsDocumentedInOpenAPI(t *testing.T) {
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
		} `json:"paths"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode openapi document: %v", err)
	}
	op, ok := doc.Paths["/v1/organizations"]["get"]
	if !ok {
		t.Fatalf("openapi document does not describe GET /v1/organizations")
	}
	if op.OperationID != "listOrganizations" {
		t.Errorf("operationId = %q, want listOrganizations", op.OperationID)
	}
	if op.RequiredAction != string(policy.ActionOrganizationRead) {
		t.Errorf("x-required-action = %q, want %q", op.RequiredAction, policy.ActionOrganizationRead)
	}
	if len(op.Security) != 1 {
		t.Fatalf("security = %+v, want exactly one requirement", op.Security)
	}
	if _, ok := op.Security[0]["ApiKeyAuth"]; !ok {
		t.Errorf("security = %+v, want it to require the ApiKeyAuth scheme", op.Security)
	}
}

// TestOrganizationsHandlerWithoutPrincipalIsInternal proves the defensive path:
// if the handler is ever reached without RequireAuth having placed a principal
// on the context, it reports a typed internal error rather than reading an
// organization for a zero principal.
func TestOrganizationsHandlerWithoutPrincipalIsInternal(t *testing.T) {
	t.Parallel()

	rec := run(organizationsHandler(fakeOrganizationReader{}), httptest.NewRequest(http.MethodGet, "/v1/organizations", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INTERNAL")
}

// TestOrganizationsHandlerWithNilReaderIsInternal proves a route registered
// without an organization reader is a wiring error reported as a typed internal
// failure — never a misleading empty list.
func TestOrganizationsHandlerWithNilReaderIsInternal(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/v1/organizations", nil)
	req = req.WithContext(policy.WithPrincipal(req.Context(),
		orgPrincipal("usr_ada", "org_acme", policy.RoleViewer)))
	rec := run(organizationsHandler(nil), req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INTERNAL")
}

// TestOrganizationResourceMapping is a focused unit test of the
// store.Organization->wire projection: identifiers pass through and timestamps
// are rendered as UTC RFC 3339 strings.
func TestOrganizationResourceMapping(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 6, 7, 8, 123456789, time.FixedZone("EST", -5*3600))
	got := organizationResourceOf(store.Organization{
		ID:          "org_acme",
		Slug:        "acme",
		DisplayName: "Acme, Inc.",
		CreatedAt:   created,
		UpdatedAt:   updated,
	})
	want := organizationResource{
		OrganizationID: "org_acme",
		Slug:           "acme",
		DisplayName:    "Acme, Inc.",
		CreatedAt:      created.Format(time.RFC3339Nano),
		UpdatedAt:      updated.UTC().Format(time.RFC3339Nano),
	}
	if got != want {
		t.Errorf("organizationResourceOf = %+v, want %+v", got, want)
	}
	if strings.HasSuffix(got.UpdatedAt, "-05:00") {
		t.Errorf("updated_at = %q, want a UTC timestamp regardless of the stored zone", got.UpdatedAt)
	}
}
