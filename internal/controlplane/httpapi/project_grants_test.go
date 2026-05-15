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
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// Contract, authorization, and tenant-isolation coverage for GET
// /v1/projects/{project_id}/grants (BE-0136). The endpoint lists the
// scoped grants attached to the project named by the {project_id} path
// parameter — by reading them through the ProjectGrantReader port. The
// tests drive it through NewHandler with a fake Authenticator, the real
// policy engine, and a fake reader — the same wiring a request hits in
// production, minus the database. The store-backed reader has its own
// isolated-Postgres integration coverage in store/project_grant_test.go.
//
// This endpoint has a single {project_id} path parameter, no request
// body, and no query parameters. The store-backed reader treats a
// cross-tenant or unknown project_id as a deterministic 404; the
// policy-matrix coverage (a later story) drives the engine-level
// resource resolution.

// fakeProjectGrantReader is a canned ProjectGrantReader for httpapi
// tests. The zero value returns an empty slice and no error from
// ListProjectGrants, which is all the tests that never reach the handler
// (the public-surface, /v1/me, and other-route suites) need. Tests that
// drive this endpoint set grants/err and read gotOrgID + gotProjectID
// back to prove the (org, project) pair forwarded to the store is the
// principal's home org plus the path project_id — never a
// caller-controlled organization id.
type fakeProjectGrantReader struct {
	grants       []store.ProjectGrant
	err          error
	gotOrgID     *string
	gotProjectID *string
	callCount    *int
}

func (f fakeProjectGrantReader) ListProjectGrants(_ context.Context, organizationID, projectID string) ([]store.ProjectGrant, error) {
	if f.gotOrgID != nil {
		*f.gotOrgID = organizationID
	}
	if f.gotProjectID != nil {
		*f.gotProjectID = projectID
	}
	if f.callCount != nil {
		*f.callCount++
	}
	return f.grants, f.err
}

// listProjectGrantsSuccessEnvelope is the decoded shape of the GET
// /v1/projects/{project_id}/grants success envelope.
type listProjectGrantsSuccessEnvelope struct {
	SchemaVersion string                   `json:"schema_version"`
	OK            bool                     `json:"ok"`
	RequestID     string                   `json:"request_id"`
	Data          listProjectGrantsPayload `json:"data"`
}

// listProjectGrantsHandlerFor builds the full NewHandler surface with an
// Authenticator that resolves every credential to id and the given
// ProjectGrantReader. It is the production request path: the
// /v1/projects/{project_id}/grants route is wrapped in RequireAuth for
// action project.grants.read.
func listProjectGrantsHandlerFor(id auth.Identity, authErr error, reader ProjectGrantReader) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		reader, nil)
}

// getProjectGrants issues GET /v1/projects/{project_id}/grants against
// handler, optionally with a bearer token.
func getProjectGrants(handler http.Handler, projectID, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v1/projects/"+projectID+"/grants", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeListProjectGrants(t *testing.T, rec *httptest.ResponseRecorder) listProjectGrantsSuccessEnvelope {
	t.Helper()
	var env listProjectGrantsSuccessEnvelope
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

// principalForGrants returns an auth.Identity for an organization-wide
// developer principal homed at organizationID. project.grants.read is a
// CapRead action so a developer in the principal's home tenant is
// admitted at the policy boundary; the tests use this to focus on
// downstream wire and persistence behavior, not on the role matrix
// (which is the policy-matrix story's job).
func principalForGrants(principalID, organizationID string) auth.Identity {
	return auth.Identity{
		Principal: policy.Principal{
			ID:             principalID,
			Kind:           "usr",
			OrganizationID: organizationID,
			Role:           policy.RoleDeveloper,
		},
		Method: "api_key",
	}
}

// seedProjectGrantWire builds a store.ProjectGrant fixture for the
// fakeProjectGrantReader. It is a plain literal helper — no database —
// so the tests stay pure unit tests of the HTTP wire path.
func seedProjectGrantWire(id, orgID, projectID, principalID, principalKind, role string, envID, svcID *string, version int64, created, updated time.Time) store.ProjectGrant {
	return store.ProjectGrant{
		ID:             id,
		OrganizationID: orgID,
		ProjectID:      projectID,
		PrincipalID:    principalID,
		PrincipalKind:  principalKind,
		Role:           role,
		EnvironmentID:  envID,
		ServiceID:      svcID,
		Version:        version,
		CreatedAt:      created,
		UpdatedAt:      updated,
	}
}

// TestListProjectGrantsReturnsVisibleGrants is the happy path: an
// authenticated developer receives every grant the source-of-truth
// database lists for a project in the principal's home organization, in
// a stable yalla.output.v1 envelope, with every column projected onto
// the wire shape.
func TestListProjectGrantsReturnsVisibleGrants(t *testing.T) {
	t.Parallel()

	const orgID = "org_grants_alpha"
	const projectID = "prj_grants_alpha"

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 6, 7, 8, 0, time.UTC)
	envID := "env_prod"
	svcID := "svc_web"

	var gotOrgID, gotProjectID string
	reader := fakeProjectGrantReader{
		gotOrgID:     &gotOrgID,
		gotProjectID: &gotProjectID,
		grants: []store.ProjectGrant{
			seedProjectGrantWire("pgrnt_one", orgID, projectID, "usr_one", "usr", "developer", nil, nil, 1, created, updated),
			seedProjectGrantWire("pgrnt_two", orgID, projectID, "sa_one", "sa", "ci", &envID, &svcID, 3, created, updated),
		},
	}

	handler := listProjectGrantsHandlerFor(principalForGrants("usr_caller", orgID), nil, reader)
	rec := getProjectGrants(handler, projectID, "yk_anything")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeListProjectGrants(t, rec)
	if len(env.Data.Grants) != 2 {
		t.Fatalf("grants len = %d, want 2 (body %s)", len(env.Data.Grants), rec.Body.String())
	}

	got0 := env.Data.Grants[0]
	if got0.GrantID != "pgrnt_one" || got0.Principal.ID != "usr_one" || got0.Principal.Kind != "usr" {
		t.Errorf("got[0] = %+v; want pgrnt_one / usr_one / usr", got0)
	}
	if got0.Role != "developer" || got0.Version != 1 {
		t.Errorf("got[0] role/version = %q/%d, want developer/1", got0.Role, got0.Version)
	}
	if got0.EnvironmentID != nil || got0.ServiceID != nil {
		t.Errorf("got[0] env/svc = %v/%v; want both nil", got0.EnvironmentID, got0.ServiceID)
	}
	if got0.CreatedAt == "" || got0.UpdatedAt == "" {
		t.Errorf("got[0] timestamps empty: %+v", got0)
	}

	got1 := env.Data.Grants[1]
	if got1.GrantID != "pgrnt_two" || got1.Principal.Kind != "sa" || got1.Role != "ci" {
		t.Errorf("got[1] = %+v; want pgrnt_two / sa / ci", got1)
	}
	if got1.EnvironmentID == nil || *got1.EnvironmentID != "env_prod" {
		t.Errorf("got[1].environment_id = %v; want env_prod", got1.EnvironmentID)
	}
	if got1.ServiceID == nil || *got1.ServiceID != "svc_web" {
		t.Errorf("got[1].service_id = %v; want svc_web", got1.ServiceID)
	}

	// The reader call MUST scope to (principal home org, path project_id)
	// — never a caller-controlled organization id (there isn't one on the
	// wire, but pin the structural property).
	if gotOrgID != orgID {
		t.Errorf("gotOrgID = %q, want %q", gotOrgID, orgID)
	}
	if gotProjectID != projectID {
		t.Errorf("gotProjectID = %q, want %q", gotProjectID, projectID)
	}
}

// TestListProjectGrantsEmptyProject proves a real project with no
// configured grants yields the deterministic empty list (a non-nil
// JSON array) — not null, not omitted.
func TestListProjectGrantsEmptyProject(t *testing.T) {
	t.Parallel()

	const orgID = "org_empty"
	const projectID = "prj_empty"

	handler := listProjectGrantsHandlerFor(principalForGrants("usr_e", orgID), nil, fakeProjectGrantReader{})
	rec := getProjectGrants(handler, projectID, "yk_x")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeListProjectGrants(t, rec)
	if env.Data.Grants == nil {
		t.Fatalf("grants = nil; want non-nil empty slice")
	}
	if len(env.Data.Grants) != 0 {
		t.Fatalf("grants len = %d, want 0", len(env.Data.Grants))
	}
	// Confirm the JSON serializes the empty slice as [] not null.
	if !strings.Contains(rec.Body.String(), `"grants":[]`) {
		t.Errorf("body missing empty grants array: %s", rec.Body.String())
	}
}

// TestListProjectGrantsRejectsUnauthenticated proves a request with no
// bearer token is rejected by RequireAuth as 401 E_AUTH before reaching
// the reader.
func TestListProjectGrantsRejectsUnauthenticated(t *testing.T) {
	t.Parallel()

	callCount := 0
	reader := fakeProjectGrantReader{callCount: &callCount}

	handler := listProjectGrantsHandlerFor(auth.Identity{}, auth.ErrNoCredentials, reader)
	rec := getProjectGrants(handler, "prj_anything", "")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	_ = decodeError(t, rec, "E_AUTH")
	if callCount != 0 {
		t.Errorf("reader call count = %d, want 0 (RequireAuth should reject before the handler)", callCount)
	}
}

// TestListProjectGrantsForwardsNotFoundFromReader proves an
// apierr.NotFound returned by the reader (a cross-tenant or unknown
// project_id) surfaces as a deterministic 404 E_NOT_FOUND on the wire.
func TestListProjectGrantsForwardsNotFoundFromReader(t *testing.T) {
	t.Parallel()

	const orgID = "org_nf"

	reader := fakeProjectGrantReader{
		err: apierr.NotFound("project", "prj_unknown"),
	}
	handler := listProjectGrantsHandlerFor(principalForGrants("usr_n", orgID), nil, reader)
	rec := getProjectGrants(handler, "prj_unknown", "yk_x")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	_ = decodeError(t, rec, "E_NOT_FOUND")
}

// TestListProjectGrantsSurfacesStoreOutage proves a typed
// apierr.StoreUnavailable from the reader surfaces as a deterministic
// 503 with the redacted upstream cause kept out of Message/Hint.
func TestListProjectGrantsSurfacesStoreOutage(t *testing.T) {
	t.Parallel()

	const orgID = "org_so"

	reader := fakeProjectGrantReader{err: apierr.StoreUnavailable(stderrors.New("boom"))}
	handler := listProjectGrantsHandlerFor(principalForGrants("usr_s", orgID), nil, reader)
	rec := getProjectGrants(handler, "prj_any", "yk_x")

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "boom") {
		t.Errorf("body leaks upstream cause %q: %s", "boom", rec.Body.String())
	}
}

// TestListProjectGrantsReturnsInternalWhenReaderUnwired proves an
// unwired reader (a programming wiring error, not a client error) is
// reported as a typed internal failure rather than serving an empty or
// misleading list.
func TestListProjectGrantsReturnsInternalWhenReaderUnwired(t *testing.T) {
	t.Parallel()

	const orgID = "org_wire"

	handler := listProjectGrantsHandlerFor(principalForGrants("usr_w", orgID), nil, nil)
	rec := getProjectGrants(handler, "prj_any", "yk_x")

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
}

// TestListProjectGrantsIsDocumentedInOpenAPI proves the route is also
// documented through the same single source of truth (newRouteTable).
// A served route that isn't documented would fail
// TestEveryRegisteredRouteIsDocumented later — pinning the property
// here keeps a regression in either direction visible in this suite
// too.
func TestListProjectGrantsIsDocumentedInOpenAPI(t *testing.T) {
	t.Parallel()

	const orgID = "org_doc"

	handler := listProjectGrantsHandlerFor(principalForGrants("usr_doc", orgID), nil, fakeProjectGrantReader{})
	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("openapi status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"/v1/projects/{project_id}/grants"`) {
		t.Errorf("openapi document does not describe /v1/projects/{project_id}/grants: %s", body)
	}
	if !strings.Contains(body, `"listProjectGrants"`) {
		t.Errorf("openapi document missing listProjectGrants operationId: %s", body)
	}
}
