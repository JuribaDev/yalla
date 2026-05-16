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
// /v1/environments/{environment_id}/grants (BE-0166). The endpoint lists
// the scoped grants attached to the environment named by the
// {environment_id} path parameter by reading them through the
// EnvironmentGrantReader port. The tests drive it through NewHandler with a
// fake Authenticator, the real policy engine, and a fake reader — the same
// wiring a request hits in production, minus the database. The store-backed
// reader has its own isolated-Postgres integration coverage in
// store/environment_grant_test.go.
//
// This endpoint has a single {environment_id} path parameter, no request
// body, and no query parameters. The store-backed reader treats a
// cross-tenant or unknown environment_id as a deterministic 404; the
// policy-matrix coverage (BE-0168) drives the engine-level resource
// resolution.

// fakeEnvironmentGrantReader is a canned EnvironmentGrantReader for httpapi
// tests. The zero value returns an empty slice and no error from
// ListEnvironmentGrants, which is all the tests that never reach the
// handler (the public-surface, /v1/me, and other-route suites) need. Tests
// that drive this endpoint set grants/err and read gotOrgID + gotEnvID
// back to prove the (org, environment) pair forwarded to the store is the
// principal's home org plus the path environment_id — never a
// caller-controlled organization id.
type fakeEnvironmentGrantReader struct {
	grants    []store.EnvironmentGrant
	err       error
	gotOrgID  *string
	gotEnvID  *string
	callCount *int
}

func (f fakeEnvironmentGrantReader) ListEnvironmentGrants(_ context.Context, organizationID, environmentID string) ([]store.EnvironmentGrant, error) {
	if f.gotOrgID != nil {
		*f.gotOrgID = organizationID
	}
	if f.gotEnvID != nil {
		*f.gotEnvID = environmentID
	}
	if f.callCount != nil {
		*f.callCount++
	}
	return f.grants, f.err
}

// listEnvironmentGrantsSuccessEnvelope is the decoded shape of the GET
// /v1/environments/{environment_id}/grants success envelope.
type listEnvironmentGrantsSuccessEnvelope struct {
	SchemaVersion string                       `json:"schema_version"`
	OK            bool                         `json:"ok"`
	RequestID     string                       `json:"request_id"`
	Data          listEnvironmentGrantsPayload `json:"data"`
}

// listEnvironmentGrantsHandlerFor builds the full NewHandler surface with
// an Authenticator that resolves every credential to id and the given
// EnvironmentGrantReader. It is the production request path: the
// /v1/environments/{environment_id}/grants route is wrapped in RequireAuth
// for action environment.grants.read.
func listEnvironmentGrantsHandlerFor(id auth.Identity, authErr error, reader EnvironmentGrantReader) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, reader, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStopper{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
}

// getEnvironmentGrants issues GET /v1/environments/{environment_id}/grants
// against handler, optionally with a bearer token.
func getEnvironmentGrants(handler http.Handler, environmentID, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v1/environments/"+environmentID+"/grants", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeListEnvironmentGrants(t *testing.T, rec *httptest.ResponseRecorder) listEnvironmentGrantsSuccessEnvelope {
	t.Helper()
	var env listEnvironmentGrantsSuccessEnvelope
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

// principalForEnvironmentGrants returns an auth.Identity for an
// organization-wide developer principal homed at organizationID.
// environment.grants.read is a CapRead action so a developer in the
// principal's home tenant is admitted at the policy boundary; the tests
// use this to focus on downstream wire and persistence behavior, not on
// the role matrix (which is the policy-matrix story's job).
func principalForEnvironmentGrants(principalID, organizationID string) auth.Identity {
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

// seedEnvironmentGrantWire builds a store.EnvironmentGrant fixture for the
// fakeEnvironmentGrantReader. It is a plain literal helper — no database —
// so the tests stay pure unit tests of the HTTP wire path.
func seedEnvironmentGrantWire(id, orgID, envID, principalID, principalKind, role string, svcID *string, version int64, created, updated time.Time) store.EnvironmentGrant {
	return store.EnvironmentGrant{
		ID:             id,
		OrganizationID: orgID,
		EnvironmentID:  envID,
		PrincipalID:    principalID,
		PrincipalKind:  principalKind,
		Role:           role,
		ServiceID:      svcID,
		Version:        version,
		CreatedAt:      created,
		UpdatedAt:      updated,
	}
}

// TestListEnvironmentGrantsReturnsVisibleGrants is the happy path: an
// authenticated developer receives every grant the source-of-truth
// database lists for an environment in the principal's home organization,
// in a stable yalla.output.v1 envelope, with every column projected onto
// the wire shape.
func TestListEnvironmentGrantsReturnsVisibleGrants(t *testing.T) {
	t.Parallel()

	const orgID = "org_egrants_alpha"
	const envID = "env_egrants_alpha"

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 6, 7, 8, 0, time.UTC)
	svcID := "svc_web"

	var gotOrgID, gotEnvID string
	reader := fakeEnvironmentGrantReader{
		gotOrgID: &gotOrgID,
		gotEnvID: &gotEnvID,
		grants: []store.EnvironmentGrant{
			seedEnvironmentGrantWire("egrnt_one", orgID, envID, "usr_one", "usr", "developer", nil, 1, created, updated),
			seedEnvironmentGrantWire("egrnt_two", orgID, envID, "sa_one", "sa", "ci", &svcID, 3, created, updated),
		},
	}

	handler := listEnvironmentGrantsHandlerFor(principalForEnvironmentGrants("usr_caller", orgID), nil, reader)
	rec := getEnvironmentGrants(handler, envID, "yk_anything")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeListEnvironmentGrants(t, rec)
	if len(env.Data.Grants) != 2 {
		t.Fatalf("grants len = %d, want 2 (body %s)", len(env.Data.Grants), rec.Body.String())
	}

	got0 := env.Data.Grants[0]
	if got0.GrantID != "egrnt_one" || got0.Principal.ID != "usr_one" || got0.Principal.Kind != "usr" {
		t.Errorf("got[0] = %+v; want egrnt_one / usr_one / usr", got0)
	}
	if got0.Role != "developer" || got0.Version != 1 {
		t.Errorf("got[0] role/version = %q/%d, want developer/1", got0.Role, got0.Version)
	}
	if got0.ServiceID != nil {
		t.Errorf("got[0] service_id = %v; want nil", got0.ServiceID)
	}
	if got0.EnvironmentID != envID {
		t.Errorf("got[0] environment_id = %q, want %q", got0.EnvironmentID, envID)
	}
	if got0.CreatedAt == "" || got0.UpdatedAt == "" {
		t.Errorf("got[0] timestamps empty: %+v", got0)
	}

	got1 := env.Data.Grants[1]
	if got1.GrantID != "egrnt_two" || got1.Principal.Kind != "sa" || got1.Role != "ci" {
		t.Errorf("got[1] = %+v; want egrnt_two / sa / ci", got1)
	}
	if got1.ServiceID == nil || *got1.ServiceID != "svc_web" {
		t.Errorf("got[1].service_id = %v; want svc_web", got1.ServiceID)
	}

	// The reader call MUST scope to (principal home org, path environment_id)
	// — never a caller-controlled organization id (there isn't one on the
	// wire, but pin the structural property).
	if gotOrgID != orgID {
		t.Errorf("gotOrgID = %q, want %q", gotOrgID, orgID)
	}
	if gotEnvID != envID {
		t.Errorf("gotEnvID = %q, want %q", gotEnvID, envID)
	}
}

// TestListEnvironmentGrantsEmptyEnvironment proves a real environment with
// no configured grants yields the deterministic empty list (a non-nil
// JSON array) — not null, not omitted.
func TestListEnvironmentGrantsEmptyEnvironment(t *testing.T) {
	t.Parallel()

	const orgID = "org_egrants_empty"
	const envID = "env_egrants_empty"

	handler := listEnvironmentGrantsHandlerFor(principalForEnvironmentGrants("usr_e", orgID), nil, fakeEnvironmentGrantReader{})
	rec := getEnvironmentGrants(handler, envID, "yk_x")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeListEnvironmentGrants(t, rec)
	if env.Data.Grants == nil {
		t.Fatalf("grants = nil; want non-nil empty slice")
	}
	if len(env.Data.Grants) != 0 {
		t.Fatalf("grants len = %d, want 0", len(env.Data.Grants))
	}
	if !strings.Contains(rec.Body.String(), `"grants":[]`) {
		t.Errorf("body missing empty grants array: %s", rec.Body.String())
	}
}

// TestListEnvironmentGrantsRejectsUnauthenticated proves a request with no
// bearer token is rejected by RequireAuth as 401 E_AUTH before reaching
// the reader.
func TestListEnvironmentGrantsRejectsUnauthenticated(t *testing.T) {
	t.Parallel()

	callCount := 0
	reader := fakeEnvironmentGrantReader{callCount: &callCount}

	handler := listEnvironmentGrantsHandlerFor(auth.Identity{}, auth.ErrNoCredentials, reader)
	rec := getEnvironmentGrants(handler, "env_anything", "")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	_ = decodeError(t, rec, "E_AUTH")
	if callCount != 0 {
		t.Errorf("reader call count = %d, want 0 (RequireAuth should reject before the handler)", callCount)
	}
}

// TestListEnvironmentGrantsForwardsNotFoundFromReader proves an
// apierr.NotFound returned by the reader (a cross-tenant or unknown
// environment_id) surfaces as a deterministic 404 E_NOT_FOUND on the wire.
func TestListEnvironmentGrantsForwardsNotFoundFromReader(t *testing.T) {
	t.Parallel()

	const orgID = "org_egrants_nf"

	reader := fakeEnvironmentGrantReader{
		err: apierr.NotFound("environment", "env_unknown"),
	}
	handler := listEnvironmentGrantsHandlerFor(principalForEnvironmentGrants("usr_n", orgID), nil, reader)
	rec := getEnvironmentGrants(handler, "env_unknown", "yk_x")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	_ = decodeError(t, rec, "E_NOT_FOUND")
}

// TestListEnvironmentGrantsSurfacesStoreOutage proves a typed
// apierr.StoreUnavailable from the reader surfaces as a deterministic
// 503 with the redacted upstream cause kept out of Message/Hint.
func TestListEnvironmentGrantsSurfacesStoreOutage(t *testing.T) {
	t.Parallel()

	const orgID = "org_egrants_so"

	reader := fakeEnvironmentGrantReader{err: apierr.StoreUnavailable(stderrors.New("boom-env-grant"))}
	handler := listEnvironmentGrantsHandlerFor(principalForEnvironmentGrants("usr_s", orgID), nil, reader)
	rec := getEnvironmentGrants(handler, "env_any", "yk_x")

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "boom-env-grant") {
		t.Errorf("body leaks upstream cause %q: %s", "boom-env-grant", rec.Body.String())
	}
}

// TestListEnvironmentGrantsReturnsInternalWhenReaderUnwired proves an
// unwired reader (a programming wiring error, not a client error) is
// reported as a typed internal failure rather than serving an empty or
// misleading list.
func TestListEnvironmentGrantsReturnsInternalWhenReaderUnwired(t *testing.T) {
	t.Parallel()

	const orgID = "org_egrants_wire"

	handler := listEnvironmentGrantsHandlerFor(principalForEnvironmentGrants("usr_w", orgID), nil, nil)
	rec := getEnvironmentGrants(handler, "env_any", "yk_x")

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
}

// TestListEnvironmentGrantsIsDocumentedInOpenAPI proves the route is also
// documented through the same single source of truth (newRouteTable).
// A served route that isn't documented would fail
// TestEveryRegisteredRouteIsDocumented later — pinning the property here
// keeps a regression in either direction visible in this suite too.
func TestListEnvironmentGrantsIsDocumentedInOpenAPI(t *testing.T) {
	t.Parallel()

	const orgID = "org_egrants_doc"

	handler := listEnvironmentGrantsHandlerFor(principalForEnvironmentGrants("usr_doc", orgID), nil, fakeEnvironmentGrantReader{})
	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("openapi status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"/v1/environments/{environment_id}/grants"`) {
		t.Errorf("openapi document does not describe /v1/environments/{environment_id}/grants: %s", body)
	}
	if !strings.Contains(body, `"listEnvironmentGrants"`) {
		t.Errorf("openapi document missing listEnvironmentGrants operationId: %s", body)
	}
}
