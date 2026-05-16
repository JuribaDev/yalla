package httpapi

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Contract and tenant-isolation coverage for GET
// /v1/environments/{environment_id}/services (BE-0178). The endpoint
// lists the services configured under the environment named by the
// {environment_id} path parameter — by reading them through the
// EnvironmentServiceReader port. The tests drive it through
// NewHandler with a fake Authenticator, the real policy engine, and
// a fake reader — the same wiring a request hits in production, minus
// the database. The store-backed reader has its own isolated-Postgres
// integration coverage in store/service_test.go — this file exercises
// the HTTP surface in isolation.
//
// This endpoint has a single {environment_id} path parameter, no
// request body, and no query parameters. The store-backed reader
// treats a cross-tenant or unknown environment_id as a deterministic
// 404; the policy-matrix coverage (BE-0180) drives the engine-level
// resource resolution.

// fakeEnvironmentServiceReader is a canned EnvironmentServiceReader
// for httpapi tests. The zero value returns an empty slice and no
// error from ListEnvironmentServices, which is all the tests that
// never reach the handler (the public-surface, /v1/me, and other-
// route suites) need. Tests that drive this endpoint set
// services/err and read gotOrgID + gotEnvironmentID back to prove the
// (org, env) pair forwarded to the store is the principal's home org
// plus the path environment_id — never a caller-controlled
// organization id.
type fakeEnvironmentServiceReader struct {
	services         []store.Service
	err              error
	gotOrgID         *string
	gotEnvironmentID *string
	callCount        *int
}

func (f fakeEnvironmentServiceReader) ListEnvironmentServices(_ context.Context, organizationID, environmentID string) ([]store.Service, error) {
	if f.gotOrgID != nil {
		*f.gotOrgID = organizationID
	}
	if f.gotEnvironmentID != nil {
		*f.gotEnvironmentID = environmentID
	}
	if f.callCount != nil {
		*f.callCount++
	}
	return f.services, f.err
}

// fakeEnvironmentServiceCreator is a canned EnvironmentServiceCreator
// for httpapi tests. The zero value returns the zero service value
// and a nil error from Create, which is all the tests that never
// reach the POST handler (the public-surface, /v1/me, and other-
// route suites) need. Tests that drive POST
// /v1/environments/{environment_id}/services set service / err and
// read gotInput + callCount back to prove the handler forwarded the
// principal's home org id and the path environment id, never a
// caller-controlled organization id, and to prove the principal /
// correlation fields landed on the audit event.
type fakeEnvironmentServiceCreator struct {
	service   store.Service
	err       error
	gotInput  *store.CreateServiceInput
	callCount *int
}

func (f fakeEnvironmentServiceCreator) Create(_ context.Context, in store.CreateServiceInput) (store.Service, error) {
	if f.gotInput != nil {
		*f.gotInput = in
	}
	if f.callCount != nil {
		*f.callCount++
	}
	return f.service, f.err
}

// listEnvironmentServicesSuccessEnvelope is the decoded shape of the
// GET /v1/environments/{environment_id}/services success envelope.
type listEnvironmentServicesSuccessEnvelope struct {
	SchemaVersion string                         `json:"schema_version"`
	OK            bool                           `json:"ok"`
	RequestID     string                         `json:"request_id"`
	Data          listEnvironmentServicesPayload `json:"data"`
}

// listEnvironmentServicesHandlerFor builds the full NewHandler
// surface with an Authenticator that resolves every credential to id
// and the given EnvironmentServiceReader. It is the production
// request path: the /v1/environments/{environment_id}/services route
// is wrapped in RequireAuth for action service.read.
func listEnvironmentServicesHandlerFor(id auth.Identity, authErr error, reader EnvironmentServiceReader) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, reader, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeBreakGlassController{}, nil, nil)
}

// getEnvironmentServices issues GET
// /v1/environments/{environment_id}/services against handler,
// optionally with a bearer token.
func getEnvironmentServices(handler http.Handler, environmentID, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v1/environments/"+environmentID+"/services", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeListEnvironmentServices(t *testing.T, rec *httptest.ResponseRecorder) listEnvironmentServicesSuccessEnvelope {
	t.Helper()
	var env listEnvironmentServicesSuccessEnvelope
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

// principalForEnvironmentServices returns an auth.Identity for an
// organization-wide developer principal homed at organizationID.
// service.read is a CapRead action so a developer in the principal's
// home tenant is admitted at the policy boundary; the tests use this
// to focus on downstream wire and persistence behavior, not on the
// role matrix (which is BE-0180's job).
func principalForEnvironmentServices(principalID, organizationID string) auth.Identity {
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

// seedServiceWire constructs a deterministic store.Service fixture
// with the columns the wire shape projects.
func seedServiceWire(id, orgID, projectID, environmentID, slug, displayName, kind string, version int64, created, updated time.Time) store.Service {
	return store.Service{
		ID:             id,
		OrganizationID: orgID,
		ProjectID:      projectID,
		EnvironmentID:  environmentID,
		Slug:           slug,
		DisplayName:    displayName,
		Kind:           kind,
		Version:        version,
		CreatedAt:      created,
		UpdatedAt:      updated,
	}
}

// TestListEnvironmentServicesHappyPath drives the production request
// path against an environment the principal's home organization owns.
// The principal is an organization-wide Developer so the policy gate
// admits the read; the reader returns two services — an application
// and a database — and the assertions pin every load-bearing field
// of the wire shape: structural identifiers, slug, display name,
// kind, version, and the timestamp projection.
func TestListEnvironmentServicesHappyPath(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const proj = "prj_web"
	const env = "env_prod"
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	updated := created.Add(time.Hour)

	var gotOrg, gotEnv string
	callCount := 0
	reader := fakeEnvironmentServiceReader{
		services: []store.Service{
			seedServiceWire("svc_api", org, proj, env, "api", "API service", "application", 3, created, updated),
			seedServiceWire("svc_db", org, proj, env, "db", "Postgres database", "database", 1, created, created),
		},
		gotOrgID:         &gotOrg,
		gotEnvironmentID: &gotEnv,
		callCount:        &callCount,
	}

	handler := listEnvironmentServicesHandlerFor(
		principalForEnvironmentServices("usr_dev", org), nil, reader)

	rec := getEnvironmentServices(handler, env, "a-valid-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("reader call count = %d, want 1", callCount)
	}
	if gotOrg != org {
		t.Errorf("reader received organization id %q, want the principal's home org %q", gotOrg, org)
	}
	if gotEnv != env {
		t.Errorf("reader received environment id %q, want the path parameter %q", gotEnv, env)
	}

	envelope := decodeListEnvironmentServices(t, rec)
	if len(envelope.Data.Services) != 2 {
		t.Fatalf("services len = %d, want 2; body %s", len(envelope.Data.Services), rec.Body.String())
	}

	api := envelope.Data.Services[0]
	if api.ID != "svc_api" || api.Slug != "api" || api.DisplayName != "API service" {
		t.Errorf("[0] = %+v, want (svc_api, api, API service)", api)
	}
	if api.OrganizationID != org || api.ProjectID != proj || api.EnvironmentID != env {
		t.Errorf("[0] tenancy = (org=%q, proj=%q, env=%q), want (%q, %q, %q)",
			api.OrganizationID, api.ProjectID, api.EnvironmentID, org, proj, env)
	}
	if api.Kind != "application" {
		t.Errorf("[0].Kind = %q, want application", api.Kind)
	}
	if api.Version != 3 {
		t.Errorf("[0].Version = %d, want 3", api.Version)
	}
	if !api.CreatedAt.Equal(created) || !api.UpdatedAt.Equal(updated) {
		t.Errorf("[0] timestamps = (%s, %s), want (%s, %s)",
			api.CreatedAt, api.UpdatedAt, created, updated)
	}

	db := envelope.Data.Services[1]
	if db.ID != "svc_db" || db.Slug != "db" || db.Kind != "database" {
		t.Errorf("[1] = %+v, want (svc_db, db, database)", db)
	}
}

// TestListEnvironmentServicesEmptyEnvironment proves an environment
// with no services renders as a deterministic empty array (not a nil
// JSON value, not a missing key) so agents can iterate it without a
// nil check.
func TestListEnvironmentServicesEmptyEnvironment(t *testing.T) {
	t.Parallel()

	const org = "org_empty"
	const env = "env_empty"

	handler := listEnvironmentServicesHandlerFor(
		principalForEnvironmentServices("usr_dev", org), nil,
		fakeEnvironmentServiceReader{services: nil})

	rec := getEnvironmentServices(handler, env, "a-valid-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	envelope := decodeListEnvironmentServices(t, rec)
	if envelope.Data.Services == nil {
		t.Fatalf("services is nil; want non-nil empty slice")
	}
	if len(envelope.Data.Services) != 0 {
		t.Errorf("services len = %d, want 0", len(envelope.Data.Services))
	}
}

// TestListEnvironmentServicesUnknownEnvironment proves an unknown or
// cross-tenant environment_id surfaces as a typed yalla.error.v1
// envelope with code e_not_found and HTTP 404 — never as an empty
// success that would invite an agent to believe the environment
// exists with no services.
func TestListEnvironmentServicesUnknownEnvironment(t *testing.T) {
	t.Parallel()

	const org = "org_unknown"
	reader := fakeEnvironmentServiceReader{
		err: apierr.NotFound("environment", "env_missing"),
	}

	handler := listEnvironmentServicesHandlerFor(
		principalForEnvironmentServices("usr_dev", org), nil, reader)

	rec := getEnvironmentServices(handler, "env_missing", "a-valid-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeNotFound))
}

// TestListEnvironmentServicesReaderOutage proves a datastore-level
// outage at the reader surfaces as a typed yalla.error.v1 envelope —
// the outage code maps to its own typed status, never disguised as
// an empty success.
func TestListEnvironmentServicesReaderOutage(t *testing.T) {
	t.Parallel()

	const org = "org_outage"
	reader := fakeEnvironmentServiceReader{
		err: apierr.StoreUnavailable(stderrors.New("connection refused")),
	}

	handler := listEnvironmentServicesHandlerFor(
		principalForEnvironmentServices("usr_dev", org), nil, reader)

	rec := getEnvironmentServices(handler, "env_prod", "a-valid-token")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	// The outage code is preserved end-to-end. The customer-facing
	// message must not echo the wrapped driver cause; only the typed
	// public message.
	body := rec.Body.String()
	if got := body; got == "" {
		t.Fatalf("error body is empty")
	}
	for _, leak := range []string{"connection refused"} {
		if containsString(body, leak) {
			t.Errorf("response body leaks driver cause %q: %s", leak, body)
		}
	}
}

// TestListEnvironmentServicesUnauthenticated proves a request with no
// bearer token is rejected at the auth boundary with a typed 401
// envelope, before the handler is reached. The reader is set up with
// a non-empty fixture and a callCount; both must remain untouched.
func TestListEnvironmentServicesUnauthenticated(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const env = "env_prod"

	callCount := 0
	reader := fakeEnvironmentServiceReader{
		services: []store.Service{
			seedServiceWire("svc_api", org, "prj_x", env, "api", "API", "application", 1,
				time.Now(), time.Now()),
		},
		callCount: &callCount,
	}

	// authErr from the authenticator is surfaced as a typed 401 by
	// RequireAuth. The reader must NOT be called because the request
	// never reaches the handler.
	handler := listEnvironmentServicesHandlerFor(auth.Identity{}, apierr.Unauthenticated("missing token"), reader)

	rec := getEnvironmentServices(handler, env, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("reader call count = %d, want 0 (auth rejected before handler)", callCount)
	}
	decodeError(t, rec, string(yerr.CodeAuth))
}

// TestListEnvironmentServicesAuthorizationDenied proves that a
// principal whose role does not admit action service.read (a CI
// principal whose grants do not cover this environment, presented
// with no organization-wide Roles) is rejected at the policy gate
// with a typed 403, BEFORE the reader is touched. The reader fixture
// would have returned data on success — its untouched callCount
// proves the authorization gate denied first.
func TestListEnvironmentServicesAuthorizationDenied(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const env = "env_prod"

	callCount := 0
	reader := fakeEnvironmentServiceReader{
		services: []store.Service{
			seedServiceWire("svc_api", org, "prj_x", env, "api", "API", "application", 1,
				time.Now(), time.Now()),
		},
		callCount: &callCount,
	}

	// A principal with no organization-wide roles and no scoped grant
	// for the resource. The policy engine denies service.read for it.
	id := auth.Identity{
		Principal: policy.Principal{
			ID:             "usr_outsider",
			Kind:           "usr",
			OrganizationID: org,
		},
	}

	handler := listEnvironmentServicesHandlerFor(id, nil, reader)

	rec := getEnvironmentServices(handler, env, "a-valid-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("reader call count = %d, want 0 (policy gate denied before handler)", callCount)
	}
	decodeError(t, rec, string(yerr.CodeForbidden))
}

// TestListEnvironmentServicesNoCallerSuppliedOrgID proves the handler
// reads from the principal's home organization id only — never from
// any caller-controlled value. The fake reader records the
// organization id it received and the test verifies it always equals
// the principal's home org, regardless of the path environment_id.
// The persistence layer's tenant-scoped query then rejects a
// cross-tenant environment_id as a typed NotFound — which is BE-0180's
// territory; this test only proves the handler does not leak a
// caller-supplied tenant boundary.
func TestListEnvironmentServicesNoCallerSuppliedOrgID(t *testing.T) {
	t.Parallel()

	const homeOrg = "org_home"
	const env = "env_other_tenant"

	var gotOrg string
	reader := fakeEnvironmentServiceReader{
		gotOrgID: &gotOrg,
	}

	handler := listEnvironmentServicesHandlerFor(
		principalForEnvironmentServices("usr_dev", homeOrg), nil, reader)

	_ = getEnvironmentServices(handler, env, "a-valid-token")
	if gotOrg != homeOrg {
		t.Errorf("reader received organization id %q, want the principal's home org %q (handler must not honour a caller-supplied id)", gotOrg, homeOrg)
	}
}

// containsString is a local case-sensitive substring check that
// avoids pulling strings into this file solely for one assertion.
func containsString(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
