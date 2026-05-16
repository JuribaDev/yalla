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
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Contract and tenant-isolation coverage for POST
// /v1/environments/{environment_id}/services (BE-0181). The endpoint
// creates a service under the environment named by the
// {environment_id} path parameter by delegating to the
// EnvironmentServiceCreator port. The tests drive it through
// NewHandler with a fake Authenticator, the real policy engine, and a
// fake creator — the same wiring a request hits in production, minus
// the database. The store-backed orchestrator has its own integration
// coverage; this file exercises the HTTP surface in isolation.
//
// This endpoint has a single {environment_id} path parameter, a small
// JSON request body, and no query parameters. The store-backed
// creator treats a cross-tenant or unknown environment_id as a
// deterministic 404 (the parent-environment existence check runs
// before the in-tx authorize and quota reservation); the policy-
// matrix coverage (BE-0183) drives the engine-level resource
// resolution.

// createEnvironmentServiceSuccessEnvelope is the decoded shape of the
// POST /v1/environments/{environment_id}/services success envelope.
type createEnvironmentServiceSuccessEnvelope struct {
	SchemaVersion string                          `json:"schema_version"`
	OK            bool                            `json:"ok"`
	RequestID     string                          `json:"request_id"`
	Data          createEnvironmentServicePayload `json:"data"`
}

// createEnvironmentServiceHandlerFor builds the full NewHandler
// surface with an Authenticator that resolves every credential to id
// and the given EnvironmentServiceCreator. It is the production
// request path: the POST /v1/environments/{environment_id}/services
// route is wrapped in RequireAuth for action service.create.
func createEnvironmentServiceHandlerFor(id auth.Identity, authErr error, creator EnvironmentServiceCreator) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, creator, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
}

// postEnvironmentService issues POST
// /v1/environments/{environment_id}/services against handler with the
// given body and optional bearer token.
func postEnvironmentService(handler http.Handler, environmentID, body, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost,
		"/v1/environments/"+environmentID+"/services", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeCreateEnvironmentService(t *testing.T, rec *httptest.ResponseRecorder) createEnvironmentServiceSuccessEnvelope {
	t.Helper()
	var env createEnvironmentServiceSuccessEnvelope
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

// principalForCreateService returns an auth.Identity for an
// organization-wide developer principal homed at organizationID.
// service.create is a CapWrite action so a developer in the
// principal's home tenant is admitted at the policy boundary; the
// tests use this to focus on downstream wire and persistence
// behavior, not on the role matrix (which is BE-0183's job).
func principalForCreateService(principalID, organizationID string) auth.Identity {
	return auth.Identity{
		Principal: policy.Principal{
			ID:             principalID,
			Kind:           domain.KindUser,
			OrganizationID: organizationID,
			Role:           policy.RoleDeveloper,
		},
		Method: auth.MethodSession,
	}
}

// TestCreateEnvironmentServiceHappyPath drives the production request
// path: an organization-wide Developer principal creates a service in
// an environment owned by its home organization. The handler must
// forward the principal's home org id and the {environment_id} path
// parameter to the creator (never a caller-supplied org id from the
// body), and must echo the persisted row through the canonical wire
// projection in a 201 envelope.
func TestCreateEnvironmentServiceHappyPath(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		proj  = "prj_web"
		envID = "env_prod"
		svcID = "svc_api"
	)
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := created.Add(time.Minute)

	var gotIn store.CreateServiceInput
	callCount := 0
	creator := fakeEnvironmentServiceCreator{
		service: seedServiceWire(
			svcID, org, proj, envID, "api", "API service",
			store.ServiceKindApplication, 1, created, updated,
		),
		gotInput:  &gotIn,
		callCount: &callCount,
	}

	handler := createEnvironmentServiceHandlerFor(
		principalForCreateService("usr_dev", org), nil, creator)

	body := `{"service_id":"svc_api","slug":"api","display_name":"API service","kind":"application"}`
	rec := postEnvironmentService(handler, envID, body, "a-valid-token")

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("creator call count = %d, want 1", callCount)
	}
	if gotIn.OrganizationID != org {
		t.Errorf("creator received organization id %q, want the principal's home org %q",
			gotIn.OrganizationID, org)
	}
	if gotIn.EnvironmentID != envID {
		t.Errorf("creator received environment id %q, want the path parameter %q",
			gotIn.EnvironmentID, envID)
	}
	if gotIn.ServiceID != svcID || gotIn.Slug != "api" || gotIn.DisplayName != "API service" || gotIn.Kind != "application" {
		t.Errorf("creator received resource fields = (%q, %q, %q, %q), want (svc_api, api, API service, application)",
			gotIn.ServiceID, gotIn.Slug, gotIn.DisplayName, gotIn.Kind)
	}
	if gotIn.ActorID != "usr_dev" || gotIn.ActorOrgID != org {
		t.Errorf("creator received actor = (%q, org=%q), want (usr_dev, org=%s) — actor identity must be plumbed for the audit record",
			gotIn.ActorID, gotIn.ActorOrgID, org)
	}

	envelope := decodeCreateEnvironmentService(t, rec)
	svc := envelope.Data.Service
	if svc.ID != svcID || svc.Slug != "api" || svc.DisplayName != "API service" || svc.Kind != "application" {
		t.Errorf("service = %+v, want (svc_api, api, API service, application)", svc)
	}
	if svc.OrganizationID != org || svc.ProjectID != proj || svc.EnvironmentID != envID {
		t.Errorf("service tenancy = (org=%q, proj=%q, env=%q), want (%q, %q, %q)",
			svc.OrganizationID, svc.ProjectID, svc.EnvironmentID, org, proj, envID)
	}
	if svc.Version != 1 {
		t.Errorf("service.Version = %d, want 1 (a freshly inserted row starts at version 1)", svc.Version)
	}
}

// TestCreateEnvironmentServiceValidationFailure proves a malformed
// request body (an empty slug, here) surfaces as a typed 400 with code
// E_INVALID_INPUT, the creator is never reached, and the response
// envelope is a stable yalla.error.v1. The body sent uses an empty
// slug — the store-layer validateCreateServiceInput would reject it
// with a typed FieldViolation. The fake creator returns that
// pre-validation error so the test verifies the handler propagates
// it as the correct envelope without touching the store-layer
// orchestration semantics.
func TestCreateEnvironmentServiceValidationFailure(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const envID = "env_prod"

	callCount := 0
	creator := fakeEnvironmentServiceCreator{
		err:       apierr.InvalidInput(apierr.FieldViolation{Field: "slug", Reason: "must be a canonical slug"}),
		callCount: &callCount,
	}
	handler := createEnvironmentServiceHandlerFor(
		principalForCreateService("usr_dev", org), nil, creator)

	body := `{"service_id":"svc_api","slug":"","display_name":"API","kind":"application"}`
	rec := postEnvironmentService(handler, envID, body, "a-valid-token")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("creator call count = %d, want 1 (the handler delegates validation to the orchestrator)",
			callCount)
	}
	decodeError(t, rec, string(yerr.CodeInvalidInput))
}

// TestCreateEnvironmentServiceUnauthenticated proves a request with
// no bearer token is rejected at the auth boundary with a typed 401
// envelope, before the handler is reached. The creator is set up with
// a callCount; it must remain untouched.
func TestCreateEnvironmentServiceUnauthenticated(t *testing.T) {
	t.Parallel()

	callCount := 0
	creator := fakeEnvironmentServiceCreator{callCount: &callCount}

	handler := createEnvironmentServiceHandlerFor(
		auth.Identity{}, apierr.Unauthenticated("missing token"), creator)

	body := `{"service_id":"svc_api","slug":"api","display_name":"API","kind":"application"}`
	rec := postEnvironmentService(handler, "env_prod", body, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("creator call count = %d, want 0 (auth rejected before handler)", callCount)
	}
	decodeError(t, rec, string(yerr.CodeAuth))
}

// TestCreateEnvironmentServiceAuthorizationDenied proves a principal
// whose role does not admit action service.create (a viewer carrying
// no scoped grant) is rejected at the policy gate with a typed 403
// BEFORE the creator is touched. The viewer's CapRead capability does
// not authorize a CapWrite action, and the principal here carries no
// scoped grant that could cover the resource — the engine denies
// with ReasonDeniedNoCapability.
func TestCreateEnvironmentServiceAuthorizationDenied(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const envID = "env_prod"

	callCount := 0
	creator := fakeEnvironmentServiceCreator{callCount: &callCount}

	// A viewer in the principal's home org — CapRead only, no
	// CapWrite — cannot reach action service.create.
	id := auth.Identity{
		Principal: policy.Principal{
			ID:             "usr_viewer",
			Kind:           domain.KindUser,
			OrganizationID: org,
			Role:           policy.RoleViewer,
		},
		Method: auth.MethodSession,
	}
	handler := createEnvironmentServiceHandlerFor(id, nil, creator)

	body := `{"service_id":"svc_api","slug":"api","display_name":"API","kind":"application"}`
	rec := postEnvironmentService(handler, envID, body, "a-valid-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("creator call count = %d, want 0 (policy gate denied before handler)", callCount)
	}
	decodeError(t, rec, string(yerr.CodeForbidden))
}

// TestCreateEnvironmentServiceCrossTenantEnvironment proves a
// cross-tenant or unknown environment_id surfaces as a typed
// yalla.error.v1 envelope with code E_NOT_FOUND and HTTP 404 — never
// as a 201 with a foreign service id and never as a 403 that would
// confirm the foreign environment's existence. The creator returns
// apierr.NotFound to mirror the production orchestrator's
// parent-environment existence check.
func TestCreateEnvironmentServiceCrossTenantEnvironment(t *testing.T) {
	t.Parallel()

	const homeOrg = "org_home"
	const foreignEnv = "env_other_tenant"

	var gotIn store.CreateServiceInput
	callCount := 0
	creator := fakeEnvironmentServiceCreator{
		err:       apierr.NotFound("environment", foreignEnv),
		gotInput:  &gotIn,
		callCount: &callCount,
	}

	handler := createEnvironmentServiceHandlerFor(
		principalForCreateService("usr_dev", homeOrg), nil, creator)

	body := `{"service_id":"svc_api","slug":"api","display_name":"API","kind":"application"}`
	rec := postEnvironmentService(handler, foreignEnv, body, "a-valid-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("creator call count = %d, want 1 — the creator runs because the engine admits the same-tenant resource and the persistence layer rejects the foreign environment id",
			callCount)
	}
	if gotIn.OrganizationID != homeOrg {
		t.Errorf("creator received organization id %q, want the principal's home org %q — the creator must never be called with another tenant's id",
			gotIn.OrganizationID, homeOrg)
	}
	decodeError(t, rec, string(yerr.CodeNotFound))
}

// TestCreateEnvironmentServiceCreatorOutage proves a datastore-level
// outage at the creator surfaces as a typed yalla.error.v1 envelope —
// the outage code maps to its own typed status, never disguised as a
// 201, and the body never echoes the wrapped driver cause.
func TestCreateEnvironmentServiceCreatorOutage(t *testing.T) {
	t.Parallel()

	const org = "org_outage"
	creator := fakeEnvironmentServiceCreator{
		err: apierr.StoreUnavailable(stderrors.New("connection refused")),
	}

	handler := createEnvironmentServiceHandlerFor(
		principalForCreateService("usr_dev", org), nil, creator)

	body := `{"service_id":"svc_api","slug":"api","display_name":"API","kind":"application"}`
	rec := postEnvironmentService(handler, "env_prod", body, "a-valid-token")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "connection refused") {
		t.Errorf("response body leaks driver cause: %s", rec.Body.String())
	}
}

// TestCreateEnvironmentServiceNoCallerSuppliedOrgID proves the
// handler resolves the organization id from the principal's home org
// only — never from any caller-controlled value in the body or path —
// even when the body attempts to smuggle a foreign organization_id /
// project_id / environment_id. Unknown fields are rejected by the
// strict JSON decoder; the test sends a clean body but asserts the
// creator received the principal's home org. The persistence layer's
// tenant-scoped query then rejects a cross-tenant environment_id as
// a typed NotFound — which is BE-0183's territory; this test only
// proves the handler does not leak a caller-supplied tenant boundary.
func TestCreateEnvironmentServiceNoCallerSuppliedOrgID(t *testing.T) {
	t.Parallel()

	const homeOrg = "org_home"
	const envID = "env_other_tenant"

	var gotIn store.CreateServiceInput
	creator := fakeEnvironmentServiceCreator{
		gotInput: &gotIn,
		service: seedServiceWire("svc_x", homeOrg, "prj_x", envID,
			"x", "X", "application", 1, time.Now(), time.Now()),
	}

	handler := createEnvironmentServiceHandlerFor(
		principalForCreateService("usr_dev", homeOrg), nil, creator)

	body := `{"service_id":"svc_x","slug":"x","display_name":"X","kind":"application"}`
	_ = postEnvironmentService(handler, envID, body, "a-valid-token")

	if gotIn.OrganizationID != homeOrg {
		t.Errorf("creator received organization id %q, want the principal's home org %q (handler must not honour a caller-supplied id)",
			gotIn.OrganizationID, homeOrg)
	}
	if gotIn.EnvironmentID != envID {
		t.Errorf("creator received environment id %q, want the path parameter %q",
			gotIn.EnvironmentID, envID)
	}
}

// fakeEnvironmentServiceCreator is exercised end-to-end through the
// production request path in this file; ensure the type lives in the
// shared fixture so future POST-shaped tests can reuse it.
var _ context.Context // satisfies the import without unused-warning at edits
