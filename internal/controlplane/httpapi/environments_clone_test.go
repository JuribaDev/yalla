package httpapi

import (
	"bytes"
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
)

// Contract tests for POST /v1/environments/{environment_id}/clone. The route
// is gated by RequireAuth on action environment.create through
// environmentIDResolver — a CapWrite action authorized against the
// (principal home organization, {environment_id}) resource. These tests
// drive the real NewHandler with a fake Authenticator, the real policy
// engine, and a fake EnvironmentCloner — the same wiring a request hits in
// production, minus the database. The store-backed orchestrator
// (store.EnvironmentService.Clone) has its own isolated-Postgres
// integration coverage in store/environment_clone_test.go.
//
// The fuller "every principal class × every authorization edge" matrix
// for this route lives in environments_clone_policy_test.go (BE-0165).

// cloneEnvironmentSuccessEnvelope is the decoded shape of the POST
// /v1/environments/{environment_id}/clone success envelope.
type cloneEnvironmentSuccessEnvelope struct {
	SchemaVersion string `json:"schema_version"`
	OK            bool   `json:"ok"`
	RequestID     string `json:"request_id"`
	Data          struct {
		Environment projectEnvironment `json:"environment"`
	} `json:"data"`
}

// cloneEnvironmentHandlerFor builds the full NewHandler surface with an
// Authenticator that resolves every credential to id and the given
// EnvironmentCloner. It is the production request path: the POST
// /v1/environments/{environment_id}/clone route is wrapped in RequireAuth
// for action environment.create.
func cloneEnvironmentHandlerFor(id auth.Identity, authErr error, cloner EnvironmentCloner) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{},
		fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, cloner, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
}

// cloneEnvironment issues POST /v1/environments/{environmentID}/clone
// against the handler with the supplied bearer token and JSON body.
func cloneEnvironment(handler http.Handler, environmentID, token, body string) *httptest.ResponseRecorder {
	var bodyReader *bytes.Reader
	if body != "" {
		bodyReader = bytes.NewReader([]byte(body))
	} else {
		bodyReader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/environments/"+environmentID+"/clone", bodyReader)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeCloneEnvironment(t *testing.T, rec *httptest.ResponseRecorder) cloneEnvironmentSuccessEnvelope {
	t.Helper()
	var env cloneEnvironmentSuccessEnvelope
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
		t.Error("request_id is empty")
	}
	return env
}

// TestCloneEnvironmentHappyPathForwardsPrincipalAndBody proves the handler
// threads the principal's home organization, the path's source environment
// id, and the decoded body fields into the store input, renders the
// returned cloned row in the stable yalla.output.v1 envelope, returns 201
// Created, and mirrors the row's authoritative version into the ETag
// response header so the caller can echo it back as the next If-Match
// precondition without re-reading the row.
func TestCloneEnvironmentHappyPathForwardsPrincipalAndBody(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	updated := created.Add(time.Minute)
	cloned := store.Environment{
		ID:             "env_acme_preview",
		OrganizationID: "org_acme",
		ProjectID:      "prj_acme_web",
		Slug:           "preview",
		DisplayName:    "Preview",
		Version:        1,
		CreatedAt:      created,
		UpdatedAt:      updated,
	}
	var captured store.CloneEnvironmentInput
	cloner := fakeEnvironmentCloner{env: cloned, gotInput: &captured}
	handler := cloneEnvironmentHandlerFor(auth.Identity{Principal: orgPrincipal("usr_acme_owner", "org_acme", policy.RoleOwner), Method: auth.MethodSession}, nil, cloner)

	body := `{"environment_id":"env_acme_preview","slug":"preview","display_name":"Preview"}`
	rec := cloneEnvironment(handler, "env_acme_prod", "valid-key", body)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	env := decodeCloneEnvironment(t, rec)
	if env.Data.Environment.ID != cloned.ID {
		t.Errorf("id = %q, want %q", env.Data.Environment.ID, cloned.ID)
	}
	if env.Data.Environment.OrganizationID != cloned.OrganizationID {
		t.Errorf("organization_id = %q, want %q", env.Data.Environment.OrganizationID, cloned.OrganizationID)
	}
	if env.Data.Environment.ProjectID != cloned.ProjectID {
		t.Errorf("project_id = %q, want %q (inherited from source)", env.Data.Environment.ProjectID, cloned.ProjectID)
	}
	if env.Data.Environment.Slug != cloned.Slug || env.Data.Environment.DisplayName != cloned.DisplayName {
		t.Errorf("slug/display = %q/%q, want %q/%q", env.Data.Environment.Slug, env.Data.Environment.DisplayName, cloned.Slug, cloned.DisplayName)
	}
	if env.Data.Environment.Version != cloned.Version {
		t.Errorf("version = %d, want %d", env.Data.Environment.Version, cloned.Version)
	}
	if env.Data.Environment.DeletionScheduledAt != nil {
		t.Errorf("deletion_scheduled_at = %v, want nil (a freshly-cloned row is live)", env.Data.Environment.DeletionScheduledAt)
	}
	if got, want := rec.Header().Get("ETag"), `"1"`; got != want {
		t.Errorf("ETag header = %q, want %q", got, want)
	}
	if captured.OrganizationID != "org_acme" {
		t.Errorf("forwarded organization_id = %q, want org_acme (principal home — never the caller)", captured.OrganizationID)
	}
	if captured.SourceEnvironmentID != "env_acme_prod" {
		t.Errorf("forwarded source_environment_id = %q, want env_acme_prod (path parameter)", captured.SourceEnvironmentID)
	}
	if captured.NewEnvironmentID != "env_acme_preview" {
		t.Errorf("forwarded new_environment_id = %q, want env_acme_preview (request body)", captured.NewEnvironmentID)
	}
	if captured.NewSlug != "preview" {
		t.Errorf("forwarded new_slug = %q, want preview (request body)", captured.NewSlug)
	}
	if captured.NewDisplayName != "Preview" {
		t.Errorf("forwarded new_display_name = %q, want Preview (request body)", captured.NewDisplayName)
	}
	if captured.ActorID != "usr_acme_owner" {
		t.Errorf("forwarded actor_id = %q, want the resolved principal", captured.ActorID)
	}
	if captured.ActorOrgID != "org_acme" {
		t.Errorf("forwarded actor_org_id = %q, want the principal's home org", captured.ActorOrgID)
	}
}

// TestCloneEnvironmentRejectsMalformedBody proves an oversized, malformed,
// or unknown-field body is a stable 400 E_INVALID_INPUT before the cloner
// runs — the malformed body is a client error, not a silent pass-through.
func TestCloneEnvironmentRejectsMalformedBody(t *testing.T) {
	t.Parallel()

	cloner := fakeEnvironmentCloner{err: stderrors.New("cloner must not be called")}
	handler := cloneEnvironmentHandlerFor(auth.Identity{Principal: orgPrincipal("usr_acme_owner", "org_acme", policy.RoleOwner), Method: auth.MethodSession}, nil, cloner)

	rec := cloneEnvironment(handler, "env_acme_prod", "valid-key", `{"environment_id":"env_x", oops malformed`)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestCloneEnvironmentRejectsUnknownField proves a body field the schema
// does not declare is a stable 400 — the strict decoder refuses to echo or
// silently accept unmodelled input.
func TestCloneEnvironmentRejectsUnknownField(t *testing.T) {
	t.Parallel()

	cloner := fakeEnvironmentCloner{err: stderrors.New("cloner must not be called")}
	handler := cloneEnvironmentHandlerFor(auth.Identity{Principal: orgPrincipal("usr_acme_owner", "org_acme", policy.RoleOwner), Method: auth.MethodSession}, nil, cloner)

	// project_id is intentionally not in the request schema — clone inherits
	// the source's project_id, the caller cannot supply one.
	rec := cloneEnvironment(handler, "env_acme_prod", "valid-key",
		`{"environment_id":"env_x","slug":"x","display_name":"X","project_id":"prj_other"}`)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestCloneEnvironmentSurfacesNotFound proves a NotFound from the store
// (the source environment does not exist in the principal's tenant) is
// rendered as a 404 error envelope — never disguised as an empty success
// or as a 403 that would confirm a cross-tenant id.
func TestCloneEnvironmentSurfacesNotFound(t *testing.T) {
	t.Parallel()

	cloner := fakeEnvironmentCloner{err: apierr.NotFound("environment", "env_ghost")}
	handler := cloneEnvironmentHandlerFor(auth.Identity{Principal: orgPrincipal("usr_acme_owner", "org_acme", policy.RoleOwner), Method: auth.MethodSession}, nil, cloner)

	rec := cloneEnvironment(handler, "env_ghost", "valid-key",
		`{"environment_id":"env_x","slug":"x","display_name":"X"}`)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

// TestCloneEnvironmentSurfacesSlugConflict proves a Conflict from the
// store (a slug collision in the inherited project) is rendered as a 409.
func TestCloneEnvironmentSurfacesSlugConflict(t *testing.T) {
	t.Parallel()

	cloner := fakeEnvironmentCloner{err: apierr.Conflict("an environment with this slug already exists in the project")}
	handler := cloneEnvironmentHandlerFor(auth.Identity{Principal: orgPrincipal("usr_acme_owner", "org_acme", policy.RoleOwner), Method: auth.MethodSession}, nil, cloner)

	rec := cloneEnvironment(handler, "env_acme_prod", "valid-key",
		`{"environment_id":"env_x","slug":"production","display_name":"Production"}`)

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusConflict, rec.Body.String())
	}
}

// TestCloneEnvironmentSurfacesInvalidInput proves a typed
// apierr.InvalidInput from the store (an invalid slug or display name) is
// rendered as a 400.
func TestCloneEnvironmentSurfacesInvalidInput(t *testing.T) {
	t.Parallel()

	cloner := fakeEnvironmentCloner{err: apierr.InvalidInput(apierr.FieldViolation{
		Field:  "slug",
		Reason: "must be a canonical slug",
	})}
	handler := cloneEnvironmentHandlerFor(auth.Identity{Principal: orgPrincipal("usr_acme_owner", "org_acme", policy.RoleOwner), Method: auth.MethodSession}, nil, cloner)

	rec := cloneEnvironment(handler, "env_acme_prod", "valid-key",
		`{"environment_id":"env_x","slug":"Not A Slug","display_name":"X"}`)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestCloneEnvironmentMissingClonerIsInternalError proves the handler
// reports a nil EnvironmentCloner as a typed internal error rather than
// serving a misleading success. The wiring goes through NewHandler so the
// request reaches the typed-internal guard inside cloneEnvironmentHandler.
func TestCloneEnvironmentMissingClonerIsInternalError(t *testing.T) {
	t.Parallel()

	a := fakeAuthenticator{identity: auth.Identity{Principal: orgPrincipal("usr_acme_owner", "org_acme", policy.RoleOwner), Method: auth.MethodSession}}
	handler := NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{},
		fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, nil, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)

	rec := cloneEnvironment(handler, "env_acme_prod", "valid-key",
		`{"environment_id":"env_x","slug":"x","display_name":"X"}`)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
}

// TestCloneEnvironmentUnauthenticatedReturns401 proves a request without
// credentials is rejected by RequireAuth before the cloner runs.
func TestCloneEnvironmentUnauthenticatedReturns401(t *testing.T) {
	t.Parallel()

	cloner := fakeEnvironmentCloner{err: stderrors.New("cloner must not be called")}
	handler := cloneEnvironmentHandlerFor(auth.Identity{}, auth.ErrNoCredentials, cloner)

	rec := cloneEnvironment(handler, "env_acme_prod", "",
		`{"environment_id":"env_x","slug":"x","display_name":"X"}`)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

// TestCloneEnvironmentOpenAPIRouteIsRegistered proves the route table
// publishes the operation — agents must be able to discover the public
// surface through /openapi.json. It pins operationId, the required
// action, RequiresAuth, and the documented success status (201).
func TestCloneEnvironmentOpenAPIRouteIsRegistered(t *testing.T) {
	t.Parallel()

	table := newRouteTable(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil,
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{},
		fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{})

	var found bool
	for _, rt := range table {
		if rt.endpoint.Method == http.MethodPost && rt.endpoint.Path == "/v1/environments/{environment_id}/clone" {
			found = true
			if rt.endpoint.OperationID != "cloneEnvironment" {
				t.Errorf("operation_id = %q, want cloneEnvironment", rt.endpoint.OperationID)
			}
			if rt.endpoint.RequiredAction != string(policy.ActionEnvironmentCreate) {
				t.Errorf("required_action = %q, want %q", rt.endpoint.RequiredAction, policy.ActionEnvironmentCreate)
			}
			if !rt.endpoint.RequiresAuth {
				t.Error("requires_auth = false, want true")
			}
			if rt.endpoint.SuccessStatus != http.StatusCreated {
				t.Errorf("success_status = %d, want %d", rt.endpoint.SuccessStatus, http.StatusCreated)
			}
			if len(rt.endpoint.PathParams) != 1 || rt.endpoint.PathParams[0].Name != "environment_id" {
				t.Errorf("path_params = %+v, want a single environment_id path param", rt.endpoint.PathParams)
			}
			break
		}
	}
	if !found {
		t.Fatalf("route POST /v1/environments/{environment_id}/clone not registered in route table")
	}
}
