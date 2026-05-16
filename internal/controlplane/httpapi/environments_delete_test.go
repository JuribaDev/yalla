package httpapi

import (
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

// Contract tests for DELETE /v1/environments/{environment_id}. The route
// is gated by RequireAuth on action environment.delete through
// environmentIDResolver — a CapWrite action authorized against the
// (principal home organization, {environment_id}) resource. These tests
// drive the real NewHandler with a fake Authenticator, the real policy
// engine, and a fake EnvironmentDeleter — the same wiring a request
// hits in production, minus the database. The store-backed orchestrator
// (store.EnvironmentService.ScheduleDeletion) has its own
// isolated-Postgres integration coverage in store/environment_delete_test.go.
//
// The fuller "every principal class × every authorization edge" matrix
// for this route lives in environments_delete_policy_test.go (BE-0162).

// deleteEnvironmentSuccessEnvelope is the decoded shape of the DELETE
// /v1/environments/{environment_id} success envelope.
type deleteEnvironmentSuccessEnvelope struct {
	SchemaVersion string `json:"schema_version"`
	OK            bool   `json:"ok"`
	RequestID     string `json:"request_id"`
	Data          struct {
		Environment projectEnvironment `json:"environment"`
	} `json:"data"`
}

// deleteEnvironmentHandlerFor builds the full NewHandler surface with an
// Authenticator that resolves every credential to id and the given
// EnvironmentDeleter. It is the production request path: the DELETE
// /v1/environments/{environment_id} route is wrapped in RequireAuth for
// action environment.delete.
func deleteEnvironmentHandlerFor(id auth.Identity, authErr error, deleter EnvironmentDeleter) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{},
		fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, deleter, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
}

// deleteEnvironment issues DELETE /v1/environments/{environmentID} against
// the handler with the supplied bearer token.
func deleteEnvironment(handler http.Handler, environmentID, token string) *httptest.ResponseRecorder {
	return deleteEnvironmentWithIfMatch(handler, environmentID, token, "")
}

// deleteEnvironmentWithIfMatch issues DELETE
// /v1/environments/{environmentID} with an optional If-Match header. An
// empty ifMatch omits the header entirely so the optional precondition
// path remains exercised.
func deleteEnvironmentWithIfMatch(handler http.Handler, environmentID, token, ifMatch string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodDelete, "/v1/environments/"+environmentID, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if ifMatch != "" {
		req.Header.Set("If-Match", ifMatch)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeDeleteEnvironment(t *testing.T, rec *httptest.ResponseRecorder) deleteEnvironmentSuccessEnvelope {
	t.Helper()
	var env deleteEnvironmentSuccessEnvelope
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

// TestDeleteEnvironmentHappyPathForwardsPrincipalAndScheduling proves the
// handler threads the principal's home organization and the path's
// environment id into the store input, renders the returned row — with
// its deletion_scheduled_at stamp — in the stable yalla.output.v1
// envelope, returns 202 Accepted because the destructive teardown is
// scheduled rather than immediate, and mirrors the row's authoritative
// version into the ETag response header so the caller can echo it back
// as the next If-Match precondition.
func TestDeleteEnvironmentHappyPathForwardsPrincipalAndScheduling(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	updated := created.Add(time.Minute)
	scheduled := updated.Add(time.Minute)
	row := store.Environment{
		ID:                  "env_acme_prod",
		OrganizationID:      "org_acme",
		ProjectID:           "prj_acme_web",
		Slug:                "production",
		DisplayName:         "Production",
		Version:             4,
		CreatedAt:           created,
		UpdatedAt:           updated,
		DeletionScheduledAt: &scheduled,
	}
	var captured store.DeleteEnvironmentInput
	deleter := fakeEnvironmentDeleter{env: row, gotInput: &captured}
	handler := deleteEnvironmentHandlerFor(auth.Identity{Principal: orgPrincipal("usr_acme_owner", "org_acme", policy.RoleOwner), Method: auth.MethodSession}, nil, deleter)

	rec := deleteEnvironment(handler, "env_acme_prod", "valid-key")

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	env := decodeDeleteEnvironment(t, rec)
	if env.Data.Environment.ID != row.ID {
		t.Errorf("id = %q, want %q", env.Data.Environment.ID, row.ID)
	}
	if env.Data.Environment.OrganizationID != row.OrganizationID {
		t.Errorf("organization_id = %q, want %q", env.Data.Environment.OrganizationID, row.OrganizationID)
	}
	if env.Data.Environment.ProjectID != row.ProjectID {
		t.Errorf("project_id = %q, want %q", env.Data.Environment.ProjectID, row.ProjectID)
	}
	if env.Data.Environment.Version != row.Version {
		t.Errorf("version = %d, want %d", env.Data.Environment.Version, row.Version)
	}
	if env.Data.Environment.DeletionScheduledAt == nil {
		t.Fatal("deletion_scheduled_at is nil, want a stamp")
	}
	if *env.Data.Environment.DeletionScheduledAt != scheduled.Format(time.RFC3339Nano) {
		t.Errorf("deletion_scheduled_at = %q, want %q", *env.Data.Environment.DeletionScheduledAt, scheduled.Format(time.RFC3339Nano))
	}
	if got, want := rec.Header().Get("ETag"), `"4"`; got != want {
		t.Errorf("ETag header = %q, want %q", got, want)
	}
	if captured.OrganizationID != "org_acme" {
		t.Errorf("forwarded organization_id = %q, want org_acme (principal home)", captured.OrganizationID)
	}
	if captured.EnvironmentID != "env_acme_prod" {
		t.Errorf("forwarded environment_id = %q, want env_acme_prod", captured.EnvironmentID)
	}
	if captured.ActorID != "usr_acme_owner" {
		t.Errorf("forwarded actor_id = %q, want the resolved principal", captured.ActorID)
	}
	if captured.ActorOrgID != "org_acme" {
		t.Errorf("forwarded actor_org_id = %q, want the principal's home org", captured.ActorOrgID)
	}
	if captured.IfMatchVersion != nil {
		t.Errorf("forwarded if_match_version = %v, want nil (no header)", *captured.IfMatchVersion)
	}
}

// TestDeleteEnvironmentForwardsIfMatchVersion proves a strong-ETag
// If-Match header is parsed and forwarded as the optimistic-concurrency
// precondition.
func TestDeleteEnvironmentForwardsIfMatchVersion(t *testing.T) {
	t.Parallel()

	stamp := time.Now().UTC()
	row := store.Environment{
		ID:                  "env_acme_prod",
		OrganizationID:      "org_acme",
		ProjectID:           "prj_acme_web",
		Slug:                "production",
		DisplayName:         "Production",
		Version:             5,
		DeletionScheduledAt: &stamp,
	}
	var captured store.DeleteEnvironmentInput
	deleter := fakeEnvironmentDeleter{env: row, gotInput: &captured}
	handler := deleteEnvironmentHandlerFor(auth.Identity{Principal: orgPrincipal("usr_acme_owner", "org_acme", policy.RoleOwner), Method: auth.MethodSession}, nil, deleter)

	rec := deleteEnvironmentWithIfMatch(handler, "env_acme_prod", "valid-key", `"4"`)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	if captured.IfMatchVersion == nil {
		t.Fatal("forwarded if_match_version is nil, want 4")
	}
	if *captured.IfMatchVersion != 4 {
		t.Errorf("forwarded if_match_version = %d, want 4", *captured.IfMatchVersion)
	}
}

// TestDeleteEnvironmentRejectsMalformedIfMatch proves a weak/wildcard/multi
// If-Match value is a stable 400 E_INVALID_INPUT before the deleter runs —
// the malformed precondition is a client error, not a silent next-write-wins
// pass-through.
func TestDeleteEnvironmentRejectsMalformedIfMatch(t *testing.T) {
	t.Parallel()

	deleter := fakeEnvironmentDeleter{err: stderrors.New("deleter must not be called")}
	handler := deleteEnvironmentHandlerFor(auth.Identity{Principal: orgPrincipal("usr_acme_owner", "org_acme", policy.RoleOwner), Method: auth.MethodSession}, nil, deleter)

	rec := deleteEnvironmentWithIfMatch(handler, "env_acme_prod", "valid-key", `W/"4"`)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestDeleteEnvironmentSurfacesNotFound proves a NotFound from the store
// is rendered as a 404 error envelope — never disguised as an empty
// success.
func TestDeleteEnvironmentSurfacesNotFound(t *testing.T) {
	t.Parallel()

	deleter := fakeEnvironmentDeleter{err: apierr.NotFound("environment", "env_ghost")}
	handler := deleteEnvironmentHandlerFor(auth.Identity{Principal: orgPrincipal("usr_acme_owner", "org_acme", policy.RoleOwner), Method: auth.MethodSession}, nil, deleter)

	rec := deleteEnvironment(handler, "env_ghost", "valid-key")

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

// TestDeleteEnvironmentSurfacesAlreadyScheduledConflict proves the
// already-scheduled Conflict from the store is rendered as a 409 — the
// caller's view of the resource lifecycle is stale, so a silent success
// would write a misleading audit record.
func TestDeleteEnvironmentSurfacesAlreadyScheduledConflict(t *testing.T) {
	t.Parallel()

	deleter := fakeEnvironmentDeleter{err: apierr.Conflict("environment deletion is already scheduled")}
	handler := deleteEnvironmentHandlerFor(auth.Identity{Principal: orgPrincipal("usr_acme_owner", "org_acme", policy.RoleOwner), Method: auth.MethodSession}, nil, deleter)

	rec := deleteEnvironment(handler, "env_acme_prod", "valid-key")

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusConflict, rec.Body.String())
	}
}

// TestDeleteEnvironmentSurfacesStaleIfMatchConflict proves the
// ConflictStale from the store is rendered as a 409 — an agent can retry
// with the authoritative If-Match after reading details.current_version
// from the envelope.
func TestDeleteEnvironmentSurfacesStaleIfMatchConflict(t *testing.T) {
	t.Parallel()

	deleter := fakeEnvironmentDeleter{err: apierr.ConflictStale(7)}
	handler := deleteEnvironmentHandlerFor(auth.Identity{Principal: orgPrincipal("usr_acme_owner", "org_acme", policy.RoleOwner), Method: auth.MethodSession}, nil, deleter)

	rec := deleteEnvironmentWithIfMatch(handler, "env_acme_prod", "valid-key", `"4"`)

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusConflict, rec.Body.String())
	}
}

// TestDeleteEnvironmentMissingDeleterIsInternalError proves the handler
// reports a nil EnvironmentDeleter as a typed internal error rather than
// serving a misleading success. The wiring goes through NewHandler so
// the request reaches the typed-internal guard inside
// deleteEnvironmentHandler.
func TestDeleteEnvironmentMissingDeleterIsInternalError(t *testing.T) {
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
		fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, nil, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)

	rec := deleteEnvironment(handler, "env_acme_prod", "valid-key")

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
}

// TestDeleteEnvironmentUnauthenticatedReturns401 proves a request without
// credentials is rejected by RequireAuth before the deleter runs.
func TestDeleteEnvironmentUnauthenticatedReturns401(t *testing.T) {
	t.Parallel()

	deleter := fakeEnvironmentDeleter{err: stderrors.New("deleter must not be called")}
	handler := deleteEnvironmentHandlerFor(auth.Identity{}, auth.ErrNoCredentials, deleter)

	rec := deleteEnvironment(handler, "env_acme_prod", "")

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

// TestDeleteEnvironmentOpenAPIRouteIsRegistered proves the route table
// publishes the operation — agents must be able to discover the public
// surface through /openapi.json. It pins operationId, the required
// action, RequiresAuth, and the documented success status (202).
func TestDeleteEnvironmentOpenAPIRouteIsRegistered(t *testing.T) {
	t.Parallel()

	table := newRouteTable(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil,
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{},
		fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{})

	var found bool
	for _, rt := range table {
		if rt.endpoint.Method == http.MethodDelete && rt.endpoint.Path == "/v1/environments/{environment_id}" {
			found = true
			if rt.endpoint.OperationID != "deleteEnvironment" {
				t.Errorf("operation_id = %q, want deleteEnvironment", rt.endpoint.OperationID)
			}
			if rt.endpoint.RequiredAction != string(policy.ActionEnvironmentDelete) {
				t.Errorf("required_action = %q, want %q", rt.endpoint.RequiredAction, policy.ActionEnvironmentDelete)
			}
			if !rt.endpoint.RequiresAuth {
				t.Error("requires_auth = false, want true")
			}
			if rt.endpoint.SuccessStatus != http.StatusAccepted {
				t.Errorf("success_status = %d, want %d", rt.endpoint.SuccessStatus, http.StatusAccepted)
			}
			if len(rt.endpoint.PathParams) != 1 || rt.endpoint.PathParams[0].Name != "environment_id" {
				t.Errorf("path_params = %+v, want a single environment_id path param", rt.endpoint.PathParams)
			}
			break
		}
	}
	if !found {
		t.Fatalf("route DELETE /v1/environments/{environment_id} not registered in route table")
	}
}
