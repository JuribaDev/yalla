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
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// Contract tests for POST /v1/services/{service_id}/restore. The route
// is gated by RequireAuth on action service.restore through
// serviceIDResolver — a CapWrite action authorized against the
// (principal home organization, {service_id}) resource. These tests
// drive the real NewHandler with a fake Authenticator, the real
// policy engine, and a fake ServiceRestorer — the same wiring a
// request hits in production, minus the database. The store-backed
// orchestrator (store.ServiceService.Restore) has its own
// isolated-Postgres integration coverage in
// store/service_restore_test.go.

// fakeServiceRestorer is a canned ServiceRestorer for httpapi tests.
// The zero value returns a zero service and no error, which is all
// the test helpers that never reach the handler need; the restore
// tests set svc/err and read got back to prove the handler forwards
// the principal's home organization, the path service id, and the
// optional If-Match precondition to the store layer unchanged.
type fakeServiceRestorer struct {
	svc store.Service
	err error
	got *store.RestoreServiceInput
}

func (f fakeServiceRestorer) Restore(_ context.Context, in store.RestoreServiceInput) (store.Service, error) {
	if f.got != nil {
		*f.got = in
	}
	return f.svc, f.err
}

// restoreServiceSuccessEnvelope is the decoded shape of the POST
// /v1/services/{service_id}/restore success envelope.
type restoreServiceSuccessEnvelope struct {
	SchemaVersion string `json:"schema_version"`
	OK            bool   `json:"ok"`
	RequestID     string `json:"request_id"`
	Data          struct {
		Service environmentService `json:"service"`
	} `json:"data"`
}

// restoreServiceViewerIdentity builds an org-wide viewer principal in
// homeOrgID. service.restore is a CapWrite action so a viewer is
// denied at the RequireAuth boundary, never reaching the handler.
func restoreServiceViewerIdentity(homeOrgID, userID string) auth.Identity {
	return auth.Identity{
		Principal: policy.Principal{
			ID:             userID,
			Kind:           domain.KindUser,
			OrganizationID: homeOrgID,
			Role:           policy.RoleViewer,
		},
		Method: auth.MethodSession,
	}
}

// restoreServiceHandlerFor builds the full NewHandler surface with an
// Authenticator that resolves every credential to id and the given
// ServiceRestorer. It is the production request path: the POST
// /v1/services/{service_id}/restore route is wrapped in RequireAuth
// for action service.restore.
func restoreServiceHandlerFor(id auth.Identity, authErr error, restorer ServiceRestorer) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{},
		fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{},
		fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{},
		fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{},
		fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, restorer, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeBreakGlassController{}, nil, nil)
}

// restoreService issues POST /v1/services/{serviceID}/restore against
// handler, optionally with a bearer token.
func restoreService(handler http.Handler, serviceID, token string) *httptest.ResponseRecorder {
	return restoreServiceWithIfMatch(handler, serviceID, token, "")
}

// restoreServiceWithIfMatch issues POST /v1/services/{serviceID}/restore
// with an optional If-Match header. An empty ifMatch omits the header
// entirely so the optional precondition path remains exercised.
func restoreServiceWithIfMatch(handler http.Handler, serviceID, token, ifMatch string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/services/"+serviceID+"/restore", nil)
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

func decodeRestoreService(t *testing.T, rec *httptest.ResponseRecorder) restoreServiceSuccessEnvelope {
	t.Helper()
	var env restoreServiceSuccessEnvelope
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

// canonicalRestoredSvc is the canned services row the happy-path tests
// render through environmentServiceOf. DeletionScheduledAt is nil —
// the restore cleared it — and every other field is non-zero so the
// projection invariants are exercised on the wire.
func canonicalRestoredSvc() store.Service {
	return store.Service{
		ID:             "svc_canonical_restore",
		OrganizationID: "org_acme",
		ProjectID:      "prj_acme_web",
		EnvironmentID:  "env_acme_prod",
		Slug:           "api",
		DisplayName:    "API",
		Kind:           "application",
		Version:        12,
		CreatedAt:      time.Date(2025, 4, 11, 9, 30, 0, 0, time.UTC),
		UpdatedAt:      time.Date(2025, 5, 16, 13, 0, 0, 0, time.UTC),
	}
}

// TestRestoreServiceSuccess proves the happy path renders 200 OK, uses
// the yalla.output.v1 envelope, mirrors the row's authoritative
// version into the ETag response header, omits deletion_scheduled_at
// (the restore cleared it), and forwards the principal's home
// organization id, the path service_id, and the actor identity to the
// ServiceRestorer port.
func TestRestoreServiceSuccess(t *testing.T) {
	t.Parallel()

	row := canonicalRestoredSvc()
	var captured store.RestoreServiceInput
	restorer := fakeServiceRestorer{svc: row, got: &captured}
	handler := restoreServiceHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, restorer)

	rec := restoreService(handler, row.ID, "valid-key")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	env := decodeRestoreService(t, rec)
	if env.Data.Service.ID != row.ID {
		t.Errorf("service.id = %q, want %q", env.Data.Service.ID, row.ID)
	}
	if env.Data.Service.OrganizationID != row.OrganizationID {
		t.Errorf("service.organization_id = %q, want %q", env.Data.Service.OrganizationID, row.OrganizationID)
	}
	if env.Data.Service.Version != row.Version {
		t.Errorf("service.version = %d, want %d", env.Data.Service.Version, row.Version)
	}
	if env.Data.Service.DeletionScheduledAt != nil {
		t.Errorf("deletion_scheduled_at = %v, want nil (restored)", *env.Data.Service.DeletionScheduledAt)
	}
	if got, want := rec.Header().Get("ETag"), `"12"`; got != want {
		t.Errorf("ETag header = %q, want %q", got, want)
	}
	if captured.OrganizationID != "org_acme" {
		t.Errorf("forwarded organization_id = %q, want org_acme (principal home)", captured.OrganizationID)
	}
	if captured.ServiceID != row.ID {
		t.Errorf("forwarded service_id = %q, want %q", captured.ServiceID, row.ID)
	}
	if captured.ActorID != "usr_owner" {
		t.Errorf("forwarded actor_id = %q, want usr_owner", captured.ActorID)
	}
	if captured.ActorOrgID != "org_acme" {
		t.Errorf("forwarded actor_org_id = %q, want org_acme", captured.ActorOrgID)
	}
	if captured.IfMatchVersion != nil {
		t.Errorf("forwarded if_match_version = %v, want nil (no header)", *captured.IfMatchVersion)
	}
}

// TestRestoreServiceForwardsIfMatch proves a strong-ETag If-Match
// header is parsed and forwarded as the optimistic-concurrency
// precondition.
func TestRestoreServiceForwardsIfMatch(t *testing.T) {
	t.Parallel()

	var captured store.RestoreServiceInput
	restorer := fakeServiceRestorer{svc: canonicalRestoredSvc(), got: &captured}
	handler := restoreServiceHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, restorer)

	rec := restoreServiceWithIfMatch(handler, "svc_canonical_restore", "valid-key", `"11"`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if captured.IfMatchVersion == nil {
		t.Fatal("forwarded if_match_version is nil, want 11")
	}
	if *captured.IfMatchVersion != 11 {
		t.Errorf("forwarded if_match_version = %d, want 11", *captured.IfMatchVersion)
	}
}

// TestRestoreServiceRejectsMalformedIfMatch proves a weak/wildcard
// If-Match value is a stable 400 E_INVALID_INPUT before the restorer
// runs — the malformed precondition is a client error, not a silent
// next-write-wins pass-through.
func TestRestoreServiceRejectsMalformedIfMatch(t *testing.T) {
	t.Parallel()

	restorer := fakeServiceRestorer{err: stderrors.New("restorer must not be called")}
	handler := restoreServiceHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, restorer)

	rec := restoreServiceWithIfMatch(handler, "svc_canonical_restore", "valid-key", `W/"11"`)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestRestoreServiceUnauthenticated proves a missing bearer token is
// rejected by RequireAuth before the restorer runs.
func TestRestoreServiceUnauthenticated(t *testing.T) {
	t.Parallel()

	restorer := fakeServiceRestorer{err: stderrors.New("restorer must not be called")}
	handler := restoreServiceHandlerFor(auth.Identity{}, auth.ErrNoCredentials, restorer)

	rec := restoreService(handler, "svc_canonical_restore", "")

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

// TestRestoreServiceForbidden proves a CapRead-only principal
// (viewer) is denied by RequireAuth for the CapWrite service.restore
// action before the handler runs.
func TestRestoreServiceForbidden(t *testing.T) {
	t.Parallel()

	restorer := fakeServiceRestorer{err: stderrors.New("restorer must not be called")}
	handler := restoreServiceHandlerFor(restoreServiceViewerIdentity("org_acme", "usr_viewer"), nil, restorer)

	rec := restoreService(handler, "svc_canonical_restore", "valid-key")

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

// TestRestoreServiceNotFound proves the typed store-layer NotFound is
// rendered as a 404 — never disguised as an empty success.
func TestRestoreServiceNotFound(t *testing.T) {
	t.Parallel()

	restorer := fakeServiceRestorer{err: apierr.NotFound("service", "svc_missing")}
	handler := restoreServiceHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, restorer)

	rec := restoreService(handler, "svc_missing", "valid-key")

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

// TestRestoreServiceNotScheduledConflict proves the
// not-scheduled-for-deletion Conflict from the store is rendered as a
// 409 — the caller's view of the resource lifecycle is stale, so a
// silent success would write a misleading audit record.
func TestRestoreServiceNotScheduledConflict(t *testing.T) {
	t.Parallel()

	restorer := fakeServiceRestorer{err: apierr.Conflict("service is not scheduled for deletion")}
	handler := restoreServiceHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, restorer)

	rec := restoreService(handler, "svc_canonical_restore", "valid-key")

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusConflict, rec.Body.String())
	}
}

// TestRestoreServiceStaleVersion proves the typed store-layer
// ConflictStale is rendered as a 409 carrying the row's current
// version under details.current_version, so an agent can retry with
// the authoritative If-Match without re-reading the row.
func TestRestoreServiceStaleVersion(t *testing.T) {
	t.Parallel()

	restorer := fakeServiceRestorer{err: apierr.ConflictStale(13)}
	handler := restoreServiceHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, restorer)

	rec := restoreServiceWithIfMatch(handler, "svc_canonical_restore", "valid-key", `"11"`)

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusConflict, rec.Body.String())
	}
}

// TestRestoreServiceStoreUnavailable proves a typed store-unavailable
// error is rendered as a 503.
func TestRestoreServiceStoreUnavailable(t *testing.T) {
	t.Parallel()

	restorer := fakeServiceRestorer{err: apierr.StoreUnavailable(stderrors.New("network blip"))}
	handler := restoreServiceHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, restorer)

	rec := restoreService(handler, "svc_canonical_restore", "valid-key")

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}
}

// TestRestoreServiceMissingRestorer proves a wiring error (nil
// restorer reaching the handler) is reported as a typed internal
// error rather than a misleading success. The wiring goes through
// NewHandler so the request reaches the typed-internal guard inside
// restoreServiceHandler.
func TestRestoreServiceMissingRestorer(t *testing.T) {
	t.Parallel()

	handler := restoreServiceHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, nil)

	rec := restoreService(handler, "svc_canonical_restore", "valid-key")

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
}

// TestRestoreServiceOpenAPIOperation proves the route table publishes
// the operation under the documented operation id and action — agents
// must be able to discover the public surface through /openapi.json.
func TestRestoreServiceOpenAPIOperation(t *testing.T) {
	t.Parallel()

	table := newRouteTable(runtime.BuildInfo{Version: "1.0.0"}, nil, nil,
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{},
		fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{},
		fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{},
		fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{},
		fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeBreakGlassController{})

	var found bool
	for _, rt := range table {
		if rt.endpoint.Method == http.MethodPost && rt.endpoint.Path == "/v1/services/{service_id}/restore" {
			found = true
			if rt.endpoint.OperationID != "restoreService" {
				t.Errorf("operation_id = %q, want restoreService", rt.endpoint.OperationID)
			}
			if rt.endpoint.RequiredAction != string(policy.ActionServiceRestore) {
				t.Errorf("required_action = %q, want %q", rt.endpoint.RequiredAction, policy.ActionServiceRestore)
			}
			if !rt.endpoint.RequiresAuth {
				t.Error("requires_auth = false, want true")
			}
			if rt.endpoint.SuccessStatus != 0 && rt.endpoint.SuccessStatus != http.StatusOK {
				t.Errorf("success_status = %d, want 0 (default 200) or %d", rt.endpoint.SuccessStatus, http.StatusOK)
			}
			break
		}
	}
	if !found {
		t.Fatalf("route POST /v1/services/{service_id}/restore not registered in route table")
	}
}
