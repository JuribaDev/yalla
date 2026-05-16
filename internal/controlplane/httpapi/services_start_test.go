package httpapi

import (
	"bytes"
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
// /v1/services/{service_id}/start (BE-0226 + BE-0227). The endpoint
// enqueues the durable provisioning job that mirrors a start into
// Dokploy and writes an immutable audit record (Action
// 'service.start') through the ServiceStarter port. The tests drive
// it through NewHandler with a fake Authenticator, the real policy
// engine, and a fake starter — the same wiring a request hits in
// production, minus the database. The full role x tenant x
// grant-scope policy matrix lives in services_start_policy_test.go
// (BE-0228).
//
// service.start is a CapDeploy action: viewer is DENIED (CapRead
// only), support is DENIED (CapRead+CapSupport — support is a
// deliberate cross-tenant READ exception, never a deploy one). The
// happy-path tests authenticate as RoleOwner so they reach the
// handler. The role matrix is exhaustively covered in the policy
// test file.

// fakeServiceStarter is a canned ServiceStarter for httpapi-layer
// tests. The zero value returns a zero service and no error, which is
// all the test helpers that never reach the handler need; the start
// tests set svc/err and read got back to prove the handler forwards
// the principal's home organization, the path service id, and the
// actor identity to the store layer unchanged.
type fakeServiceStarter struct {
	svc store.Service
	err error
	got *store.StartServiceInput
}

func (f fakeServiceStarter) Start(_ context.Context, in store.StartServiceInput) (store.Service, error) {
	if f.got != nil {
		*f.got = in
	}
	return f.svc, f.err
}

// startServiceSuccessEnvelope is the decoded shape of the POST
// /v1/services/{service_id}/start success envelope.
type startServiceSuccessEnvelope struct {
	SchemaVersion string `json:"schema_version"`
	OK            bool   `json:"ok"`
	RequestID     string `json:"request_id"`
	Data          struct {
		Service environmentService `json:"service"`
	} `json:"data"`
}

// startServiceViewerIdentity builds an org-wide viewer principal in
// homeOrgID. service.start is a CapDeploy action so a viewer is
// denied at the RequireAuth boundary, never reaching the handler.
func startServiceViewerIdentity(homeOrgID, userID string) auth.Identity {
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

// startServiceHandlerFor builds the full NewHandler surface with an
// Authenticator that resolves every credential to id and the given
// ServiceStarter. It is the production request path: the POST
// /v1/services/{service_id}/start route is wrapped in RequireAuth for
// action service.start.
func startServiceHandlerFor(id auth.Identity, authErr error, starter ServiceStarter) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
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
		fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, starter, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{},
		fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
}

// startService issues POST /v1/services/{service_id}/start against
// handler with the given body. An empty token omits the Authorization
// header so the unauthenticated path is exercised.
func startService(handler http.Handler, serviceID, token string, body []byte) *httptest.ResponseRecorder {
	var reader *bytes.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	var req *http.Request
	if reader == nil {
		req = httptest.NewRequest(http.MethodPost, "/v1/services/"+serviceID+"/start", nil)
	} else {
		req = httptest.NewRequest(http.MethodPost, "/v1/services/"+serviceID+"/start", reader)
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeStartService(t *testing.T, rec *httptest.ResponseRecorder) startServiceSuccessEnvelope {
	t.Helper()
	var env startServiceSuccessEnvelope
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

// canonicalStartedSvc is the canned services row the happy-path tests
// render through environmentServiceOf. Start does NOT mutate the
// persisted service row, so the projection mirrors the current row
// as-is.
func canonicalStartedSvc() store.Service {
	created := time.Date(2026, 5, 16, 9, 0, 0, 0, time.UTC)
	return store.Service{
		ID:             "svc_canonical_start",
		OrganizationID: "org_acme",
		ProjectID:      "prj_acme_web",
		EnvironmentID:  "env_acme_prod",
		Slug:           "api",
		DisplayName:    "API",
		Kind:           store.ServiceKindApplication,
		Version:        7,
		CreatedAt:      created,
		UpdatedAt:      created,
	}
}

// TestStartServiceSuccess proves the happy path renders 202 Accepted,
// uses the yalla.output.v1 envelope, projects the current service
// row, and forwards the principal's home organization id, the path
// service_id, and the actor identity to the ServiceStarter port.
// Start is fire-and-forget, so the request body is empty.
func TestStartServiceSuccess(t *testing.T) {
	t.Parallel()

	row := canonicalStartedSvc()
	var captured store.StartServiceInput
	starter := fakeServiceStarter{svc: row, got: &captured}
	handler := startServiceHandlerFor(ownerIdentity(row.OrganizationID, "usr_owner"), nil, starter)

	rec := startService(handler, row.ID, "valid-key", nil)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	env := decodeStartService(t, rec)
	if env.Data.Service.ID != row.ID {
		t.Errorf("service.id = %q, want %q", env.Data.Service.ID, row.ID)
	}
	if env.Data.Service.Slug != row.Slug {
		t.Errorf("service.slug = %q, want %q", env.Data.Service.Slug, row.Slug)
	}
	if captured.OrganizationID != row.OrganizationID {
		t.Errorf("forwarded organization_id = %q, want %q (principal home)", captured.OrganizationID, row.OrganizationID)
	}
	if captured.ServiceID != row.ID {
		t.Errorf("forwarded service_id = %q, want %q", captured.ServiceID, row.ID)
	}
	if captured.ActorID != "usr_owner" {
		t.Errorf("forwarded actor_id = %q, want usr_owner", captured.ActorID)
	}
	if captured.ActorOrgID != row.OrganizationID {
		t.Errorf("forwarded actor_org_id = %q, want %q", captured.ActorOrgID, row.OrganizationID)
	}
}

// TestStartServiceUnauthenticated proves a missing bearer token is
// rejected by RequireAuth before the starter runs.
func TestStartServiceUnauthenticated(t *testing.T) {
	t.Parallel()

	starter := fakeServiceStarter{
		svc: canonicalStartedSvc(),
		err: stderrors.New("starter must not be called"),
	}
	handler := startServiceHandlerFor(auth.Identity{}, auth.ErrNoCredentials, starter)

	rec := startService(handler, "svc_acme_api", "", nil)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

// TestStartServiceForbidden proves a CapRead-only principal (viewer)
// is denied by RequireAuth for the CapDeploy service.start action
// before the handler runs.
func TestStartServiceForbidden(t *testing.T) {
	t.Parallel()

	starter := fakeServiceStarter{err: stderrors.New("starter must not be called")}
	handler := startServiceHandlerFor(startServiceViewerIdentity("org_acme", "usr_viewer"), nil, starter)

	rec := startService(handler, "svc_acme_api", "valid-key", nil)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

// TestStartServiceNotFound proves the typed store-layer NotFound —
// the disposition for a cross-tenant or unknown service_id — is
// rendered as a 404, never as a silent success that would emit a
// misleading audit record.
func TestStartServiceNotFound(t *testing.T) {
	t.Parallel()

	starter := fakeServiceStarter{err: apierr.NotFound("service", "svc_missing")}
	handler := startServiceHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, starter)

	rec := startService(handler, "svc_missing", "valid-key", nil)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

// TestStartServiceScheduledForDeletionConflict proves a 409 from the
// store — the parent service is already scheduled for deletion — is
// rendered as a 409. A start cannot land on a service whose teardown
// is queued.
func TestStartServiceScheduledForDeletionConflict(t *testing.T) {
	t.Parallel()

	starter := fakeServiceStarter{err: apierr.Conflict("the service is scheduled for deletion and cannot accept new operations")}
	handler := startServiceHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, starter)

	rec := startService(handler, "svc_acme_api", "valid-key", nil)

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409; body %s", rec.Code, rec.Body.String())
	}
}

// TestStartServiceStoreUnavailable proves a typed store-unavailable
// error is rendered as a 503 — the datastore outage surfaces as the
// typed 503, never disguised as a 500 leaking the pgx cause.
func TestStartServiceStoreUnavailable(t *testing.T) {
	t.Parallel()

	starter := fakeServiceStarter{err: apierr.StoreUnavailable(stderrors.New("pgx: dial tcp: connection refused"))}
	handler := startServiceHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, starter)

	rec := startService(handler, "svc_acme_api", "valid-key", nil)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeUnavailable))
	if strings.Contains(rec.Body.String(), "dial tcp") || strings.Contains(rec.Body.String(), "connection refused") {
		t.Errorf("response leaks driver-level cause: %s", rec.Body.String())
	}
}

// TestStartServiceCrossTenantNoForeignEcho proves the handler never
// trusts the path service_id to override the principal's home
// organization id: a cross-tenant service_id is reported as 404 (the
// store's tenant-scoped existence check) — never disguised as a 200
// with another tenant's data and never as a 403 that would confirm
// existence. The captured OrganizationID input is the principal's
// home org, not the path id.
func TestStartServiceCrossTenantNoForeignEcho(t *testing.T) {
	t.Parallel()

	const (
		attackerOrg = "org_attacker"
		victimSvc   = "svc_victim_owns"
		victimOrg   = "org_victim"
	)
	var captured store.StartServiceInput
	starter := fakeServiceStarter{
		err: apierr.NotFound("service", victimSvc),
		got: &captured,
	}

	handler := startServiceHandlerFor(ownerIdentity(attackerOrg, "usr_attacker"), nil, starter)

	rec := startService(handler, victimSvc, "valid-key", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	if captured.OrganizationID != attackerOrg {
		t.Errorf("starter received org id %q, want the attacker's home org %q (path service_id must never override)",
			captured.OrganizationID, attackerOrg)
	}
	if body := rec.Body.String(); strings.Contains(body, victimOrg) {
		t.Errorf("response body %s echoed the cross-tenant organization id", body)
	}
}

// TestStartServiceMissingStarter proves a wiring error (nil starter
// reaching the handler) is reported as a typed internal error rather
// than a misleading success. The wiring goes through NewHandler so
// the request reaches the typed-internal guard inside
// startServiceHandler.
func TestStartServiceMissingStarter(t *testing.T) {
	t.Parallel()

	handler := startServiceHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, nil)

	rec := startService(handler, "svc_acme_api", "valid-key", nil)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
}

// TestStartServiceOpenAPIRouteIsRegistered proves the OpenAPI
// document carries the POST /v1/services/{service_id}/start operation
// with the stable operationId, the service.start required action, the
// services tag, and 202 Accepted success status — every detail an
// agent reads to discover the endpoint.
func TestStartServiceOpenAPIRouteIsRegistered(t *testing.T) {
	t.Parallel()

	table := newRouteTable(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil,
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
		fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{},
		fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{})

	var found bool
	for _, rt := range table {
		if rt.endpoint.Method == http.MethodPost && rt.endpoint.Path == "/v1/services/{service_id}/start" {
			found = true
			if rt.endpoint.OperationID != "startService" {
				t.Errorf("operation_id = %q, want startService", rt.endpoint.OperationID)
			}
			if rt.endpoint.RequiredAction != string(policy.ActionServiceStart) {
				t.Errorf("required_action = %q, want %q", rt.endpoint.RequiredAction, policy.ActionServiceStart)
			}
			if !rt.endpoint.RequiresAuth {
				t.Errorf("requires_auth = false, want true")
			}
			if rt.endpoint.SuccessStatus != http.StatusAccepted {
				t.Errorf("success_status = %d, want %d", rt.endpoint.SuccessStatus, http.StatusAccepted)
			}
			var hasServices bool
			for _, tag := range rt.endpoint.Tags {
				if tag == tagServices {
					hasServices = true
				}
			}
			if !hasServices {
				t.Errorf("tags = %v, want %q", rt.endpoint.Tags, tagServices)
			}
		}
	}
	if !found {
		t.Errorf("POST /v1/services/{service_id}/start not in route table")
	}
}
