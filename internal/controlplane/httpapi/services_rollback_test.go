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
// /v1/services/{service_id}/rollback (BE-0217 + BE-0218). The endpoint
// inserts a new deployments row whose source / source_ref are copied
// verbatim from a previously persisted terminal-succeeded deployment
// in the same service, then enqueues the durable provisioning job that
// mirrors the rollback into Dokploy — by writing the deployment row,
// the job, and an immutable audit record (Action 'deployment.rollback')
// through the DeploymentRollbacker port. The tests drive it through
// NewHandler with a fake Authenticator, the real policy engine, and a
// fake rollbacker — the same wiring a request hits in production,
// minus the database. The full role x tenant x grant-scope policy
// matrix lives in services_rollback_policy_test.go (BE-0219).
//
// deployment.rollback is a CapDeploy action: viewer is DENIED (CapRead
// only), support is DENIED (CapRead+CapSupport — support is a
// deliberate cross-tenant READ exception, never a deploy one). The
// happy-path tests authenticate as RoleOwner so they reach the
// handler. The role matrix is exhaustively covered in the policy test
// file.

// fakeDeploymentRollbacker is a canned DeploymentRollbacker for
// httpapi-layer tests. The zero value returns a zero deployment and no
// error, which is all the test helpers that never reach the handler
// need; the rollback tests set dep/err and read got back to prove the
// handler forwards the principal's home organization, the path
// service id, the request body's target deployment id, the request
// body's idempotency key, and the actor identity to the store layer
// unchanged.
type fakeDeploymentRollbacker struct {
	dep store.Deployment
	err error
	got *store.RollbackDeploymentInput
}

func (f fakeDeploymentRollbacker) Rollback(_ context.Context, in store.RollbackDeploymentInput) (store.Deployment, error) {
	if f.got != nil {
		*f.got = in
	}
	return f.dep, f.err
}

// rollbackServiceDeploymentSuccessEnvelope is the decoded shape of the
// POST /v1/services/{service_id}/rollback success envelope.
type rollbackServiceDeploymentSuccessEnvelope struct {
	SchemaVersion string `json:"schema_version"`
	OK            bool   `json:"ok"`
	RequestID     string `json:"request_id"`
	Data          struct {
		Deployment serviceDeployment `json:"deployment"`
	} `json:"data"`
}

// rollbackDeploymentViewerIdentity builds an org-wide viewer principal
// in homeOrgID. deployment.rollback is a CapDeploy action so a viewer
// is denied at the RequireAuth boundary, never reaching the handler.
func rollbackDeploymentViewerIdentity(homeOrgID, userID string) auth.Identity {
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

// rollbackServiceDeploymentHandlerFor builds the full NewHandler
// surface with an Authenticator that resolves every credential to id
// and the given DeploymentRollbacker. It is the production request
// path: the POST /v1/services/{service_id}/rollback route is wrapped
// in RequireAuth for action deployment.rollback.
func rollbackServiceDeploymentHandlerFor(id auth.Identity, authErr error, rollbacker DeploymentRollbacker) http.Handler {
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
		fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{},
		fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, rollbacker, fakeBreakGlassController{}, nil, nil)
}

// rollbackServiceDeployment issues POST
// /v1/services/{service_id}/rollback against handler with the given
// body. An empty token omits the Authorization header so the
// unauthenticated path is exercised.
func rollbackServiceDeployment(handler http.Handler, serviceID, token string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/services/"+serviceID+"/rollback", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func canonicalRollbackBody() []byte {
	return []byte(`{"target_deployment_id":"dep_canonical_target","idempotency_key":"idem-rollback-1"}`)
}

func decodeRollbackServiceDeployment(t *testing.T, rec *httptest.ResponseRecorder) rollbackServiceDeploymentSuccessEnvelope {
	t.Helper()
	var env rollbackServiceDeploymentSuccessEnvelope
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

// canonicalRollbackDeployment is the canned deployments row the
// happy-path tests render through serviceDeploymentOf. Status is
// 'queued' (the post-insert pre-converge value the rollbacker returns),
// Source / SourceRef are the values the rollback unit of work copied
// verbatim from the persisted target deployment row.
func canonicalRollbackDeployment() store.Deployment {
	created := time.Date(2026, 5, 16, 9, 0, 0, 0, time.UTC)
	return store.Deployment{
		ID:             "dep_canonical_rollback",
		OrganizationID: "org_acme",
		ProjectID:      "prj_acme_web",
		EnvironmentID:  "env_acme_prod",
		ServiceID:      "svc_acme_api",
		Source:         store.DeploymentSourceGit,
		SourceRef:      "main@abc123",
		Status:         store.DeploymentStatusQueued,
		RequestedBy:    "usr_owner",
		IdempotencyKey: "idem-rollback-1",
		Version:        1,
		CreatedAt:      created,
		UpdatedAt:      created,
	}
}

// TestRollbackServiceDeploymentSuccess proves the happy path renders
// 202 Accepted, uses the yalla.output.v1 envelope, projects the new
// rollback deployment with its copied source / source_ref, and
// forwards the principal's home organization id, the path service_id,
// the body's target_deployment_id, the body's idempotency_key, and
// the actor identity to the DeploymentRollbacker port.
func TestRollbackServiceDeploymentSuccess(t *testing.T) {
	t.Parallel()

	row := canonicalRollbackDeployment()
	var captured store.RollbackDeploymentInput
	rollbacker := fakeDeploymentRollbacker{dep: row, got: &captured}
	handler := rollbackServiceDeploymentHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, rollbacker)

	rec := rollbackServiceDeployment(handler, row.ServiceID, "valid-key", canonicalRollbackBody())

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	env := decodeRollbackServiceDeployment(t, rec)
	if env.Data.Deployment.ID != row.ID {
		t.Errorf("deployment.id = %q, want %q", env.Data.Deployment.ID, row.ID)
	}
	if env.Data.Deployment.Status != string(store.DeploymentStatusQueued) {
		t.Errorf("deployment.status = %q, want %q", env.Data.Deployment.Status, store.DeploymentStatusQueued)
	}
	if env.Data.Deployment.Source != string(row.Source) || env.Data.Deployment.SourceRef != row.SourceRef {
		t.Errorf("deployment.source / source_ref = (%q, %q), want (%q, %q) — the rollback row copies the target's source verbatim",
			env.Data.Deployment.Source, env.Data.Deployment.SourceRef, row.Source, row.SourceRef)
	}
	if captured.OrganizationID != "org_acme" {
		t.Errorf("forwarded organization_id = %q, want org_acme (principal home)", captured.OrganizationID)
	}
	if captured.ServiceID != row.ServiceID {
		t.Errorf("forwarded service_id = %q, want %q", captured.ServiceID, row.ServiceID)
	}
	if captured.TargetDeploymentID != "dep_canonical_target" {
		t.Errorf("forwarded target_deployment_id = %q, want dep_canonical_target", captured.TargetDeploymentID)
	}
	if captured.IdempotencyKey != "idem-rollback-1" {
		t.Errorf("forwarded idempotency_key = %q, want idem-rollback-1", captured.IdempotencyKey)
	}
	if captured.ActorID != "usr_owner" {
		t.Errorf("forwarded actor_id = %q, want usr_owner", captured.ActorID)
	}
	if captured.ActorOrgID != "org_acme" {
		t.Errorf("forwarded actor_org_id = %q, want org_acme", captured.ActorOrgID)
	}
}

// TestRollbackServiceDeploymentRejectsUnknownField proves the request
// body decoder is strict — an unknown field is a typed 400 that never
// reaches the rollbacker.
func TestRollbackServiceDeploymentRejectsUnknownField(t *testing.T) {
	t.Parallel()

	rollbacker := fakeDeploymentRollbacker{err: stderrors.New("rollbacker must not be called")}
	handler := rollbackServiceDeploymentHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, rollbacker)
	body := []byte(`{"target_deployment_id":"dep_target","idempotency_key":"idem-1","organization_id":"org_x"}`)

	rec := rollbackServiceDeployment(handler, "svc_acme_api", "valid-key", body)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestRollbackServiceDeploymentRejectsMalformedJSON proves a malformed
// JSON body is a typed 400 that never reaches the rollbacker.
func TestRollbackServiceDeploymentRejectsMalformedJSON(t *testing.T) {
	t.Parallel()

	rollbacker := fakeDeploymentRollbacker{err: stderrors.New("rollbacker must not be called")}
	handler := rollbackServiceDeploymentHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, rollbacker)

	rec := rollbackServiceDeployment(handler, "svc_acme_api", "valid-key", []byte(`{"target_deployment_id":`))

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestRollbackServiceDeploymentForwardsValidationToStore proves the
// handler delegates field-shape validation to the store layer — a
// typed InvalidInput from the rollbacker is rendered as a 400.
func TestRollbackServiceDeploymentForwardsValidationToStore(t *testing.T) {
	t.Parallel()

	rollbacker := fakeDeploymentRollbacker{err: apierr.InvalidInput(apierr.FieldViolation{Field: "idempotency_key", Reason: "must not be blank"})}
	handler := rollbackServiceDeploymentHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, rollbacker)
	body := []byte(`{"target_deployment_id":"dep_target","idempotency_key":""}`)

	rec := rollbackServiceDeployment(handler, "svc_acme_api", "valid-key", body)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
}

// TestRollbackServiceDeploymentIgnoresOrganizationIDInBody proves the
// handler ignores body-level organization_id / project_id /
// environment_id / service_id fields (rejected by the strict
// decoder) — the wire-level tenant boundary is structural.
func TestRollbackServiceDeploymentIgnoresOrganizationIDInBody(t *testing.T) {
	t.Parallel()

	rollbacker := fakeDeploymentRollbacker{err: stderrors.New("rollbacker must not be called")}
	handler := rollbackServiceDeploymentHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, rollbacker)
	body := []byte(`{"target_deployment_id":"dep_target","idempotency_key":"idem-1","service_id":"svc_attacker"}`)

	rec := rollbackServiceDeployment(handler, "svc_acme_api", "valid-key", body)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (strict decoder rejects unknown service_id); body %s",
			rec.Code, rec.Body.String())
	}
}

// TestRollbackServiceDeploymentUnauthenticated proves a missing bearer
// token is rejected by RequireAuth before the rollbacker runs — no
// service id, target deployment id, or idempotency key can leak.
func TestRollbackServiceDeploymentUnauthenticated(t *testing.T) {
	t.Parallel()

	rollbacker := fakeDeploymentRollbacker{
		dep: canonicalRollbackDeployment(),
		err: stderrors.New("rollbacker must not be called"),
	}
	handler := rollbackServiceDeploymentHandlerFor(auth.Identity{}, auth.ErrNoCredentials, rollbacker)

	rec := rollbackServiceDeployment(handler, "svc_acme_api", "", canonicalRollbackBody())

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

// TestRollbackServiceDeploymentForbidden proves a CapRead-only
// principal (viewer) is denied by RequireAuth for the CapDeploy
// deployment.rollback action before the handler runs.
func TestRollbackServiceDeploymentForbidden(t *testing.T) {
	t.Parallel()

	rollbacker := fakeDeploymentRollbacker{err: stderrors.New("rollbacker must not be called")}
	handler := rollbackServiceDeploymentHandlerFor(rollbackDeploymentViewerIdentity("org_acme", "usr_viewer"), nil, rollbacker)

	rec := rollbackServiceDeployment(handler, "svc_acme_api", "valid-key", canonicalRollbackBody())

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

// TestRollbackServiceDeploymentNotFound proves the typed store-layer
// NotFound — the disposition for a cross-tenant or unknown service_id,
// or a target deployment that belongs to another tenant / another
// service — is rendered as a 404, never as a silent success that
// would emit a misleading audit record.
func TestRollbackServiceDeploymentNotFound(t *testing.T) {
	t.Parallel()

	rollbacker := fakeDeploymentRollbacker{err: apierr.NotFound("service", "svc_missing")}
	handler := rollbackServiceDeploymentHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, rollbacker)

	rec := rollbackServiceDeployment(handler, "svc_missing", "valid-key", canonicalRollbackBody())

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

// TestRollbackServiceDeploymentTargetNotSucceededConflict proves a 409
// from the store — the target deployment is in a non-succeeded
// lifecycle status (queued / running / failed / cancelled /
// rolled_back) — is rendered as a 409. A rollback target must be a
// known-good deployment.
func TestRollbackServiceDeploymentTargetNotSucceededConflict(t *testing.T) {
	t.Parallel()

	rollbacker := fakeDeploymentRollbacker{err: apierr.Conflict("the target deployment must be in the 'succeeded' status to roll back to")}
	handler := rollbackServiceDeploymentHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, rollbacker)

	rec := rollbackServiceDeployment(handler, "svc_acme_api", "valid-key", canonicalRollbackBody())

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409; body %s", rec.Code, rec.Body.String())
	}
}

// TestRollbackServiceDeploymentServiceScheduledForDeletionConflict
// proves a 409 from the store — the parent service is already
// scheduled for deletion — is rendered as a 409. A rollback cannot
// land on a service whose teardown is queued.
func TestRollbackServiceDeploymentServiceScheduledForDeletionConflict(t *testing.T) {
	t.Parallel()

	rollbacker := fakeDeploymentRollbacker{err: apierr.Conflict("the service is scheduled for deletion and cannot accept new deployments")}
	handler := rollbackServiceDeploymentHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, rollbacker)

	rec := rollbackServiceDeployment(handler, "svc_acme_api", "valid-key", canonicalRollbackBody())

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409; body %s", rec.Code, rec.Body.String())
	}
}

// TestRollbackServiceDeploymentStoreUnavailable proves a typed
// store-unavailable error is rendered as a 503 — the datastore outage
// surfaces as the typed 503, never disguised as a 500 leaking the pgx
// cause.
func TestRollbackServiceDeploymentStoreUnavailable(t *testing.T) {
	t.Parallel()

	rollbacker := fakeDeploymentRollbacker{err: apierr.StoreUnavailable(stderrors.New("pgx: dial tcp: connection refused"))}
	handler := rollbackServiceDeploymentHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, rollbacker)

	rec := rollbackServiceDeployment(handler, "svc_acme_api", "valid-key", canonicalRollbackBody())

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeUnavailable))
	if strings.Contains(rec.Body.String(), "dial tcp") || strings.Contains(rec.Body.String(), "connection refused") {
		t.Errorf("response leaks driver-level cause: %s", rec.Body.String())
	}
}

// TestRollbackServiceDeploymentCrossTenantNoForeignEcho proves the
// handler never trusts the path service_id to override the principal's
// home organization id: a cross-tenant service_id is reported as 404
// (the store's tenant-scoped existence check) — never disguised as a
// 200 with another tenant's data and never as a 403 that would confirm
// existence. The captured OrganizationID input is the principal's home
// org, not the path id.
func TestRollbackServiceDeploymentCrossTenantNoForeignEcho(t *testing.T) {
	t.Parallel()

	const (
		attackerOrg   = "org_attacker"
		victimSvc     = "svc_victim_owns"
		victimDep     = "dep_victim_target"
		victimOrgRoot = "org_victim"
	)
	var captured store.RollbackDeploymentInput
	rollbacker := fakeDeploymentRollbacker{
		err: apierr.NotFound("service", victimSvc),
		got: &captured,
	}

	handler := rollbackServiceDeploymentHandlerFor(
		ownerIdentity(attackerOrg, "usr_attacker"), nil, rollbacker)

	body := []byte(`{"target_deployment_id":"` + victimDep + `","idempotency_key":"idem-1"}`)
	rec := rollbackServiceDeployment(handler, victimSvc, "valid-key", body)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	if captured.OrganizationID != attackerOrg {
		t.Errorf("rollbacker received org id %q, want the attacker's home org %q (path service_id must never override)",
			captured.OrganizationID, attackerOrg)
	}
	if body := rec.Body.String(); strings.Contains(body, victimOrgRoot) {
		t.Errorf("response body %s echoed the cross-tenant organization id", body)
	}
}

// TestRollbackServiceDeploymentMissingRollbacker proves a wiring error
// (nil rollbacker reaching the handler) is reported as a typed
// internal error rather than a misleading success. The wiring goes
// through NewHandler so the request reaches the typed-internal guard
// inside rollbackServiceDeploymentHandler.
func TestRollbackServiceDeploymentMissingRollbacker(t *testing.T) {
	t.Parallel()

	handler := rollbackServiceDeploymentHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, nil)

	rec := rollbackServiceDeployment(handler, "svc_acme_api", "valid-key", canonicalRollbackBody())

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
}

// TestRollbackServiceDeploymentOpenAPIRouteIsRegistered proves the
// OpenAPI document carries the POST /v1/services/{service_id}/rollback
// operation with the stable operationId, the deployment.rollback
// required action, the services + deployments tags, and 202 Accepted
// success status — every detail an agent reads to discover the
// endpoint.
func TestRollbackServiceDeploymentOpenAPIRouteIsRegistered(t *testing.T) {
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
		fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{},
		fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{})

	var found bool
	for _, rt := range table {
		if rt.endpoint.Method == http.MethodPost && rt.endpoint.Path == "/v1/services/{service_id}/rollback" {
			found = true
			if rt.endpoint.OperationID != "rollbackServiceDeployment" {
				t.Errorf("operation_id = %q, want rollbackServiceDeployment", rt.endpoint.OperationID)
			}
			if rt.endpoint.RequiredAction != string(policy.ActionDeploymentRollback) {
				t.Errorf("required_action = %q, want %q", rt.endpoint.RequiredAction, policy.ActionDeploymentRollback)
			}
			if !rt.endpoint.RequiresAuth {
				t.Errorf("requires_auth = false, want true")
			}
			if rt.endpoint.SuccessStatus != http.StatusAccepted {
				t.Errorf("success_status = %d, want %d", rt.endpoint.SuccessStatus, http.StatusAccepted)
			}
			var hasServices, hasDeployments bool
			for _, tag := range rt.endpoint.Tags {
				if tag == tagServices {
					hasServices = true
				}
				if tag == tagDeployments {
					hasDeployments = true
				}
			}
			if !hasServices || !hasDeployments {
				t.Errorf("tags = %v, want both %q and %q", rt.endpoint.Tags, tagServices, tagDeployments)
			}
		}
	}
	if !found {
		t.Errorf("POST /v1/services/{service_id}/rollback not in route table")
	}
}
