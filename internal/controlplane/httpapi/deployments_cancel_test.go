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
// /v1/deployments/{deployment_id}/cancel (BE-0214 + BE-0215). The
// endpoint transitions a non-terminal deployment to the terminal
// 'cancelled' status — by writing the lifecycle change and an
// immutable audit record through the DeploymentCanceler port. The
// tests drive it through NewHandler with a fake Authenticator, the
// real policy engine, and a fake canceler — the same wiring a request
// hits in production, minus the database. The full role x tenant x
// grant-scope policy matrix lives in deployments_cancel_policy_test.go
// (BE-0216).
//
// deployment.cancel is a CapDeploy action: viewer is DENIED (CapRead
// only), support is DENIED (CapRead+CapSupport — support is a
// deliberate cross-tenant READ exception, never a deploy one). The
// happy-path tests authenticate as RoleOwner so they reach the
// handler. The role matrix is exhaustively covered in the policy test
// file.

// fakeDeploymentCanceler is a canned DeploymentCanceler for httpapi-
// layer tests. The zero value returns a zero deployment and no error,
// which is all the test helpers that never reach the handler need;
// the cancel tests set dep/err and read got back to prove the handler
// forwards the principal's home organization, the path deployment id,
// the optional If-Match precondition, and the actor identity to the
// store layer unchanged.
type fakeDeploymentCanceler struct {
	dep store.Deployment
	err error
	got *store.CancelDeploymentInput
}

func (f fakeDeploymentCanceler) Cancel(_ context.Context, in store.CancelDeploymentInput) (store.Deployment, error) {
	if f.got != nil {
		*f.got = in
	}
	return f.dep, f.err
}

// cancelServiceDeploymentSuccessEnvelope is the decoded shape of the
// POST /v1/deployments/{deployment_id}/cancel success envelope.
type cancelServiceDeploymentSuccessEnvelope struct {
	SchemaVersion string `json:"schema_version"`
	OK            bool   `json:"ok"`
	RequestID     string `json:"request_id"`
	Data          struct {
		Deployment serviceDeployment `json:"deployment"`
	} `json:"data"`
}

// cancelDeploymentViewerIdentity builds an org-wide viewer principal
// in homeOrgID. deployment.cancel is a CapDeploy action so a viewer is
// denied at the RequireAuth boundary, never reaching the handler.
func cancelDeploymentViewerIdentity(homeOrgID, userID string) auth.Identity {
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

// cancelServiceDeploymentHandlerFor builds the full NewHandler surface
// with an Authenticator that resolves every credential to id and the
// given DeploymentCanceler. It is the production request path: the
// POST /v1/deployments/{deployment_id}/cancel route is wrapped in
// RequireAuth for action deployment.cancel.
func cancelServiceDeploymentHandlerFor(id auth.Identity, authErr error, canceler DeploymentCanceler) http.Handler {
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
		fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{},
		fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, canceler, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
}

// cancelServiceDeployment issues POST /v1/deployments/{deployment_id}/cancel
// against handler, optionally with a bearer token.
func cancelServiceDeployment(handler http.Handler, deploymentID, token string) *httptest.ResponseRecorder {
	return cancelServiceDeploymentWithIfMatch(handler, deploymentID, token, "")
}

// cancelServiceDeploymentWithIfMatch issues POST /v1/deployments/{deployment_id}/cancel
// with an optional If-Match header. An empty ifMatch omits the header
// entirely so the optional-precondition path remains exercised.
func cancelServiceDeploymentWithIfMatch(handler http.Handler, deploymentID, token, ifMatch string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/deployments/"+deploymentID+"/cancel", nil)
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

func decodeCancelServiceDeployment(t *testing.T, rec *httptest.ResponseRecorder) cancelServiceDeploymentSuccessEnvelope {
	t.Helper()
	var env cancelServiceDeploymentSuccessEnvelope
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

// canonicalCancelledDeployment is the canned deployments row the
// happy-path tests render through serviceDeploymentOf. Status is
// 'cancelled' (the post-transition value the canceler returns),
// FinishedAt is non-nil (the deployments_finished_consistent CHECK
// requires it on a terminal row), and Version is bumped to 4 so the
// ETag mirror is non-trivially asserted.
func canonicalCancelledDeployment() store.Deployment {
	started := time.Date(2026, 5, 16, 7, 30, 0, 0, time.UTC)
	finished := time.Date(2026, 5, 16, 7, 35, 0, 0, time.UTC)
	return store.Deployment{
		ID:             "dep_canonical_cancel",
		OrganizationID: "org_acme",
		ProjectID:      "prj_acme_web",
		EnvironmentID:  "env_acme_prod",
		ServiceID:      "svc_acme_api",
		Source:         store.DeploymentSourceGit,
		SourceRef:      "main@abc123",
		Status:         store.DeploymentStatusCancelled,
		RequestedBy:    "usr_owner",
		IdempotencyKey: "idem-cancel-1",
		Version:        4,
		CreatedAt:      time.Date(2026, 5, 16, 7, 28, 0, 0, time.UTC),
		UpdatedAt:      finished,
		StartedAt:      &started,
		FinishedAt:     &finished,
	}
}

// TestCancelServiceDeploymentSuccess proves the happy path renders 200
// OK, uses the yalla.output.v1 envelope, mirrors the row's
// authoritative version into the ETag response header, projects the
// terminal-cancelled deployment with its finished_at populated, and
// forwards the principal's home organization id, the path
// deployment_id, and the actor identity to the DeploymentCanceler
// port.
func TestCancelServiceDeploymentSuccess(t *testing.T) {
	t.Parallel()

	row := canonicalCancelledDeployment()
	var captured store.CancelDeploymentInput
	canceler := fakeDeploymentCanceler{dep: row, got: &captured}
	handler := cancelServiceDeploymentHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, canceler)

	rec := cancelServiceDeployment(handler, row.ID, "valid-key")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	env := decodeCancelServiceDeployment(t, rec)
	if env.Data.Deployment.ID != row.ID {
		t.Errorf("deployment.id = %q, want %q", env.Data.Deployment.ID, row.ID)
	}
	if env.Data.Deployment.Status != string(store.DeploymentStatusCancelled) {
		t.Errorf("deployment.status = %q, want %q", env.Data.Deployment.Status, store.DeploymentStatusCancelled)
	}
	if env.Data.Deployment.Version != row.Version {
		t.Errorf("deployment.version = %d, want %d", env.Data.Deployment.Version, row.Version)
	}
	if env.Data.Deployment.FinishedAt == nil {
		t.Error("deployment.finished_at = nil, want non-nil for a terminal row")
	}
	if got, want := rec.Header().Get("ETag"), `"4"`; got != want {
		t.Errorf("ETag header = %q, want %q", got, want)
	}
	if captured.OrganizationID != "org_acme" {
		t.Errorf("forwarded organization_id = %q, want org_acme (principal home)", captured.OrganizationID)
	}
	if captured.DeploymentID != row.ID {
		t.Errorf("forwarded deployment_id = %q, want %q", captured.DeploymentID, row.ID)
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

// TestCancelServiceDeploymentForwardsIfMatch proves a strong-ETag
// If-Match header is parsed and forwarded as the optimistic-
// concurrency precondition.
func TestCancelServiceDeploymentForwardsIfMatch(t *testing.T) {
	t.Parallel()

	var captured store.CancelDeploymentInput
	canceler := fakeDeploymentCanceler{dep: canonicalCancelledDeployment(), got: &captured}
	handler := cancelServiceDeploymentHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, canceler)

	rec := cancelServiceDeploymentWithIfMatch(handler, "dep_canonical_cancel", "valid-key", `"3"`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if captured.IfMatchVersion == nil {
		t.Fatal("forwarded if_match_version is nil, want 3")
	}
	if *captured.IfMatchVersion != 3 {
		t.Errorf("forwarded if_match_version = %d, want 3", *captured.IfMatchVersion)
	}
}

// TestCancelServiceDeploymentRejectsMalformedIfMatch proves a weak
// If-Match value is a stable 400 E_INVALID_INPUT before the canceler
// runs — the malformed precondition is a client error, not a silent
// next-write-wins pass-through.
func TestCancelServiceDeploymentRejectsMalformedIfMatch(t *testing.T) {
	t.Parallel()

	canceler := fakeDeploymentCanceler{err: stderrors.New("canceler must not be called")}
	handler := cancelServiceDeploymentHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, canceler)

	rec := cancelServiceDeploymentWithIfMatch(handler, "dep_canonical_cancel", "valid-key", `W/"3"`)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestCancelServiceDeploymentRejectsWildcardIfMatch proves the "*"
// wildcard form of If-Match is rejected with a typed 400 — for a
// state-changing request the strong-ETag precondition is the only
// meaningful form this API understands.
func TestCancelServiceDeploymentRejectsWildcardIfMatch(t *testing.T) {
	t.Parallel()

	canceler := fakeDeploymentCanceler{err: stderrors.New("canceler must not be called")}
	handler := cancelServiceDeploymentHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, canceler)

	rec := cancelServiceDeploymentWithIfMatch(handler, "dep_canonical_cancel", "valid-key", "*")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestCancelServiceDeploymentUnauthenticated proves a missing bearer
// token is rejected by RequireAuth before the canceler runs — no
// deployment id, source ref, or idempotency key can leak.
func TestCancelServiceDeploymentUnauthenticated(t *testing.T) {
	t.Parallel()

	canceler := fakeDeploymentCanceler{
		dep: canonicalCancelledDeployment(),
		err: stderrors.New("canceler must not be called"),
	}
	handler := cancelServiceDeploymentHandlerFor(auth.Identity{}, auth.ErrNoCredentials, canceler)

	rec := cancelServiceDeployment(handler, "dep_canonical_cancel", "")

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

// TestCancelServiceDeploymentForbidden proves a CapRead-only principal
// (viewer) is denied by RequireAuth for the CapDeploy
// deployment.cancel action before the handler runs.
func TestCancelServiceDeploymentForbidden(t *testing.T) {
	t.Parallel()

	canceler := fakeDeploymentCanceler{err: stderrors.New("canceler must not be called")}
	handler := cancelServiceDeploymentHandlerFor(cancelDeploymentViewerIdentity("org_acme", "usr_viewer"), nil, canceler)

	rec := cancelServiceDeployment(handler, "dep_canonical_cancel", "valid-key")

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

// TestCancelServiceDeploymentNotFound proves the typed store-layer
// NotFound — the disposition for a cross-tenant or unknown
// deployment_id — is rendered as a 404, never as a silent success
// that would emit a misleading audit record.
func TestCancelServiceDeploymentNotFound(t *testing.T) {
	t.Parallel()

	canceler := fakeDeploymentCanceler{err: apierr.NotFound("deployment", "dep_missing")}
	handler := cancelServiceDeploymentHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, canceler)

	rec := cancelServiceDeployment(handler, "dep_missing", "valid-key")

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

// TestCancelServiceDeploymentTerminalConflict proves a Conflict from
// the store — the deployment is already terminal — is rendered as a
// 409. A second cancel against the same deployment is a deterministic
// 409, never a silent success that would emit a duplicate audit
// record for an already-cancelled row.
func TestCancelServiceDeploymentTerminalConflict(t *testing.T) {
	t.Parallel()

	canceler := fakeDeploymentCanceler{err: apierr.Conflict("the deployment is in a terminal state and cannot be cancelled")}
	handler := cancelServiceDeploymentHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, canceler)

	rec := cancelServiceDeployment(handler, "dep_canonical_cancel", "valid-key")

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusConflict, rec.Body.String())
	}
}

// TestCancelServiceDeploymentStaleVersion proves the typed store-layer
// ConflictStale is rendered as a 409 carrying the row's current
// version under details.current_version, so an agent can retry with
// the authoritative If-Match without re-reading the row.
func TestCancelServiceDeploymentStaleVersion(t *testing.T) {
	t.Parallel()

	canceler := fakeDeploymentCanceler{err: apierr.ConflictStale(7)}
	handler := cancelServiceDeploymentHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, canceler)

	rec := cancelServiceDeploymentWithIfMatch(handler, "dep_canonical_cancel", "valid-key", `"3"`)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusConflict, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"current_version"`) {
		t.Errorf("stale-version body must carry details.current_version; got %s", rec.Body.String())
	}
}

// TestCancelServiceDeploymentStoreUnavailable proves a typed
// store-unavailable error is rendered as a 503 — the datastore
// outage surfaces as the typed 503, never disguised as a 500 leaking
// the pgx cause.
func TestCancelServiceDeploymentStoreUnavailable(t *testing.T) {
	t.Parallel()

	canceler := fakeDeploymentCanceler{err: apierr.StoreUnavailable(stderrors.New("pgx: dial tcp: connection refused"))}
	handler := cancelServiceDeploymentHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, canceler)

	rec := cancelServiceDeployment(handler, "dep_canonical_cancel", "valid-key")

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeUnavailable))
	if strings.Contains(rec.Body.String(), "dial tcp") || strings.Contains(rec.Body.String(), "connection refused") {
		t.Errorf("response leaks driver-level cause: %s", rec.Body.String())
	}
}

// TestCancelServiceDeploymentCrossTenantNoForeignEcho proves the
// handler never trusts the path deployment_id to override the
// principal's home organization id: a cross-tenant deployment_id is
// reported as 404 (the store's tenant-scoped existence check) — never
// disguised as a 200 with another tenant's data and never as a 403
// that would confirm existence. The captured OrganizationID input is
// the principal's home org, not the path id.
func TestCancelServiceDeploymentCrossTenantNoForeignEcho(t *testing.T) {
	t.Parallel()

	const (
		attackerOrg = "org_attacker"
		victimDep   = "dep_victim_owns"
	)
	var captured store.CancelDeploymentInput
	canceler := fakeDeploymentCanceler{
		err: apierr.NotFound("deployment", victimDep),
		got: &captured,
	}

	handler := cancelServiceDeploymentHandlerFor(
		ownerIdentity(attackerOrg, "usr_attacker"), nil, canceler)

	rec := cancelServiceDeployment(handler, victimDep, "valid-key")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	if captured.OrganizationID != attackerOrg {
		t.Errorf("canceler received organization id %q, want the attacker's home org %q (path deployment_id must never override)",
			captured.OrganizationID, attackerOrg)
	}
}

// TestCancelServiceDeploymentMissingCanceler proves a wiring error
// (nil canceler reaching the handler) is reported as a typed internal
// error rather than a misleading success. The wiring goes through
// NewHandler so the request reaches the typed-internal guard inside
// cancelServiceDeploymentHandler.
func TestCancelServiceDeploymentMissingCanceler(t *testing.T) {
	t.Parallel()

	handler := cancelServiceDeploymentHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, nil)

	rec := cancelServiceDeployment(handler, "dep_canonical_cancel", "valid-key")

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
}

// TestCancelServiceDeploymentOpenAPIRouteIsRegistered proves the
// OpenAPI document carries the POST
// /v1/deployments/{deployment_id}/cancel operation with the stable
// operationId, the deployment.cancel required action, and the
// deployments tag — every detail an agent reads to discover the
// endpoint.
func TestCancelServiceDeploymentOpenAPIRouteIsRegistered(t *testing.T) {
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
		fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{},
		fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{})

	var found bool
	for _, rt := range table {
		if rt.endpoint.Method == http.MethodPost && rt.endpoint.Path == "/v1/deployments/{deployment_id}/cancel" {
			found = true
			if rt.endpoint.OperationID != "cancelServiceDeployment" {
				t.Errorf("operation_id = %q, want cancelServiceDeployment", rt.endpoint.OperationID)
			}
			if rt.endpoint.RequiredAction != string(policy.ActionDeploymentCancel) {
				t.Errorf("required_action = %q, want %q", rt.endpoint.RequiredAction, policy.ActionDeploymentCancel)
			}
			if !rt.endpoint.RequiresAuth {
				t.Errorf("requires_auth = false, want true")
			}
			var hasDeployments bool
			for _, tag := range rt.endpoint.Tags {
				if tag == tagDeployments {
					hasDeployments = true
				}
			}
			if !hasDeployments {
				t.Errorf("tags = %v, want %q", rt.endpoint.Tags, tagDeployments)
			}
		}
	}
	if !found {
		t.Errorf("POST /v1/deployments/{deployment_id}/cancel not in route table")
	}
}
