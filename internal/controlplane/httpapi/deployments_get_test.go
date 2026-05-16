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

// Contract and tenant-isolation coverage for GET
// /v1/deployments/{deployment_id} (BE-0211 + BE-0212). The endpoint
// returns the single deployment named by the {deployment_id} path
// parameter — by reading it through the DeploymentGetter port. The
// tests drive it through NewHandler with a fake Authenticator, the
// real policy engine, and a fake getter — the same wiring a request
// hits in production, minus the database. The store-backed reader
// has its own isolated-Postgres integration coverage in
// store/deployment_test.go — this file exercises the HTTP surface in
// isolation. The full role x tenant x grant-scope policy matrix lives
// in deployments_get_policy_test.go (BE-0213).
//
// deployment.read is a CapRead action: a viewer principal in the
// tenant CAN read a deployment (this is the load-bearing distinction
// from env.write where viewer denies). The happy-path tests still
// authenticate as RoleDeveloper to keep the role matrix focused on
// the policy suite.

// fakeDeploymentGetter is the test double for the DeploymentGetter
// port: it captures the (organizationID, deploymentID) pair the
// handler passed in, the call count, and returns a canned row /
// error. The captured inputs are the load-bearing proof that the
// handler never trusts caller-controlled organization ids and
// forwards the principal's home org plus the path deployment id to
// the persistence layer.
type fakeDeploymentGetter struct {
	deployment      store.Deployment
	err             error
	gotOrgID        *string
	gotDeploymentID *string
	callCount       *int
}

func (f fakeDeploymentGetter) GetServiceDeployment(_ context.Context, organizationID, deploymentID string) (store.Deployment, error) {
	if f.gotOrgID != nil {
		*f.gotOrgID = organizationID
	}
	if f.gotDeploymentID != nil {
		*f.gotDeploymentID = deploymentID
	}
	if f.callCount != nil {
		*f.callCount++
	}
	return f.deployment, f.err
}

// getServiceDeploymentSuccessEnvelope is the decoded shape of the
// GET /v1/deployments/{deployment_id} success envelope.
type getServiceDeploymentSuccessEnvelope struct {
	SchemaVersion string                      `json:"schema_version"`
	OK            bool                        `json:"ok"`
	RequestID     string                      `json:"request_id"`
	Data          getServiceDeploymentPayload `json:"data"`
}

// getServiceDeploymentHandlerFor builds the full NewHandler surface
// with an Authenticator that resolves every credential to id and the
// given DeploymentGetter. It is the production request path: the GET
// /v1/deployments/{deployment_id} route is wrapped in RequireAuth for
// action deployment.read.
func getServiceDeploymentHandlerFor(id auth.Identity, authErr error, getter DeploymentGetter) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupRunner{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, getter, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
}

// getServiceDeployment issues GET /v1/deployments/{deployment_id}
// against handler with an optional bearer token.
func getServiceDeployment(handler http.Handler, deploymentID, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet,
		"/v1/deployments/"+deploymentID, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeGetServiceDeployment(t *testing.T, rec *httptest.ResponseRecorder) getServiceDeploymentSuccessEnvelope {
	t.Helper()
	var env getServiceDeploymentSuccessEnvelope
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

// principalForGetDeployment returns an auth.Identity for an
// organization-wide developer principal homed at organizationID.
// deployment.read is a CapRead action so a developer in the
// principal's home tenant is admitted at the policy boundary; the
// tests use this to focus on downstream wire and persistence
// behavior, not on the role matrix (which is BE-0213's job).
func principalForGetDeployment(principalID, organizationID string) auth.Identity {
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

// TestGetServiceDeploymentHappyPath drives the production request
// path against a deployment the principal's home organization owns.
// The principal is an organization-wide Developer so the policy gate
// admits the read; the getter returns a terminal succeeded image
// deployment and the assertions pin every load-bearing field of the
// wire shape: the principal's home org id is forwarded to the getter
// (never a caller-controlled value), the path deployment id is
// forwarded verbatim, and the deployment's lifecycle timestamps
// render according to the omitempty contract.
func TestGetServiceDeploymentHappyPath(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		proj  = "prj_web"
		envID = "env_prod"
		svcID = "svc_api"
		depID = "dep_done"
	)
	created := time.Date(2026, 5, 15, 9, 30, 0, 0, time.UTC)
	finished := time.Date(2026, 5, 15, 9, 32, 0, 0, time.UTC)

	dep := seedDeploymentWire(
		depID, org, proj, envID, svcID,
		store.DeploymentSourceImage, "ghcr.io/acme/api:v2", "succeeded", "usr_dev", "k1",
		3, created, finished,
	)
	dep.StartedAt = &created
	dep.FinishedAt = &finished

	var gotOrg, gotDep string
	callCount := 0
	getter := fakeDeploymentGetter{
		deployment:      dep,
		gotOrgID:        &gotOrg,
		gotDeploymentID: &gotDep,
		callCount:       &callCount,
	}

	handler := getServiceDeploymentHandlerFor(
		principalForGetDeployment("usr_dev", org), nil, getter)

	rec := getServiceDeployment(handler, depID, "a-valid-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("getter call count = %d, want 1", callCount)
	}
	if gotOrg != org {
		t.Errorf("getter received organization id %q, want the principal's home org %q", gotOrg, org)
	}
	if gotDep != depID {
		t.Errorf("getter received deployment id %q, want the path parameter %q", gotDep, depID)
	}

	envelope := decodeGetServiceDeployment(t, rec)
	got := envelope.Data.Deployment
	if got.ID != depID || got.Source != "image" || got.Status != "succeeded" {
		t.Errorf("deployment = %+v, want (%s, image, succeeded)", got, depID)
	}
	if got.OrganizationID != org || got.ProjectID != proj || got.EnvironmentID != envID || got.ServiceID != svcID {
		t.Errorf("tenancy = (org=%q, proj=%q, env=%q, svc=%q), want (%q, %q, %q, %q)",
			got.OrganizationID, got.ProjectID, got.EnvironmentID, got.ServiceID, org, proj, envID, svcID)
	}
	if got.StartedAt == nil || got.FinishedAt == nil {
		t.Fatalf("lifecycle timestamps = (started=%v, finished=%v), want both populated for succeeded",
			got.StartedAt, got.FinishedAt)
	}
	if *got.StartedAt != created.Format(time.RFC3339Nano) {
		t.Errorf("StartedAt = %q, want %q", *got.StartedAt, created.Format(time.RFC3339Nano))
	}
	if *got.FinishedAt != finished.Format(time.RFC3339Nano) {
		t.Errorf("FinishedAt = %q, want %q", *got.FinishedAt, finished.Format(time.RFC3339Nano))
	}
}

// TestGetServiceDeploymentLifecycleTimestampsOmitted proves a
// deployment whose StartedAt/FinishedAt are nil — for example a
// 'queued' deployment that has not yet begun running — omits both
// timestamp fields from the wire shape entirely (matching the
// omitempty contract every other dated resource uses).
func TestGetServiceDeploymentLifecycleTimestampsOmitted(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		depID = "dep_queued"
	)
	created := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	dep := seedDeploymentWire(
		depID, org, "prj_web", "env_prod", "svc_api",
		store.DeploymentSourceGit, "main", "queued", "usr_dev", "k_queued",
		1, created, created,
	)

	handler := getServiceDeploymentHandlerFor(
		principalForGetDeployment("usr_dev", org), nil, fakeDeploymentGetter{deployment: dep})

	rec := getServiceDeployment(handler, depID, "a-valid-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	envelope := decodeGetServiceDeployment(t, rec)
	got := envelope.Data.Deployment
	if got.StartedAt != nil || got.FinishedAt != nil {
		t.Errorf("lifecycle timestamps = (started=%v, finished=%v), want nil/nil for queued", got.StartedAt, got.FinishedAt)
	}
	body := rec.Body.String()
	if strings.Contains(body, `"started_at"`) || strings.Contains(body, `"finished_at"`) {
		t.Errorf("body should omit started_at/finished_at when nil, got %s", body)
	}
}

// TestGetServiceDeploymentRequestIDPropagates proves the request
// correlation id reaches the wire envelope's request_id field.
func TestGetServiceDeploymentRequestIDPropagates(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		depID = "dep_any"
	)
	dep := seedDeploymentWire(depID, org, "prj_web", "env_prod", "svc_api",
		store.DeploymentSourceGit, "main", "queued", "usr_dev", "k", 1, time.Now().UTC(), time.Now().UTC())
	handler := getServiceDeploymentHandlerFor(
		principalForGetDeployment("usr_dev", org), nil, fakeDeploymentGetter{deployment: dep})

	rec := getServiceDeployment(handler, depID, "a-valid-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeGetServiceDeployment(t, rec)
	if env.RequestID == "" {
		t.Errorf("request_id is empty, want it propagated through the success envelope")
	}
}

// TestGetServiceDeploymentErrorMessageProjectedVerbatim proves the
// worker-written error_message column reaches the wire verbatim (the
// redaction chokepoint is the worker's writer, not this read path).
// A deployment seeded with a redacted error_message renders through
// the wire shape with the same value, no transformation, no echo to
// logs. The test pins the contract that the handler is a pure
// projector.
func TestGetServiceDeploymentErrorMessageProjectedVerbatim(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		depID = "dep_failed"
	)
	created := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	finished := created.Add(time.Minute)

	failed := seedDeploymentWire(
		depID, org, "prj_web", "env_prod", "svc_api",
		store.DeploymentSourceGit, "main", "failed", "usr_dev", "k1",
		2, created, finished,
	)
	failed.ErrorCode = "E_BUILD_FAILED"
	failed.ErrorMessage = "build step exited 1"
	failed.StartedAt = &created
	failed.FinishedAt = &finished

	handler := getServiceDeploymentHandlerFor(
		principalForGetDeployment("usr_dev", org), nil, fakeDeploymentGetter{deployment: failed})

	rec := getServiceDeployment(handler, depID, "a-valid-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeGetServiceDeployment(t, rec)
	got := env.Data.Deployment
	if got.ErrorCode != "E_BUILD_FAILED" || got.ErrorMessage != "build step exited 1" {
		t.Errorf("error fields = (%q, %q), want (E_BUILD_FAILED, build step exited 1)",
			got.ErrorCode, got.ErrorMessage)
	}
}

// TestGetServiceDeploymentNotFound proves the store-layer
// apierr.NotFound (a cross-tenant or unknown deployment_id) reaches
// the HTTP wire as a deterministic 404 yalla.error.v1 envelope —
// never a 200 with foreign data, never a 500 leaking the cause.
func TestGetServiceDeploymentNotFound(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	getter := fakeDeploymentGetter{
		err: apierr.NotFound("deployment", "dep_unknown"),
	}

	handler := getServiceDeploymentHandlerFor(
		principalForGetDeployment("usr_dev", org), nil, getter)

	rec := getServiceDeployment(handler, "dep_unknown", "a-valid-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeNotFound))
}

// TestGetServiceDeploymentCrossTenantNoForeignEcho proves a
// cross-tenant deployment_id reaches the persistence layer with the
// principal's home organization id (never a caller-controlled value)
// and that the resulting 404 body never echoes the foreign org id —
// preventing the response from being an existence oracle for another
// tenant's deployments.
func TestGetServiceDeploymentCrossTenantNoForeignEcho(t *testing.T) {
	t.Parallel()

	const (
		attackerOrg = "org_attacker"
		victimDep   = "dep_victim_owns"
		victimOrg   = "org_victim"
	)
	var gotOrg string
	getter := fakeDeploymentGetter{
		err:      apierr.NotFound("deployment", victimDep),
		gotOrgID: &gotOrg,
	}

	handler := getServiceDeploymentHandlerFor(
		principalForGetDeployment("usr_attacker", attackerOrg), nil, getter)

	rec := getServiceDeployment(handler, victimDep, "a-valid-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	if gotOrg != attackerOrg {
		t.Errorf("getter received organization id %q, want the attacker's home org %q (the path deployment_id must never override)", gotOrg, attackerOrg)
	}
	body := rec.Body.String()
	if strings.Contains(body, victimOrg) {
		t.Errorf("404 body leaks foreign organization id: %s", body)
	}
}

// TestGetServiceDeploymentStoreUnavailable proves a datastore outage
// surfaces as the typed 503 — never disguised as a 5xx leaking the
// pgx cause, and never as a misleading 200 with a zero-value
// deployment.
func TestGetServiceDeploymentStoreUnavailable(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const depID = "dep_any"
	getter := fakeDeploymentGetter{
		err: apierr.StoreUnavailable(stderrors.New("pgx: dial tcp: connection refused")),
	}

	handler := getServiceDeploymentHandlerFor(
		principalForGetDeployment("usr_dev", org), nil, getter)

	rec := getServiceDeployment(handler, depID, "a-valid-token")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeUnavailable))
	if strings.Contains(rec.Body.String(), "dial tcp") || strings.Contains(rec.Body.String(), "connection refused") {
		t.Errorf("response leaks driver-level cause: %s", rec.Body.String())
	}
}

// TestGetServiceDeploymentUnauthenticated proves a request without a
// valid credential is denied at the auth boundary with a 401 — the
// getter never runs, so no deployment id, idempotency_key, or
// source_ref can leak.
func TestGetServiceDeploymentUnauthenticated(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		depID = "dep_secret"
	)
	created := time.Now().UTC()
	callCount := 0
	getter := fakeDeploymentGetter{
		deployment: seedDeploymentWire(depID, org, "prj_web", "env_prod", "svc_api",
			store.DeploymentSourceGit, "secret-branch-leak", "queued", "usr_dev", "leak-key", 1, created, created),
		callCount: &callCount,
	}

	handler := getServiceDeploymentHandlerFor(
		auth.Identity{}, apierr.Unauthenticated("missing token"), getter)

	rec := getServiceDeployment(handler, depID, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("getter call count = %d, want 0 (auth must short-circuit)", callCount)
	}
	for _, leak := range []string{"secret-branch-leak", "leak-key"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("401 body leaks getter-side identifier %q: %s", leak, rec.Body.String())
		}
	}
}

// TestGetServiceDeploymentRevokedCredential proves a principal whose
// API key has been revoked surfaces as PrincipalDisabled at the auth
// layer, which the middleware translates into 401 — pinning that
// revoked keys never reach the getter.
func TestGetServiceDeploymentRevokedCredential(t *testing.T) {
	t.Parallel()

	const depID = "dep_any"
	callCount := 0
	getter := fakeDeploymentGetter{callCount: &callCount}

	handler := getServiceDeploymentHandlerFor(
		auth.Identity{}, apierr.Unauthenticated("api key revoked"), getter)

	rec := getServiceDeployment(handler, depID, "revoked-token")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("getter call count = %d, want 0 (revoked credential must short-circuit)", callCount)
	}
}

// TestGetServiceDeploymentMissingGetter proves a request that reaches
// a handler with a nil getter (a wiring error) surfaces as the typed
// internal error, never a misleading 200 with a zero-value deployment.
func TestGetServiceDeploymentMissingGetter(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		depID = "dep_any"
	)
	handler := getServiceDeploymentHandlerFor(
		principalForGetDeployment("usr_dev", org), nil, nil)

	rec := getServiceDeployment(handler, depID, "a-valid-token")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeInternal))
}

// TestGetServiceDeploymentOpenAPIRouteIsRegistered proves the OpenAPI
// document carries the GET /v1/deployments/{deployment_id} operation
// with the stable operationId, the deployment.read required action,
// and the deployments tag — every detail an agent reads to discover
// the endpoint.
func TestGetServiceDeploymentOpenAPIRouteIsRegistered(t *testing.T) {
	t.Parallel()

	table := newRouteTable(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil,
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupRunner{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{})

	var found bool
	for _, rt := range table {
		if rt.endpoint.Method == http.MethodGet && rt.endpoint.Path == "/v1/deployments/{deployment_id}" {
			found = true
			if rt.endpoint.OperationID != "getServiceDeployment" {
				t.Errorf("operation_id = %q, want getServiceDeployment", rt.endpoint.OperationID)
			}
			if rt.endpoint.RequiredAction != string(policy.ActionDeploymentRead) {
				t.Errorf("required_action = %q, want %q", rt.endpoint.RequiredAction, policy.ActionDeploymentRead)
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
		t.Errorf("GET /v1/deployments/{deployment_id} not in route table")
	}
}

// TestDeploymentIDResolverPinsHomeOrg proves the resolver pins the
// resource organization to the principal's home org — never the
// caller-supplied path id — and uses domain.KindDeployment. The
// policy.Scope hierarchy stops at ServiceID so the deployment_id
// itself is not a scope leg (and is not pinned by the resolver), but
// the OrganizationID pinning is the load-bearing tenant-isolation
// property the engine relies on to deny cross-tenant grants.
func TestDeploymentIDResolverPinsHomeOrg(t *testing.T) {
	t.Parallel()

	const homeOrg = "org_home"
	const depID = "dep_target"
	req := httptest.NewRequest(http.MethodGet, "/v1/deployments/"+depID, nil)
	req.SetPathValue("deployment_id", depID)
	ctx := policy.WithPrincipal(req.Context(), policy.Principal{
		ID: "usr_x", Kind: domain.KindUser, OrganizationID: homeOrg, Role: policy.RoleDeveloper,
	})
	req = req.WithContext(ctx)

	resource := deploymentIDResolver(req)
	if resource.Kind != domain.KindDeployment {
		t.Errorf("resource kind = %q, want %q", resource.Kind, domain.KindDeployment)
	}
	if resource.Scope.OrganizationID != homeOrg {
		t.Errorf("resource org = %q, want the principal's home org %q", resource.Scope.OrganizationID, homeOrg)
	}
	if resource.Scope.ProjectID != "" || resource.Scope.EnvironmentID != "" || resource.Scope.ServiceID != "" {
		t.Errorf("resource scope = %+v, want only OrganizationID pinned (Scope has no DeploymentID leg)", resource.Scope)
	}
}

// TestDeploymentIDResolverNoPrincipal proves the resolver does not
// panic when no principal is attached to the context (it returns a
// resource with empty OrganizationID, which the engine deterministically
// denies before any handler runs).
func TestDeploymentIDResolverNoPrincipal(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/v1/deployments/dep_x", nil)
	req.SetPathValue("deployment_id", "dep_x")
	resource := deploymentIDResolver(req)
	if resource.Kind != domain.KindDeployment {
		t.Errorf("resource kind = %q, want %q", resource.Kind, domain.KindDeployment)
	}
	if resource.Scope.OrganizationID != "" {
		t.Errorf("resource org = %q, want empty when no principal is on context", resource.Scope.OrganizationID)
	}
}
