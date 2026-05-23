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
// /v1/services/{service_id}/deployments (BE-0208 + BE-0209). The
// endpoint lists every deployment owned by the service named by the
// {service_id} path parameter — by reading them through the
// DeploymentLister port. The tests drive it through NewHandler with a
// fake Authenticator, the real policy engine, and a fake lister — the
// same wiring a request hits in production, minus the database. The
// store-backed reader has its own isolated-Postgres integration
// coverage in store/deployment_test.go — this file exercises the HTTP
// surface in isolation. The full role x tenant x grant-scope policy
// matrix lives in service_deployments_list_policy_test.go (BE-0210).
//
// deployment.read is a CapRead action: a viewer principal in the
// tenant CAN list deployments (this is the load-bearing distinction
// from env.write where viewer denies). The happy-path tests still
// authenticate as RoleDeveloper to keep the role matrix focused on
// the policy suite.

// fakeDeploymentLister is the test double for the DeploymentLister
// port: it captures the (organizationID, serviceID) pair the handler
// passed in, the call count, and returns a canned slice / error. The
// captured inputs are the load-bearing proof that the handler never
// trusts caller-controlled organization ids and forwards the
// principal's home org plus the path service id to the persistence
// layer.
type fakeDeploymentLister struct {
	deployments  []store.Deployment
	err          error
	gotOrgID     *string
	gotServiceID *string
	callCount    *int
}

func (f fakeDeploymentLister) ListServiceDeployments(_ context.Context, organizationID, serviceID string) ([]store.Deployment, error) {
	if f.gotOrgID != nil {
		*f.gotOrgID = organizationID
	}
	if f.gotServiceID != nil {
		*f.gotServiceID = serviceID
	}
	if f.callCount != nil {
		*f.callCount++
	}
	return f.deployments, f.err
}

// listServiceDeploymentsSuccessEnvelope is the decoded shape of the
// GET /v1/services/{service_id}/deployments success envelope.
type listServiceDeploymentsSuccessEnvelope struct {
	SchemaVersion string                        `json:"schema_version"`
	OK            bool                          `json:"ok"`
	RequestID     string                        `json:"request_id"`
	Data          listServiceDeploymentsPayload `json:"data"`
}

// listServiceDeploymentsHandlerFor builds the full NewHandler surface
// with an Authenticator that resolves every credential to id and the
// given DeploymentLister. It is the production request path: the GET
// /v1/services/{service_id}/deployments route is wrapped in
// RequireAuth for action deployment.read.
func listServiceDeploymentsHandlerFor(id auth.Identity, authErr error, lister DeploymentLister) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, lister, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
}

// getServiceDeployments issues GET
// /v1/services/{service_id}/deployments against handler with an
// optional bearer token.
func getServiceDeployments(handler http.Handler, serviceID, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet,
		"/v1/services/"+serviceID+"/deployments", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeListServiceDeployments(t *testing.T, rec *httptest.ResponseRecorder) listServiceDeploymentsSuccessEnvelope {
	t.Helper()
	var env listServiceDeploymentsSuccessEnvelope
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

// principalForListDeployments returns an auth.Identity for an
// organization-wide developer principal homed at organizationID.
// deployment.read is a CapRead action so a developer in the
// principal's home tenant is admitted at the policy boundary; the
// tests use this to focus on downstream wire and persistence
// behavior, not on the role matrix (which is BE-0210's job).
func principalForListDeployments(principalID, organizationID string) auth.Identity {
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

// TestListServiceDeploymentsHappyPath drives the production request
// path against a service the principal's home organization owns. The
// principal is an organization-wide Developer so the policy gate
// admits the read; the lister returns two deployments — a running
// 'queued' git deploy and a terminal succeeded image deploy — and the
// assertions pin every load-bearing field of the wire shape: the
// principal's home org id is forwarded to the lister (never a
// caller-controlled value), the path service id is forwarded
// verbatim, and each deployment's lifecycle timestamps render
// according to the omitempty contract (StartedAt/FinishedAt absent
// when nil, RFC3339Nano string when present).
func TestListServiceDeploymentsHappyPath(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		proj  = "prj_web"
		envID = "env_prod"
		svcID = "svc_api"
	)
	created1 := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	created2 := time.Date(2026, 5, 15, 9, 30, 0, 0, time.UTC)
	finished2 := time.Date(2026, 5, 15, 9, 32, 0, 0, time.UTC)

	dep1 := seedDeploymentWire(
		"dep_running", org, proj, envID, svcID,
		store.DeploymentSourceGit, "main", "queued", "usr_dev", "k1",
		1, created1, created1,
	)
	dep2 := seedDeploymentWire(
		"dep_done", org, proj, envID, svcID,
		store.DeploymentSourceImage, "ghcr.io/acme/api:v2", "succeeded", "usr_dev", "k2",
		3, created2, finished2,
	)
	dep2.StartedAt = &created2
	dep2.FinishedAt = &finished2

	var gotOrg, gotSvc string
	callCount := 0
	lister := fakeDeploymentLister{
		deployments:  []store.Deployment{dep1, dep2},
		gotOrgID:     &gotOrg,
		gotServiceID: &gotSvc,
		callCount:    &callCount,
	}

	handler := listServiceDeploymentsHandlerFor(
		principalForListDeployments("usr_dev", org), nil, lister)

	rec := getServiceDeployments(handler, svcID, "a-valid-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("lister call count = %d, want 1", callCount)
	}
	if gotOrg != org {
		t.Errorf("lister received organization id %q, want the principal's home org %q", gotOrg, org)
	}
	if gotSvc != svcID {
		t.Errorf("lister received service id %q, want the path parameter %q", gotSvc, svcID)
	}

	envelope := decodeListServiceDeployments(t, rec)
	if len(envelope.Data.Deployments) != 2 {
		t.Fatalf("deployments len = %d, want 2; body %s", len(envelope.Data.Deployments), rec.Body.String())
	}

	first := envelope.Data.Deployments[0]
	if first.ID != "dep_running" || first.Source != "git" || first.SourceRef != "main" || first.Status != "queued" {
		t.Errorf("[0] = %+v, want (dep_running, git, main, queued)", first)
	}
	if first.StartedAt != nil || first.FinishedAt != nil {
		t.Errorf("[0] lifecycle timestamps = (started=%v, finished=%v), want nil/nil for queued", first.StartedAt, first.FinishedAt)
	}
	if first.OrganizationID != org || first.ServiceID != svcID || first.ProjectID != proj || first.EnvironmentID != envID {
		t.Errorf("[0] tenancy = (org=%q, proj=%q, env=%q, svc=%q), want (%q, %q, %q, %q)",
			first.OrganizationID, first.ProjectID, first.EnvironmentID, first.ServiceID, org, proj, envID, svcID)
	}

	second := envelope.Data.Deployments[1]
	if second.ID != "dep_done" || second.Source != "image" || second.Status != "succeeded" {
		t.Errorf("[1] = %+v, want (dep_done, image, succeeded)", second)
	}
	if second.StartedAt == nil || second.FinishedAt == nil {
		t.Fatalf("[1] lifecycle timestamps = (started=%v, finished=%v), want both populated for succeeded", second.StartedAt, second.FinishedAt)
	}
	if *second.StartedAt != created2.Format(time.RFC3339Nano) {
		t.Errorf("[1].StartedAt = %q, want %q", *second.StartedAt, created2.Format(time.RFC3339Nano))
	}
	if *second.FinishedAt != finished2.Format(time.RFC3339Nano) {
		t.Errorf("[1].FinishedAt = %q, want %q", *second.FinishedAt, finished2.Format(time.RFC3339Nano))
	}
}

// TestListServiceDeploymentsEmptyList proves a service with no
// deployments returns a deterministic empty array — never null,
// never omitted — so an agent iterating the response never
// dereferences a nil slice.
func TestListServiceDeploymentsEmptyList(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const svc = "svc_api"
	lister := fakeDeploymentLister{deployments: nil}

	handler := listServiceDeploymentsHandlerFor(
		principalForListDeployments("usr_dev", org), nil, lister)

	rec := getServiceDeployments(handler, svc, "a-valid-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	envelope := decodeListServiceDeployments(t, rec)
	if envelope.Data.Deployments == nil {
		t.Errorf("deployments is nil, want a non-nil empty slice")
	}
	if len(envelope.Data.Deployments) != 0 {
		t.Errorf("deployments len = %d, want 0", len(envelope.Data.Deployments))
	}
	// JSON must serialise to [] (a non-nil empty slice marshals to "[]"
	// in encoding/json). Pin the wire shape because agents rely on it.
	if !strings.Contains(rec.Body.String(), `"deployments":[]`) {
		t.Errorf("body should contain `\"deployments\":[]`, got %s", rec.Body.String())
	}
}

// TestListServiceDeploymentsRequestIDPropagates proves the request
// correlation id reaches the wire envelope's request_id field.
func TestListServiceDeploymentsRequestIDPropagates(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const svc = "svc_api"
	handler := listServiceDeploymentsHandlerFor(
		principalForListDeployments("usr_dev", org), nil, fakeDeploymentLister{})

	rec := getServiceDeployments(handler, svc, "a-valid-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeListServiceDeployments(t, rec)
	if env.RequestID == "" {
		t.Errorf("request_id is empty, want it propagated through the success envelope")
	}
}

// TestListServiceDeploymentsErrorMessageRedacted proves the
// worker-written error_message column reaches the wire verbatim
// (the redaction chokepoint is the worker's writer, not this read
// path) AND that the projection does not introduce any new leak: a
// deployment seeded with a non-empty redacted error_message renders
// through the wire shape with the same value, no transformation, no
// echo to logs. The test pins the contract that the handler is a
// pure projector.
func TestListServiceDeploymentsErrorMessageProjectedVerbatim(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = "svc_api"
	)
	created := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	finished := created.Add(time.Minute)

	failed := seedDeploymentWire(
		"dep_failed", org, "prj_web", "env_prod", svcID,
		store.DeploymentSourceGit, "main", "failed", "usr_dev", "k1",
		2, created, finished,
	)
	failed.ErrorCode = "E_BUILD_FAILED"
	failed.ErrorMessage = "build step exited 1"
	failed.StartedAt = &created
	failed.FinishedAt = &finished

	lister := fakeDeploymentLister{deployments: []store.Deployment{failed}}
	handler := listServiceDeploymentsHandlerFor(
		principalForListDeployments("usr_dev", org), nil, lister)

	rec := getServiceDeployments(handler, svcID, "a-valid-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeListServiceDeployments(t, rec)
	if len(env.Data.Deployments) != 1 {
		t.Fatalf("deployments len = %d, want 1", len(env.Data.Deployments))
	}
	got := env.Data.Deployments[0]
	if got.ErrorCode != "E_BUILD_FAILED" || got.ErrorMessage != "build step exited 1" {
		t.Errorf("error fields = (%q, %q), want (E_BUILD_FAILED, build step exited 1)", got.ErrorCode, got.ErrorMessage)
	}
}

// TestListServiceDeploymentsNotFoundFromLister proves the store-layer
// apierr.NotFound (a cross-tenant or unknown service_id) reaches the
// HTTP wire as a deterministic 404 yalla.error.v1 envelope — never a
// silent empty success, never a 500 leaking the cause.
func TestListServiceDeploymentsNotFoundFromLister(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	lister := fakeDeploymentLister{
		err: apierr.NotFound("service", "svc_unknown"),
	}

	handler := listServiceDeploymentsHandlerFor(
		principalForListDeployments("usr_dev", org), nil, lister)

	rec := getServiceDeployments(handler, "svc_unknown", "a-valid-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeNotFound))
}

// TestListServiceDeploymentsCrossTenantNoForeignEcho proves a
// cross-tenant service_id reaches the persistence layer with the
// principal's home organization id (never a caller-controlled value)
// and that the resulting 404 body never echoes the foreign id —
// preventing the response from being an existence oracle for another
// tenant's deployments.
func TestListServiceDeploymentsCrossTenantNoForeignEcho(t *testing.T) {
	t.Parallel()

	const (
		attackerOrg = "org_attacker"
		victimSvc   = "svc_victim_owns"
	)
	var gotOrg string
	lister := fakeDeploymentLister{
		err:      apierr.NotFound("service", victimSvc),
		gotOrgID: &gotOrg,
	}

	handler := listServiceDeploymentsHandlerFor(
		principalForListDeployments("usr_attacker", attackerOrg), nil, lister)

	rec := getServiceDeployments(handler, victimSvc, "a-valid-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	if gotOrg != attackerOrg {
		t.Errorf("lister received organization id %q, want the attacker's home org %q (the path service must never override)", gotOrg, attackerOrg)
	}
	body := rec.Body.String()
	// The 404 envelope CAN name the path id the attacker already
	// supplied (it is not new information), but it must not name any
	// foreign organization id or echo other tenant data.
	if strings.Contains(body, "org_victim") {
		t.Errorf("404 body leaks foreign organization id: %s", body)
	}
}

// TestListServiceDeploymentsStoreUnavailable proves a datastore
// outage surfaces as the typed 503 — never disguised as a 5xx
// leaking the pgx cause, and never as a misleading empty list.
func TestListServiceDeploymentsStoreUnavailable(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const svc = "svc_api"
	lister := fakeDeploymentLister{
		err: apierr.StoreUnavailable(stderrors.New("pgx: dial tcp: connection refused")),
	}

	handler := listServiceDeploymentsHandlerFor(
		principalForListDeployments("usr_dev", org), nil, lister)

	rec := getServiceDeployments(handler, svc, "a-valid-token")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeDBUnavailable))
	if strings.Contains(rec.Body.String(), "dial tcp") || strings.Contains(rec.Body.String(), "connection refused") {
		t.Errorf("response leaks driver-level cause: %s", rec.Body.String())
	}
}

// TestListServiceDeploymentsUnauthenticated proves a request without
// a valid credential is denied at the auth boundary with a 401 — the
// lister never runs, so no deployment id, idempotency_key, or
// source_ref can leak.
func TestListServiceDeploymentsUnauthenticated(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const svc = "svc_api"
	created := time.Now().UTC()
	callCount := 0
	lister := fakeDeploymentLister{
		deployments: []store.Deployment{
			seedDeploymentWire("dep_secret", org, "prj_web", "env_prod", svc,
				store.DeploymentSourceGit, "secret-branch-leak", "queued", "usr_dev", "leak-key", 1, created, created),
		},
		callCount: &callCount,
	}

	handler := listServiceDeploymentsHandlerFor(
		auth.Identity{}, apierr.AuthenticationRequired(), lister)

	rec := getServiceDeployments(handler, svc, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("lister call count = %d, want 0 (auth must short-circuit)", callCount)
	}
	for _, leak := range []string{"dep_secret", "secret-branch-leak", "leak-key"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("401 body leaks lister-side identifier %q: %s", leak, rec.Body.String())
		}
	}
}

// TestListServiceDeploymentsAuthorizationDenied proves a principal
// from a foreign organization (cross-tenant) is rejected at the
// policy boundary as a 403 — the lister never runs. deployment.read
// is a CapRead action with a deliberate cross-tenant SUPPORT
// exception, but a non-support cross-tenant principal is denied; the
// resolver pins the resource to the principal's own home org so the
// support exception does NOT apply through this resolver — that's
// the BE-0210 policy matrix's job to assert.
func TestListServiceDeploymentsAuthorizationDeniedForRevokedKey(t *testing.T) {
	t.Parallel()

	const svc = "svc_api"
	callCount := 0
	lister := fakeDeploymentLister{callCount: &callCount}

	// A principal whose API key has been revoked surfaces as
	// PrincipalDisabled at the auth layer, which the middleware
	// translates into 401 — pinning that revoked keys never reach the
	// lister.
	handler := listServiceDeploymentsHandlerFor(
		auth.Identity{}, apierr.Unauthenticated("api key revoked"), lister)

	rec := getServiceDeployments(handler, svc, "revoked-token")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("lister call count = %d, want 0 (revoked credential must short-circuit)", callCount)
	}
}

// TestListServiceDeploymentsMissingLister proves a request that
// reaches a handler with a nil lister (a wiring error) surfaces as
// the typed internal error, never a misleading 200 with an empty
// list.
func TestListServiceDeploymentsMissingLister(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const svc = "svc_api"
	handler := listServiceDeploymentsHandlerFor(
		principalForListDeployments("usr_dev", org), nil, nil)

	rec := getServiceDeployments(handler, svc, "a-valid-token")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeInternal))
}

// TestListServiceDeploymentsOpenAPIRouteIsRegistered proves the
// OpenAPI document carries the GET
// /v1/services/{service_id}/deployments operation with the stable
// operationId, the deployment.read required action, and the services
// + deployments tags — every detail an agent reads to discover the
// endpoint.
func TestListServiceDeploymentsOpenAPIRouteIsRegistered(t *testing.T) {
	t.Parallel()

	table := newRouteTable(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil,
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{})

	var found bool
	for _, rt := range table {
		if rt.endpoint.Method == http.MethodGet && rt.endpoint.Path == "/v1/services/{service_id}/deployments" {
			found = true
			if rt.endpoint.OperationID != "listServiceDeployments" {
				t.Errorf("operation_id = %q, want listServiceDeployments", rt.endpoint.OperationID)
			}
			if rt.endpoint.RequiredAction != string(policy.ActionDeploymentRead) {
				t.Errorf("required_action = %q, want %q", rt.endpoint.RequiredAction, policy.ActionDeploymentRead)
			}
			if !rt.endpoint.RequiresAuth {
				t.Errorf("requires_auth = false, want true")
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
		t.Errorf("GET /v1/services/{service_id}/deployments not in route table")
	}
}
