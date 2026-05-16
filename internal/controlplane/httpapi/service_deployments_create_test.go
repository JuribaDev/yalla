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

// Contract, authorization, and tenant-isolation coverage for POST
// /v1/services/{service_id}/deployments (BE-0206). The endpoint
// records customer intent to deploy the service through the
// DeploymentCreator port; the tests drive it through NewHandler with
// a fake Authenticator, the real policy engine, and a fake creator —
// the same wiring a request hits in production, minus the database.
// The store-backed creator has its own isolated-Postgres integration
// coverage in store/deployment_test.go (added with the persistence
// story) — this file exercises the HTTP surface in isolation. The
// full role x tenant x grant-scope matrix lives in
// service_deployments_create_policy_test.go (BE-0207).
//
// deployment.create is a CapDeploy action: viewer and support
// principals in the tenant cannot create deployments, but CI keys
// can — that is the load-bearing distinction from env.write (where
// CI denies). The happy-path tests therefore authenticate as
// RoleDeveloper to keep the role matrix focused on the policy suite.
//
// Validation surface: the body decoder rejects oversized/malformed/
// unknown-field bodies as 400 (the global validate.DecodeJSON
// contract). Field-level validation of source taxonomy, source_ref
// shape, idempotency key shape, and the cross-tenant tenant guard is
// the store-layer's job and is asserted through the creator error
// path here, not by re-validating in the handler.

// fakeDeploymentCreator is the test double for the DeploymentCreator
// port: it captures the CreateDeploymentInput a test passed in, the
// call count, and returns a canned Deployment / error. The captured
// input is the single load-bearing proof that the handler never
// trusts caller-controlled organization ids and plumbs the
// authenticated principal's identity to the audit record.
type fakeDeploymentCreator struct {
	deployment store.Deployment
	err        error
	gotInput   *store.CreateDeploymentInput
	callCount  *int
}

func (f fakeDeploymentCreator) Create(_ context.Context, in store.CreateDeploymentInput) (store.Deployment, error) {
	if f.gotInput != nil {
		*f.gotInput = in
	}
	if f.callCount != nil {
		*f.callCount++
	}
	return f.deployment, f.err
}

// createServiceDeploymentSuccessEnvelope is the decoded shape of the
// POST /v1/services/{service_id}/deployments success envelope.
type createServiceDeploymentSuccessEnvelope struct {
	SchemaVersion string                         `json:"schema_version"`
	OK            bool                           `json:"ok"`
	RequestID     string                         `json:"request_id"`
	Data          createServiceDeploymentPayload `json:"data"`
}

// seedDeploymentWire is the helper every contract / policy test uses
// to seed a canonical Deployment for the fake creator to return. The
// timestamps and structural ids are deterministic so leak guards can
// needle for them and assertions can compare verbatim.
func seedDeploymentWire(id, orgID, projectID, environmentID, serviceID string, source store.DeploymentSource, sourceRef, status, requestedBy, idempotencyKey string, version int64, created, updated time.Time) store.Deployment {
	return store.Deployment{
		ID:             id,
		OrganizationID: orgID,
		ProjectID:      projectID,
		EnvironmentID:  environmentID,
		ServiceID:      serviceID,
		Source:         source,
		SourceRef:      sourceRef,
		Status:         store.DeploymentStatus(status),
		RequestedBy:    requestedBy,
		IdempotencyKey: idempotencyKey,
		Version:        version,
		CreatedAt:      created,
		UpdatedAt:      updated,
	}
}

// createServiceDeploymentHandlerFor builds the full NewHandler
// surface with an Authenticator that resolves every credential to id
// and the given DeploymentCreator. It is the production request
// path: the POST /v1/services/{service_id}/deployments route is
// wrapped in RequireAuth for action deployment.create.
func createServiceDeploymentHandlerFor(id auth.Identity, authErr error, creator DeploymentCreator) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, creator, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
}

// postServiceDeployment issues POST
// /v1/services/{service_id}/deployments against handler with the
// given body and optional bearer token.
func postServiceDeployment(handler http.Handler, serviceID, body, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost,
		"/v1/services/"+serviceID+"/deployments", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeCreateServiceDeployment(t *testing.T, rec *httptest.ResponseRecorder) createServiceDeploymentSuccessEnvelope {
	t.Helper()
	var env createServiceDeploymentSuccessEnvelope
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

// principalForCreateDeployment returns an auth.Identity for an
// organization-wide developer principal homed at organizationID.
// deployment.create is a CapDeploy action so a developer in the
// principal's home tenant is admitted at the policy boundary; the
// tests use this to focus on downstream wire and persistence
// behavior, not on the role matrix (which is BE-0207's job).
func principalForCreateDeployment(principalID, organizationID string) auth.Identity {
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

// TestCreateServiceDeploymentHappyPath drives the production request
// path: an organization-wide Developer principal creates a deployment
// against a service owned by its home organization. The handler must
// forward the principal's home org id and the {service_id} path
// parameter to the creator (never a caller-supplied org id from the
// body), and must echo the persisted row through the canonical wire
// projection in a 202 envelope (a deployment is asynchronously
// provisioned — 202 Accepted, not 201).
func TestCreateServiceDeploymentHappyPath(t *testing.T) {
	t.Parallel()

	const (
		org     = "org_acme"
		project = "prj_web"
		envID   = "env_prod"
		svcID   = "svc_api"
		depID   = "dep_abc123"
		idemKey = "deploy-2026-05-16-001"
	)
	created := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	updated := created

	var gotIn store.CreateDeploymentInput
	callCount := 0
	creator := fakeDeploymentCreator{
		deployment: seedDeploymentWire(
			depID, org, project, envID, svcID,
			store.DeploymentSourceGit, "main", "queued", "usr_dev", idemKey,
			1, created, updated,
		),
		gotInput:  &gotIn,
		callCount: &callCount,
	}

	handler := createServiceDeploymentHandlerFor(
		principalForCreateDeployment("usr_dev", org), nil, creator)

	body := `{"source":"git","source_ref":"main","idempotency_key":"deploy-2026-05-16-001"}`
	rec := postServiceDeployment(handler, svcID, body, "a-valid-token")

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("creator call count = %d, want 1", callCount)
	}
	if gotIn.OrganizationID != org {
		t.Errorf("creator received organization id %q, want the principal's home org %q",
			gotIn.OrganizationID, org)
	}
	if gotIn.ServiceID != svcID {
		t.Errorf("creator received service id %q, want the path parameter %q",
			gotIn.ServiceID, svcID)
	}
	if gotIn.Source != store.DeploymentSourceGit || gotIn.SourceRef != "main" || gotIn.IdempotencyKey != idemKey {
		t.Errorf("creator received intent fields = (%q, %q, %q), want (git, main, %s)",
			gotIn.Source, gotIn.SourceRef, gotIn.IdempotencyKey, idemKey)
	}
	if gotIn.ActorID != "usr_dev" || gotIn.ActorOrgID != org {
		t.Errorf("creator received actor = (%q, org=%q), want (usr_dev, org=%s) — actor identity must be plumbed for the audit record",
			gotIn.ActorID, gotIn.ActorOrgID, org)
	}

	envelope := decodeCreateServiceDeployment(t, rec)
	dep := envelope.Data.Deployment
	if dep.ID != depID {
		t.Errorf("deployment.id = %q, want %q", dep.ID, depID)
	}
	if dep.OrganizationID != org || dep.ProjectID != project || dep.EnvironmentID != envID || dep.ServiceID != svcID {
		t.Errorf("deployment tenancy = (org=%q, proj=%q, env=%q, svc=%q), want (%q, %q, %q, %q)",
			dep.OrganizationID, dep.ProjectID, dep.EnvironmentID, dep.ServiceID, org, project, envID, svcID)
	}
	if dep.Source != "git" || dep.SourceRef != "main" || dep.Status != "queued" {
		t.Errorf("deployment intent = (source=%q, ref=%q, status=%q), want (git, main, queued)",
			dep.Source, dep.SourceRef, dep.Status)
	}
	if dep.Version != 1 {
		t.Errorf("deployment.Version = %d, want 1", dep.Version)
	}
}

// TestCreateServiceDeploymentRequestIDPropagates proves the request
// correlation id reaches the wire envelope's request_id field. The
// telemetry.Correlate middleware generates a fresh request id when
// the request carries none, so the envelope's request_id must be
// non-empty regardless of whether the caller supplied an
// X-Request-Id header.
func TestCreateServiceDeploymentRequestIDPropagates(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = "svc_api"
	)
	creator := fakeDeploymentCreator{
		deployment: seedDeploymentWire("dep_xyz", org, "prj_web", "env_prod", svcID,
			store.DeploymentSourceManual, "", "queued", "usr_dev", "k1", 1, time.Now().UTC(), time.Now().UTC()),
	}
	handler := createServiceDeploymentHandlerFor(
		principalForCreateDeployment("usr_dev", org), nil, creator)

	body := `{"source":"manual","source_ref":"","idempotency_key":"k1"}`
	rec := postServiceDeployment(handler, svcID, body, "a-valid-token")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body %s", rec.Code, rec.Body.String())
	}
	env := decodeCreateServiceDeployment(t, rec)
	if env.RequestID == "" {
		t.Errorf("request_id is empty, want it propagated through the success envelope")
	}
}

// TestCreateServiceDeploymentValidationFailure proves a malformed
// request body (a non-canonical source value, here) surfaces as a
// typed 400 with code E_INVALID_INPUT and a stable yalla.error.v1
// envelope. The fake creator returns a pre-validation error so the
// test verifies the handler propagates it as the correct envelope
// without touching the store-layer orchestration semantics.
func TestCreateServiceDeploymentValidationFailure(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const svcID = "svc_api"

	callCount := 0
	creator := fakeDeploymentCreator{
		err:       apierr.InvalidInput(apierr.FieldViolation{Field: "source", Reason: `must be one of "git", "image", or "manual"`}),
		callCount: &callCount,
	}
	handler := createServiceDeploymentHandlerFor(
		principalForCreateDeployment("usr_dev", org), nil, creator)

	body := `{"source":"bogus","source_ref":"main","idempotency_key":"k1"}`
	rec := postServiceDeployment(handler, svcID, body, "a-valid-token")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("creator call count = %d, want 1 (the handler delegates validation to the orchestrator)",
			callCount)
	}
	decodeError(t, rec, string(yerr.CodeInvalidInput))
}

// TestCreateServiceDeploymentMalformedJSON proves an oversized,
// malformed, or unknown-field body is rejected by the strict decoder
// before the creator is touched. The endpoint never echoes the
// caller's input back in the error envelope.
func TestCreateServiceDeploymentMalformedJSON(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const svcID = "svc_api"

	callCount := 0
	creator := fakeDeploymentCreator{callCount: &callCount}
	handler := createServiceDeploymentHandlerFor(
		principalForCreateDeployment("usr_dev", org), nil, creator)

	body := `{"source":"git","unknown_field":"x"}`
	rec := postServiceDeployment(handler, svcID, body, "a-valid-token")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (strict JSON decoder); body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("creator call count = %d, want 0 — strict-decode failures must precede the creator",
			callCount)
	}
	decodeError(t, rec, string(yerr.CodeInvalidInput))
}

// TestCreateServiceDeploymentUnauthenticated proves a request with
// no bearer token is rejected at the auth boundary with a typed 401
// envelope, before the handler is reached. The creator is set up
// with a callCount; it must remain untouched.
func TestCreateServiceDeploymentUnauthenticated(t *testing.T) {
	t.Parallel()

	callCount := 0
	creator := fakeDeploymentCreator{callCount: &callCount}

	handler := createServiceDeploymentHandlerFor(
		auth.Identity{}, apierr.Unauthenticated("missing token"), creator)

	body := `{"source":"git","source_ref":"main","idempotency_key":"k1"}`
	rec := postServiceDeployment(handler, "svc_api", body, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("creator call count = %d, want 0 (auth rejected before handler)", callCount)
	}
	decodeError(t, rec, string(yerr.CodeAuth))
}

// TestCreateServiceDeploymentAuthorizationDenied proves a principal
// whose role does not admit action deployment.create (a viewer
// carrying no scoped grant) is rejected at the policy gate with a
// typed 403 BEFORE the creator is touched. The viewer's CapRead
// capability does not authorize a CapDeploy action.
func TestCreateServiceDeploymentAuthorizationDenied(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const svcID = "svc_api"

	callCount := 0
	creator := fakeDeploymentCreator{callCount: &callCount}
	viewer := auth.Identity{
		Principal: policy.Principal{
			ID:             "usr_viewer",
			Kind:           domain.KindUser,
			OrganizationID: org,
			Role:           policy.RoleViewer,
		},
		Method: auth.MethodSession,
	}
	handler := createServiceDeploymentHandlerFor(viewer, nil, creator)

	body := `{"source":"git","source_ref":"main","idempotency_key":"k1"}`
	rec := postServiceDeployment(handler, svcID, body, "a-valid-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("creator call count = %d, want 0 (policy denied before handler)", callCount)
	}
	decodeError(t, rec, string(yerr.CodeForbidden))
}

// TestCreateServiceDeploymentNotFoundCrossTenant proves a
// cross-tenant or unknown service_id reaches the persistence layer
// with the principal's home organization id and surfaces as a
// deterministic 404 — never disguised as a 200 or a 403 that would
// confirm the foreign service's existence. The creator receives the
// principal's home org id (never a caller-controlled value).
func TestCreateServiceDeploymentNotFoundCrossTenant(t *testing.T) {
	t.Parallel()

	const (
		ownOrg       = "org_attacker"
		foreignSvcID = "svc_victim"
	)

	var gotIn store.CreateDeploymentInput
	callCount := 0
	creator := fakeDeploymentCreator{
		err:       apierr.NotFound("service", foreignSvcID),
		gotInput:  &gotIn,
		callCount: &callCount,
	}
	handler := createServiceDeploymentHandlerFor(
		principalForCreateDeployment("usr_mallory", ownOrg), nil, creator)

	body := `{"source":"git","source_ref":"main","idempotency_key":"k1"}`
	rec := postServiceDeployment(handler, foreignSvcID, body, "a-valid-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("creator call count = %d, want 1 — engine admits the same-tenant resource, persistence rejects the foreign id",
			callCount)
	}
	if gotIn.OrganizationID != ownOrg {
		t.Errorf("creator received org id %q, want the attacker's home org %q — handler must NEVER trust a caller-controlled organization id",
			gotIn.OrganizationID, ownOrg)
	}
	decodeError(t, rec, string(yerr.CodeNotFound))
}

// TestCreateServiceDeploymentConflict proves a duplicate
// idempotency-key insertion failure that produced an apierr.Conflict
// surfaces as a stable 409 with a yalla.error.v1 envelope. The
// store-layer idempotency short-circuit returns the previously
// persisted deployment verbatim; this case exercises the path where
// the conflict is irreducible (a concurrent writer beat us to the
// unique key and the lookup-then-insert race lost). The redaction
// chokepoint is non-negotiable: the message never echoes the caller-
// supplied idempotency key.
func TestCreateServiceDeploymentConflict(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const svcID = "svc_api"

	creator := fakeDeploymentCreator{
		err: apierr.Conflict("a deployment with this idempotency key already exists"),
	}
	handler := createServiceDeploymentHandlerFor(
		principalForCreateDeployment("usr_dev", org), nil, creator)

	body := `{"source":"git","source_ref":"main","idempotency_key":"k1"}`
	rec := postServiceDeployment(handler, svcID, body, "a-valid-token")
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body %s", rec.Code, rec.Body.String())
	}
	denyEnv := decodeError(t, rec, string(yerr.CodeConflict))
	if strings.Contains(denyEnv.Error.Message, "k1") {
		t.Errorf("error.message = %q, must not echo the caller-supplied idempotency key", denyEnv.Error.Message)
	}
}

// TestCreateServiceDeploymentUnwiredCreator proves the route reports
// a typed internal error rather than serving a misleading 2xx when
// the DeploymentCreator port is unwired. This is the wiring guard
// the route entry inherits from NewHandler: a nil creator at
// NewHandler time still registers the route, but a request that
// actually reaches the handler is reported as 500 E_SERVER.
func TestCreateServiceDeploymentUnwiredCreator(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const svcID = "svc_api"

	handler := createServiceDeploymentHandlerFor(
		principalForCreateDeployment("usr_dev", org), nil, nil)

	body := `{"source":"git","source_ref":"main","idempotency_key":"k1"}`
	rec := postServiceDeployment(handler, svcID, body, "a-valid-token")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeInternal))
}

// TestCreateServiceDeploymentOpenAPIRegistration proves the
// generated OpenAPI document carries an operation registered at
// POST /v1/services/{service_id}/deployments with the canonical
// operationId, the deployment.create required action, and the
// services + deployments tags. The discovery surface must match the
// served surface verbatim.
func TestCreateServiceDeploymentOpenAPIRegistration(t *testing.T) {
	t.Parallel()

	creator := fakeDeploymentCreator{}
	handler := createServiceDeploymentHandlerFor(
		principalForCreateDeployment("usr_dev", "org_acme"), nil, creator)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("openapi status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	// Look for the operation id, the path, and the canonical required
	// action — three structural facts that pin the wire contract.
	for _, needle := range []string{
		`"operationId": "createServiceDeployment"`,
		`"/v1/services/{service_id}/deployments"`,
		`"deployment.create"`,
		`"deployments"`,
	} {
		if !strings.Contains(body, needle) {
			t.Errorf("openapi.json is missing %q", needle)
		}
	}
}

// TestCreateServiceDeploymentStoreOutage proves a typed
// StoreUnavailable from the creator surfaces as a 503 with a
// E_STORE_UNAVAILABLE envelope — the persistence outage must never
// be disguised as a 5xx without a stable error code.
func TestCreateServiceDeploymentStoreOutage(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const svcID = "svc_api"

	creator := fakeDeploymentCreator{
		err: apierr.StoreUnavailable(stderrors.New("connection refused")),
	}
	handler := createServiceDeploymentHandlerFor(
		principalForCreateDeployment("usr_dev", org), nil, creator)

	body := `{"source":"git","source_ref":"main","idempotency_key":"k1"}`
	rec := postServiceDeployment(handler, svcID, body, "a-valid-token")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeUnavailable))
}
