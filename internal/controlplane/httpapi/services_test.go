package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// fakeServiceReader is a canned ServiceReader for httpapi contract
// tests of GET /v1/services/{service_id}. It supplies a fixed response
// (or error) and records the (organization_id, service_id) tuple the
// handler called with so tests can assert the handler forwards exactly
// the principal's home organization (never a caller-supplied id) and
// the path service_id verbatim.
//
// The fake intentionally does not enforce tenant scoping itself — that
// is the production *store.ServiceReader's job, proven by its
// integration tests. The HTTP-layer contract under test is "the handler
// asks the port using the principal's home org and the path
// service_id", regardless of how the port answers.
type fakeServiceReader struct {
	svc       store.Service
	err       error
	gotOrgID  *string
	gotSvcID  *string
	callCount *int
}

func (f fakeServiceReader) GetService(_ context.Context, organizationID, serviceID string) (store.Service, error) {
	if f.gotOrgID != nil {
		*f.gotOrgID = organizationID
	}
	if f.gotSvcID != nil {
		*f.gotSvcID = serviceID
	}
	if f.callCount != nil {
		*f.callCount++
	}
	return f.svc, f.err
}

// canonicalServiceForGet is the canned services row the GET-by-id
// happy-path tests render through environmentServiceOf. Every field is
// non-zero so the projection invariants — id, organization_id,
// project_id, environment_id, slug, display_name, kind, version,
// created_at, updated_at — are exercised on the wire.
var canonicalServiceForGet = store.Service{
	ID:             "svc_canonical_get",
	OrganizationID: "org_acme_svc_get",
	ProjectID:      "prj_acme_web",
	EnvironmentID:  "env_acme_prod",
	Slug:           "api",
	DisplayName:    "API",
	Kind:           "application",
	Version:        4,
	CreatedAt:      time.Date(2025, 4, 11, 9, 30, 0, 0, time.UTC),
	UpdatedAt:      time.Date(2025, 4, 12, 10, 0, 0, 0, time.UTC),
}

// principalForSvcGet is a canned org-wide read principal — it admits
// action service.read at the (home org, service_id) resource the
// resolver builds.
var principalForSvcGet = policy.Principal{
	ID:             "usr_get_svc",
	OrganizationID: "org_acme_svc_get",
	Role:           policy.RoleAdmin,
}

// authForSvcGet is a fake Authenticator that maps a canned bearer
// token to principalForSvcGet. Tests that need a different principal
// build their own Authenticator.
type authForSvcGet struct{}

func (authForSvcGet) Authenticate(_ context.Context, token string) (auth.Identity, error) {
	if token != "a-valid-token" {
		return auth.Identity{}, auth.ErrInvalidCredentials
	}
	return auth.Identity{Method: auth.MethodAPIKey, Principal: principalForSvcGet}, nil
}

// getServiceHandlerFor wraps the production NewHandler with a canned
// authenticator and the supplied reader. Every other port is a no-op
// fake; the test exercises only the GET-service vertical.
func getServiceHandlerFor(t *testing.T, reader ServiceReader) http.Handler {
	t.Helper()
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, authForSvcGet{}, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{},
		fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, reader, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
}

// getService fires GET /v1/services/{service_id} with the supplied
// bearer token and returns the response recorder.
func getService(handler http.Handler, svcID, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v1/services/"+svcID, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// decodeGetServiceBody decodes the success envelope into the
// environmentService wire shape so assertions read the JSON contract,
// not the in-process Go type.
func decodeGetServiceBody(t *testing.T, rec *httptest.ResponseRecorder) environmentService {
	t.Helper()
	var env struct {
		Data           getServicePayload `json:"data"`
		SchemaVersion  string            `json:"schema_version"`
		RequestID      string            `json:"request_id"`
		ResponseStatus string            `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode body: %v (body=%s)", err, rec.Body.String())
	}
	if env.SchemaVersion != "yalla.output.v1" {
		t.Errorf("schema_version = %q, want yalla.output.v1", env.SchemaVersion)
	}
	if env.RequestID == "" {
		t.Errorf("request_id is empty")
	}
	return env.Data.Service
}

// TestGetServiceHappyPath proves a request with a valid bearer token
// reaches the reader with the principal's home organization id (never
// a caller-supplied id) and the path service_id, and renders the
// canonical row through environmentServiceOf in a stable
// yalla.output.v1 envelope.
func TestGetServiceHappyPath(t *testing.T) {
	t.Parallel()

	var gotOrg, gotSvc string
	reader := fakeServiceReader{
		svc:      canonicalServiceForGet,
		gotOrgID: &gotOrg,
		gotSvcID: &gotSvc,
	}
	handler := getServiceHandlerFor(t, reader)

	rec := getService(handler, canonicalServiceForGet.ID, "a-valid-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if gotOrg != principalForSvcGet.OrganizationID {
		t.Errorf("reader called with org_id = %q; want %q (principal home org, never a caller-supplied id)", gotOrg, principalForSvcGet.OrganizationID)
	}
	if gotSvc != canonicalServiceForGet.ID {
		t.Errorf("reader called with service_id = %q; want %q (path parameter, verbatim)", gotSvc, canonicalServiceForGet.ID)
	}

	got := decodeGetServiceBody(t, rec)
	if got.ID != canonicalServiceForGet.ID {
		t.Errorf("service.id = %q; want %q", got.ID, canonicalServiceForGet.ID)
	}
	if got.OrganizationID != canonicalServiceForGet.OrganizationID {
		t.Errorf("service.organization_id = %q; want %q", got.OrganizationID, canonicalServiceForGet.OrganizationID)
	}
	if got.ProjectID != canonicalServiceForGet.ProjectID {
		t.Errorf("service.project_id = %q; want %q", got.ProjectID, canonicalServiceForGet.ProjectID)
	}
	if got.EnvironmentID != canonicalServiceForGet.EnvironmentID {
		t.Errorf("service.environment_id = %q; want %q", got.EnvironmentID, canonicalServiceForGet.EnvironmentID)
	}
	if got.Slug != canonicalServiceForGet.Slug || got.DisplayName != canonicalServiceForGet.DisplayName {
		t.Errorf("service.(slug, display_name) = (%q, %q); want (%q, %q)", got.Slug, got.DisplayName, canonicalServiceForGet.Slug, canonicalServiceForGet.DisplayName)
	}
	if got.Kind != canonicalServiceForGet.Kind {
		t.Errorf("service.kind = %q; want %q", got.Kind, canonicalServiceForGet.Kind)
	}
	if got.Version != canonicalServiceForGet.Version {
		t.Errorf("service.version = %d; want %d", got.Version, canonicalServiceForGet.Version)
	}
	if !got.CreatedAt.Equal(canonicalServiceForGet.CreatedAt) {
		t.Errorf("service.created_at = %v; want %v", got.CreatedAt, canonicalServiceForGet.CreatedAt)
	}
	if !got.UpdatedAt.Equal(canonicalServiceForGet.UpdatedAt) {
		t.Errorf("service.updated_at = %v; want %v", got.UpdatedAt, canonicalServiceForGet.UpdatedAt)
	}
}

// TestGetServiceNotFoundIsTypedError proves the handler maps a
// reader-side apierr.NotFound onto a stable yalla.error.v1 404 with
// the E_NOT_FOUND code. The reader-side semantics are: a cross-tenant
// or unknown service_id surfaces as the same 404 — the response is
// not an oracle that reveals which service_ids exist in another
// tenant.
func TestGetServiceNotFoundIsTypedError(t *testing.T) {
	t.Parallel()

	reader := fakeServiceReader{err: apierr.NotFound("service", "svc_unknown")}
	handler := getServiceHandlerFor(t, reader)

	rec := getService(handler, "svc_unknown", "a-valid-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeNotFound))
}

// TestGetServiceCrossTenantBehavesAsNotFound proves a cross-tenant
// service_id (a service that exists in another tenant) is rendered as
// the same deterministic 404 an unknown id is rendered as. The
// handler trusts the reader's tenant-scoping (proven by store
// integration tests) — the contract is "no oracle". This test asserts
// the wire shape, not the SQL filter.
func TestGetServiceCrossTenantBehavesAsNotFound(t *testing.T) {
	t.Parallel()

	reader := fakeServiceReader{err: apierr.NotFound("service", "svc_other_tenant")}
	handler := getServiceHandlerFor(t, reader)

	rec := getService(handler, "svc_other_tenant", "a-valid-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeNotFound))
}

// TestGetServiceUnauthenticated proves a request with no bearer token
// is rejected at the middleware with 401 E_AUTH and never reaches the
// reader. The reader call counter must remain at zero.
func TestGetServiceUnauthenticated(t *testing.T) {
	t.Parallel()

	calls := 0
	reader := fakeServiceReader{svc: canonicalServiceForGet, callCount: &calls}
	handler := getServiceHandlerFor(t, reader)

	rec := getService(handler, canonicalServiceForGet.ID, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	if calls != 0 {
		t.Errorf("reader was called %d times for an unauthenticated request; want 0", calls)
	}
	decodeError(t, rec, string(yerr.CodeAuth))
}

// TestGetServiceInvalidCredentials proves a request with a bearer
// token the authenticator rejects is rendered as the same uniform 401
// E_AUTH, never as a 5xx and never echoing the supplied token. The
// reader is never called.
func TestGetServiceInvalidCredentials(t *testing.T) {
	t.Parallel()

	calls := 0
	reader := fakeServiceReader{svc: canonicalServiceForGet, callCount: &calls}
	handler := getServiceHandlerFor(t, reader)

	rec := getService(handler, canonicalServiceForGet.ID, "this-is-not-a-valid-token")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	if calls != 0 {
		t.Errorf("reader was called %d times for an invalid-credentials request; want 0", calls)
	}
	if strings.Contains(rec.Body.String(), "this-is-not-a-valid-token") {
		t.Errorf("response body echoes the supplied bearer token: %s", rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeAuth))
}

// TestGetServiceReaderOutageIsTypedError proves a reader-side store
// outage is rendered as a stable yalla.error.v1 5xx envelope — the
// typed apierr.StoreUnavailable with code E_STORE_UNAVAILABLE — and
// the raw cause never reaches the wire.
func TestGetServiceReaderOutageIsTypedError(t *testing.T) {
	t.Parallel()

	reader := fakeServiceReader{err: apierr.StoreUnavailable(errors.New("connection refused"))}
	handler := getServiceHandlerFor(t, reader)

	rec := getService(handler, canonicalServiceForGet.ID, "a-valid-token")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "connection refused") {
		t.Errorf("response body leaks raw store cause: %s", rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeUnavailable))
}

// TestGetServiceNilReaderReportsInternal proves a NewHandler call site
// that forgot to wire a ServiceReader is reported as a typed internal
// error (E_INTERNAL) at request time — never as a misleading 200 with
// no body and never as a panic. This is the wiring guard.
func TestGetServiceNilReaderReportsInternal(t *testing.T) {
	t.Parallel()

	handler := getServiceHandlerFor(t, nil)

	rec := getService(handler, canonicalServiceForGet.ID, "a-valid-token")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeInternal))
}

// TestGetServiceResponseEnvelopeIsRedactedAndStable proves the success
// response carries the documented yalla.output.v1 envelope, renders
// no log-suspect tokens (the bearer token never appears in the body),
// and emits no fields beyond the documented environmentService shape —
// preventing accidental wire-level leakage of additional store.Service
// columns added in the future.
func TestGetServiceResponseEnvelopeIsRedactedAndStable(t *testing.T) {
	t.Parallel()

	reader := fakeServiceReader{svc: canonicalServiceForGet}
	handler := getServiceHandlerFor(t, reader)

	rec := getService(handler, canonicalServiceForGet.ID, "a-valid-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "a-valid-token") {
		t.Errorf("response body echoes the bearer token: %s", body)
	}

	var generic map[string]any
	if err := json.NewDecoder(bytes.NewReader(rec.Body.Bytes())).Decode(&generic); err != nil {
		t.Fatalf("decode generic: %v", err)
	}
	data, ok := generic["data"].(map[string]any)
	if !ok {
		t.Fatalf("data is not an object: %#v", generic["data"])
	}
	svcObj, ok := data["service"].(map[string]any)
	if !ok {
		t.Fatalf("data.service is not an object: %#v", data["service"])
	}
	wantKeys := map[string]struct{}{
		"id":              {},
		"organization_id": {},
		"project_id":      {},
		"environment_id":  {},
		"slug":            {},
		"display_name":    {},
		"kind":            {},
		"version":         {},
		"created_at":      {},
		"updated_at":      {},
	}
	for k := range svcObj {
		if _, ok := wantKeys[k]; !ok {
			t.Errorf("unexpected field %q in service payload — environmentService shape regression", k)
		}
	}
	for k := range wantKeys {
		if _, ok := svcObj[k]; !ok {
			t.Errorf("missing field %q in service payload", k)
		}
	}
}

// TestGetServiceDoesNotLogBearerToken proves the per-request log
// record (telemetry.RequestLogging is wired by NewHandler) never
// echoes the bearer token, even on the success path. A request log
// that leaks credentials would defeat the audit-readability
// invariant.
func TestGetServiceDoesNotLogBearerToken(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	reader := fakeServiceReader{svc: canonicalServiceForGet}
	handler := NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, authForSvcGet{}, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{},
		fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, reader, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, logger, nil)

	rec := getService(handler, canonicalServiceForGet.ID, "a-valid-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(logs.String(), "a-valid-token") {
		t.Errorf("structured log record echoes the bearer token: %s", logs.String())
	}
	_, _ = io.Copy(io.Discard, rec.Body)
}

// TestGetServiceOpenAPIRouteIsRegistered proves the OpenAPI document
// carries the GET /v1/services/{service_id} operation with the stable
// operationId, the service.read required action, and the services tag
// — every detail an agent reads to discover the endpoint.
func TestGetServiceOpenAPIRouteIsRegistered(t *testing.T) {
	t.Parallel()

	table := newRouteTable(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil,
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{})

	var found bool
	for _, rt := range table {
		if rt.endpoint.Method == http.MethodGet && rt.endpoint.Path == "/v1/services/{service_id}" {
			found = true
			if rt.endpoint.OperationID != "getService" {
				t.Errorf("operation_id = %q, want getService", rt.endpoint.OperationID)
			}
			if rt.endpoint.RequiredAction != string(policy.ActionServiceRead) {
				t.Errorf("required_action = %q, want %q", rt.endpoint.RequiredAction, policy.ActionServiceRead)
			}
			if !rt.endpoint.RequiresAuth {
				t.Errorf("requires_auth = false, want true")
			}
			var hasServicesTag bool
			for _, tag := range rt.endpoint.Tags {
				if tag == tagServices {
					hasServicesTag = true
				}
			}
			if !hasServicesTag {
				t.Errorf("tags = %v, want to contain %q", rt.endpoint.Tags, tagServices)
			}
			if len(rt.endpoint.PathParams) != 1 || rt.endpoint.PathParams[0].Name != "service_id" {
				t.Errorf("path_params = %+v, want a single service_id path param", rt.endpoint.PathParams)
			}
			if rt.resolver == nil {
				t.Errorf("resolver is nil; the route must use serviceIDResolver so authorize is evaluated against the (home org, service_id) resource")
			}
		}
	}
	if !found {
		t.Errorf("OpenAPI route GET /v1/services/{service_id} is not registered")
	}
}

// TestServiceIDResolverPinsHomeOrganizationAndPathServiceID proves the
// resolver always builds the policy.Resource from the principal's home
// organization id (never a caller-supplied id) and the path service_id
// verbatim. This is the structural anti-spoof guard that keeps a
// cross-tenant service_id from being evaluated against another tenant.
func TestServiceIDResolverPinsHomeOrganizationAndPathServiceID(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/v1/services/svc_target", nil)
	req.SetPathValue("service_id", "svc_target")
	req = req.WithContext(policy.WithPrincipal(req.Context(), policy.Principal{
		ID:             "usr_test_resolver",
		OrganizationID: "org_principal_home",
	}))

	got := serviceIDResolver(req)
	if got.Scope.OrganizationID != "org_principal_home" {
		t.Errorf("Scope.OrganizationID = %q; want %q (principal home org, never the path)", got.Scope.OrganizationID, "org_principal_home")
	}
	if got.Scope.ServiceID != "svc_target" {
		t.Errorf("Scope.ServiceID = %q; want %q (path parameter, verbatim)", got.Scope.ServiceID, "svc_target")
	}
	if got.Scope.ProjectID != "" {
		t.Errorf("Scope.ProjectID = %q; want empty (bare-id route carries no parent project_id)", got.Scope.ProjectID)
	}
	if got.Scope.EnvironmentID != "" {
		t.Errorf("Scope.EnvironmentID = %q; want empty (bare-id route carries no parent environment_id)", got.Scope.EnvironmentID)
	}
}

// TestServiceIDResolverWithoutPrincipalLeavesOrganizationEmpty proves
// the resolver leaves OrganizationID empty when no principal is on the
// request context. This is the structural fallback — the route is
// gated by RequireAuth which never lets an unauthenticated request
// reach the resolver in production, but a resolver that silently
// invented an organization id would be a defence-in-depth regression.
func TestServiceIDResolverWithoutPrincipalLeavesOrganizationEmpty(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/v1/services/svc_target", nil)
	req.SetPathValue("service_id", "svc_target")

	got := serviceIDResolver(req)
	if got.Scope.OrganizationID != "" {
		t.Errorf("Scope.OrganizationID = %q; want empty (no principal on context)", got.Scope.OrganizationID)
	}
	if got.Scope.ServiceID != "svc_target" {
		t.Errorf("Scope.ServiceID = %q; want %q", got.Scope.ServiceID, "svc_target")
	}
}
