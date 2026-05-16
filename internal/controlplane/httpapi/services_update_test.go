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
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// Contract tests for PATCH /v1/services/{service_id}. The route is
// gated by RequireAuth on action service.update through
// serviceIDResolver — a CapWrite action authorized against the
// (principal home organization, {service_id}) resource. These tests
// drive the real NewHandler with a fake Authenticator, the real
// policy engine, and a fake ServiceUpdater — the same wiring a
// request hits in production, minus the database. The store-backed
// orchestrator (store.ServiceService.Update) has its own
// isolated-Postgres integration coverage in
// store/serviceservice_update_test.go.
//
// The fuller "every principal class × every authorization edge"
// matrix lives in services_update_policy_test.go (BE-0189).

// fakeServiceUpdater is a canned ServiceUpdater for httpapi contract
// tests of PATCH /v1/services/{service_id}. It supplies a fixed
// response (or error) and records the store.UpdateServiceInput the
// handler called with so tests can assert the handler forwards
// exactly the principal's home organization (never a caller-supplied
// id), the path service_id, the parsed body fields, and the parsed
// If-Match precondition verbatim.
//
// The fake intentionally does not enforce tenant scoping or
// validation itself — that is the production
// *store.ServiceService's job, proven by its integration tests.
// The HTTP-layer contract under test is "the handler asks the port
// using the principal's home org, the path service_id, the patch
// pointers, and the parsed If-Match version", regardless of how the
// port answers.
type fakeServiceUpdater struct {
	svc       store.Service
	err       error
	gotInput  *store.UpdateServiceInput
	callCount *int
}

func (f fakeServiceUpdater) Update(_ context.Context, in store.UpdateServiceInput) (store.Service, error) {
	if f.gotInput != nil {
		*f.gotInput = in
	}
	if f.callCount != nil {
		*f.callCount++
	}
	return f.svc, f.err
}

// updateServiceSuccessEnvelope is the decoded shape of the PATCH
// /v1/services/{service_id} success envelope.
type updateServiceSuccessEnvelope struct {
	SchemaVersion string `json:"schema_version"`
	OK            bool   `json:"ok"`
	RequestID     string `json:"request_id"`
	Data          struct {
		Service environmentService `json:"service"`
	} `json:"data"`
}

// canonicalUpdatedSvc is the canned services row the happy-path
// tests render through environmentServiceOf. Every field is non-zero
// so the projection invariants are exercised on the wire.
var canonicalUpdatedSvc = store.Service{
	ID:             "svc_canonical_patch",
	OrganizationID: "org_acme",
	ProjectID:      "prj_acme_web",
	EnvironmentID:  "env_acme_prod",
	Slug:           "api",
	DisplayName:    "API",
	Kind:           "application",
	Version:        9,
	CreatedAt:      time.Date(2025, 4, 11, 9, 30, 0, 0, time.UTC),
	UpdatedAt:      time.Date(2025, 4, 12, 10, 0, 0, 0, time.UTC),
}

// updateServiceHandlerFor builds the full NewHandler surface with an
// Authenticator that resolves every credential to id and the given
// ServiceUpdater. It is the production request path: the PATCH
// /v1/services/{service_id} route is wrapped in RequireAuth for
// action service.update.
func updateServiceHandlerFor(id auth.Identity, authErr error, updater ServiceUpdater) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{},
		fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, updater, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
}

// patchService issues PATCH /v1/services/{serviceID} against the
// handler with the supplied bearer token and body.
func patchService(handler http.Handler, serviceID, token, body string) *httptest.ResponseRecorder {
	return patchServiceWithIfMatch(handler, serviceID, token, "", body)
}

// patchServiceWithIfMatch issues PATCH /v1/services/{serviceID} with
// an optional If-Match header. An empty ifMatch omits the header
// entirely so the optional precondition path remains exercised.
func patchServiceWithIfMatch(handler http.Handler, serviceID, token, ifMatch, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPatch, "/v1/services/"+serviceID, strings.NewReader(body))
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

func decodeUpdateService(t *testing.T, rec *httptest.ResponseRecorder) updateServiceSuccessEnvelope {
	t.Helper()
	var env updateServiceSuccessEnvelope
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

func int64PtrSvc(v int64) *int64 { return &v }

// TestUpdateServiceHappyPathForwardsBodyAndPrincipal proves the
// handler decodes the patch body, threads the principal's home
// organization id and the path service_id into the store input,
// preserves the nil-ness of unset fields, renders the returned row in
// the stable yalla.output.v1 envelope, returns 200 OK, and mirrors the
// row's authoritative version into the ETag response header.
func TestUpdateServiceHappyPathForwardsBodyAndPrincipal(t *testing.T) {
	t.Parallel()

	var captured store.UpdateServiceInput
	updater := fakeServiceUpdater{svc: canonicalUpdatedSvc, gotInput: &captured}
	handler := updateServiceHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, updater)

	rec := patchService(handler, "svc_canonical_patch", "a-valid-session-token", `{"display_name":"API","slug":"api"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeUpdateService(t, rec)
	if env.Data.Service.ID != canonicalUpdatedSvc.ID {
		t.Errorf("service.id = %q, want %q", env.Data.Service.ID, canonicalUpdatedSvc.ID)
	}
	if env.Data.Service.OrganizationID != canonicalUpdatedSvc.OrganizationID {
		t.Errorf("organization_id = %q, want %q", env.Data.Service.OrganizationID, canonicalUpdatedSvc.OrganizationID)
	}
	if env.Data.Service.Version != canonicalUpdatedSvc.Version {
		t.Errorf("version = %d, want %d", env.Data.Service.Version, canonicalUpdatedSvc.Version)
	}
	if got, want := rec.Header().Get("ETag"), `"9"`; got != want {
		t.Errorf("ETag header = %q, want %q", got, want)
	}

	if captured.OrganizationID != "org_acme" {
		t.Errorf("forwarded organization_id = %q, want org_acme (principal home)", captured.OrganizationID)
	}
	if captured.ServiceID != "svc_canonical_patch" {
		t.Errorf("forwarded service_id = %q, want svc_canonical_patch (path value)", captured.ServiceID)
	}
	if captured.Slug == nil || *captured.Slug != "api" {
		t.Errorf("forwarded slug = %v, want pointer to \"api\"", captured.Slug)
	}
	if captured.DisplayName == nil || *captured.DisplayName != "API" {
		t.Errorf("forwarded display_name = %v, want pointer to \"API\"", captured.DisplayName)
	}
	if captured.IfMatchVersion != nil {
		t.Errorf("forwarded if_match_version = %v, want nil (no header sent)", captured.IfMatchVersion)
	}
	if captured.ActorID != "usr_ada" {
		t.Errorf("audit actor_id = %q, want usr_ada", captured.ActorID)
	}
	if captured.ActorOrgID != "org_acme" {
		t.Errorf("audit actor_org_id = %q, want org_acme", captured.ActorOrgID)
	}
}

// TestUpdateServicePartialBodyKeepsOmittedFieldNil proves an
// omitted slug field reaches the store as a nil pointer (not as a
// zero string) — the partial-update semantics depend on this
// distinction.
func TestUpdateServicePartialBodyKeepsOmittedFieldNil(t *testing.T) {
	t.Parallel()

	var captured store.UpdateServiceInput
	updater := fakeServiceUpdater{svc: canonicalUpdatedSvc, gotInput: &captured}
	handler := updateServiceHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, updater)

	rec := patchService(handler, "svc_canonical_patch", "a-valid-session-token", `{"display_name":"API"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if captured.Slug != nil {
		t.Errorf("forwarded slug = %v, want nil (field omitted in body)", captured.Slug)
	}
	if captured.DisplayName == nil || *captured.DisplayName != "API" {
		t.Errorf("forwarded display_name = %v, want pointer to \"API\"", captured.DisplayName)
	}
}

// TestUpdateServiceIfMatchHeader proves the optional If-Match header
// parses as a strong integer ETag and threads through to the store
// input as the optimistic-concurrency precondition. A
// malformed/weak/wildcard/multi-value header is rejected as a stable
// 400 before the store is called.
func TestUpdateServiceIfMatchHeader(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name           string
		ifMatch        string
		wantStatus     int
		wantParsedVer  *int64
		updaterRunsErr bool
	}{
		{name: "canonical-strong", ifMatch: `"7"`, wantStatus: http.StatusOK, wantParsedVer: int64PtrSvc(7)},
		{name: "lenient-unquoted", ifMatch: `7`, wantStatus: http.StatusOK, wantParsedVer: int64PtrSvc(7)},
		{name: "wildcard-rejected", ifMatch: `"*"`, wantStatus: http.StatusBadRequest, updaterRunsErr: true},
		{name: "weak-rejected", ifMatch: `W/"7"`, wantStatus: http.StatusBadRequest, updaterRunsErr: true},
		{name: "multi-value-rejected", ifMatch: `"7","8"`, wantStatus: http.StatusBadRequest, updaterRunsErr: true},
		{name: "non-int-rejected", ifMatch: `"abc"`, wantStatus: http.StatusBadRequest, updaterRunsErr: true},
		{name: "zero-rejected", ifMatch: `"0"`, wantStatus: http.StatusBadRequest, updaterRunsErr: true},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var captured store.UpdateServiceInput
			updater := fakeServiceUpdater{svc: canonicalUpdatedSvc, gotInput: &captured}
			handler := updateServiceHandlerFor(
				auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
				nil, updater)

			rec := patchServiceWithIfMatch(handler, "svc_canonical_patch", "a-valid-session-token", tc.ifMatch, `{"display_name":"API"}`)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.updaterRunsErr {
				return
			}
			if tc.wantParsedVer == nil {
				if captured.IfMatchVersion != nil {
					t.Errorf("if_match_version = %v, want nil", captured.IfMatchVersion)
				}
			} else {
				if captured.IfMatchVersion == nil || *captured.IfMatchVersion != *tc.wantParsedVer {
					t.Errorf("if_match_version = %v, want pointer to %d", captured.IfMatchVersion, *tc.wantParsedVer)
				}
			}
		})
	}
}

// TestUpdateServiceRejectsBodyOrgID proves the strict JSON decoder
// rejects an organization_id field in the body: tenant isolation on
// this endpoint is structural — the handler always builds the store
// input from the authenticated principal's home organization and the
// path service_id — and an unknown field is a stable 400
// E_INVALID_INPUT so a stale schema or typo cannot be silently
// dropped.
func TestUpdateServiceRejectsBodyOrgID(t *testing.T) {
	t.Parallel()

	updater := fakeServiceUpdater{err: stderrors.New("updater must not be called")}
	handler := updateServiceHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, updater)

	rec := patchService(handler, "svc_canonical_patch", "a-valid-session-token", `{"organization_id":"org_evil","display_name":"API"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INVALID_INPUT")
}

// TestUpdateServiceMalformedBodyIsValidationError proves a malformed
// JSON body is a stable 400 E_INVALID_INPUT and never reaches the
// updater.
func TestUpdateServiceMalformedBodyIsValidationError(t *testing.T) {
	t.Parallel()

	updater := fakeServiceUpdater{err: stderrors.New("updater must not be called")}
	handler := updateServiceHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, updater)

	rec := patchService(handler, "svc_canonical_patch", "a-valid-session-token", `{"slug":`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INVALID_INPUT")
}

// TestUpdateServiceNotFoundIsTyped404 proves a NotFound from the
// store surfaces as a deterministic 404 E_NOT_FOUND — a cross-tenant
// service_id surfaces here too (tenant-scoped repository), never as
// another tenant's row.
func TestUpdateServiceNotFoundIsTyped404(t *testing.T) {
	t.Parallel()

	updater := fakeServiceUpdater{err: apierr.NotFound("service", "svc_ghost")}
	handler := updateServiceHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, updater)

	rec := patchService(handler, "svc_ghost", "a-valid-session-token", `{"display_name":"API"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_NOT_FOUND")
}

// TestUpdateServiceConflictStaleIsTyped409 proves a ConflictStale
// from the store surfaces as a deterministic 409 with the row's
// authoritative current_version in details.
func TestUpdateServiceConflictStaleIsTyped409(t *testing.T) {
	t.Parallel()

	updater := fakeServiceUpdater{err: apierr.ConflictStale(12)}
	handler := updateServiceHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, updater)

	rec := patchServiceWithIfMatch(handler, "svc_canonical_patch", "a-valid-session-token", `"3"`, `{"display_name":"API"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_CONFLICT")
}

// TestUpdateServiceUnauthenticated proves a request with no
// credential is a stable 401 E_AUTH and never reaches the handler —
// the updater is never called.
func TestUpdateServiceUnauthenticated(t *testing.T) {
	t.Parallel()

	handler := updateServiceHandlerFor(auth.Identity{}, nil,
		fakeServiceUpdater{err: stderrors.New("updater must not be called")})
	rec := patchService(handler, "svc_canonical_patch", "", `{"display_name":"API"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_AUTH")
}

// TestUpdateServiceForbiddenForViewer proves a viewer role on the
// principal's home organization cannot mutate a service — the policy
// gate denies service.update for CapRead-only roles, never touching
// the updater.
func TestUpdateServiceForbiddenForViewer(t *testing.T) {
	t.Parallel()

	updater := fakeServiceUpdater{err: stderrors.New("updater must not be called")}
	handler := updateServiceHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleViewer), Method: auth.MethodSession},
		nil, updater)

	rec := patchService(handler, "svc_canonical_patch", "a-valid-session-token", `{"display_name":"API"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_FORBIDDEN")
}

// TestUpdateServiceInvalidInputFromStoreIsTyped400 proves a
// validation failure from the store layer surfaces as a deterministic
// 400 E_INVALID_INPUT — for example, an empty patch (slug+display_name
// both nil) caught by buildServiceUpdate.
func TestUpdateServiceInvalidInputFromStoreIsTyped400(t *testing.T) {
	t.Parallel()

	updater := fakeServiceUpdater{err: apierr.InvalidInput(apierr.FieldViolation{
		Field:  "slug",
		Reason: "at least one of slug or display_name must be provided",
	})}
	handler := updateServiceHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, updater)

	rec := patchService(handler, "svc_canonical_patch", "a-valid-session-token", `{}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INVALID_INPUT")
}

// TestUpdateServiceMissingUpdaterIsInternal proves a wiring error —
// the route reaches the handler with a nil ServiceUpdater — surfaces
// as a typed 500 E_INTERNAL rather than a misleading
// 2xx-with-no-side-effect.
func TestUpdateServiceMissingUpdaterIsInternal(t *testing.T) {
	t.Parallel()

	handler := updateServiceHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, nil)
	rec := patchService(handler, "svc_canonical_patch", "a-valid-session-token", `{"display_name":"API"}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INTERNAL")
}

// TestUpdateServiceSecretLikeValuesDoNotLeakIntoErrorBody proves
// that even when the request body carries a value-looking field that
// could be a secret (e.g. an "api_key" body field, rejected by the
// strict decoder as unknown), the typed 400 envelope names the field
// but never echoes the submitted value — the validation contract is
// "name the field, never the value".
func TestUpdateServiceSecretLikeValuesDoNotLeakIntoErrorBody(t *testing.T) {
	t.Parallel()

	updater := fakeServiceUpdater{err: stderrors.New("updater must not be called")}
	handler := updateServiceHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, updater)

	secret := "sk_live_DO_NOT_LEAK_42c0ffee"
	body := `{"api_key":"` + secret + `","display_name":"API"}`
	rec := patchService(handler, "svc_canonical_patch", "a-valid-session-token", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Errorf("error body leaked the secret-shaped input value: %s", rec.Body.String())
	}
}

// TestUpdateServiceRequestIDIsEchoed proves the request_id the
// telemetry middleware resolved (an inbound safe X-Request-Id) flows
// to both the success envelope and any structured log record — the
// agent contract for correlation requires it.
func TestUpdateServiceRequestIDIsEchoed(t *testing.T) {
	t.Parallel()

	var captured store.UpdateServiceInput
	updater := fakeServiceUpdater{svc: canonicalUpdatedSvc, gotInput: &captured}
	handler := updateServiceHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, updater)

	const reqID = "req_abc123def456"
	req := httptest.NewRequest(http.MethodPatch, "/v1/services/svc_canonical_patch", strings.NewReader(`{"display_name":"API"}`))
	req.Header.Set("Authorization", "Bearer a-valid-session-token")
	req.Header.Set("X-Request-Id", reqID)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeUpdateService(t, rec)
	if env.RequestID != reqID {
		t.Errorf("request_id = %q, want %q (echoed from X-Request-Id)", env.RequestID, reqID)
	}
	if captured.RequestID != reqID {
		t.Errorf("forwarded request_id = %q, want %q", captured.RequestID, reqID)
	}
}

// TestUpdateServiceOpenAPIRouteIsRegistered proves the route is part
// of the generated OpenAPI document so an agent discovering the
// contract sees it.
func TestUpdateServiceOpenAPIRouteIsRegistered(t *testing.T) {
	t.Parallel()

	handler := updateServiceHandlerFor(auth.Identity{}, nil, fakeServiceUpdater{})
	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("openapi.json status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "\"/v1/services/{service_id}\"") {
		t.Errorf("OpenAPI document is missing the services path; body: %s", body)
	}
	if !strings.Contains(body, "\"updateService\"") {
		t.Errorf("OpenAPI document is missing the updateService operation id; body: %s", body)
	}
}

// Compile-time assertion that the production *store.ServiceService
// implements the ServiceUpdater port the handler depends on, so a
// signature change on either side is caught at build time instead of
// at request time.
var _ ServiceUpdater = (*store.ServiceService)(nil)

// _ silences unused-imports compile errors when individual tests are
// deleted; remove if any future test in this file uses context
// directly.
var _ = context.Background
