package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// deleteServiceViewerIdentity builds an org-wide viewer principal in
// homeOrgID. service.delete is a CapWrite action so a viewer is denied
// at the RequireAuth boundary, never reaching the handler.
func deleteServiceViewerIdentity(homeOrgID, userID string) auth.Identity {
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

// Contract tests for DELETE /v1/services/{service_id}. The route is
// production-wired through NewHandler with RequireAuth gating action
// service.delete (CapWrite, no support cross-tenant exception), so the
// tests prove: the handler asks the ServiceDeleter port with the
// principal's home org id, the path service_id, the parsed If-Match
// version, the actor identity, and the request correlation; every
// typed store-layer error is reflected verbatim in the response
// envelope; success renders 202 Accepted with the soft-deleted row in
// a stable yalla.output.v1 envelope and mirrors the new row version
// into the ETag response header; and the path is registered with the
// stable OpenAPI operation id deleteService.

// fakeServiceDeleter is a canned ServiceDeleter for httpapi-layer
// tests of DELETE /v1/services/{service_id}. It supplies a fixed
// response (or error) and records the store.DeleteServiceInput the
// handler called with so tests can assert the handler forwards
// exactly the principal's home organization (never a caller-supplied
// id), the path service_id, the parsed If-Match precondition, the
// resolved actor identity, and the request correlation verbatim.
//
// The fake intentionally does not enforce tenant scoping or
// validation itself — that is the production *store.ServiceService's
// job, proven by its integration tests. The HTTP-layer contract under
// test is "the handler asks the port using the principal's home org,
// the path service_id, and the parsed If-Match version", regardless
// of how the port answers.
type fakeServiceDeleter struct {
	svc       store.Service
	err       error
	gotInput  *store.DeleteServiceInput
	callCount *int
}

func (f fakeServiceDeleter) ScheduleDeletion(_ context.Context, in store.DeleteServiceInput) (store.Service, error) {
	if f.gotInput != nil {
		*f.gotInput = in
	}
	if f.callCount != nil {
		*f.callCount++
	}
	return f.svc, f.err
}

// deleteServiceSuccessEnvelope is the decoded shape of the DELETE
// /v1/services/{service_id} success envelope.
type deleteServiceSuccessEnvelope struct {
	SchemaVersion string `json:"schema_version"`
	OK            bool   `json:"ok"`
	RequestID     string `json:"request_id"`
	Data          struct {
		Service environmentService `json:"service"`
	} `json:"data"`
}

// canonicalDeletedSvc is the canned services row the happy-path tests
// render through environmentServiceOf. Every field is non-zero —
// including DeletionScheduledAt — so the projection invariants are
// exercised on the wire.
func canonicalDeletedSvc() store.Service {
	scheduled := time.Date(2025, 5, 16, 12, 0, 0, 0, time.UTC)
	return store.Service{
		ID:                  "svc_canonical_delete",
		OrganizationID:      "org_acme",
		ProjectID:           "prj_acme_web",
		EnvironmentID:       "env_acme_prod",
		Slug:                "api",
		DisplayName:         "API",
		Kind:                "application",
		Version:             10,
		CreatedAt:           time.Date(2025, 4, 11, 9, 30, 0, 0, time.UTC),
		UpdatedAt:           time.Date(2025, 5, 16, 12, 0, 0, 0, time.UTC),
		DeletionScheduledAt: &scheduled,
	}
}

// deleteServiceHandlerFor builds the full NewHandler surface with an
// Authenticator that resolves every credential to id and the given
// ServiceDeleter. It is the production request path: the DELETE
// /v1/services/{service_id} route is wrapped in RequireAuth for
// action service.delete.
func deleteServiceHandlerFor(id auth.Identity, authErr error, deleter ServiceDeleter) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{},
		fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, deleter, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
}

// deleteService fires DELETE /v1/services/{serviceID} with the
// supplied bearer token. The handler must accept an empty body; the
// helper sets none on purpose.
func deleteService(handler http.Handler, serviceID, token string) *httptest.ResponseRecorder {
	return deleteServiceWithIfMatch(handler, serviceID, token, "")
}

// deleteServiceWithIfMatch fires DELETE /v1/services/{serviceID} with
// the supplied bearer token and optional If-Match precondition header.
func deleteServiceWithIfMatch(handler http.Handler, serviceID, token, ifMatch string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodDelete, "/v1/services/"+serviceID, nil)
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

// decodeDeleteServiceBody parses the response body as a delete-service
// success envelope and returns the t.Fatal-fast result, so each test
// case can keep its assertions terse.
func decodeDeleteServiceBody(t *testing.T, rec *httptest.ResponseRecorder) deleteServiceSuccessEnvelope {
	t.Helper()
	var env deleteServiceSuccessEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode body: %v\nbody=%s", err, rec.Body.String())
	}
	return env
}

// TestDeleteServiceSuccess proves the happy path renders 202 Accepted,
// uses the yalla.output.v1 envelope, mirrors the row's authoritative
// version into the ETag response header, and surfaces the
// deletion_scheduled_at timestamp as an RFC 3339 string under the
// services row's wire shape.
func TestDeleteServiceSuccess(t *testing.T) {
	var gotInput store.DeleteServiceInput
	deleter := fakeServiceDeleter{
		svc:      canonicalDeletedSvc(),
		gotInput: &gotInput,
	}
	handler := deleteServiceHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, deleter)

	rec := deleteService(handler, "svc_canonical_delete", "tok")

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202, body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	if got := rec.Header().Get("ETag"); got != "\"10\"" {
		t.Errorf("ETag = %q, want %q", got, "\"10\"")
	}

	env := decodeDeleteServiceBody(t, rec)
	if env.SchemaVersion != apienvelope.SuccessSchema {
		t.Errorf("schema_version = %q, want %q", env.SchemaVersion, apienvelope.SuccessSchema)
	}
	if !env.OK {
		t.Errorf("ok = false, want true")
	}
	if env.RequestID == "" {
		t.Error("request_id is empty; envelope must always carry one")
	}
	if env.Data.Service.ID != "svc_canonical_delete" {
		t.Errorf("service.id = %q, want svc_canonical_delete", env.Data.Service.ID)
	}
	if env.Data.Service.Version != 10 {
		t.Errorf("service.version = %d, want 10", env.Data.Service.Version)
	}
	if env.Data.Service.DeletionScheduledAt == nil {
		t.Fatal("service.deletion_scheduled_at is nil; want RFC 3339 timestamp")
	}
	if got, want := *env.Data.Service.DeletionScheduledAt, "2025-05-16T12:00:00Z"; got != want {
		t.Errorf("service.deletion_scheduled_at = %q, want %q", got, want)
	}

	if gotInput.OrganizationID != "org_acme" {
		t.Errorf("forwarded organization_id = %q, want org_acme", gotInput.OrganizationID)
	}
	if gotInput.ServiceID != "svc_canonical_delete" {
		t.Errorf("forwarded service_id = %q, want svc_canonical_delete", gotInput.ServiceID)
	}
	if gotInput.IfMatchVersion != nil {
		t.Errorf("forwarded if_match_version = %v, want nil (no header sent)", *gotInput.IfMatchVersion)
	}
	if gotInput.ActorID != "usr_owner" {
		t.Errorf("forwarded actor_id = %q, want usr_owner", gotInput.ActorID)
	}
	if gotInput.ActorOrgID != "org_acme" {
		t.Errorf("forwarded actor_org_id = %q, want org_acme", gotInput.ActorOrgID)
	}
}

// TestDeleteServiceForwardsIfMatch proves a well-formed If-Match
// header is parsed into a non-nil *int64 the handler forwards to the
// port, so an optimistic-concurrency precondition can never be
// silently dropped.
func TestDeleteServiceForwardsIfMatch(t *testing.T) {
	var gotInput store.DeleteServiceInput
	deleter := fakeServiceDeleter{
		svc:      canonicalDeletedSvc(),
		gotInput: &gotInput,
	}
	handler := deleteServiceHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, deleter)

	rec := deleteServiceWithIfMatch(handler, "svc_canonical_delete", "tok", "\"9\"")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202, body=%s", rec.Code, rec.Body.String())
	}
	if gotInput.IfMatchVersion == nil {
		t.Fatal("forwarded if_match_version is nil; want *int64=9")
	}
	if *gotInput.IfMatchVersion != 9 {
		t.Errorf("forwarded if_match_version = %d, want 9", *gotInput.IfMatchVersion)
	}
}

// TestDeleteServiceRejectsMalformedIfMatch proves a malformed
// If-Match header surfaces as a typed 400 InvalidInput envelope —
// never as a silent next-write-wins (nil precondition) call.
func TestDeleteServiceRejectsMalformedIfMatch(t *testing.T) {
	var callCount int
	deleter := fakeServiceDeleter{
		svc:       canonicalDeletedSvc(),
		callCount: &callCount,
	}
	handler := deleteServiceHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, deleter)

	rec := deleteServiceWithIfMatch(handler, "svc_canonical_delete", "tok", "not-an-etag")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("port called %d times despite malformed If-Match; want 0", callCount)
	}
}

// TestDeleteServiceUnauthenticated proves a missing bearer token is
// rejected at the RequireAuth boundary as 401 — the deleter is never
// called, so an unauthenticated caller can never trigger a scheduled
// deletion.
func TestDeleteServiceUnauthenticated(t *testing.T) {
	var callCount int
	deleter := fakeServiceDeleter{
		svc:       canonicalDeletedSvc(),
		callCount: &callCount,
	}
	handler := deleteServiceHandlerFor(auth.Identity{}, auth.ErrNoCredentials, deleter)

	rec := deleteService(handler, "svc_canonical_delete", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body=%s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("deleter called %d times despite missing credentials; want 0", callCount)
	}
}

// TestDeleteServiceForbidden proves a CapRead-only principal (viewer)
// is rejected at the RequireAuth boundary as 403; service.delete is
// CapWrite and viewers/support cannot mutate even within their home
// tenant. The deleter is never called.
func TestDeleteServiceForbidden(t *testing.T) {
	var callCount int
	deleter := fakeServiceDeleter{
		svc:       canonicalDeletedSvc(),
		callCount: &callCount,
	}
	handler := deleteServiceHandlerFor(deleteServiceViewerIdentity("org_acme", "usr_viewer"), nil, deleter)

	rec := deleteService(handler, "svc_canonical_delete", "tok")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("deleter called %d times despite viewer principal; want 0", callCount)
	}
}

// TestDeleteServiceNotFound proves the typed store-layer NotFound
// surfaces as a deterministic 404 with the typed yalla.error.v1
// envelope.
func TestDeleteServiceNotFound(t *testing.T) {
	deleter := fakeServiceDeleter{err: apierr.NotFound("service", "svc_missing")}
	handler := deleteServiceHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, deleter)

	rec := deleteService(handler, "svc_missing", "tok")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), string(yerr.CodeNotFound)) {
		t.Errorf("error code not present in body: %s", rec.Body.String())
	}
}

// TestDeleteServiceAlreadyScheduled proves the typed store-layer
// Conflict (service already scheduled for deletion) surfaces as 409
// with the typed yalla.error.v1 envelope — never disguised as a 202
// or a 200.
func TestDeleteServiceAlreadyScheduled(t *testing.T) {
	deleter := fakeServiceDeleter{err: apierr.Conflict("service deletion is already scheduled")}
	handler := deleteServiceHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, deleter)

	rec := deleteService(handler, "svc_canonical_delete", "tok")
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), string(yerr.CodeConflict)) {
		t.Errorf("error code not present in body: %s", rec.Body.String())
	}
}

// TestDeleteServiceStaleVersion proves the typed store-layer
// ConflictStale (If-Match precondition rejected) surfaces as 409
// carrying the row's authoritative version under
// details.current_version.
func TestDeleteServiceStaleVersion(t *testing.T) {
	deleter := fakeServiceDeleter{err: apierr.ConflictStale(11)}
	handler := deleteServiceHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, deleter)

	rec := deleteServiceWithIfMatch(handler, "svc_canonical_delete", "tok", "\"7\"")
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "current_version") {
		t.Errorf("details.current_version not present in body: %s", rec.Body.String())
	}
}

// TestDeleteServiceStoreUnavailable proves a typed store-unavailable
// failure surfaces as 503 — never as a 500 leaking the cause, never
// as a 404 disguising the outage as a missing row.
func TestDeleteServiceStoreUnavailable(t *testing.T) {
	deleter := fakeServiceDeleter{err: apierr.StoreUnavailable(errors.New("network blip"))}
	handler := deleteServiceHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, deleter)

	rec := deleteService(handler, "svc_canonical_delete", "tok")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503, body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "network blip") {
		t.Errorf("body leaks the wrapped cause: %s", rec.Body.String())
	}
}

// TestDeleteServiceMissingDeleter proves a wiring error (nil deleter
// reached at request time) surfaces as a typed Internal — never as a
// 404 silently disguising the outage as a missing service. The
// handler is built with a nil port; the RequireAuth gate still admits
// the request because the policy boundary is unrelated to the port
// wiring.
func TestDeleteServiceMissingDeleter(t *testing.T) {
	handler := deleteServiceHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, nil)

	rec := deleteService(handler, "svc_canonical_delete", "tok")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500, body=%s", rec.Code, rec.Body.String())
	}
}

// TestDeleteServiceOpenAPIOperation proves the route table is
// registered with the stable OpenAPI operation id deleteService and
// the action constant service.delete, so an agent inspecting the
// served openapi.json sees a documented, authoritative DELETE
// /v1/services/{service_id} operation it can call without divining
// internal details.
func TestDeleteServiceOpenAPIOperation(t *testing.T) {
	handler := deleteServiceHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, fakeServiceDeleter{svc: canonicalDeletedSvc()})

	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("openapi status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "\"deleteService\"") {
		t.Errorf("operationId deleteService not found in openapi document")
	}
	if !strings.Contains(body, "\"/v1/services/{service_id}\"") {
		t.Errorf("path /v1/services/{service_id} not found in openapi document")
	}
	if !strings.Contains(body, string(policy.ActionServiceDelete)) {
		t.Errorf("required action service.delete not found in openapi document")
	}
}
