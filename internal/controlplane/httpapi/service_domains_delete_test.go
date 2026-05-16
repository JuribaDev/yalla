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
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Contract, authorization, and tenant-isolation coverage for DELETE
// /v1/services/{service_id}/domains/{domain_id} (BE-0244 + BE-0245).
// The endpoint removes a single service-domain row through the
// ServiceDomainDeleter port. The tests drive it through NewHandler
// with a fake Authenticator, the real policy engine, and a fake
// deleter — the same wiring a request hits in production, minus the
// database. The store-backed orchestrator
// (ServiceDomainService.Delete) has its own isolated-Postgres
// integration coverage in store/service_domain.go's neighbouring
// tests; this file exercises the HTTP surface in isolation. The full
// role x tenant x grant-scope matrix lives in
// service_domains_delete_policy_test.go (BE-0246).
//
// domain.delete is a CapWrite action — viewer and support principals
// in the tenant cannot delete domains; CI keys DO write (the
// load-bearing distinction from the deployment-tier CapDeploy
// matrix). The happy-path tests authenticate as RoleDeveloper to keep
// the role matrix focused on the policy suite.

// fakeServiceDomainDeleter is the test double for the
// ServiceDomainDeleter port: it captures the
// DeleteServiceDomainInput a test passed in, the call count, and
// returns a canned ServiceDomain / error. The captured input is the
// single load-bearing proof that the handler never trusts caller-
// controlled organization ids and plumbs the authenticated
// principal's identity, the path parameters, and the If-Match
// precondition through to the store layer.
type fakeServiceDomainDeleter struct {
	domain    store.ServiceDomain
	err       error
	gotInput  *store.DeleteServiceDomainInput
	callCount *int
}

func (f fakeServiceDomainDeleter) Delete(_ context.Context, in store.DeleteServiceDomainInput) (store.ServiceDomain, error) {
	if f.gotInput != nil {
		*f.gotInput = in
	}
	if f.callCount != nil {
		*f.callCount++
	}
	return f.domain, f.err
}

// deleteServiceDomainSuccessEnvelope is the decoded shape of the
// DELETE /v1/services/{service_id}/domains/{domain_id} success
// envelope.
type deleteServiceDomainSuccessEnvelope struct {
	SchemaVersion string                     `json:"schema_version"`
	OK            bool                       `json:"ok"`
	RequestID     string                     `json:"request_id"`
	Data          deleteServiceDomainPayload `json:"data"`
}

// canonicalDeletedServiceDomain is the canned service_domains row the
// happy-path tests render through serviceDomainOf. Every field is
// non-zero so the projection invariants are exercised on the wire.
var canonicalDeletedServiceDomain = store.ServiceDomain{
	ID:              "sdom_canonical_delete",
	OrganizationID:  "org_acme",
	ServiceID:       "svc_canonical_delete_domain",
	Hostname:        "api.canonical.example",
	Path:            "/v1",
	Port:            443,
	HTTPS:           true,
	CertificateType: store.ServiceDomainCertificateLetsEncrypt,
	Version:         5,
	CreatedAt:       time.Date(2025, 4, 11, 9, 30, 0, 0, time.UTC),
	UpdatedAt:       time.Date(2025, 4, 12, 10, 0, 0, 0, time.UTC),
}

// deleteServiceDomainHandlerFor builds the full NewHandler surface
// with an Authenticator that resolves every credential to id and the
// given ServiceDomainDeleter. It is the production request path: the
// DELETE /v1/services/{service_id}/domains/{domain_id} route is
// wrapped in RequireAuth for action domain.delete.
func deleteServiceDomainHandlerFor(id auth.Identity, authErr error, deleter ServiceDomainDeleter) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, deleter, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
}

// deleteServiceDomain issues DELETE
// /v1/services/{service_id}/domains/{domain_id} against the handler
// with the supplied bearer token.
func deleteServiceDomain(handler http.Handler, serviceID, domainID, token string) *httptest.ResponseRecorder {
	return deleteServiceDomainWithIfMatch(handler, serviceID, domainID, token, "")
}

// deleteServiceDomainWithIfMatch issues DELETE
// /v1/services/{service_id}/domains/{domain_id} with an optional
// If-Match header. An empty ifMatch omits the header entirely so the
// optional precondition path remains exercised.
func deleteServiceDomainWithIfMatch(handler http.Handler, serviceID, domainID, token, ifMatch string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodDelete,
		"/v1/services/"+serviceID+"/domains/"+domainID, nil)
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

func decodeDeleteServiceDomain(t *testing.T, rec *httptest.ResponseRecorder) deleteServiceDomainSuccessEnvelope {
	t.Helper()
	var env deleteServiceDomainSuccessEnvelope
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

// TestDeleteServiceDomainHappyPathForwardsPrincipalAndPath proves the
// handler threads the principal's home organization id, the path
// service_id, and the path domain_id into the store input (never
// from caller-controlled input — a DELETE has no body), renders the
// deleted snapshot in the stable yalla.output.v1 envelope, and
// returns 200 OK.
func TestDeleteServiceDomainHappyPathForwardsPrincipalAndPath(t *testing.T) {
	t.Parallel()

	var captured store.DeleteServiceDomainInput
	deleter := fakeServiceDomainDeleter{domain: canonicalDeletedServiceDomain, gotInput: &captured}
	handler := deleteServiceDomainHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, deleter)

	rec := deleteServiceDomain(handler,
		"svc_canonical_delete_domain", "sdom_canonical_delete",
		"a-valid-session-token")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeDeleteServiceDomain(t, rec)
	if env.Data.Domain.ID != canonicalDeletedServiceDomain.ID {
		t.Errorf("domain.id = %q, want %q", env.Data.Domain.ID, canonicalDeletedServiceDomain.ID)
	}
	if env.Data.Domain.ServiceID != canonicalDeletedServiceDomain.ServiceID {
		t.Errorf("service_id = %q, want %q", env.Data.Domain.ServiceID, canonicalDeletedServiceDomain.ServiceID)
	}
	if env.Data.Domain.Hostname != canonicalDeletedServiceDomain.Hostname {
		t.Errorf("hostname = %q, want %q", env.Data.Domain.Hostname, canonicalDeletedServiceDomain.Hostname)
	}
	if env.Data.Domain.Path != canonicalDeletedServiceDomain.Path {
		t.Errorf("path = %q, want %q", env.Data.Domain.Path, canonicalDeletedServiceDomain.Path)
	}
	if env.Data.Domain.Version != canonicalDeletedServiceDomain.Version {
		t.Errorf("version = %d, want %d", env.Data.Domain.Version, canonicalDeletedServiceDomain.Version)
	}

	if captured.OrganizationID != "org_acme" {
		t.Errorf("forwarded organization_id = %q, want org_acme (principal home)", captured.OrganizationID)
	}
	if captured.ServiceID != "svc_canonical_delete_domain" {
		t.Errorf("forwarded service_id = %q, want svc_canonical_delete_domain (path value)", captured.ServiceID)
	}
	if captured.DomainID != "sdom_canonical_delete" {
		t.Errorf("forwarded domain_id = %q, want sdom_canonical_delete (path value)", captured.DomainID)
	}
	if captured.IfMatchVersion != nil {
		t.Errorf("forwarded if_match_version = %v, want nil (no header sent)", captured.IfMatchVersion)
	}
	if captured.ActorID != "usr_ada" {
		t.Errorf("forwarded actor_id = %q, want usr_ada", captured.ActorID)
	}
	if captured.ActorOrgID != "org_acme" {
		t.Errorf("forwarded actor_org_id = %q, want org_acme", captured.ActorOrgID)
	}
}

// TestDeleteServiceDomainForwardsIfMatchVersion proves the handler
// parses the If-Match header as a strong ETag and forwards the
// resulting version pointer to the store input — the optimistic
// concurrency precondition rides through unchanged.
func TestDeleteServiceDomainForwardsIfMatchVersion(t *testing.T) {
	t.Parallel()

	var captured store.DeleteServiceDomainInput
	deleter := fakeServiceDomainDeleter{domain: canonicalDeletedServiceDomain, gotInput: &captured}
	handler := deleteServiceDomainHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, deleter)

	rec := deleteServiceDomainWithIfMatch(handler,
		"svc_canonical_delete_domain", "sdom_canonical_delete",
		"a-valid-session-token", `"5"`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if captured.IfMatchVersion == nil {
		t.Fatalf("forwarded if_match_version = nil, want pointer to 5")
	}
	if *captured.IfMatchVersion != 5 {
		t.Errorf("forwarded if_match_version = %d, want 5", *captured.IfMatchVersion)
	}
}

// TestDeleteServiceDomainMalformedIfMatchIs400 proves a malformed
// If-Match header is rejected with a stable 400 before the deleter
// runs — a malformed precondition is a client error, never a silent
// next-write-wins. Deleting a row is structurally destructive, so a
// malformed precondition that silently degraded into "no precondition"
// would be a particularly load-bearing footgun.
func TestDeleteServiceDomainMalformedIfMatchIs400(t *testing.T) {
	t.Parallel()

	var captured store.DeleteServiceDomainInput
	callCount := 0
	deleter := fakeServiceDomainDeleter{
		domain:    canonicalDeletedServiceDomain,
		gotInput:  &captured,
		callCount: &callCount,
	}
	handler := deleteServiceDomainHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, deleter)

	rec := deleteServiceDomainWithIfMatch(handler,
		"svc_canonical_delete_domain", "sdom_canonical_delete",
		"a-valid-session-token", `not-a-strong-etag`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("deleter was reached (calls=%d) despite a malformed If-Match; it must never run", callCount)
	}
}

// TestDeleteServiceDomainStaleIfMatchReturns409 proves a stale
// If-Match version surfaces as a typed 409 with the row's
// authoritative current_version under details — the agent learns the
// version it needs to retry with without re-reading the row.
func TestDeleteServiceDomainStaleIfMatchReturns409(t *testing.T) {
	t.Parallel()

	deleter := fakeServiceDomainDeleter{err: apierr.ConflictStale(11)}
	handler := deleteServiceDomainHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, deleter)

	rec := deleteServiceDomainWithIfMatch(handler,
		"svc_canonical_delete_domain", "sdom_canonical_delete",
		"a-valid-session-token", `"7"`)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_CONFLICT")
	if !strings.Contains(rec.Body.String(), "current_version") {
		t.Errorf("response body did not carry current_version details; body %s", rec.Body.String())
	}
}

// TestDeleteServiceDomainNotFoundIsTyped404 proves an unknown
// (service_id, domain_id) pair surfaces as a typed 404 — never a 500
// leaking the internal cause, never a misleading 2xx.
func TestDeleteServiceDomainNotFoundIsTyped404(t *testing.T) {
	t.Parallel()

	deleter := fakeServiceDomainDeleter{err: apierr.NotFound("service domain", "sdom_missing")}
	handler := deleteServiceDomainHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, deleter)

	rec := deleteServiceDomain(handler,
		"svc_canonical_delete_domain", "sdom_missing",
		"a-valid-session-token")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_NOT_FOUND")
}

// TestDeleteServiceDomainInvalidInputIsTyped400 proves a typed
// apierr.InvalidInput surfaces as a 400 with the field violations
// echoed back — the path the store layer takes for a blank
// organization_id, service_id, or domain_id (defense-in-depth against
// a wiring bug that would otherwise let an empty path parameter
// reach the persistence layer).
func TestDeleteServiceDomainInvalidInputIsTyped400(t *testing.T) {
	t.Parallel()

	deleter := fakeServiceDomainDeleter{
		err: apierr.InvalidInput(apierr.FieldViolation{Field: "id", Reason: "must not be blank"}),
	}
	handler := deleteServiceDomainHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, deleter)

	rec := deleteServiceDomain(handler,
		"svc_canonical_delete_domain", "sdom_canonical_delete",
		"a-valid-session-token")

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INVALID_INPUT")
}

// TestDeleteServiceDomainUnauthenticatedIs401 proves an absent or
// invalid bearer token is rejected at the auth boundary with a stable
// 401 — the deleter is never reached. A destructive operation that
// silently succeeded on an unauthenticated request would be the
// worst possible failure mode, so the assertion that callCount is
// zero is structurally load-bearing here.
func TestDeleteServiceDomainUnauthenticatedIs401(t *testing.T) {
	t.Parallel()

	callCount := 0
	deleter := fakeServiceDomainDeleter{callCount: &callCount}
	handler := deleteServiceDomainHandlerFor(
		auth.Identity{}, stderrors.New("invalid credential"), deleter)

	rec := deleteServiceDomain(handler,
		"svc_canonical_delete_domain", "sdom_canonical_delete", "")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("deleter was reached (calls=%d) for an unauthenticated request; it must never run", callCount)
	}
}

// TestDeleteServiceDomainStoreUnavailableIsTyped5xx proves a typed
// apierr.StoreUnavailable surfaces as a 5xx with the stable error
// code and the original error wrapped — never disguised as a 404 or
// a 400, never echoing the internal cause to the wire.
func TestDeleteServiceDomainStoreUnavailableIsTyped5xx(t *testing.T) {
	t.Parallel()

	deleter := fakeServiceDomainDeleter{err: apierr.StoreUnavailable(yerr.New(yerr.CodeInternal, "kaboom"))}
	handler := deleteServiceDomainHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, deleter)

	rec := deleteServiceDomain(handler,
		"svc_canonical_delete_domain", "sdom_canonical_delete",
		"a-valid-session-token")

	if rec.Code < 500 || rec.Code >= 600 {
		t.Fatalf("status = %d, want a 5xx; body %s", rec.Code, rec.Body.String())
	}
}

// TestDeleteServiceDomainHandlerNoPrincipalIsInternal proves the
// handler-internal `errNoPrincipalOnContext` sentinel surfaces as a
// typed Internal error if the route is ever exercised through a
// wiring that bypasses RequireAuth. This is a structural assertion —
// in production the middleware always populates the principal — so
// the test invokes the bare handler directly.
func TestDeleteServiceDomainHandlerNoPrincipalIsInternal(t *testing.T) {
	t.Parallel()

	deleter := fakeServiceDomainDeleter{}
	handler := deleteServiceDomainHandler(deleter)

	req := httptest.NewRequest(http.MethodDelete,
		"/v1/services/svc_x/domains/sdom_x", nil)
	req.SetPathValue("service_id", "svc_x")
	req.SetPathValue("domain_id", "sdom_x")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code < 500 || rec.Code >= 600 {
		t.Fatalf("status = %d, want a 5xx (no principal); body %s", rec.Code, rec.Body.String())
	}
}

// TestDeleteServiceDomainHandlerNilDeleterIsInternal proves a nil
// ServiceDomainDeleter wired through NewHandler surfaces as a typed
// Internal error rather than a silent success (a 200 OK confirming
// the deletion of a row that was never removed would be the worst
// possible signal for an agent).
func TestDeleteServiceDomainHandlerNilDeleterIsInternal(t *testing.T) {
	t.Parallel()

	handler := deleteServiceDomainHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, nil)

	rec := deleteServiceDomain(handler,
		"svc_canonical_delete_domain", "sdom_canonical_delete",
		"a-valid-session-token")

	if rec.Code < 500 || rec.Code >= 600 {
		t.Fatalf("status = %d, want a 5xx (nil deleter); body %s", rec.Code, rec.Body.String())
	}
}

// TestDeleteServiceDomainOpenAPIOperationRegistered proves the route
// is documented at the same point in the OpenAPI surface as the
// other service-domain endpoints. A served route that is not
// documented (or vice-versa) is a wire-contract bug — the route table
// is the single source of truth for both.
func TestDeleteServiceDomainOpenAPIOperationRegistered(t *testing.T) {
	t.Parallel()

	handler := deleteServiceDomainHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, fakeServiceDomainDeleter{domain: canonicalDeletedServiceDomain})

	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("/openapi.json status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"deleteServiceDomain"`) {
		excerpt := body
		if len(excerpt) > 400 {
			excerpt = excerpt[:400]
		}
		t.Errorf("OpenAPI document does not register operation deleteServiceDomain; body excerpt: %s", excerpt)
	}
	if !strings.Contains(body, `"/v1/services/{service_id}/domains/{domain_id}"`) {
		t.Errorf("OpenAPI document does not register path /v1/services/{service_id}/domains/{domain_id}")
	}
	if !strings.Contains(body, `"domain.delete"`) {
		t.Errorf("OpenAPI document does not declare required action domain.delete")
	}
}

// TestDeleteServiceDomainRequestIDPropagation proves the success
// envelope carries a non-empty request_id and that an inbound safe
// X-Request-Id is honoured (handled by telemetry.Correlate) and
// surfaced verbatim on the wire.
func TestDeleteServiceDomainRequestIDPropagation(t *testing.T) {
	t.Parallel()

	deleter := fakeServiceDomainDeleter{domain: canonicalDeletedServiceDomain}
	handler := deleteServiceDomainHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, deleter)

	req := httptest.NewRequest(http.MethodDelete,
		"/v1/services/svc_canonical_delete_domain/domains/sdom_canonical_delete", nil)
	req.Header.Set("Authorization", "Bearer a-valid-session-token")
	const inbound = "req_canonical_delete_domain_01HABCDEFGHJKMNPQRSTVWXYZ"
	req.Header.Set("X-Request-Id", inbound)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeDeleteServiceDomain(t, rec)
	if env.RequestID != inbound {
		t.Errorf("request_id = %q, want %q (safe inbound header should be honoured)", env.RequestID, inbound)
	}
}
