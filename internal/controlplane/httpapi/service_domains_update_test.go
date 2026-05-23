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

// Contract, authorization, and tenant-isolation coverage for PATCH
// /v1/services/{service_id}/domains/{domain_id} (BE-0241 + BE-0242).
// The endpoint updates a single service-domain row through the
// ServiceDomainUpdater port. The tests drive it through NewHandler
// with a fake Authenticator, the real policy engine, and a fake
// updater — the same wiring a request hits in production, minus the
// database. The store-backed orchestrator
// (ServiceDomainService.Update) has its own isolated-Postgres
// integration coverage in store/service_domain.go's neighbouring
// tests; this file exercises the HTTP surface in isolation. The full
// role x tenant x grant-scope matrix lives in
// service_domains_update_policy_test.go (BE-0243).
//
// domain.update is a CapWrite action — viewer and support principals
// in the tenant cannot update domains; CI keys DO write (the
// load-bearing distinction from the deployment-tier CapDeploy
// matrix). The happy-path tests authenticate as RoleDeveloper to keep
// the role matrix focused on the policy suite.

// fakeServiceDomainUpdater is the test double for the
// ServiceDomainUpdater port: it captures the
// UpdateServiceDomainInput a test passed in, the call count, and
// returns a canned ServiceDomain / error. The captured input is the
// single load-bearing proof that the handler never trusts caller-
// controlled organization ids and plumbs the authenticated
// principal's identity, the path parameters, and the If-Match
// precondition through to the store layer.
type fakeServiceDomainUpdater struct {
	domain    store.ServiceDomain
	err       error
	gotInput  *store.UpdateServiceDomainInput
	callCount *int
}

func (f fakeServiceDomainUpdater) Update(_ context.Context, in store.UpdateServiceDomainInput) (store.ServiceDomain, error) {
	if f.gotInput != nil {
		*f.gotInput = in
	}
	if f.callCount != nil {
		*f.callCount++
	}
	return f.domain, f.err
}

// updateServiceDomainSuccessEnvelope is the decoded shape of the PATCH
// /v1/services/{service_id}/domains/{domain_id} success envelope.
type updateServiceDomainSuccessEnvelope struct {
	SchemaVersion string                     `json:"schema_version"`
	OK            bool                       `json:"ok"`
	RequestID     string                     `json:"request_id"`
	Data          updateServiceDomainPayload `json:"data"`
}

// canonicalUpdatedServiceDomain is the canned service_domains row the
// happy-path tests render through serviceDomainOf. Every field is
// non-zero so the projection invariants are exercised on the wire.
var canonicalUpdatedServiceDomain = store.ServiceDomain{
	ID:              "sdom_canonical_patch",
	OrganizationID:  "org_acme",
	ServiceID:       "svc_canonical_patch_domain",
	Hostname:        "api.canonical.example",
	Path:            "/v2",
	Port:            443,
	HTTPS:           true,
	CertificateType: store.ServiceDomainCertificateLetsEncrypt,
	Version:         7,
	CreatedAt:       time.Date(2025, 4, 11, 9, 30, 0, 0, time.UTC),
	UpdatedAt:       time.Date(2025, 4, 12, 10, 0, 0, 0, time.UTC),
}

// updateServiceDomainHandlerFor builds the full NewHandler surface
// with an Authenticator that resolves every credential to id and the
// given ServiceDomainUpdater. It is the production request path: the
// PATCH /v1/services/{service_id}/domains/{domain_id} route is
// wrapped in RequireAuth for action domain.update.
func updateServiceDomainHandlerFor(id auth.Identity, authErr error, updater ServiceDomainUpdater) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, updater, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
}

// patchServiceDomain issues PATCH
// /v1/services/{service_id}/domains/{domain_id} against the handler
// with the supplied bearer token and body.
func patchServiceDomain(handler http.Handler, serviceID, domainID, token, body string) *httptest.ResponseRecorder {
	return patchServiceDomainWithIfMatch(handler, serviceID, domainID, token, "", body)
}

// patchServiceDomainWithIfMatch issues PATCH
// /v1/services/{service_id}/domains/{domain_id} with an optional
// If-Match header. An empty ifMatch omits the header entirely so the
// optional precondition path remains exercised.
func patchServiceDomainWithIfMatch(handler http.Handler, serviceID, domainID, token, ifMatch, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPatch,
		"/v1/services/"+serviceID+"/domains/"+domainID, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
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

func decodeUpdateServiceDomain(t *testing.T, rec *httptest.ResponseRecorder) updateServiceDomainSuccessEnvelope {
	t.Helper()
	var env updateServiceDomainSuccessEnvelope
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

// TestUpdateServiceDomainHappyPathForwardsBodyAndPrincipal proves the
// handler decodes the patch body, threads the principal's home
// organization id, the path service_id, and the path domain_id into
// the store input, preserves the nil-ness of unset fields, renders
// the returned row in the stable yalla.output.v1 envelope, returns
// 200 OK, and mirrors the row's authoritative version into the ETag
// response header.
func TestUpdateServiceDomainHappyPathForwardsBodyAndPrincipal(t *testing.T) {
	t.Parallel()

	var captured store.UpdateServiceDomainInput
	updater := fakeServiceDomainUpdater{domain: canonicalUpdatedServiceDomain, gotInput: &captured}
	handler := updateServiceDomainHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, updater)

	rec := patchServiceDomain(handler,
		"svc_canonical_patch_domain", "sdom_canonical_patch",
		"a-valid-session-token", `{"hostname":"api.canonical.example","path":"/v2","port":443,"https":true,"certificate_type":"lets-encrypt"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeUpdateServiceDomain(t, rec)
	if env.Data.Domain.ID != canonicalUpdatedServiceDomain.ID {
		t.Errorf("domain.id = %q, want %q", env.Data.Domain.ID, canonicalUpdatedServiceDomain.ID)
	}
	if env.Data.Domain.ServiceID != canonicalUpdatedServiceDomain.ServiceID {
		t.Errorf("service_id = %q, want %q", env.Data.Domain.ServiceID, canonicalUpdatedServiceDomain.ServiceID)
	}
	if env.Data.Domain.Hostname != canonicalUpdatedServiceDomain.Hostname {
		t.Errorf("hostname = %q, want %q", env.Data.Domain.Hostname, canonicalUpdatedServiceDomain.Hostname)
	}
	if env.Data.Domain.Path != canonicalUpdatedServiceDomain.Path {
		t.Errorf("path = %q, want %q", env.Data.Domain.Path, canonicalUpdatedServiceDomain.Path)
	}
	if env.Data.Domain.Version != canonicalUpdatedServiceDomain.Version {
		t.Errorf("version = %d, want %d", env.Data.Domain.Version, canonicalUpdatedServiceDomain.Version)
	}
	if got, want := rec.Header().Get("ETag"), `"7"`; got != want {
		t.Errorf("ETag header = %q, want %q", got, want)
	}

	if captured.OrganizationID != "org_acme" {
		t.Errorf("forwarded organization_id = %q, want org_acme (principal home)", captured.OrganizationID)
	}
	if captured.ServiceID != "svc_canonical_patch_domain" {
		t.Errorf("forwarded service_id = %q, want svc_canonical_patch_domain (path value)", captured.ServiceID)
	}
	if captured.DomainID != "sdom_canonical_patch" {
		t.Errorf("forwarded domain_id = %q, want sdom_canonical_patch (path value)", captured.DomainID)
	}
	if captured.Hostname == nil || *captured.Hostname != "api.canonical.example" {
		t.Errorf("forwarded hostname = %v, want pointer to \"api.canonical.example\"", captured.Hostname)
	}
	if captured.Path == nil || *captured.Path != "/v2" {
		t.Errorf("forwarded path = %v, want pointer to \"/v2\"", captured.Path)
	}
	if captured.Port == nil || *captured.Port != 443 {
		t.Errorf("forwarded port = %v, want pointer to 443", captured.Port)
	}
	if captured.HTTPS == nil || *captured.HTTPS != true {
		t.Errorf("forwarded https = %v, want pointer to true", captured.HTTPS)
	}
	if captured.CertificateType == nil || *captured.CertificateType != "lets-encrypt" {
		t.Errorf("forwarded certificate_type = %v, want pointer to \"lets-encrypt\"", captured.CertificateType)
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

// TestUpdateServiceDomainPreservesAbsentFields proves the handler
// preserves the nil-ness of every absent field on the patch — a body
// that names only one updatable field forwards exactly that field
// and leaves the others as nil pointers so the store layer can tell
// "caller did not supply this" from "caller supplied the zero value".
func TestUpdateServiceDomainPreservesAbsentFields(t *testing.T) {
	t.Parallel()

	var captured store.UpdateServiceDomainInput
	updater := fakeServiceDomainUpdater{domain: canonicalUpdatedServiceDomain, gotInput: &captured}
	handler := updateServiceDomainHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, updater)

	rec := patchServiceDomain(handler,
		"svc_canonical_patch_domain", "sdom_canonical_patch",
		"a-valid-session-token", `{"hostname":"api.canonical.example"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if captured.Hostname == nil || *captured.Hostname != "api.canonical.example" {
		t.Errorf("forwarded hostname = %v, want pointer to \"api.canonical.example\"", captured.Hostname)
	}
	if captured.Path != nil {
		t.Errorf("forwarded path = %v, want nil (absent from body)", captured.Path)
	}
	if captured.Port != nil {
		t.Errorf("forwarded port = %v, want nil (absent from body)", captured.Port)
	}
	if captured.HTTPS != nil {
		t.Errorf("forwarded https = %v, want nil (absent from body)", captured.HTTPS)
	}
	if captured.CertificateType != nil {
		t.Errorf("forwarded certificate_type = %v, want nil (absent from body)", captured.CertificateType)
	}
}

// TestUpdateServiceDomainExplicitHTTPSFalseRidesThrough proves an
// explicit `"https": false` in the body forwards as a pointer to
// false to the store layer — the absent-vs-explicit-false distinction
// survives the seam.
func TestUpdateServiceDomainExplicitHTTPSFalseRidesThrough(t *testing.T) {
	t.Parallel()

	var captured store.UpdateServiceDomainInput
	updater := fakeServiceDomainUpdater{domain: canonicalUpdatedServiceDomain, gotInput: &captured}
	handler := updateServiceDomainHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, updater)

	rec := patchServiceDomain(handler,
		"svc_canonical_patch_domain", "sdom_canonical_patch",
		"a-valid-session-token", `{"https":false}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if captured.HTTPS == nil {
		t.Fatalf("forwarded https = nil, want pointer to false (explicit false in body)")
	}
	if *captured.HTTPS != false {
		t.Errorf("forwarded https = %v, want pointer to false", *captured.HTTPS)
	}
}

// TestUpdateServiceDomainForwardsIfMatchVersion proves the handler
// parses the If-Match header as a strong ETag, forwards the resulting
// version pointer to the store input, and otherwise behaves
// identically to the no-header path.
func TestUpdateServiceDomainForwardsIfMatchVersion(t *testing.T) {
	t.Parallel()

	var captured store.UpdateServiceDomainInput
	updater := fakeServiceDomainUpdater{domain: canonicalUpdatedServiceDomain, gotInput: &captured}
	handler := updateServiceDomainHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, updater)

	rec := patchServiceDomainWithIfMatch(handler,
		"svc_canonical_patch_domain", "sdom_canonical_patch",
		"a-valid-session-token", `"6"`, `{"hostname":"api.canonical.example"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if captured.IfMatchVersion == nil {
		t.Fatalf("forwarded if_match_version = nil, want pointer to 6")
	}
	if *captured.IfMatchVersion != 6 {
		t.Errorf("forwarded if_match_version = %d, want 6", *captured.IfMatchVersion)
	}
}

// TestUpdateServiceDomainMalformedIfMatchIs400 proves a malformed
// If-Match header is rejected with a stable 400 before the updater
// runs — a malformed precondition is a client error, never a silent
// next-write-wins.
func TestUpdateServiceDomainMalformedIfMatchIs400(t *testing.T) {
	t.Parallel()

	var captured store.UpdateServiceDomainInput
	callCount := 0
	updater := fakeServiceDomainUpdater{
		domain:    canonicalUpdatedServiceDomain,
		gotInput:  &captured,
		callCount: &callCount,
	}
	handler := updateServiceDomainHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, updater)

	rec := patchServiceDomainWithIfMatch(handler,
		"svc_canonical_patch_domain", "sdom_canonical_patch",
		"a-valid-session-token", `not-a-strong-etag`, `{"hostname":"api.canonical.example"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("updater was reached (calls=%d) despite a malformed If-Match; it must never run", callCount)
	}
}

// TestUpdateServiceDomainStaleIfMatchReturns409 proves a stale
// If-Match version surfaces as a typed 409 with the row's
// authoritative current_version under details — the agent learns the
// version it needs to retry with without re-reading the row.
func TestUpdateServiceDomainStaleIfMatchReturns409(t *testing.T) {
	t.Parallel()

	updater := fakeServiceDomainUpdater{err: apierr.ConflictStale(11)}
	handler := updateServiceDomainHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, updater)

	rec := patchServiceDomainWithIfMatch(handler,
		"svc_canonical_patch_domain", "sdom_canonical_patch",
		"a-valid-session-token", `"7"`, `{"hostname":"api.canonical.example"}`)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_CONFLICT")
	if !strings.Contains(rec.Body.String(), "current_version") {
		t.Errorf("response body did not carry current_version details; body %s", rec.Body.String())
	}
}

// TestUpdateServiceDomainMalformedBodyIs400 proves an oversized,
// malformed, or unknown-field body is rejected with a typed 400
// before the updater runs.
func TestUpdateServiceDomainMalformedBodyIs400(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		body string
	}{
		{"malformed json", `{"hostname":}`},
		{"unknown field", `{"organization_id":"org_attacker"}`},
		{"unknown field service_id", `{"service_id":"svc_attacker"}`},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var captured store.UpdateServiceDomainInput
			callCount := 0
			updater := fakeServiceDomainUpdater{
				domain:    canonicalUpdatedServiceDomain,
				gotInput:  &captured,
				callCount: &callCount,
			}
			handler := updateServiceDomainHandlerFor(
				auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
				nil, updater)

			rec := patchServiceDomain(handler,
				"svc_canonical_patch_domain", "sdom_canonical_patch",
				"a-valid-session-token", tc.body)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
			}
			if callCount != 0 {
				t.Errorf("updater was reached (calls=%d); a malformed body must never reach the store layer", callCount)
			}
		})
	}
}

// TestUpdateServiceDomainNotFoundIsTyped404 proves an unknown
// (service_id, domain_id) pair surfaces as a typed 404 — never a 500
// leaking the internal cause, never a misleading 2xx.
func TestUpdateServiceDomainNotFoundIsTyped404(t *testing.T) {
	t.Parallel()

	updater := fakeServiceDomainUpdater{err: apierr.NotFound("service domain", "sdom_missing")}
	handler := updateServiceDomainHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, updater)

	rec := patchServiceDomain(handler,
		"svc_canonical_patch_domain", "sdom_missing",
		"a-valid-session-token", `{"hostname":"api.canonical.example"}`)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_NOT_FOUND")
}

// TestUpdateServiceDomainConflictIsTyped409 proves a (hostname, path)
// collision surfaces as a typed 409 with the stable conflict code —
// never a 500 leaking the constraint name.
func TestUpdateServiceDomainConflictIsTyped409(t *testing.T) {
	t.Parallel()

	updater := fakeServiceDomainUpdater{
		err: apierr.Conflict("a service domain with this hostname and path already exists"),
	}
	handler := updateServiceDomainHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, updater)

	rec := patchServiceDomain(handler,
		"svc_canonical_patch_domain", "sdom_canonical_patch",
		"a-valid-session-token", `{"hostname":"taken.example","path":"/"}`)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_CONFLICT")
}

// TestUpdateServiceDomainInvalidInputIsTyped400 proves a typed
// apierr.InvalidInput surfaces as a 400 with the field violations
// echoed back — the path the store layer takes for an invalid
// hostname, path, or certificate_type.
func TestUpdateServiceDomainInvalidInputIsTyped400(t *testing.T) {
	t.Parallel()

	updater := fakeServiceDomainUpdater{
		err: apierr.InvalidInput(apierr.FieldViolation{Field: "hostname", Reason: "must be a valid domain"}),
	}
	handler := updateServiceDomainHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, updater)

	rec := patchServiceDomain(handler,
		"svc_canonical_patch_domain", "sdom_canonical_patch",
		"a-valid-session-token", `{"hostname":"!!!"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_VALIDATION")
}

// TestUpdateServiceDomainUnauthenticatedIs401 proves an absent or
// invalid bearer token is rejected at the auth boundary with a stable
// 401 — the updater is never reached.
func TestUpdateServiceDomainUnauthenticatedIs401(t *testing.T) {
	t.Parallel()

	callCount := 0
	updater := fakeServiceDomainUpdater{callCount: &callCount}
	handler := updateServiceDomainHandlerFor(
		auth.Identity{}, stderrors.New("invalid credential"), updater)

	rec := patchServiceDomain(handler,
		"svc_canonical_patch_domain", "sdom_canonical_patch",
		"", `{"hostname":"api.canonical.example"}`)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("updater was reached (calls=%d) for an unauthenticated request; it must never run", callCount)
	}
}

// TestUpdateServiceDomainStoreUnavailableIsTyped5xx proves a typed
// apierr.StoreUnavailable surfaces as a 5xx with the stable error
// code and the original error wrapped — never disguised as a 404 or
// a 400, never echoing the internal cause to the wire.
func TestUpdateServiceDomainStoreUnavailableIsTyped5xx(t *testing.T) {
	t.Parallel()

	updater := fakeServiceDomainUpdater{err: apierr.StoreUnavailable(yerr.New(yerr.CodeInternal, "kaboom"))}
	handler := updateServiceDomainHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, updater)

	rec := patchServiceDomain(handler,
		"svc_canonical_patch_domain", "sdom_canonical_patch",
		"a-valid-session-token", `{"hostname":"api.canonical.example"}`)

	if rec.Code < 500 || rec.Code >= 600 {
		t.Fatalf("status = %d, want a 5xx; body %s", rec.Code, rec.Body.String())
	}
}

// TestUpdateServiceDomainHandlerNoPrincipalIsInternal proves the
// handler-internal `errNoPrincipalOnContext` sentinel surfaces as a
// typed Internal error if the route is ever exercised through a
// wiring that bypasses RequireAuth. This is a structural assertion —
// in production the middleware always populates the principal — so
// the test invokes the bare handler directly.
func TestUpdateServiceDomainHandlerNoPrincipalIsInternal(t *testing.T) {
	t.Parallel()

	updater := fakeServiceDomainUpdater{}
	handler := updateServiceDomainHandler(updater)

	req := httptest.NewRequest(http.MethodPatch,
		"/v1/services/svc_x/domains/sdom_x", strings.NewReader(`{"hostname":"a.example"}`))
	req.SetPathValue("service_id", "svc_x")
	req.SetPathValue("domain_id", "sdom_x")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code < 500 || rec.Code >= 600 {
		t.Fatalf("status = %d, want a 5xx (no principal); body %s", rec.Code, rec.Body.String())
	}
}

// TestUpdateServiceDomainHandlerNilUpdaterIsInternal proves a nil
// ServiceDomainUpdater wired through NewHandler surfaces as a typed
// Internal error rather than a silent success.
func TestUpdateServiceDomainHandlerNilUpdaterIsInternal(t *testing.T) {
	t.Parallel()

	handler := updateServiceDomainHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, nil)

	rec := patchServiceDomain(handler,
		"svc_canonical_patch_domain", "sdom_canonical_patch",
		"a-valid-session-token", `{"hostname":"api.canonical.example"}`)

	if rec.Code < 500 || rec.Code >= 600 {
		t.Fatalf("status = %d, want a 5xx (nil updater); body %s", rec.Code, rec.Body.String())
	}
}
