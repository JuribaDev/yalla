package httpapi

import (
	"encoding/json"
	stderrors "errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// Contract and tenant-isolation coverage for PATCH
// /v1/organizations/{org_id}/limits (BE-0097). The endpoint upserts
// organization-scoped quota policies for the organization named by the
// {org_id} path parameter through the LimitsUpdater port; the tests drive
// it through NewHandler with a fake Authenticator, the real policy engine,
// and a fake updater — the same wiring a request hits in production, minus
// the database. The store-backed updater has its own isolated-Postgres
// integration coverage in store/limits_service_test.go.
//
// limits.write is a CapAdmin action: a viewer, developer, or support
// principal in the tenant cannot mutate limits, only an owner or admin in
// the tenant can — and unlike CapRead actions there is no cross-tenant
// support exception. The happy-path tests therefore authenticate as
// RoleAdmin or RoleOwner. The authorization matrix lives in
// limits_patch_policy_test.go (BE-0099).
//
// Validation surface: the body decoder rejects oversized/malformed/
// unknown-field bodies as 400 (the global validate.DecodeJSON contract),
// the handler additionally surfaces a 400 for an empty patch and for an
// entry missing limit_value (the symmetric early reject of the
// store-layer's identical violation). Field-level validation of resource
// names, ranges, enforcement modes, and duplicate detection is the
// store-layer's job and is asserted through the updater error path here,
// not by re-validating in the handler.

// updateLimitsSuccessEnvelope is the decoded shape of the PATCH
// /v1/organizations/{org_id}/limits success envelope.
type updateLimitsSuccessEnvelope struct {
	SchemaVersion string              `json:"schema_version"`
	OK            bool                `json:"ok"`
	RequestID     string              `json:"request_id"`
	Data          updateLimitsPayload `json:"data"`
}

// patchLimits issues PATCH /v1/organizations/{orgID}/limits against handler
// with body, optionally with a bearer token.
func patchLimits(handler http.Handler, orgID, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPatch,
		"/v1/organizations/"+orgID+"/limits",
		strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// decodeUpdateLimits decodes the JSON success body returned by PATCH
// /v1/organizations/{org_id}/limits into the wire shape the contract pins
// down.
func decodeUpdateLimits(t *testing.T, rec *httptest.ResponseRecorder) updateLimitsSuccessEnvelope {
	t.Helper()
	var env updateLimitsSuccessEnvelope
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

// TestUpdateLimitsReturnsEffectiveLimits is the happy path: an authenticated
// admin principal PATCHing its own organization's limits receives the
// post-write effective limits in a stable yalla.output.v1 envelope, exactly
// as the updater returned them.
func TestUpdateLimitsReturnsEffectiveLimits(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	post := []store.EffectiveQuotaLimit{
		{Resource: store.QuotaResourceProjects, LimitValue: 25, EnforcementMode: store.EnforcementModeHard, Scope: store.QuotaScopeOrganization},
		{Resource: store.QuotaResourceServices, LimitValue: 100, EnforcementMode: store.EnforcementModeHard, Scope: store.QuotaScopeOrganization},
	}
	var got store.UpdateLimitsInput
	updater := fakeLimitsUpdater{limits: post, got: &got}
	handler := updateLimitsHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", orgID, policy.RoleAdmin), Method: auth.MethodSession},
		nil, updater)

	body := `{"limits":[{"resource":"projects","limit_value":25},{"resource":"services","limit_value":100,"enforcement_mode":"hard"}]}`
	rec := patchLimits(handler, orgID, "a-valid-session-token", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeUpdateLimits(t, rec)
	want := []limitResource{
		{Resource: "projects", LimitValue: 25, EnforcementMode: "hard", Source: "organization"},
		{Resource: "services", LimitValue: 100, EnforcementMode: "hard", Source: "organization"},
	}
	if len(env.Data.Limits) != len(want) {
		t.Fatalf("limits = %+v, want %+v", env.Data.Limits, want)
	}
	for i, w := range want {
		if env.Data.Limits[i] != w {
			t.Errorf("limits[%d] = %+v, want %+v", i, env.Data.Limits[i], w)
		}
	}

	// The handler must forward the decoded request to the updater exactly,
	// including the {org_id} path parameter (so a cross-tenant smuggling
	// attempt is impossible at this seam) and the principal/correlation
	// fields needed to file the audit record. limit_value is the pointer
	// indirection's payload — supplying 0 must round-trip as 0, not the
	// zero value of an absent field.
	if got.OrganizationID != orgID {
		t.Errorf("updater received org_id %q, want the path parameter %q", got.OrganizationID, orgID)
	}
	if len(got.Items) != 2 {
		t.Fatalf("updater received %d items, want 2: %+v", len(got.Items), got.Items)
	}
	if got.Items[0].Resource != store.QuotaResourceProjects || got.Items[0].LimitValue != 25 {
		t.Errorf("items[0] = %+v, want projects/25", got.Items[0])
	}
	if got.Items[1].Resource != store.QuotaResourceServices || got.Items[1].LimitValue != 100 ||
		got.Items[1].EnforcementMode != store.EnforcementModeHard {
		t.Errorf("items[1] = %+v, want services/100/hard", got.Items[1])
	}
	if got.ActorID != "usr_ada" || got.ActorOrgID != orgID {
		t.Errorf("updater received actor=(%q, %q), want (usr_ada, %q)", got.ActorID, got.ActorOrgID, orgID)
	}
}

// TestUpdateLimitsForwardsZeroLimitValue proves the limit_value pointer
// distinguishes "field omitted" from "limit set to zero": a body that names
// 0 reaches the store layer as a 0 (a meaningful extreme value), not as a
// missing field surfaced as a 400.
func TestUpdateLimitsForwardsZeroLimitValue(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	var got store.UpdateLimitsInput
	updater := fakeLimitsUpdater{
		limits: []store.EffectiveQuotaLimit{{
			Resource: store.QuotaResourceProjects, LimitValue: 0,
			EnforcementMode: store.EnforcementModeHard, Scope: store.QuotaScopeOrganization,
		}},
		got: &got,
	}
	handler := updateLimitsHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", orgID, policy.RoleAdmin), Method: auth.MethodSession},
		nil, updater)

	body := `{"limits":[{"resource":"projects","limit_value":0}]}`
	rec := patchLimits(handler, orgID, "a-valid-session-token", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if len(got.Items) != 1 || got.Items[0].LimitValue != 0 {
		t.Errorf("items = %+v, want a single projects/0 entry", got.Items)
	}
}

// TestUpdateLimitsRejectsMissingLimitValue proves the handler surfaces a
// stable 400 (apierr.InvalidInput) when an entry omits limit_value — the
// store layer would also reject it, but a per-entry field-path error here
// keeps the contract symmetric and gives agents a stable wire shape before
// any database work would happen.
func TestUpdateLimitsRejectsMissingLimitValue(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	var got store.UpdateLimitsInput
	updater := fakeLimitsUpdater{got: &got}
	handler := updateLimitsHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", orgID, policy.RoleAdmin), Method: auth.MethodSession},
		nil, updater)

	body := `{"limits":[{"resource":"projects"}]}`
	rec := patchLimits(handler, orgID, "a-valid-session-token", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INVALID_INPUT")
	if got.OrganizationID != "" {
		t.Errorf("updater was reached for an invalid request: %+v", got)
	}
}

// TestUpdateLimitsRejectsEmptyLimitsArray proves a patch with no entries is
// itself a 400 — a mutation that changes nothing is a client error, not a
// silent success — without the store layer running.
func TestUpdateLimitsRejectsEmptyLimitsArray(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	var got store.UpdateLimitsInput
	updater := fakeLimitsUpdater{got: &got}
	handler := updateLimitsHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", orgID, policy.RoleAdmin), Method: auth.MethodSession},
		nil, updater)

	rec := patchLimits(handler, orgID, "a-valid-session-token", `{"limits":[]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INVALID_INPUT")
	if got.OrganizationID != "" {
		t.Errorf("updater was reached for an empty patch: %+v", got)
	}
}

// TestUpdateLimitsRejectsMalformedBody proves an unparseable JSON body is a
// stable 400 (apierr.Invalid) with no echo of the input — the global
// validate.DecodeJSON contract, asserted again here so a regression in the
// handler's decode wiring fails this story.
func TestUpdateLimitsRejectsMalformedBody(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	handler := updateLimitsHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", orgID, policy.RoleAdmin), Method: auth.MethodSession},
		nil, fakeLimitsUpdater{})

	rec := patchLimits(handler, orgID, "a-valid-session-token", `{ this is not json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
}

// TestUpdateLimitsUnauthenticatedReturns401 proves an unauthenticated request
// never reaches the handler: the auth middleware rejects it with a stable
// 401 E_AUTH envelope, before the updater is touched.
func TestUpdateLimitsUnauthenticatedReturns401(t *testing.T) {
	t.Parallel()

	var got store.UpdateLimitsInput
	updater := fakeLimitsUpdater{got: &got}
	handler := updateLimitsHandlerFor(auth.Identity{}, apierr.Unauthenticated("missing token"), updater)

	rec := patchLimits(handler, "org_acme", "", `{"limits":[{"resource":"projects","limit_value":10}]}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_AUTH")
	if got.OrganizationID != "" {
		t.Errorf("updater was reached for an unauthenticated request: %+v", got)
	}
}

// TestUpdateLimitsCrossTenantReturns403 proves a cross-tenant {org_id} is
// rejected by the policy engine with a deterministic 403 before the handler
// runs. limits.write is CapAdmin and has no cross-tenant support exception
// — even a Support principal in another tenant cannot mutate limits.
func TestUpdateLimitsCrossTenantReturns403(t *testing.T) {
	t.Parallel()

	var got store.UpdateLimitsInput
	updater := fakeLimitsUpdater{got: &got}
	intruder := orgPrincipal("usr_mallory", "org_attacker", policy.RoleOwner)
	handler := updateLimitsHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, updater)

	rec := patchLimits(handler, "org_victim", "a-valid-session-token", `{"limits":[{"resource":"projects","limit_value":99}]}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_FORBIDDEN")
	if got.OrganizationID != "" {
		t.Errorf("updater was reached for a cross-tenant request: %+v", got)
	}
}

// TestUpdateLimitsViewerReturns403 proves a viewer principal in the caller's
// own tenant is rejected with a stable 403 — limits.write requires CapAdmin
// (not the all-roles CapRead of limits.read), so a viewer with read
// permission is structurally not enough.
func TestUpdateLimitsViewerReturns403(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	var got store.UpdateLimitsInput
	updater := fakeLimitsUpdater{got: &got}
	viewer := orgPrincipal("usr_view", orgID, policy.RoleViewer)
	handler := updateLimitsHandlerFor(
		auth.Identity{Principal: viewer, Method: auth.MethodSession}, nil, updater)

	rec := patchLimits(handler, orgID, "a-valid-session-token", `{"limits":[{"resource":"projects","limit_value":99}]}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_FORBIDDEN")
	if got.OrganizationID != "" {
		t.Errorf("updater was reached for an unauthorized request: %+v", got)
	}
}

// TestUpdateLimitsNotFoundOrganization proves an {org_id} that has no row in
// the source-of-truth database surfaces as the typed 404 the store layer
// emits, never disguised as a 409 (constraint violation) or a silent
// success.
func TestUpdateLimitsNotFoundOrganization(t *testing.T) {
	t.Parallel()

	const orgID = "org_missing"
	updater := fakeLimitsUpdater{err: apierr.NotFound("organization", orgID)}
	handler := updateLimitsHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", orgID, policy.RoleAdmin), Method: auth.MethodSession},
		nil, updater)

	rec := patchLimits(handler, orgID, "a-valid-session-token", `{"limits":[{"resource":"projects","limit_value":99}]}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_NOT_FOUND")
}

// TestUpdateLimitsUpdaterErrorMapsToTypedStatus proves a store outage
// surfaces as the typed 5xx the apierr taxonomy produces, never as a
// misleading 200 or an unredacted message.
func TestUpdateLimitsUpdaterErrorMapsToTypedStatus(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	updater := fakeLimitsUpdater{err: apierr.StoreUnavailable(stderrors.New("connection reset"))}
	handler := updateLimitsHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", orgID, policy.RoleAdmin), Method: auth.MethodSession},
		nil, updater)

	rec := patchLimits(handler, orgID, "a-valid-session-token", `{"limits":[{"resource":"projects","limit_value":99}]}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_UNAVAILABLE")
	if strings.Contains(env.Error.Message, "connection reset") {
		t.Errorf("error message %q leaks the raw cause", env.Error.Message)
	}
}

// TestUpdateLimitsMissingUpdaterIsInternalError proves a wiring error — the
// handler reached with a nil LimitsUpdater — surfaces as a typed 5xx
// E_INTERNAL rather than a misleading empty success.
func TestUpdateLimitsMissingUpdaterIsInternalError(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	a := fakeAuthenticator{identity: auth.Identity{Principal: orgPrincipal("usr_ada", orgID, policy.RoleAdmin), Method: auth.MethodSession}}
	handler := NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, nil, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeBreakGlassController{}, nil)

	rec := patchLimits(handler, orgID, "a-valid-session-token", `{"limits":[{"resource":"projects","limit_value":99}]}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_INTERNAL")
	if strings.Contains(env.Error.Message, "limits updater") {
		t.Errorf("error message %q leaks internal detail", env.Error.Message)
	}
}

// TestUpdateLimitsRouteIsDocumentedAsRequiringLimitsWrite ties the served
// route to the OpenAPI document: PATCH /v1/organizations/{org_id}/limits
// must require authentication and declare action limits.write, so any
// future drift between the registered route and the policy catalog fails
// here in addition to the route-table invariant tests.
func TestUpdateLimitsRouteIsDocumentedAsRequiringLimitsWrite(t *testing.T) {
	t.Parallel()

	table := newRouteTable(runtime.BuildInfo{}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, fakeEnvironmentServiceReader{}, fakeBreakGlassController{})
	var found bool
	for _, rt := range table {
		if rt.endpoint.Method != http.MethodPatch || rt.endpoint.Path != "/v1/organizations/{org_id}/limits" {
			continue
		}
		found = true
		if !rt.endpoint.RequiresAuth {
			t.Errorf("PATCH /v1/organizations/{org_id}/limits requires_auth = false, want true")
		}
		if rt.endpoint.RequiredAction != string(policy.ActionLimitsWrite) {
			t.Errorf("required_action = %q, want %q", rt.endpoint.RequiredAction, string(policy.ActionLimitsWrite))
		}
		if rt.resolver == nil {
			t.Errorf("route has no ResourceResolver; cross-tenant {org_id} would only be checked against the principal's own org")
		}
	}
	if !found {
		t.Fatalf("PATCH /v1/organizations/{org_id}/limits is not registered")
	}
}
