package httpapi

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// Contract and tenant-isolation coverage for GET
// /v1/organizations/{org_id}/limits (BE-0094). The endpoint reads the
// effective quota limits of the organization named by the {org_id} path
// parameter through the LimitsReader port; the tests drive it through
// NewHandler with a fake Authenticator, the real policy engine, and a fake
// reader — the same wiring a request hits in production, minus the database.
// The store-backed reader has its own isolated-Postgres integration coverage
// in store/limits_test.go.
//
// This endpoint has no request body and no query parameters: its only input
// is the {org_id} path parameter, an opaque identifier. There is therefore no
// syntactic request to reject — a malformed or unknown id surfaces as an
// empty list when the principal is authorized for it, or, for an id outside
// the principal's tenant, as the deterministic 403 the policy engine returns
// through organizationIDResolver. Those two paths are the "validation" and
// "authorization" coverage for this story.

// fakeLimitsReader is a canned LimitsReader for httpapi tests. The zero value
// returns a nil slice and no error, which is all the test helpers that never
// reach the handler (the public-surface and unrelated-endpoint suites) need;
// the limits tests set limits/err and read got back to prove the handler
// forwards the path parameter to the store layer unchanged.
type fakeLimitsReader struct {
	limits []store.EffectiveQuotaLimit
	err    error
	got    *string
}

func (f fakeLimitsReader) ListEffectiveLimits(_ context.Context, organizationID string) ([]store.EffectiveQuotaLimit, error) {
	if f.got != nil {
		*f.got = organizationID
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.limits, nil
}

// fakeLimitsUpdater is a canned LimitsUpdater for httpapi tests. The zero
// value returns a nil slice and no error and records nothing, which is all
// the suites that never reach the PATCH handler need; the PATCH tests set
// limits/err and read got back to prove the handler forwards the validated
// input to the store layer unchanged.
type fakeLimitsUpdater struct {
	limits []store.EffectiveQuotaLimit
	err    error
	got    *store.UpdateLimitsInput
}

func (f fakeLimitsUpdater) UpdateLimits(_ context.Context, in store.UpdateLimitsInput) ([]store.EffectiveQuotaLimit, error) {
	if f.got != nil {
		*f.got = in
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.limits, nil
}

// listLimitsHandlerFor builds an http.Handler that points at the GET
// /v1/organizations/{org_id}/limits route, wired through the same
// NewHandler the production binary uses. id and authErr drive the fake
// authenticator; reader is the LimitsReader the handler reads from.
func listLimitsHandlerFor(id auth.Identity, authErr error, reader LimitsReader) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		reader, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		nil)
}

// updateLimitsHandlerFor builds an http.Handler that points at the PATCH
// /v1/organizations/{org_id}/limits route, wired through the same NewHandler
// the production binary uses. id and authErr drive the fake authenticator;
// updater is the LimitsUpdater the handler writes through.
func updateLimitsHandlerFor(id auth.Identity, authErr error, updater LimitsUpdater) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, updater, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		nil)
}

// limitsActorIdentity returns an authenticated owner Identity bound to the
// named organization, so the request authorizes for action limits.read
// against {org_id}.
func limitsActorIdentity(orgID, actorID string) auth.Identity {
	return auth.Identity{
		Principal: policy.Principal{
			ID:             actorID,
			Kind:           domain.KindUser,
			OrganizationID: orgID,
			Role:           policy.RoleOwner,
		},
	}
}

// decodeLimitsList decodes the JSON success body returned by GET
// /v1/organizations/{org_id}/limits into the wire shape the contract pins
// down.
func decodeLimitsList(t *testing.T, body []byte) listLimitsPayload {
	t.Helper()
	var env struct {
		SchemaVersion string            `json:"schema_version"`
		RequestID     string            `json:"request_id"`
		Data          listLimitsPayload `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("json.Unmarshal: %v\nbody = %s", err, string(body))
	}
	if env.SchemaVersion != "yalla.output.v1" {
		t.Errorf("schema_version = %q, want yalla.output.v1", env.SchemaVersion)
	}
	if env.RequestID == "" {
		t.Errorf("request_id is empty")
	}
	return env.Data
}

// decodeErrorEnvelope decodes the JSON error body returned by the limits
// route into the wire shape the error contract pins down.
func decodeErrorEnvelope(t *testing.T, body []byte) (code, message string, requestID string) {
	t.Helper()
	var env struct {
		SchemaVersion string `json:"schema_version"`
		RequestID     string `json:"request_id"`
		Error         struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("json.Unmarshal: %v\nbody = %s", err, string(body))
	}
	if env.SchemaVersion != "yalla.error.v1" {
		t.Errorf("schema_version = %q, want yalla.error.v1", env.SchemaVersion)
	}
	return env.Error.Code, env.Error.Message, env.RequestID
}

// TestListLimitsReturnsStableEnvelope proves the success path: an authorized
// owner sees the effective limits for its own organization rendered in the
// stable yalla.output.v1 envelope, in the order the LimitsReader returned
// them — the deterministic resource ordering is the responsibility of the
// repository, which has its own integration coverage. Field names, types,
// and the wire shape are pinned down here.
func TestListLimitsReturnsStableEnvelope(t *testing.T) {
	t.Parallel()

	const orgID = "org_001"
	reader := fakeLimitsReader{
		limits: []store.EffectiveQuotaLimit{
			{
				Resource:        store.QuotaResourceProjects,
				LimitValue:      10,
				EnforcementMode: store.EnforcementModeHard,
				Scope:           store.QuotaScopeOrganization,
			},
			{
				Resource:        store.QuotaResourceServices,
				LimitValue:      25,
				EnforcementMode: store.EnforcementModeHard,
				Scope:           store.QuotaScopePlanDefault,
			},
			{
				Resource:        store.QuotaResourceMonthlyDeployments,
				LimitValue:      1_000,
				EnforcementMode: store.EnforcementModeMetered,
				Scope:           store.QuotaScopePlanDefault,
			},
		},
	}

	handler := listLimitsHandlerFor(limitsActorIdentity(orgID, "user_owner"), nil, reader)

	req := httptest.NewRequest(http.MethodGet, "/v1/organizations/"+orgID+"/limits", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	payload := decodeLimitsList(t, rec.Body.Bytes())
	if got, want := len(payload.Limits), 3; got != want {
		t.Fatalf("len(limits) = %d, want %d; body = %s", got, want, rec.Body.String())
	}
	want := []limitResource{
		{Resource: "projects", LimitValue: 10, EnforcementMode: "hard", Source: "organization"},
		{Resource: "services", LimitValue: 25, EnforcementMode: "hard", Source: "plan_default"},
		{Resource: "monthly_deployments", LimitValue: 1_000, EnforcementMode: "metered", Source: "plan_default"},
	}
	for i, got := range payload.Limits {
		if got != want[i] {
			t.Errorf("limits[%d] = %+v, want %+v", i, got, want[i])
		}
	}
}

// TestListLimitsEmptyOrganizationReturnsEmptyArray proves the empty-but-valid
// case: an organization with no configured policies renders an empty array,
// never null. Agents can iterate the response without a nil check.
func TestListLimitsEmptyOrganizationReturnsEmptyArray(t *testing.T) {
	t.Parallel()

	const orgID = "org_empty"
	handler := listLimitsHandlerFor(limitsActorIdentity(orgID, "user_owner"), nil, fakeLimitsReader{limits: nil})

	req := httptest.NewRequest(http.MethodGet, "/v1/organizations/"+orgID+"/limits", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"limits":[]`) {
		t.Errorf("expected an empty limits array literal, body = %s", rec.Body.String())
	}
}

// TestListLimitsForwardsPathOrgID proves the handler forwards the {org_id}
// path parameter to the reader verbatim — the tenant boundary lives at the
// policy resolver, not at the reader, and the reader has its own tenant-
// scoping integration coverage. The principal is the same tenant as the
// path parameter so the policy engine returns Allow.
func TestListLimitsForwardsPathOrgID(t *testing.T) {
	t.Parallel()

	const orgID = "org_forward"
	var seen string
	reader := fakeLimitsReader{got: &seen}
	handler := listLimitsHandlerFor(limitsActorIdentity(orgID, "user_owner"), nil, reader)

	req := httptest.NewRequest(http.MethodGet, "/v1/organizations/"+orgID+"/limits", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if seen != orgID {
		t.Errorf("reader received organization id %q, want %q", seen, orgID)
	}
}

// TestListLimitsUnauthenticatedReturns401 proves an unauthenticated request
// never reaches the handler: the auth middleware rejects it with 401 and
// emits a stable yalla.error.v1 envelope, before any reader is touched.
func TestListLimitsUnauthenticatedReturns401(t *testing.T) {
	t.Parallel()

	var seen string
	reader := fakeLimitsReader{got: &seen}
	handler := listLimitsHandlerFor(auth.Identity{}, apierr.Unauthenticated("missing token"), reader)

	req := httptest.NewRequest(http.MethodGet, "/v1/organizations/org_001/limits", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body = %s", rec.Code, rec.Body.String())
	}
	code, _, _ := decodeErrorEnvelope(t, rec.Body.Bytes())
	if code != "E_AUTH" {
		t.Errorf("error code = %q, want E_AUTH", code)
	}
	if seen != "" {
		t.Errorf("reader was called for an unauthenticated request: %q", seen)
	}
}

// TestListLimitsCrossTenantReturns403 proves a cross-tenant {org_id} is
// rejected with a deterministic 403 by the policy engine before the handler
// reads anything: the principal is bound to org_self but the path names
// org_other, so organizationIDResolver authorizes against org_other and the
// developer-capability principal fails the limits.read check.
func TestListLimitsCrossTenantReturns403(t *testing.T) {
	t.Parallel()

	var seen string
	reader := fakeLimitsReader{got: &seen}
	id := auth.Identity{
		Principal: policy.Principal{
			ID:             "user_developer",
			Kind:           domain.KindUser,
			OrganizationID: "org_self",
			Role:           policy.RoleDeveloper,
		},
	}
	handler := listLimitsHandlerFor(id, nil, reader)

	req := httptest.NewRequest(http.MethodGet, "/v1/organizations/org_other/limits", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", rec.Code, rec.Body.String())
	}
	if seen != "" {
		t.Errorf("reader was called for a cross-tenant request: %q", seen)
	}
}

// TestListLimitsReaderErrorMapsToTypedStatus proves a store outage surfaces
// as the typed 5xx the apierr taxonomy produces, never as a misleading empty
// list or an unredacted message.
func TestListLimitsReaderErrorMapsToTypedStatus(t *testing.T) {
	t.Parallel()

	const orgID = "org_001"
	reader := fakeLimitsReader{err: apierr.StoreUnavailable(stderrors.New("connection reset"))}
	handler := listLimitsHandlerFor(limitsActorIdentity(orgID, "user_owner"), nil, reader)

	req := httptest.NewRequest(http.MethodGet, "/v1/organizations/"+orgID+"/limits", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body = %s", rec.Code, rec.Body.String())
	}
	code, message, _ := decodeErrorEnvelope(t, rec.Body.Bytes())
	if code != "E_UNAVAILABLE" {
		t.Errorf("error code = %q, want E_UNAVAILABLE", code)
	}
	if strings.Contains(message, "connection reset") {
		t.Errorf("error message %q leaks the raw cause", message)
	}
}

// TestListLimitsMissingReaderIsInternalError proves a wiring error — the
// handler reached with a nil LimitsReader — surfaces as a typed 5xx rather
// than a misleading empty list. This is the same defensive shape every
// other endpoint takes for its persistence port.
func TestListLimitsMissingReaderIsInternalError(t *testing.T) {
	t.Parallel()

	const orgID = "org_001"
	a := fakeAuthenticator{identity: limitsActorIdentity(orgID, "user_owner")}
	handler := NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		nil, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/organizations/"+orgID+"/limits", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body = %s", rec.Code, rec.Body.String())
	}
	code, message, _ := decodeErrorEnvelope(t, rec.Body.Bytes())
	if code != "E_INTERNAL" {
		t.Errorf("error code = %q, want E_INTERNAL", code)
	}
	if strings.Contains(message, "limits reader") {
		t.Errorf("error message %q leaks internal detail", message)
	}
}
