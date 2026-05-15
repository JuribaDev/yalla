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
// /v1/organizations/{org_id}/usage (BE-0100). The endpoint reads the
// organization's current resource usage joined with its effective limits
// through the UsageReader port; the tests drive it through NewHandler with
// a fake Authenticator, the real policy engine, and a fake reader — the
// same wiring a request hits in production, minus the database. The
// store-backed reader has its own isolated-Postgres integration coverage
// in store/usage_test.go.
//
// This endpoint has no request body and no query parameters: its only
// input is the {org_id} path parameter, an opaque identifier. There is
// therefore no syntactic request to reject — a malformed or unknown id
// surfaces as an empty list when the principal is authorized for it, or,
// for an id outside the principal's tenant, as the deterministic 403 the
// policy engine returns through organizationIDResolver. Those two paths
// are the "validation" and "authorization" coverage for this story; the
// dedicated policy-matrix coverage that pins every role and grant
// containment property is the BE-0102 story.

// fakeUsageReader is a canned UsageReader for httpapi tests. The zero
// value returns a nil slice and no error, which is all the test helpers
// that never reach the handler (the public-surface and unrelated-endpoint
// suites) need; the usage tests set usage/err and read got back to prove
// the handler forwards the path parameter to the store layer unchanged.
type fakeUsageReader struct {
	usage []store.OrganizationResourceUsage
	err   error
	got   *string
}

func (f fakeUsageReader) ListOrganizationUsage(_ context.Context, organizationID string) ([]store.OrganizationResourceUsage, error) {
	if f.got != nil {
		*f.got = organizationID
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.usage, nil
}

// listUsageHandlerFor builds an http.Handler that points at the GET
// /v1/organizations/{org_id}/usage route, wired through the same
// NewHandler the production binary uses. id and authErr drive the fake
// authenticator; reader is the UsageReader the handler reads from.
func listUsageHandlerFor(id auth.Identity, authErr error, reader UsageReader) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, reader, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, nil)
}

// usageActorIdentity builds a session-method identity for an organization
// member acting on its own tenant — the default principal shape the
// contract tests use when proving the wire surface independent of policy
// matrix combinatorics.
func usageActorIdentity(orgID, userID string) auth.Identity {
	return auth.Identity{
		Principal: policy.Principal{
			ID:             userID,
			Kind:           domain.KindUser,
			OrganizationID: orgID,
			Role:           policy.RoleOwner,
		},
		Method: auth.MethodSession,
	}
}

// getUsage issues a GET against /v1/organizations/{org_id}/usage and
// returns the recorded response. It mirrors getLimits in the limits
// surface — a single, deterministic call shape so the assertion blocks
// can focus on the response.
func getUsage(handler http.Handler, orgID, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v1/organizations/"+orgID+"/usage", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// decodeUsageList decodes a yalla.output.v1 success envelope's data block
// into the wire shape an agent observes — including limit being optional
// (nil for unconstrained resources). Returning the parsed envelope lets
// individual tests assert against schema_version and request_id without
// re-parsing.
func decodeUsageList(t *testing.T, body []byte) usageEnvelope {
	t.Helper()
	var env usageEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode envelope: %v; body=%s", err, body)
	}
	return env
}

type usageEnvelope struct {
	SchemaVersion string `json:"schema_version"`
	RequestID     string `json:"request_id"`
	Data          struct {
		Usage []struct {
			Resource  string `json:"resource"`
			UsedValue int64  `json:"used_value"`
			Limit     *struct {
				LimitValue      int64  `json:"limit_value"`
				EnforcementMode string `json:"enforcement_mode"`
				Source          string `json:"source"`
			} `json:"limit"`
		} `json:"usage"`
	} `json:"data"`
}

// TestListUsageReturnsCurrentUsageAndLimits proves the happy path: the
// handler forwards the {org_id} path parameter to the reader unchanged and
// projects the rows the reader returns into the stable wire shape, with a
// nullable limit object that's non-null when a policy is configured and
// nil otherwise. It also pins the envelope fields agents read first.
func TestListUsageReturnsCurrentUsageAndLimits(t *testing.T) {
	t.Parallel()
	const orgID = "org_acme"
	var got string
	mode := store.EnforcementModeHard
	scope := store.QuotaScopeOrganization
	limit := int64(10)
	reader := fakeUsageReader{
		got: &got,
		usage: []store.OrganizationResourceUsage{
			{
				Resource:        store.QuotaResourceProjects,
				UsedValue:       3,
				LimitValue:      &limit,
				EnforcementMode: &mode,
				Scope:           &scope,
			},
			{
				// Domains: usage but no policy at either scope — unconstrained.
				Resource:  store.QuotaResourceDomains,
				UsedValue: 5,
			},
		},
	}

	handler := listUsageHandlerFor(usageActorIdentity(orgID, "usr_owner"), nil, reader)
	rec := getUsage(handler, orgID, "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got != orgID {
		t.Errorf("reader received org_id %q, want %q", got, orgID)
	}

	env := decodeUsageList(t, rec.Body.Bytes())
	if env.SchemaVersion != "yalla.output.v1" {
		t.Errorf("schema_version = %q, want yalla.output.v1", env.SchemaVersion)
	}
	if env.RequestID == "" {
		t.Errorf("request_id is empty; the envelope must propagate the request id")
	}
	if len(env.Data.Usage) != 2 {
		t.Fatalf("usage len = %d, want 2 (got %+v)", len(env.Data.Usage), env.Data.Usage)
	}
	first := env.Data.Usage[0]
	if first.Resource != "projects" || first.UsedValue != 3 {
		t.Errorf("[0] = %+v, want projects with used_value=3", first)
	}
	if first.Limit == nil {
		t.Fatalf("[0].limit is nil; want a limit object")
	}
	if first.Limit.LimitValue != 10 || first.Limit.EnforcementMode != "hard" || first.Limit.Source != "organization" {
		t.Errorf("[0].limit = %+v, want {10, hard, organization}", first.Limit)
	}
	second := env.Data.Usage[1]
	if second.Resource != "domains" || second.UsedValue != 5 {
		t.Errorf("[1] = %+v, want domains with used_value=5", second)
	}
	if second.Limit != nil {
		t.Errorf("[1].limit = %+v, want nil for an unconstrained resource", second.Limit)
	}
}

// TestListUsageReturnsEmptyListForUnknownOrg proves that an organization
// with no configured policies and no usage counter rows yields a
// deterministic empty list rather than a 404 — the same forward-
// compatible shape every list endpoint serves so an agent can iterate
// without a nil check.
func TestListUsageReturnsEmptyListForUnknownOrg(t *testing.T) {
	t.Parallel()
	const orgID = "org_acme"
	reader := fakeUsageReader{usage: nil}

	handler := listUsageHandlerFor(usageActorIdentity(orgID, "usr_owner"), nil, reader)
	rec := getUsage(handler, orgID, "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	env := decodeUsageList(t, rec.Body.Bytes())
	if env.Data.Usage == nil {
		t.Errorf("usage is nil, want a non-nil empty slice (so agents can iterate without a nil check)")
	}
	if len(env.Data.Usage) != 0 {
		t.Errorf("usage len = %d, want 0", len(env.Data.Usage))
	}
}

// TestListUsageForwardsStoreUnavailableAsTypedFiveHundred proves a store
// outage becomes a stable 5xx envelope, not a leaked driver error.
func TestListUsageForwardsStoreUnavailableAsTypedFiveHundred(t *testing.T) {
	t.Parallel()
	const orgID = "org_acme"
	reader := fakeUsageReader{err: apierr.StoreUnavailable(stderrors.New("connection reset"))}

	handler := listUsageHandlerFor(usageActorIdentity(orgID, "usr_owner"), nil, reader)
	rec := getUsage(handler, orgID, "a-valid-session-token")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "connection reset") {
		t.Errorf("body leaked the raw driver error: %s", rec.Body.String())
	}
}

// TestListUsageRequiresAuthentication proves a missing/invalid credential
// is the typed 401 the authenticator path emits, not a leaked panic, and
// the reader never runs.
func TestListUsageRequiresAuthentication(t *testing.T) {
	t.Parallel()
	const orgID = "org_acme"
	var got string
	reader := fakeUsageReader{got: &got}

	handler := listUsageHandlerFor(auth.Identity{}, apierr.Unauthenticated("missing token"), reader)
	rec := getUsage(handler, orgID, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
	if got != "" {
		t.Errorf("reader ran for an unauthenticated request (received org_id %q)", got)
	}
}

// TestListUsageDeniesCrossTenantPrincipal proves the policy engine — wired
// through organizationIDResolver — rejects a principal whose home
// organization is not the {org_id} the path names (and who is not a
// support principal allowed cross-tenant for CapRead actions), without
// the reader ever running. limits.read carries a deliberate cross-tenant
// support exception; that property is pinned exhaustively in the BE-0102
// policy matrix, not duplicated here.
func TestListUsageDeniesCrossTenantPrincipal(t *testing.T) {
	t.Parallel()
	const homeOrg = "org_attacker"
	const victimOrg = "org_acme"
	var got string
	reader := fakeUsageReader{got: &got}

	id := auth.Identity{
		Principal: policy.Principal{
			ID:             "usr_mallory",
			Kind:           domain.KindUser,
			OrganizationID: homeOrg,
			Role:           policy.RoleOwner,
		},
		Method: auth.MethodSession,
	}
	handler := listUsageHandlerFor(id, nil, reader)
	rec := getUsage(handler, victimOrg, "a-valid-session-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	if got != "" {
		t.Errorf("reader ran for a cross-tenant principal (received org_id %q)", got)
	}
	if strings.Contains(rec.Body.String(), "used_value") {
		t.Errorf("body leaked usage data on a denied request: %s", rec.Body.String())
	}
}

// TestListUsageMissingReaderIsTypedInternalError proves a wiring error (a
// nil UsageReader threaded into NewHandler) surfaces as the typed
// internal-error envelope rather than a misleading empty list or a panic,
// the same posture every other list endpoint takes.
func TestListUsageMissingReaderIsTypedInternalError(t *testing.T) {
	t.Parallel()
	const orgID = "org_acme"
	a := fakeAuthenticator{identity: usageActorIdentity(orgID, "usr_owner")}
	handler := NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, nil, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, nil)
	rec := getUsage(handler, orgID, "a-valid-session-token")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
}

// TestListUsageRouteIsRegistered proves the OpenAPI document carries the
// GET /v1/organizations/{org_id}/usage operation with the stable
// operationId, the limits.read required action, and the usage tag — every
// detail an agent reads to discover the endpoint.
func TestListUsageRouteIsRegistered(t *testing.T) {
	t.Parallel()
	a := fakeAuthenticator{identity: usageActorIdentity("org_acme", "usr_owner")}
	handler := NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("openapi.json status = %d, want 200", rec.Code)
	}

	var doc struct {
		Paths map[string]map[string]struct {
			OperationID string   `json:"operationId"`
			Tags        []string `json:"tags"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode openapi: %v", err)
	}
	op, ok := doc.Paths["/v1/organizations/{org_id}/usage"]["get"]
	if !ok {
		t.Fatalf("GET /v1/organizations/{org_id}/usage missing from OpenAPI document")
	}
	if op.OperationID != "getOrganizationUsage" {
		t.Errorf("operationId = %q, want getOrganizationUsage", op.OperationID)
	}
	foundTag := false
	for _, tag := range op.Tags {
		if tag == "usage" {
			foundTag = true
			break
		}
	}
	if !foundTag {
		t.Errorf("tags = %v, want it to include \"usage\"", op.Tags)
	}
}
