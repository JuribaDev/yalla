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
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
)

// Contract, authorization, and tenant-isolation coverage for GET
// /v1/organizations/{org_id}/members (BE-0061). The endpoint lists the
// memberships of the organization named by the {org_id} path parameter,
// joined with each member's global user identity, read through the
// MembershipReader port; the tests drive it through NewHandler with a fake
// Authenticator, the real policy engine, and a fake reader — the same wiring
// a request hits in production, minus the database. The store-backed reader
// has its own isolated-Postgres integration coverage in
// store/membership_test.go.
//
// This endpoint has no request body and no query parameters: its only input
// is the {org_id} path parameter, an opaque identifier. There is therefore no
// syntactic request to reject — a malformed or unknown id surfaces as an
// empty list when the principal is authorized for it, or, for an id outside
// the principal's tenant, as the deterministic 403 the policy engine returns
// through organizationIDResolver. Those two paths are the "validation" and
// "authorization" coverage for this story.

// fakeMembershipReader is a canned MembershipReader for httpapi tests. The
// zero value returns an empty list and no error from ListMembers and a typed
// not-found from GetMember, which is all the tests that never reach the
// handler (the public-surface, /v1/me, and other-org-route suites) need.
// Member tests set members/err and read gotOrgID back to prove the list read
// is scoped to the {org_id} path parameter; getMember tests set member/getErr
// and read gotMemberOrgID/gotMemberUserID back to prove the read is scoped to
// both the {org_id} and the {member_id} path parameters.
type fakeMembershipReader struct {
	members         []store.OrganizationMember
	err             error
	gotOrgID        *string
	member          store.OrganizationMember
	getErr          error
	gotMemberOrgID  *string
	gotMemberUserID *string
}

func (f fakeMembershipReader) ListMembers(_ context.Context, organizationID string) ([]store.OrganizationMember, error) {
	if f.gotOrgID != nil {
		*f.gotOrgID = organizationID
	}
	return f.members, f.err
}

func (f fakeMembershipReader) GetMember(_ context.Context, organizationID, userID string) (store.OrganizationMember, error) {
	if f.gotMemberOrgID != nil {
		*f.gotMemberOrgID = organizationID
	}
	if f.gotMemberUserID != nil {
		*f.gotMemberUserID = userID
	}
	if f.getErr != nil {
		return store.OrganizationMember{}, f.getErr
	}
	if f.member.UserID == "" {
		return store.OrganizationMember{}, apierr.NotFound("membership", userID)
	}
	return f.member, nil
}

// fakeMembershipCreator is a canned MembershipCreator for httpapi tests. The
// zero value returns a zero OrganizationMember and no error, which is all the
// test helpers that never reach the handler (the public-surface and GET
// suites) need; the POST member tests set member/err and read got back to
// prove the handler forwards the validated request and the authenticated
// actor to the store layer unchanged.
type fakeMembershipCreator struct {
	member store.OrganizationMember
	err    error
	got    *store.AddMembershipInput
}

func (f fakeMembershipCreator) Add(_ context.Context, in store.AddMembershipInput) (store.OrganizationMember, error) {
	if f.got != nil {
		*f.got = in
	}
	return f.member, f.err
}

// fakeMembershipUpdater is a canned MembershipUpdater for httpapi tests. The
// zero value returns a zero OrganizationMember and no error, which is all the
// test helpers that never reach the PATCH handler (the public-surface, GET,
// and POST suites) need; the PATCH member tests set member/err and read got
// back to prove the handler forwards the validated request and the
// authenticated actor to the store layer unchanged.
type fakeMembershipUpdater struct {
	member store.OrganizationMember
	err    error
	got    *store.UpdateMembershipInput
}

func (f fakeMembershipUpdater) UpdateMember(_ context.Context, in store.UpdateMembershipInput) (store.OrganizationMember, error) {
	if f.got != nil {
		*f.got = in
	}
	return f.member, f.err
}

// fakeMembershipRemover is a canned MembershipRemover for httpapi tests. The
// zero value returns a zero OrganizationMember and no error, which is all the
// test helpers that never reach the DELETE handler (the public-surface, GET,
// POST, and PATCH suites) need; the DELETE member tests set member/err and
// read got back to prove the handler forwards the validated request and the
// authenticated actor to the store layer unchanged.
type fakeMembershipRemover struct {
	member store.OrganizationMember
	err    error
	got    *store.RemoveMembershipInput
}

func (f fakeMembershipRemover) Remove(_ context.Context, in store.RemoveMembershipInput) (store.OrganizationMember, error) {
	if f.got != nil {
		*f.got = in
	}
	return f.member, f.err
}

// listMembersSuccessEnvelope is the decoded shape of the GET
// /v1/organizations/{org_id}/members success envelope.
type listMembersSuccessEnvelope struct {
	SchemaVersion string             `json:"schema_version"`
	OK            bool               `json:"ok"`
	RequestID     string             `json:"request_id"`
	Data          listMembersPayload `json:"data"`
}

// listMembersHandlerFor builds the full NewHandler surface with an
// Authenticator that resolves every credential to id and the given
// MembershipReader. It is the production request path: the
// /v1/organizations/{org_id}/members route is wrapped in RequireAuth for
// action members.read.
func listMembersHandlerFor(id auth.Identity, authErr error, reader MembershipReader) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{}, reader, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{}, fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{}, fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{}, fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
}

// getMembers issues GET /v1/organizations/{orgID}/members against handler,
// optionally with a bearer token.
func getMembers(handler http.Handler, orgID, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v1/organizations/"+orgID+"/members", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeListMembers(t *testing.T, rec *httptest.ResponseRecorder) listMembersSuccessEnvelope {
	t.Helper()
	var env listMembersSuccessEnvelope
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

// seedMember builds a store.OrganizationMember fixture for the
// fakeMembershipReader. It is a plain literal helper — no database — so the
// tests stay pure unit tests of the HTTP wire path.
func seedMember(orgID, userID, email, displayName, role string, roleVersion int64, created, updated time.Time) store.OrganizationMember {
	return store.OrganizationMember{
		Membership: store.Membership{
			OrganizationID: orgID,
			UserID:         userID,
			Role:           role,
			RoleVersion:    roleVersion,
			CreatedAt:      created,
			UpdatedAt:      updated,
		},
		Email:           email,
		UserDisplayName: displayName,
	}
}

// TestListMembersReturnsMembers is the happy path: an authenticated principal
// requesting its own organization's members receives them in a stable
// yalla.output.v1 envelope, with every source-of-truth field projected onto
// the wire shape.
func TestListMembersReturnsMembers(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 6, 7, 8, 0, time.UTC)
	reader := fakeMembershipReader{members: []store.OrganizationMember{
		seedMember("org_acme", "usr_ada", "ada@acme.example", "Ada Lovelace", "owner", 3, created, updated),
		seedMember("org_acme", "usr_grace", "grace@acme.example", "Grace Hopper", "admin", 1, created, updated),
	}}
	handler := listMembersHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleViewer)}, nil, reader)

	rec := getMembers(handler, "org_acme", "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q, want application/json", got)
	}

	env := decodeListMembers(t, rec)
	if len(env.Data.Members) != 2 {
		t.Fatalf("members = %+v, want exactly 2", env.Data.Members)
	}
	want := memberResource{
		UserID:          "usr_ada",
		Email:           "ada@acme.example",
		UserDisplayName: "Ada Lovelace",
		Role:            "owner",
		RoleVersion:     3,
		CreatedAt:       created.Format(time.RFC3339Nano),
		UpdatedAt:       updated.Format(time.RFC3339Nano),
	}
	if env.Data.Members[0] != want {
		t.Errorf("members[0] = %+v, want %+v", env.Data.Members[0], want)
	}
}

// TestListMembersScopesReadToPathParameter proves the handler reads exactly
// the organization named by the {org_id} path parameter — the path id is the
// sole input that selects the rows.
func TestListMembersScopesReadToPathParameter(t *testing.T) {
	t.Parallel()

	var gotID string
	reader := fakeMembershipReader{gotOrgID: &gotID}
	handler := listMembersHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner)}, nil, reader)

	rec := getMembers(handler, "org_acme", "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if gotID != "org_acme" {
		t.Errorf("reader received organization id %q, want org_acme", gotID)
	}
}

// TestListMembersEmptyListIsAStableEmptyArray proves an organization with no
// members renders an empty array, not a JSON null, so agents can iterate the
// response without a nil check.
func TestListMembersEmptyListIsAStableEmptyArray(t *testing.T) {
	t.Parallel()

	reader := fakeMembershipReader{members: nil}
	handler := listMembersHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner)}, nil, reader)

	rec := getMembers(handler, "org_acme", "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"members":[]`) {
		t.Errorf("body %s does not carry the stable empty-list shape \"members\":[]", rec.Body.String())
	}
}

// TestListMembersCrossTenantIsForbidden proves a principal listing members
// outside its own tenant is denied with a deterministic 403 E_FORBIDDEN
// carrying the stable cross-tenant reason — and the reader is never reached,
// so a cross-tenant id can never reveal another tenant's members or even
// whether that organization exists.
func TestListMembersCrossTenantIsForbidden(t *testing.T) {
	t.Parallel()

	var gotID string
	reader := fakeMembershipReader{
		members:  []store.OrganizationMember{seedMember("org_victim", "usr_v", "v@victim.example", "V", "owner", 1, time.Now(), time.Now())},
		gotOrgID: &gotID,
	}
	handler := listMembersHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_mallory", "org_attacker", policy.RoleOwner)}, nil, reader)

	rec := getMembers(handler, "org_victim", "a-valid-session-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedCrossTenant)
	}
	if gotID != "" {
		t.Errorf("reader was reached with id %q for a cross-tenant request; it must never run", gotID)
	}
	if strings.Contains(env.Error.Message, "org_victim") {
		t.Errorf("error message %q echoes the cross-tenant organization id", env.Error.Message)
	}
}

// TestListMembersSupportReadsAnotherTenant proves the one deliberate
// cross-tenant exception: a support principal performing a read is allowed
// to list members of an organization outside its home tenant, exactly as the
// policy matrix specifies for CapRead actions.
func TestListMembersSupportReadsAnotherTenant(t *testing.T) {
	t.Parallel()

	var gotID string
	reader := fakeMembershipReader{
		members: []store.OrganizationMember{
			seedMember("org_customer", "usr_c", "c@customer.example", "Customer", "owner", 1, time.Now().UTC(), time.Now().UTC()),
		},
		gotOrgID: &gotID,
	}
	handler := listMembersHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_support", "org_yalla", policy.RoleSupport)}, nil, reader)

	rec := getMembers(handler, "org_customer", "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeListMembers(t, rec)
	if len(env.Data.Members) != 1 || env.Data.Members[0].UserID != "usr_c" {
		t.Errorf("members = %+v, want exactly the one customer member", env.Data.Members)
	}
	if gotID != "org_customer" {
		t.Errorf("reader received id %q, want org_customer", gotID)
	}
}

// TestListMembersRequiresAuthentication proves a request with no credential
// is a stable 401 E_AUTH and never reaches the reader.
func TestListMembersRequiresAuthentication(t *testing.T) {
	t.Parallel()

	handler := listMembersHandlerFor(auth.Identity{}, nil,
		fakeMembershipReader{err: stderrors.New("reader must not be called")})

	rec := getMembers(handler, "org_acme", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_AUTHENTICATION_REQUIRED")
	if env.Error.Message != "authentication is required" {
		t.Errorf("message = %q, want %q", env.Error.Message, "authentication is required")
	}
}

// TestListMembersInvalidCredentials proves an unverifiable credential is a
// stable 401 E_AUTH_INVALID — distinct from the missing-credential contract.
func TestListMembersInvalidCredentials(t *testing.T) {
	t.Parallel()

	handler := listMembersHandlerFor(auth.Identity{}, auth.ErrInvalidCredentials,
		fakeMembershipReader{err: stderrors.New("reader must not be called")})

	rec := getMembers(handler, "org_acme", "yk_bogus")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_AUTH_INVALID")
	if env.Error.Message != "the supplied credentials are invalid" {
		t.Errorf("message = %q, want %q", env.Error.Message, "the supplied credentials are invalid")
	}
}

// TestListMembersDisabledPrincipal proves a revoked or expired credential
// surfaces as a disabled principal and is denied with a 403 E_FORBIDDEN
// carrying the stable reason — and the reader is never reached.
func TestListMembersDisabledPrincipal(t *testing.T) {
	t.Parallel()

	disabled := orgPrincipal("usr_ada", "org_acme", policy.RoleOwner)
	disabled.Disabled = true
	handler := listMembersHandlerFor(auth.Identity{Principal: disabled}, nil,
		fakeMembershipReader{err: stderrors.New("reader must not be called")})

	rec := getMembers(handler, "org_acme", "a-revoked-session-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
	}
}

// TestListMembersReaderUnavailable proves a datastore outage surfaces as its
// own typed 5xx, never disguised as a not-found or an empty success — and
// the wrapped driver cause never reaches the user-facing message.
func TestListMembersReaderUnavailable(t *testing.T) {
	t.Parallel()

	reader := fakeMembershipReader{err: apierr.StoreUnavailable(stderrors.New("connection refused"))}
	handler := listMembersHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleViewer)}, nil, reader)

	rec := getMembers(handler, "org_acme", "a-valid-session-token")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_UNAVAILABLE")
	if strings.Contains(env.Error.Message, "connection refused") {
		t.Errorf("error message %q leaks the wrapped datastore cause", env.Error.Message)
	}
}

// TestListMembersPropagatesRequestID proves the resolved request_id reaches
// both the response envelope and the echoed response header.
func TestListMembersPropagatesRequestID(t *testing.T) {
	t.Parallel()

	handler := listMembersHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleViewer)}, nil,
		fakeMembershipReader{})

	req := httptest.NewRequest(http.MethodGet, "/v1/organizations/org_acme/members", nil)
	req.Header.Set("Authorization", "Bearer a-valid-session-token")
	req.Header.Set(telemetry.HeaderRequestID, "caller-supplied-id")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeListMembers(t, rec)
	if env.RequestID != "caller-supplied-id" {
		t.Errorf("envelope request_id = %q, want caller-supplied-id", env.RequestID)
	}
	if got := rec.Header().Get(telemetry.HeaderRequestID); got != "caller-supplied-id" {
		t.Errorf("response header request_id = %q, want caller-supplied-id", got)
	}
}

// TestListMembersHandlerWithoutPrincipalIsInternal proves the defensive path:
// if the handler is ever reached without RequireAuth having placed a
// principal on the context, it reports a typed internal error rather than
// reading members for a zero principal.
func TestListMembersHandlerWithoutPrincipalIsInternal(t *testing.T) {
	t.Parallel()

	rec := run(listMembersHandler(fakeMembershipReader{}),
		httptest.NewRequest(http.MethodGet, "/v1/organizations/org_acme/members", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INTERNAL")
}

// TestListMembersHandlerWithNilReaderIsInternal proves a route registered
// without a membership reader is a wiring error reported as a typed internal
// failure — never a misleading empty list.
func TestListMembersHandlerWithNilReaderIsInternal(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/v1/organizations/org_acme/members", nil)
	req = req.WithContext(policy.WithPrincipal(req.Context(),
		orgPrincipal("usr_ada", "org_acme", policy.RoleViewer)))
	rec := run(listMembersHandler(nil), req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INTERNAL")
}

// TestListMembersIsDocumentedInOpenAPI proves the served route is also a
// documented route: GET /v1/organizations/{org_id}/members appears in the
// OpenAPI document requiring the API-key security scheme, naming its policy
// action through the x-required-action extension, and declaring the {org_id}
// path parameter.
func TestListMembersIsDocumentedInOpenAPI(t *testing.T) {
	t.Parallel()

	handler := listMembersHandlerFor(auth.Identity{}, nil, fakeMembershipReader{})
	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}

	var doc struct {
		Paths map[string]map[string]struct {
			OperationID    string                `json:"operationId"`
			Security       []map[string][]string `json:"security"`
			RequiredAction string                `json:"x-required-action"`
			Parameters     []struct {
				Name     string `json:"name"`
				In       string `json:"in"`
				Required bool   `json:"required"`
			} `json:"parameters"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode openapi document: %v", err)
	}
	op, ok := doc.Paths["/v1/organizations/{org_id}/members"]["get"]
	if !ok {
		t.Fatalf("openapi document does not describe GET /v1/organizations/{org_id}/members")
	}
	if op.OperationID != "listOrganizationMembers" {
		t.Errorf("operationId = %q, want listOrganizationMembers", op.OperationID)
	}
	if op.RequiredAction != string(policy.ActionMembersRead) {
		t.Errorf("x-required-action = %q, want %q", op.RequiredAction, policy.ActionMembersRead)
	}
	if len(op.Security) != 1 || len(op.Security[0]) != 1 {
		t.Errorf("security = %+v, want it to require the ApiKeyAuth scheme", op.Security)
	}
	if len(op.Parameters) != 1 {
		t.Fatalf("parameters = %+v, want exactly one path parameter", op.Parameters)
	}
	p := op.Parameters[0]
	if p.Name != "org_id" || p.In != "path" || !p.Required {
		t.Errorf("path parameter = %+v, want {Name:org_id In:path Required:true}", p)
	}
}

// getMemberSuccessEnvelope is the decoded shape of the GET
// /v1/organizations/{org_id}/members/{member_id} success envelope.
type getMemberSuccessEnvelope struct {
	SchemaVersion string           `json:"schema_version"`
	OK            bool             `json:"ok"`
	RequestID     string           `json:"request_id"`
	Data          getMemberPayload `json:"data"`
}

// getMember issues GET /v1/organizations/{orgID}/members/{memberID} against
// handler, optionally with a bearer token.
func getMember(handler http.Handler, orgID, memberID, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v1/organizations/"+orgID+"/members/"+memberID, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeGetMember(t *testing.T, rec *httptest.ResponseRecorder) getMemberSuccessEnvelope {
	t.Helper()
	var env getMemberSuccessEnvelope
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

// TestGetMemberReturnsMember is the happy path for GET
// /v1/organizations/{org_id}/members/{member_id}: an authenticated principal
// requesting a member of its own organization receives the joined membership
// in a stable yalla.output.v1 envelope, with every source-of-truth field
// projected onto the wire shape.
func TestGetMemberReturnsMember(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 6, 7, 8, 0, time.UTC)
	reader := fakeMembershipReader{member: seedMember(
		"org_acme", "usr_ada", "ada@acme.example", "Ada Lovelace", "owner", 3, created, updated,
	)}
	handler := listMembersHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_grace", "org_acme", policy.RoleViewer)}, nil, reader)

	rec := getMember(handler, "org_acme", "usr_ada", "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q, want application/json", got)
	}

	env := decodeGetMember(t, rec)
	want := memberResource{
		UserID:          "usr_ada",
		Email:           "ada@acme.example",
		UserDisplayName: "Ada Lovelace",
		Role:            "owner",
		RoleVersion:     3,
		CreatedAt:       created.Format(time.RFC3339Nano),
		UpdatedAt:       updated.Format(time.RFC3339Nano),
	}
	if env.Data.Member != want {
		t.Errorf("member = %+v, want %+v", env.Data.Member, want)
	}
}

// TestGetMemberScopesReadToPathParameters proves the handler reads exactly
// the membership named by ({org_id}, {member_id}) — both path values reach
// the reader, in order, so the read is scoped to the tenant the path names
// and the user the path names, never just one or the other.
func TestGetMemberScopesReadToPathParameters(t *testing.T) {
	t.Parallel()

	var gotOrg, gotUser string
	reader := fakeMembershipReader{
		member: seedMember("org_acme", "usr_ada", "ada@acme.example", "Ada Lovelace",
			"owner", 1, time.Now().UTC(), time.Now().UTC()),
		gotMemberOrgID:  &gotOrg,
		gotMemberUserID: &gotUser,
	}
	handler := listMembersHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_grace", "org_acme", policy.RoleOwner)}, nil, reader)

	rec := getMember(handler, "org_acme", "usr_ada", "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if gotOrg != "org_acme" {
		t.Errorf("reader received organization id %q, want org_acme", gotOrg)
	}
	if gotUser != "usr_ada" {
		t.Errorf("reader received member id %q, want usr_ada", gotUser)
	}
}

// TestGetMemberNotFoundIsStable proves a member id with no row in the tenant
// surfaces as a deterministic 404 E_NOT_FOUND — the typed contract that
// makes a cross-tenant member_id indistinguishable from a missing row.
func TestGetMemberNotFoundIsStable(t *testing.T) {
	t.Parallel()

	reader := fakeMembershipReader{getErr: apierr.NotFound("membership", "usr_missing")}
	handler := listMembersHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner)}, nil, reader)

	rec := getMember(handler, "org_acme", "usr_missing", "a-valid-session-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_NOT_FOUND")
}

// TestGetMemberCrossTenantIsForbidden proves a principal reading a member of
// another tenant is denied with a deterministic 403 E_FORBIDDEN carrying the
// stable cross-tenant reason — and the reader is never reached, so a
// cross-tenant id can never reveal another tenant's members or even whether
// that organization exists.
func TestGetMemberCrossTenantIsForbidden(t *testing.T) {
	t.Parallel()

	var gotOrg, gotUser string
	reader := fakeMembershipReader{
		member: seedMember("org_victim", "usr_v", "v@victim.example", "V", "owner", 1,
			time.Now().UTC(), time.Now().UTC()),
		gotMemberOrgID:  &gotOrg,
		gotMemberUserID: &gotUser,
	}
	handler := listMembersHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_mallory", "org_attacker", policy.RoleOwner)}, nil, reader)

	rec := getMember(handler, "org_victim", "usr_v", "a-valid-session-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedCrossTenant)
	}
	if gotOrg != "" || gotUser != "" {
		t.Errorf("reader was reached with org=%q user=%q for a cross-tenant request; it must never run", gotOrg, gotUser)
	}
	if strings.Contains(env.Error.Message, "org_victim") {
		t.Errorf("error message %q echoes the cross-tenant organization id", env.Error.Message)
	}
}

// TestGetMemberSupportReadsAnotherTenant proves the one deliberate
// cross-tenant exception: a support principal performing a read is allowed
// to read a member of an organization outside its home tenant, exactly as
// the policy matrix specifies for CapRead actions.
func TestGetMemberSupportReadsAnotherTenant(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	reader := fakeMembershipReader{member: seedMember(
		"org_customer", "usr_c", "c@customer.example", "Customer", "owner", 1, now, now,
	)}
	handler := listMembersHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_support", "org_yalla", policy.RoleSupport)}, nil, reader)

	rec := getMember(handler, "org_customer", "usr_c", "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeGetMember(t, rec)
	if env.Data.Member.UserID != "usr_c" {
		t.Errorf("member.user_id = %q, want usr_c", env.Data.Member.UserID)
	}
}

// TestGetMemberRequiresAuthentication proves a request with no credential is
// a stable 401 E_AUTH and never reaches the reader.
func TestGetMemberRequiresAuthentication(t *testing.T) {
	t.Parallel()

	handler := listMembersHandlerFor(auth.Identity{}, nil,
		fakeMembershipReader{getErr: stderrors.New("reader must not be called")})

	rec := getMember(handler, "org_acme", "usr_ada", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_AUTHENTICATION_REQUIRED")
	if env.Error.Message != "authentication is required" {
		t.Errorf("message = %q, want %q", env.Error.Message, "authentication is required")
	}
}

// TestGetMemberInvalidCredentials proves an unverifiable credential is a
// stable 401 E_AUTH_INVALID — distinct from the missing-credential contract.
func TestGetMemberInvalidCredentials(t *testing.T) {
	t.Parallel()

	handler := listMembersHandlerFor(auth.Identity{}, auth.ErrInvalidCredentials,
		fakeMembershipReader{getErr: stderrors.New("reader must not be called")})

	rec := getMember(handler, "org_acme", "usr_ada", "yk_bogus")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_AUTH_INVALID")
	if env.Error.Message != "the supplied credentials are invalid" {
		t.Errorf("message = %q, want %q", env.Error.Message, "the supplied credentials are invalid")
	}
}

// TestGetMemberDisabledPrincipal proves a revoked or expired credential
// surfaces as a disabled principal and is denied with a 403 E_FORBIDDEN
// carrying the stable reason — and the reader is never reached.
func TestGetMemberDisabledPrincipal(t *testing.T) {
	t.Parallel()

	disabled := orgPrincipal("usr_ada", "org_acme", policy.RoleOwner)
	disabled.Disabled = true
	handler := listMembersHandlerFor(auth.Identity{Principal: disabled}, nil,
		fakeMembershipReader{getErr: stderrors.New("reader must not be called")})

	rec := getMember(handler, "org_acme", "usr_ada", "a-revoked-session-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
	}
}

// TestGetMemberReaderUnavailable proves a datastore outage surfaces as its
// own typed 5xx, never disguised as a not-found or a zero member — and the
// wrapped driver cause never reaches the user-facing message.
func TestGetMemberReaderUnavailable(t *testing.T) {
	t.Parallel()

	reader := fakeMembershipReader{getErr: apierr.StoreUnavailable(stderrors.New("connection refused"))}
	handler := listMembersHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleViewer)}, nil, reader)

	rec := getMember(handler, "org_acme", "usr_ada", "a-valid-session-token")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_UNAVAILABLE")
	if strings.Contains(env.Error.Message, "connection refused") {
		t.Errorf("error message %q leaks the wrapped datastore cause", env.Error.Message)
	}
}

// TestGetMemberPropagatesRequestID proves the resolved request_id reaches
// both the response envelope and the echoed response header.
func TestGetMemberPropagatesRequestID(t *testing.T) {
	t.Parallel()

	reader := fakeMembershipReader{member: seedMember(
		"org_acme", "usr_ada", "ada@acme.example", "Ada Lovelace", "owner", 1,
		time.Now().UTC(), time.Now().UTC(),
	)}
	handler := listMembersHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleViewer)}, nil, reader)

	req := httptest.NewRequest(http.MethodGet, "/v1/organizations/org_acme/members/usr_ada", nil)
	req.Header.Set("Authorization", "Bearer a-valid-session-token")
	req.Header.Set(telemetry.HeaderRequestID, "caller-supplied-id")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeGetMember(t, rec)
	if env.RequestID != "caller-supplied-id" {
		t.Errorf("envelope request_id = %q, want caller-supplied-id", env.RequestID)
	}
	if got := rec.Header().Get(telemetry.HeaderRequestID); got != "caller-supplied-id" {
		t.Errorf("response header request_id = %q, want caller-supplied-id", got)
	}
}

// TestGetMemberHandlerWithoutPrincipalIsInternal proves the defensive path:
// if the handler is ever reached without RequireAuth having placed a
// principal on the context, it reports a typed internal error rather than
// reading a member for a zero principal.
func TestGetMemberHandlerWithoutPrincipalIsInternal(t *testing.T) {
	t.Parallel()

	rec := run(getMemberHandler(fakeMembershipReader{}),
		httptest.NewRequest(http.MethodGet, "/v1/organizations/org_acme/members/usr_ada", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INTERNAL")
}

// TestGetMemberHandlerWithNilReaderIsInternal proves a route registered
// without a membership reader is a wiring error reported as a typed internal
// failure — never a misleading not-found.
func TestGetMemberHandlerWithNilReaderIsInternal(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/v1/organizations/org_acme/members/usr_ada", nil)
	req = req.WithContext(policy.WithPrincipal(req.Context(),
		orgPrincipal("usr_ada", "org_acme", policy.RoleViewer)))
	rec := run(getMemberHandler(nil), req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INTERNAL")
}

// TestGetMemberIsDocumentedInOpenAPI proves the served route is also a
// documented route: GET /v1/organizations/{org_id}/members/{member_id}
// appears in the OpenAPI document requiring the API-key security scheme,
// naming its policy action through the x-required-action extension, and
// declaring both {org_id} and {member_id} as path parameters.
func TestGetMemberIsDocumentedInOpenAPI(t *testing.T) {
	t.Parallel()

	handler := listMembersHandlerFor(auth.Identity{}, nil, fakeMembershipReader{})
	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}

	var doc struct {
		Paths map[string]map[string]struct {
			OperationID    string                `json:"operationId"`
			Security       []map[string][]string `json:"security"`
			RequiredAction string                `json:"x-required-action"`
			Parameters     []struct {
				Name     string `json:"name"`
				In       string `json:"in"`
				Required bool   `json:"required"`
			} `json:"parameters"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode openapi document: %v", err)
	}
	op, ok := doc.Paths["/v1/organizations/{org_id}/members/{member_id}"]["get"]
	if !ok {
		t.Fatalf("openapi document does not describe GET /v1/organizations/{org_id}/members/{member_id}")
	}
	if op.OperationID != "getOrganizationMember" {
		t.Errorf("operationId = %q, want getOrganizationMember", op.OperationID)
	}
	if op.RequiredAction != string(policy.ActionMembersRead) {
		t.Errorf("x-required-action = %q, want %q", op.RequiredAction, policy.ActionMembersRead)
	}
	if len(op.Security) != 1 || len(op.Security[0]) != 1 {
		t.Errorf("security = %+v, want it to require the ApiKeyAuth scheme", op.Security)
	}
	if len(op.Parameters) != 2 {
		t.Fatalf("parameters = %+v, want two path parameters", op.Parameters)
	}
	gotParams := map[string]bool{}
	for _, p := range op.Parameters {
		if p.In != "path" || !p.Required {
			t.Errorf("path parameter %q = %+v, want {In:path Required:true}", p.Name, p)
		}
		gotParams[p.Name] = true
	}
	for _, want := range []string{"org_id", "member_id"} {
		if !gotParams[want] {
			t.Errorf("missing path parameter %q; got %+v", want, op.Parameters)
		}
	}
}

// TestMemberResourceMapping is a focused unit test of the
// store.OrganizationMember -> wire projection: identifiers and the role
// pass through verbatim, and timestamps are rendered as UTC RFC 3339 strings
// regardless of the stored zone.
func TestMemberResourceMapping(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 6, 7, 8, 123456789, time.FixedZone("EST", -5*3600))
	got := memberResourceOf(seedMember("org_acme", "usr_ada", "ada@acme.example", "Ada Lovelace", "owner", 7, created, updated))
	want := memberResource{
		UserID:          "usr_ada",
		Email:           "ada@acme.example",
		UserDisplayName: "Ada Lovelace",
		Role:            "owner",
		RoleVersion:     7,
		CreatedAt:       created.Format(time.RFC3339Nano),
		UpdatedAt:       updated.UTC().Format(time.RFC3339Nano),
	}
	if got != want {
		t.Errorf("memberResourceOf = %+v, want %+v", got, want)
	}
	if strings.HasSuffix(got.UpdatedAt, "-05:00") {
		t.Errorf("updated_at = %q, want a UTC timestamp regardless of the stored zone", got.UpdatedAt)
	}
}
