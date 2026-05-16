package httpapi

import (
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

// Contract, authorization, and wiring coverage for POST
// /v1/organizations/{org_id}/members (BE-0064). The endpoint adds an existing
// global user to the organization the {org_id} path parameter names, with the
// requested role, through the MembershipCreator port; the tests drive it
// through NewHandler with a fake Authenticator, the real policy engine, and
// a fake creator — the same wiring a request hits in production, minus the
// database. The store-backed orchestrator (store.MembershipService) has its
// own isolated-Postgres integration coverage in
// store/membershipservice_test.go and white-box validation coverage in
// store/membershipservice_internal_test.go.

// addMemberSuccessEnvelope is the decoded shape of the POST
// /v1/organizations/{org_id}/members success envelope.
type addMemberSuccessEnvelope struct {
	SchemaVersion string           `json:"schema_version"`
	OK            bool             `json:"ok"`
	RequestID     string           `json:"request_id"`
	Data          addMemberPayload `json:"data"`
}

// addMemberHandlerFor builds the full NewHandler surface with an
// Authenticator that resolves every credential to id and the given
// MembershipCreator. It is the production request path: the POST
// /v1/organizations/{org_id}/members route is wrapped in RequireAuth for
// action members.manage and goes through organizationIDResolver.
func addMemberHandlerFor(id auth.Identity, authErr error, creator MembershipCreator) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{}, fakeMembershipReader{}, creator, fakeMembershipUpdater{}, fakeMembershipRemover{}, fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{}, fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{}, fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeBreakGlassController{}, nil, nil)
}

// postMember issues POST /v1/organizations/{orgID}/members against handler
// with body, optionally with a bearer token.
func postMember(handler http.Handler, orgID, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/organizations/"+orgID+"/members", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeAddMember(t *testing.T, rec *httptest.ResponseRecorder) addMemberSuccessEnvelope {
	t.Helper()
	var env addMemberSuccessEnvelope
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

// TestAddMemberSuccess is the happy path: a valid request creates the
// membership, the handler returns 201 with the stable yalla.output.v1
// envelope, and the added member is projected onto the wire shape.
func TestAddMemberSuccess(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	creator := fakeMembershipCreator{member: seedMember(
		"org_acme", "usr_grace", "grace@acme.example", "Grace Hopper", "admin", 1, created, created)}
	handler := addMemberHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	rec := postMember(handler, "org_acme", "a-valid-session-token",
		`{"user_id":"usr_grace","role":"admin"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q, want application/json", got)
	}

	env := decodeAddMember(t, rec)
	if env.Data.Member.UserID != "usr_grace" || env.Data.Member.Role != "admin" {
		t.Errorf("member = %+v, want user usr_grace with role admin", env.Data.Member)
	}
}

// TestAddMemberForwardsActorAndPath proves the handler delegates: it forwards
// the decoded request body, the {org_id} path parameter, and the
// authenticated principal — never caller-controlled actor fields — to the
// store layer unchanged.
func TestAddMemberForwardsActorAndPath(t *testing.T) {
	t.Parallel()

	var captured store.AddMembershipInput
	creator := fakeMembershipCreator{
		member: seedMember("org_acme", "usr_grace", "g@acme.example", "Grace", "admin", 1, time.Now().UTC(), time.Now().UTC()),
		got:    &captured,
	}
	handler := addMemberHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	rec := postMember(handler, "org_acme", "a-valid-session-token",
		`{"user_id":"usr_grace","role":"admin"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	if captured.OrganizationID != "org_acme" {
		t.Errorf("forwarded organization_id = %q, want org_acme from the path", captured.OrganizationID)
	}
	if captured.UserID != "usr_grace" || captured.Role != "admin" {
		t.Errorf("forwarded user_id/role = %q/%q, want usr_grace/admin", captured.UserID, captured.Role)
	}
	if captured.ActorID != "usr_ada" || captured.ActorOrgID != "org_acme" {
		t.Errorf("forwarded actor = %q/%q, want the authenticated principal usr_ada/org_acme",
			captured.ActorID, captured.ActorOrgID)
	}
	if captured.ActorKind == "" {
		t.Errorf("forwarded actor kind is empty, want the authenticated principal's kind")
	}
}

// TestAddMemberMalformedBodyIsValidationError proves a syntactically broken
// body is a stable 400 E_INVALID_INPUT and never reaches the store layer.
func TestAddMemberMalformedBodyIsValidationError(t *testing.T) {
	t.Parallel()

	creator := fakeMembershipCreator{err: stderrors.New("creator must not be called")}
	handler := addMemberHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	rec := postMember(handler, "org_acme", "a-valid-session-token", `{"user_id":`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INVALID_INPUT")
}

// TestAddMemberUnknownFieldIsValidationError proves the body is strictly
// decoded: an unknown field is a stable 400 E_INVALID_INPUT, so a client
// typo or a stale schema cannot be silently dropped.
func TestAddMemberUnknownFieldIsValidationError(t *testing.T) {
	t.Parallel()

	creator := fakeMembershipCreator{err: stderrors.New("creator must not be called")}
	handler := addMemberHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	rec := postMember(handler, "org_acme", "a-valid-session-token",
		`{"user_id":"usr_grace","role":"admin","invited_by":"usr_x"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INVALID_INPUT")
}

// TestAddMemberInvalidInputIsValidationError proves a request the store
// layer rejects — an invalid role or user id — surfaces as the typed 400
// E_INVALID_INPUT the validator produces.
func TestAddMemberInvalidInputIsValidationError(t *testing.T) {
	t.Parallel()

	creator := fakeMembershipCreator{err: apierr.InvalidInput(apierr.FieldViolation{
		Field:  "role",
		Reason: "must be one of owner, admin, or member",
	})}
	handler := addMemberHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	rec := postMember(handler, "org_acme", "a-valid-session-token",
		`{"user_id":"usr_grace","role":"emperor"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INVALID_INPUT")
}

// TestAddMemberUserNotFound proves the targeted not-found path: a user_id
// that names no row surfaces as the typed 404 E_NOT_FOUND the store layer
// produces, never disguised as a 409 conflict.
func TestAddMemberUserNotFound(t *testing.T) {
	t.Parallel()

	creator := fakeMembershipCreator{err: apierr.NotFound("user", "usr_ghost")}
	handler := addMemberHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	rec := postMember(handler, "org_acme", "a-valid-session-token",
		`{"user_id":"usr_ghost","role":"member"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_NOT_FOUND")
}

// TestAddMemberDuplicateIsConflict proves an already-a-member collision
// surfaces as the typed 409 E_CONFLICT the store layer produces, never
// disguised as a 500 or a success.
func TestAddMemberDuplicateIsConflict(t *testing.T) {
	t.Parallel()

	creator := fakeMembershipCreator{err: apierr.Conflict("the user is already a member of this organization")}
	handler := addMemberHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	rec := postMember(handler, "org_acme", "a-valid-session-token",
		`{"user_id":"usr_grace","role":"member"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_CONFLICT")
}

// TestAddMemberUnauthenticated proves a request with no credential is a
// stable 401 E_AUTH and never reaches the handler — the creator is never
// called.
func TestAddMemberUnauthenticated(t *testing.T) {
	t.Parallel()

	handler := addMemberHandlerFor(auth.Identity{}, nil,
		fakeMembershipCreator{err: stderrors.New("creator must not be called")})
	rec := postMember(handler, "org_acme", "", `{"user_id":"usr_grace","role":"member"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_AUTH")
	if env.Error.Message != "authentication is required" {
		t.Errorf("message = %q, want %q", env.Error.Message, "authentication is required")
	}
}

// TestAddMemberInvalidCredentials proves an unverifiable credential is a
// stable 401 E_AUTH — identical to the missing-credential contract.
func TestAddMemberInvalidCredentials(t *testing.T) {
	t.Parallel()

	handler := addMemberHandlerFor(auth.Identity{}, auth.ErrInvalidCredentials,
		fakeMembershipCreator{err: stderrors.New("creator must not be called")})
	rec := postMember(handler, "org_acme", "yk_bogus", `{"user_id":"usr_grace","role":"member"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_AUTH")
}

// TestAddMemberCrossTenantIsForbidden proves a principal adding a member
// outside its own tenant is denied with a deterministic 403 E_FORBIDDEN
// carrying the stable cross-tenant reason — and the creator is never reached,
// so a cross-tenant id can never mutate another tenant's membership graph or
// even confirm that organization exists.
func TestAddMemberCrossTenantIsForbidden(t *testing.T) {
	t.Parallel()

	creator := fakeMembershipCreator{err: stderrors.New("creator must not be called")}
	handler := addMemberHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_mallory", "org_attacker", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	rec := postMember(handler, "org_victim", "a-valid-session-token",
		`{"user_id":"usr_grace","role":"admin"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedCrossTenant)
	}
	if strings.Contains(env.Error.Message, "org_victim") {
		t.Errorf("error message %q echoes the cross-tenant organization id", env.Error.Message)
	}
}

// TestAddMemberDisabledPrincipal proves a revoked or expired credential
// surfaces as a disabled principal and is denied with a 403 E_FORBIDDEN
// carrying the stable reason — and the creator is never reached.
func TestAddMemberDisabledPrincipal(t *testing.T) {
	t.Parallel()

	disabled := orgPrincipal("usr_ada", "org_acme", policy.RoleOwner)
	disabled.Disabled = true
	creator := fakeMembershipCreator{err: stderrors.New("creator must not be called")}
	handler := addMemberHandlerFor(auth.Identity{Principal: disabled, Method: auth.MethodSession}, nil, creator)

	rec := postMember(handler, "org_acme", "a-revoked-session-token",
		`{"user_id":"usr_grace","role":"admin"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
	}
}

// TestAddMemberDependencyFailureIsTyped5xx proves a datastore outage surfaces
// as its own typed 5xx, never disguised as a 400, a 409, or a success — and
// the wrapped driver cause never reaches the user-facing message.
func TestAddMemberDependencyFailureIsTyped5xx(t *testing.T) {
	t.Parallel()

	creator := fakeMembershipCreator{err: apierr.StoreUnavailable(stderrors.New("connection refused"))}
	handler := addMemberHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	rec := postMember(handler, "org_acme", "a-valid-session-token",
		`{"user_id":"usr_grace","role":"admin"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_UNAVAILABLE")
	if strings.Contains(env.Error.Message, "connection refused") {
		t.Errorf("error message %q leaks the wrapped datastore cause", env.Error.Message)
	}
}

// TestAddMemberPropagatesRequestID proves the resolved request_id reaches
// both the response envelope and the echoed response header.
func TestAddMemberPropagatesRequestID(t *testing.T) {
	t.Parallel()

	creator := fakeMembershipCreator{member: seedMember(
		"org_acme", "usr_grace", "g@acme.example", "Grace", "admin", 1, time.Now().UTC(), time.Now().UTC())}
	handler := addMemberHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	req := httptest.NewRequest(http.MethodPost, "/v1/organizations/org_acme/members",
		strings.NewReader(`{"user_id":"usr_grace","role":"admin"}`))
	req.Header.Set("Authorization", "Bearer a-valid-session-token")
	req.Header.Set(telemetry.HeaderRequestID, "caller-supplied-id")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	env := decodeAddMember(t, rec)
	if env.RequestID != "caller-supplied-id" {
		t.Errorf("envelope request_id = %q, want caller-supplied-id", env.RequestID)
	}
	if got := rec.Header().Get(telemetry.HeaderRequestID); got != "caller-supplied-id" {
		t.Errorf("response header request_id = %q, want caller-supplied-id", got)
	}
}

// TestAddMemberHandlerWithoutPrincipalIsInternal proves the defensive path:
// if the handler is ever reached without RequireAuth having placed a
// principal on the context, it reports a typed internal error rather than
// adding a member for a zero principal.
func TestAddMemberHandlerWithoutPrincipalIsInternal(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPost, "/v1/organizations/org_acme/members",
		strings.NewReader(`{"user_id":"usr_grace","role":"admin"}`))
	rec := run(addMemberHandler(fakeMembershipCreator{}), req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INTERNAL")
}

// TestAddMemberHandlerWithNilCreatorIsInternal proves a route registered
// without a membership creator is a wiring error reported as a typed
// internal failure — never a silently dropped write.
func TestAddMemberHandlerWithNilCreatorIsInternal(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPost, "/v1/organizations/org_acme/members",
		strings.NewReader(`{"user_id":"usr_grace","role":"admin"}`))
	req = req.WithContext(policy.WithPrincipal(req.Context(),
		orgPrincipal("usr_ada", "org_acme", policy.RoleOwner)))
	rec := run(addMemberHandler(nil), req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INTERNAL")
}

// TestAddMemberIsDocumentedInOpenAPI proves the served route is also a
// documented route: POST /v1/organizations/{org_id}/members appears in the
// OpenAPI document requiring the API-key security scheme, naming its policy
// action through the x-required-action extension, declaring the {org_id}
// path parameter, and documenting a 201 success response.
func TestAddMemberIsDocumentedInOpenAPI(t *testing.T) {
	t.Parallel()

	handler := addMemberHandlerFor(auth.Identity{}, nil, fakeMembershipCreator{})
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
			Responses map[string]any `json:"responses"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode openapi document: %v", err)
	}
	op, ok := doc.Paths["/v1/organizations/{org_id}/members"]["post"]
	if !ok {
		t.Fatalf("openapi document does not describe POST /v1/organizations/{org_id}/members")
	}
	if op.OperationID != "addOrganizationMember" {
		t.Errorf("operationId = %q, want addOrganizationMember", op.OperationID)
	}
	if op.RequiredAction != string(policy.ActionMembersManage) {
		t.Errorf("x-required-action = %q, want %q", op.RequiredAction, policy.ActionMembersManage)
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
	if _, ok := op.Responses["201"]; !ok {
		t.Errorf("responses = %+v, want a documented 201 success response", op.Responses)
	}
}

// TestAddMemberResponseShape proves the success body carries a single
// member resource in the stable wire shape — never a list — and surfaces the
// joined user identity (email, display_name) the store layer returns.
func TestAddMemberResponseShape(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	creator := fakeMembershipCreator{member: seedMember(
		"org_acme", "usr_grace", "grace@acme.example", "Grace Hopper", "admin", 1, created, created)}
	handler := addMemberHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	rec := postMember(handler, "org_acme", "a-valid-session-token",
		`{"user_id":"usr_grace","role":"admin"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	// Reading members[0] would be a wiring error — the success payload is a
	// single member object, not a list. The decoded envelope tolerates only
	// the documented shape.
	if strings.Contains(rec.Body.String(), `"members"`) {
		t.Errorf("body %s carries a list shape, want a single member object", rec.Body.String())
	}
	env := decodeAddMember(t, rec)
	if env.Data.Member.Email != "grace@acme.example" || env.Data.Member.UserDisplayName != "Grace Hopper" {
		t.Errorf("member = %+v, want the joined user email and display name", env.Data.Member)
	}
}
