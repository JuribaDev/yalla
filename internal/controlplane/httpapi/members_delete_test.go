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

// Contract, authorization, and wiring coverage for DELETE
// /v1/organizations/{org_id}/members/{member_id} (BE-0073). The endpoint
// removes the member named by ({org_id}, {member_id}) through the
// MembershipRemover port; the tests drive it through NewHandler with a fake
// Authenticator, the real policy engine, and a fake remover — the same
// wiring a request hits in production, minus the database. The store-backed
// orchestrator (store.MembershipService.Remove) has its own isolated-
// Postgres integration coverage in store/membershipservice_test.go and
// white-box validation coverage in store/membershipservice_internal_test.go.
//
// The endpoint has no request body and no query parameters: its only inputs
// are the {org_id} and {member_id} path parameters. There is therefore no
// syntactic request to reject — a malformed or unknown id surfaces as a
// 404 from the store layer when the principal is authorized for the
// tenant, or, for an id outside the principal's tenant, as the
// deterministic 403 the policy engine returns through memberIDResolver.

// removeMemberSuccessEnvelope is the decoded shape of the DELETE
// /v1/organizations/{org_id}/members/{member_id} success envelope.
type removeMemberSuccessEnvelope struct {
	SchemaVersion string              `json:"schema_version"`
	OK            bool                `json:"ok"`
	RequestID     string              `json:"request_id"`
	Data          removeMemberPayload `json:"data"`
}

// removeMemberHandlerFor builds the full NewHandler surface with an
// Authenticator that resolves every credential to id and the given
// MembershipRemover. It is the production request path: the DELETE
// /v1/organizations/{org_id}/members/{member_id} route is wrapped in
// RequireAuth for action members.manage and goes through memberIDResolver.
func removeMemberHandlerFor(id auth.Identity, authErr error, remover MembershipRemover) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, remover, fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{}, fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{}, fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeBreakGlassController{}, nil, nil)
}

// deleteMember issues DELETE /v1/organizations/{orgID}/members/{memberID}
// against handler, optionally with a bearer token.
func deleteMember(handler http.Handler, orgID, memberID, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodDelete,
		"/v1/organizations/"+orgID+"/members/"+memberID, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeRemoveMember(t *testing.T, rec *httptest.ResponseRecorder) removeMemberSuccessEnvelope {
	t.Helper()
	var env removeMemberSuccessEnvelope
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

// TestRemoveMemberSuccess is the happy path: a valid request removes the
// member, the handler returns 200 with the stable yalla.output.v1 envelope,
// and the removed member — exactly as it stood at the moment of removal —
// is projected onto the wire shape so agents see what was removed.
func TestRemoveMemberSuccess(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := created.Add(time.Hour)
	remover := fakeMembershipRemover{member: seedMember(
		"org_acme", "usr_grace", "grace@acme.example", "Grace Hopper", "admin", 4, created, updated)}
	handler := removeMemberHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, remover)

	rec := deleteMember(handler, "org_acme", "usr_grace", "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q, want application/json", got)
	}

	env := decodeRemoveMember(t, rec)
	if env.Data.Member.UserID != "usr_grace" || env.Data.Member.Role != "admin" {
		t.Errorf("member = %+v, want user usr_grace with role admin (the role held at removal time)",
			env.Data.Member)
	}
	if env.Data.Member.RoleVersion != 4 {
		t.Errorf("role_version = %d, want 4 — the version at removal time must reach the wire",
			env.Data.Member.RoleVersion)
	}
}

// TestRemoveMemberForwardsActorAndPath proves the handler delegates: it
// forwards both path parameters and the authenticated principal — never
// caller-controlled actor fields — to the store layer unchanged.
func TestRemoveMemberForwardsActorAndPath(t *testing.T) {
	t.Parallel()

	var captured store.RemoveMembershipInput
	remover := fakeMembershipRemover{
		member: seedMember("org_acme", "usr_grace", "g@acme.example", "Grace", "admin", 2,
			time.Now().UTC(), time.Now().UTC()),
		got: &captured,
	}
	handler := removeMemberHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, remover)

	rec := deleteMember(handler, "org_acme", "usr_grace", "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if captured.OrganizationID != "org_acme" {
		t.Errorf("forwarded organization_id = %q, want org_acme from the path", captured.OrganizationID)
	}
	if captured.UserID != "usr_grace" {
		t.Errorf("forwarded user_id = %q, want usr_grace from the path", captured.UserID)
	}
	if captured.ActorID != "usr_ada" || captured.ActorOrgID != "org_acme" {
		t.Errorf("forwarded actor = %q/%q, want the authenticated principal usr_ada/org_acme",
			captured.ActorID, captured.ActorOrgID)
	}
	if captured.ActorKind == "" {
		t.Errorf("forwarded actor kind is empty, want the authenticated principal's kind")
	}
}

// TestRemoveMemberNotFound proves a {member_id} that names no row — and a
// member_id paired with the wrong org — surfaces as the typed 404
// E_NOT_FOUND the store layer produces, never disguised as a success.
func TestRemoveMemberNotFound(t *testing.T) {
	t.Parallel()

	remover := fakeMembershipRemover{err: apierr.NotFound("membership", "usr_ghost")}
	handler := removeMemberHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, remover)

	rec := deleteMember(handler, "org_acme", "usr_ghost", "a-valid-session-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_NOT_FOUND")
}

// TestRemoveMemberUnauthenticated proves a request with no credential is a
// stable 401 E_AUTH and never reaches the handler — the remover is never
// called.
func TestRemoveMemberUnauthenticated(t *testing.T) {
	t.Parallel()

	handler := removeMemberHandlerFor(auth.Identity{}, nil,
		fakeMembershipRemover{err: stderrors.New("remover must not be called")})
	rec := deleteMember(handler, "org_acme", "usr_grace", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_AUTH")
	if env.Error.Message != "authentication is required" {
		t.Errorf("message = %q, want %q", env.Error.Message, "authentication is required")
	}
}

// TestRemoveMemberInvalidCredentials proves an unverifiable credential is a
// stable 401 E_AUTH — identical to the missing-credential contract.
func TestRemoveMemberInvalidCredentials(t *testing.T) {
	t.Parallel()

	handler := removeMemberHandlerFor(auth.Identity{}, auth.ErrInvalidCredentials,
		fakeMembershipRemover{err: stderrors.New("remover must not be called")})
	rec := deleteMember(handler, "org_acme", "usr_grace", "yk_bogus")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_AUTH")
}

// TestRemoveMemberCrossTenantIsForbidden proves a principal removing a
// member outside its own tenant is denied with a deterministic 403
// E_FORBIDDEN carrying the stable cross-tenant reason — and the remover is
// never reached, so a cross-tenant id can never mutate another tenant's
// membership graph or even confirm that organization exists.
func TestRemoveMemberCrossTenantIsForbidden(t *testing.T) {
	t.Parallel()

	remover := fakeMembershipRemover{err: stderrors.New("remover must not be called")}
	handler := removeMemberHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_mallory", "org_attacker", policy.RoleOwner), Method: auth.MethodSession},
		nil, remover)

	rec := deleteMember(handler, "org_victim", "usr_grace", "a-valid-session-token")
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

// TestRemoveMemberDisabledPrincipal proves a revoked or expired credential
// surfaces as a disabled principal and is denied with a 403 E_FORBIDDEN
// carrying the stable reason — and the remover is never reached.
func TestRemoveMemberDisabledPrincipal(t *testing.T) {
	t.Parallel()

	disabled := orgPrincipal("usr_ada", "org_acme", policy.RoleOwner)
	disabled.Disabled = true
	remover := fakeMembershipRemover{err: stderrors.New("remover must not be called")}
	handler := removeMemberHandlerFor(auth.Identity{Principal: disabled, Method: auth.MethodSession}, nil, remover)

	rec := deleteMember(handler, "org_acme", "usr_grace", "a-revoked-session-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
	}
}

// TestRemoveMemberDependencyFailureIsTyped5xx proves a datastore outage
// surfaces as its own typed 5xx, never disguised as a 400, a 404, or a
// success — and the wrapped driver cause never reaches the user-facing
// message.
func TestRemoveMemberDependencyFailureIsTyped5xx(t *testing.T) {
	t.Parallel()

	remover := fakeMembershipRemover{err: apierr.StoreUnavailable(stderrors.New("connection refused"))}
	handler := removeMemberHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, remover)

	rec := deleteMember(handler, "org_acme", "usr_grace", "a-valid-session-token")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_UNAVAILABLE")
	if strings.Contains(env.Error.Message, "connection refused") {
		t.Errorf("error message %q leaks the wrapped datastore cause", env.Error.Message)
	}
}

// TestRemoveMemberPropagatesRequestID proves the resolved request_id reaches
// both the response envelope and the echoed response header.
func TestRemoveMemberPropagatesRequestID(t *testing.T) {
	t.Parallel()

	remover := fakeMembershipRemover{member: seedMember(
		"org_acme", "usr_grace", "g@acme.example", "Grace", "admin", 2, time.Now().UTC(), time.Now().UTC())}
	handler := removeMemberHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, remover)

	req := httptest.NewRequest(http.MethodDelete, "/v1/organizations/org_acme/members/usr_grace", nil)
	req.Header.Set("Authorization", "Bearer a-valid-session-token")
	req.Header.Set(telemetry.HeaderRequestID, "caller-supplied-id")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeRemoveMember(t, rec)
	if env.RequestID != "caller-supplied-id" {
		t.Errorf("envelope request_id = %q, want caller-supplied-id", env.RequestID)
	}
	if got := rec.Header().Get(telemetry.HeaderRequestID); got != "caller-supplied-id" {
		t.Errorf("response header request_id = %q, want caller-supplied-id", got)
	}
}

// TestRemoveMemberHandlerWithoutPrincipalIsInternal proves the defensive
// path: if the handler is ever reached without RequireAuth having placed a
// principal on the context, it reports a typed internal error rather than
// removing a member for a zero principal.
func TestRemoveMemberHandlerWithoutPrincipalIsInternal(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodDelete, "/v1/organizations/org_acme/members/usr_grace", nil)
	rec := run(removeMemberHandler(fakeMembershipRemover{}), req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INTERNAL")
}

// TestRemoveMemberHandlerWithNilRemoverIsInternal proves a route registered
// without a membership remover is a wiring error reported as a typed
// internal failure — never a silently dropped write.
func TestRemoveMemberHandlerWithNilRemoverIsInternal(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodDelete, "/v1/organizations/org_acme/members/usr_grace", nil)
	req = req.WithContext(policy.WithPrincipal(req.Context(),
		orgPrincipal("usr_ada", "org_acme", policy.RoleOwner)))
	rec := run(removeMemberHandler(nil), req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INTERNAL")
}

// TestRemoveMemberIsDocumentedInOpenAPI proves the served route is also a
// documented route: DELETE /v1/organizations/{org_id}/members/{member_id}
// appears in the OpenAPI document requiring the API-key security scheme,
// naming its policy action through the x-required-action extension,
// declaring both path parameters, and documenting a 200 success response.
func TestRemoveMemberIsDocumentedInOpenAPI(t *testing.T) {
	t.Parallel()

	handler := removeMemberHandlerFor(auth.Identity{}, nil, fakeMembershipRemover{})
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
	op, ok := doc.Paths["/v1/organizations/{org_id}/members/{member_id}"]["delete"]
	if !ok {
		t.Fatalf("openapi document does not describe DELETE /v1/organizations/{org_id}/members/{member_id}")
	}
	if op.OperationID != "removeOrganizationMember" {
		t.Errorf("operationId = %q, want removeOrganizationMember", op.OperationID)
	}
	if op.RequiredAction != string(policy.ActionMembersManage) {
		t.Errorf("x-required-action = %q, want %q", op.RequiredAction, policy.ActionMembersManage)
	}
	if len(op.Security) != 1 || len(op.Security[0]) != 1 {
		t.Errorf("security = %+v, want it to require the ApiKeyAuth scheme", op.Security)
	}
	if len(op.Parameters) != 2 {
		t.Fatalf("parameters = %+v, want exactly two path parameters", op.Parameters)
	}
	wantParams := map[string]bool{"org_id": false, "member_id": false}
	for _, p := range op.Parameters {
		if p.In != "path" || !p.Required {
			t.Errorf("path parameter = %+v, want in=path required=true", p)
		}
		if _, ok := wantParams[p.Name]; !ok {
			t.Errorf("unexpected parameter %q", p.Name)
			continue
		}
		wantParams[p.Name] = true
	}
	for name, present := range wantParams {
		if !present {
			t.Errorf("missing path parameter %q", name)
		}
	}
	if _, ok := op.Responses["200"]; !ok {
		t.Errorf("responses = %+v, want a documented 200 success response", op.Responses)
	}
}

// TestRemoveMemberResponseShape proves the success body carries a single
// member resource in the stable wire shape — never a list — and surfaces
// the joined user identity (email, display_name) and the role_version held
// at removal time. Returning the terminal view (rather than 204) is the
// stable contract — the row no longer exists, but the body is the
// audit-grade record of what was removed.
func TestRemoveMemberResponseShape(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := created.Add(time.Hour)
	remover := fakeMembershipRemover{member: seedMember(
		"org_acme", "usr_grace", "grace@acme.example", "Grace Hopper", "admin", 4, created, updated)}
	handler := removeMemberHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, remover)

	rec := deleteMember(handler, "org_acme", "usr_grace", "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	// Reading members[0] would be a wiring error — the success payload is a
	// single member object, not a list. The decoded envelope tolerates only
	// the documented shape.
	if strings.Contains(rec.Body.String(), `"members"`) {
		t.Errorf("body %s carries a list shape, want a single member object", rec.Body.String())
	}
	env := decodeRemoveMember(t, rec)
	if env.Data.Member.Email != "grace@acme.example" || env.Data.Member.UserDisplayName != "Grace Hopper" {
		t.Errorf("member = %+v, want the joined user email and display name", env.Data.Member)
	}
	if env.Data.Member.RoleVersion != 4 {
		t.Errorf("role_version on the wire = %d, want 4 — the version at removal time must reach the wire shape",
			env.Data.Member.RoleVersion)
	}
}
