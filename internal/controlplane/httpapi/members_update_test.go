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

// Contract, authorization, and wiring coverage for PATCH
// /v1/organizations/{org_id}/members/{member_id} (BE-0070). The endpoint
// updates the role of the member named by ({org_id}, {member_id}) through
// the MembershipUpdater port; the tests drive it through NewHandler with a
// fake Authenticator, the real policy engine, and a fake updater — the same
// wiring a request hits in production, minus the database. The store-backed
// orchestrator (store.MembershipService.UpdateMember) has its own
// isolated-Postgres integration coverage in
// store/membershipservice_test.go and white-box validation coverage in
// store/membershipservice_internal_test.go.

// updateMemberSuccessEnvelope is the decoded shape of the PATCH
// /v1/organizations/{org_id}/members/{member_id} success envelope.
type updateMemberSuccessEnvelope struct {
	SchemaVersion string              `json:"schema_version"`
	OK            bool                `json:"ok"`
	RequestID     string              `json:"request_id"`
	Data          updateMemberPayload `json:"data"`
}

// updateMemberHandlerFor builds the full NewHandler surface with an
// Authenticator that resolves every credential to id and the given
// MembershipUpdater. It is the production request path: the PATCH
// /v1/organizations/{org_id}/members/{member_id} route is wrapped in
// RequireAuth for action members.manage and goes through memberIDResolver.
func updateMemberHandlerFor(id auth.Identity, authErr error, updater MembershipUpdater) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, updater, fakeMembershipRemover{}, fakeLimitsReader{}, fakeLimitsUpdater{}, fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{}, nil)
}

// patchMember issues PATCH /v1/organizations/{orgID}/members/{memberID}
// against handler with body, optionally with a bearer token.
func patchMember(handler http.Handler, orgID, memberID, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPatch,
		"/v1/organizations/"+orgID+"/members/"+memberID, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeUpdateMember(t *testing.T, rec *httptest.ResponseRecorder) updateMemberSuccessEnvelope {
	t.Helper()
	var env updateMemberSuccessEnvelope
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

// TestUpdateMemberSuccess is the happy path: a valid request updates the
// role, the handler returns 200 with the stable yalla.output.v1 envelope,
// and the updated member — including the freshly bumped role_version — is
// projected onto the wire shape.
func TestUpdateMemberSuccess(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := created.Add(time.Hour)
	updater := fakeMembershipUpdater{member: seedMember(
		"org_acme", "usr_grace", "grace@acme.example", "Grace Hopper", "admin", 4, created, updated)}
	handler := updateMemberHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, updater)

	rec := patchMember(handler, "org_acme", "usr_grace", "a-valid-session-token",
		`{"role":"admin"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q, want application/json", got)
	}

	env := decodeUpdateMember(t, rec)
	if env.Data.Member.UserID != "usr_grace" || env.Data.Member.Role != "admin" {
		t.Errorf("member = %+v, want user usr_grace with role admin", env.Data.Member)
	}
	if env.Data.Member.RoleVersion != 4 {
		t.Errorf("role_version = %d, want 4 — the bumped version must reach the wire",
			env.Data.Member.RoleVersion)
	}
}

// TestUpdateMemberForwardsActorAndPath proves the handler delegates: it
// forwards the decoded role, both path parameters, and the authenticated
// principal — never caller-controlled actor fields — to the store layer
// unchanged.
func TestUpdateMemberForwardsActorAndPath(t *testing.T) {
	t.Parallel()

	var captured store.UpdateMembershipInput
	updater := fakeMembershipUpdater{
		member: seedMember("org_acme", "usr_grace", "g@acme.example", "Grace", "admin", 2,
			time.Now().UTC(), time.Now().UTC()),
		got: &captured,
	}
	handler := updateMemberHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, updater)

	rec := patchMember(handler, "org_acme", "usr_grace", "a-valid-session-token",
		`{"role":"admin"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if captured.OrganizationID != "org_acme" {
		t.Errorf("forwarded organization_id = %q, want org_acme from the path", captured.OrganizationID)
	}
	if captured.UserID != "usr_grace" {
		t.Errorf("forwarded user_id = %q, want usr_grace from the path", captured.UserID)
	}
	if captured.Role != "admin" {
		t.Errorf("forwarded role = %q, want admin from the body", captured.Role)
	}
	if captured.ActorID != "usr_ada" || captured.ActorOrgID != "org_acme" {
		t.Errorf("forwarded actor = %q/%q, want the authenticated principal usr_ada/org_acme",
			captured.ActorID, captured.ActorOrgID)
	}
	if captured.ActorKind == "" {
		t.Errorf("forwarded actor kind is empty, want the authenticated principal's kind")
	}
}

// TestUpdateMemberMalformedBodyIsValidationError proves a syntactically
// broken body is a stable 400 E_INVALID_INPUT and never reaches the store
// layer.
func TestUpdateMemberMalformedBodyIsValidationError(t *testing.T) {
	t.Parallel()

	updater := fakeMembershipUpdater{err: stderrors.New("updater must not be called")}
	handler := updateMemberHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, updater)

	rec := patchMember(handler, "org_acme", "usr_grace", "a-valid-session-token", `{"role":`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INVALID_INPUT")
}

// TestUpdateMemberUnknownFieldIsValidationError proves the body is strictly
// decoded: an unknown field is a stable 400 E_INVALID_INPUT, so a client
// typo or a stale schema cannot be silently dropped.
func TestUpdateMemberUnknownFieldIsValidationError(t *testing.T) {
	t.Parallel()

	updater := fakeMembershipUpdater{err: stderrors.New("updater must not be called")}
	handler := updateMemberHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, updater)

	rec := patchMember(handler, "org_acme", "usr_grace", "a-valid-session-token",
		`{"role":"admin","grants":[]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INVALID_INPUT")
}

// TestUpdateMemberMissingRoleIsValidationError proves a PATCH that names no
// updatable field — today, no role field — is itself a client error: the
// boundary rejects it as a stable 400 E_INVALID_INPUT naming the role field,
// without ever reaching the store layer.
func TestUpdateMemberMissingRoleIsValidationError(t *testing.T) {
	t.Parallel()

	updater := fakeMembershipUpdater{err: stderrors.New("updater must not be called")}
	handler := updateMemberHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, updater)

	rec := patchMember(handler, "org_acme", "usr_grace", "a-valid-session-token", `{}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INVALID_INPUT")
}

// TestUpdateMemberInvalidRoleIsValidationError proves a request the store
// layer rejects — an unknown role — surfaces as the typed 400
// E_INVALID_INPUT the validator produces.
func TestUpdateMemberInvalidRoleIsValidationError(t *testing.T) {
	t.Parallel()

	updater := fakeMembershipUpdater{err: apierr.InvalidInput(apierr.FieldViolation{
		Field:  "role",
		Reason: "must be one of owner, admin, or member",
	})}
	handler := updateMemberHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, updater)

	rec := patchMember(handler, "org_acme", "usr_grace", "a-valid-session-token",
		`{"role":"emperor"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INVALID_INPUT")
}

// TestUpdateMemberNotFound proves a {member_id} that names no row — and a
// member_id paired with the wrong org — surfaces as the typed 404
// E_NOT_FOUND the store layer produces, never disguised as a 409 or a
// success.
func TestUpdateMemberNotFound(t *testing.T) {
	t.Parallel()

	updater := fakeMembershipUpdater{err: apierr.NotFound("membership", "usr_ghost")}
	handler := updateMemberHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, updater)

	rec := patchMember(handler, "org_acme", "usr_ghost", "a-valid-session-token",
		`{"role":"member"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_NOT_FOUND")
}

// TestUpdateMemberUnauthenticated proves a request with no credential is a
// stable 401 E_AUTH and never reaches the handler — the updater is never
// called.
func TestUpdateMemberUnauthenticated(t *testing.T) {
	t.Parallel()

	handler := updateMemberHandlerFor(auth.Identity{}, nil,
		fakeMembershipUpdater{err: stderrors.New("updater must not be called")})
	rec := patchMember(handler, "org_acme", "usr_grace", "", `{"role":"member"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_AUTH")
	if env.Error.Message != "authentication is required" {
		t.Errorf("message = %q, want %q", env.Error.Message, "authentication is required")
	}
}

// TestUpdateMemberInvalidCredentials proves an unverifiable credential is a
// stable 401 E_AUTH — identical to the missing-credential contract.
func TestUpdateMemberInvalidCredentials(t *testing.T) {
	t.Parallel()

	handler := updateMemberHandlerFor(auth.Identity{}, auth.ErrInvalidCredentials,
		fakeMembershipUpdater{err: stderrors.New("updater must not be called")})
	rec := patchMember(handler, "org_acme", "usr_grace", "yk_bogus", `{"role":"member"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_AUTH")
}

// TestUpdateMemberCrossTenantIsForbidden proves a principal updating a
// member outside its own tenant is denied with a deterministic 403
// E_FORBIDDEN carrying the stable cross-tenant reason — and the updater is
// never reached, so a cross-tenant id can never mutate another tenant's
// membership graph or even confirm that organization exists.
func TestUpdateMemberCrossTenantIsForbidden(t *testing.T) {
	t.Parallel()

	updater := fakeMembershipUpdater{err: stderrors.New("updater must not be called")}
	handler := updateMemberHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_mallory", "org_attacker", policy.RoleOwner), Method: auth.MethodSession},
		nil, updater)

	rec := patchMember(handler, "org_victim", "usr_grace", "a-valid-session-token",
		`{"role":"admin"}`)
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

// TestUpdateMemberDisabledPrincipal proves a revoked or expired credential
// surfaces as a disabled principal and is denied with a 403 E_FORBIDDEN
// carrying the stable reason — and the updater is never reached.
func TestUpdateMemberDisabledPrincipal(t *testing.T) {
	t.Parallel()

	disabled := orgPrincipal("usr_ada", "org_acme", policy.RoleOwner)
	disabled.Disabled = true
	updater := fakeMembershipUpdater{err: stderrors.New("updater must not be called")}
	handler := updateMemberHandlerFor(auth.Identity{Principal: disabled, Method: auth.MethodSession}, nil, updater)

	rec := patchMember(handler, "org_acme", "usr_grace", "a-revoked-session-token",
		`{"role":"admin"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
	}
}

// TestUpdateMemberDependencyFailureIsTyped5xx proves a datastore outage
// surfaces as its own typed 5xx, never disguised as a 400, a 404, or a
// success — and the wrapped driver cause never reaches the user-facing
// message.
func TestUpdateMemberDependencyFailureIsTyped5xx(t *testing.T) {
	t.Parallel()

	updater := fakeMembershipUpdater{err: apierr.StoreUnavailable(stderrors.New("connection refused"))}
	handler := updateMemberHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, updater)

	rec := patchMember(handler, "org_acme", "usr_grace", "a-valid-session-token",
		`{"role":"admin"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_UNAVAILABLE")
	if strings.Contains(env.Error.Message, "connection refused") {
		t.Errorf("error message %q leaks the wrapped datastore cause", env.Error.Message)
	}
}

// TestUpdateMemberPropagatesRequestID proves the resolved request_id reaches
// both the response envelope and the echoed response header.
func TestUpdateMemberPropagatesRequestID(t *testing.T) {
	t.Parallel()

	updater := fakeMembershipUpdater{member: seedMember(
		"org_acme", "usr_grace", "g@acme.example", "Grace", "admin", 2, time.Now().UTC(), time.Now().UTC())}
	handler := updateMemberHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, updater)

	req := httptest.NewRequest(http.MethodPatch, "/v1/organizations/org_acme/members/usr_grace",
		strings.NewReader(`{"role":"admin"}`))
	req.Header.Set("Authorization", "Bearer a-valid-session-token")
	req.Header.Set(telemetry.HeaderRequestID, "caller-supplied-id")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeUpdateMember(t, rec)
	if env.RequestID != "caller-supplied-id" {
		t.Errorf("envelope request_id = %q, want caller-supplied-id", env.RequestID)
	}
	if got := rec.Header().Get(telemetry.HeaderRequestID); got != "caller-supplied-id" {
		t.Errorf("response header request_id = %q, want caller-supplied-id", got)
	}
}

// TestUpdateMemberHandlerWithoutPrincipalIsInternal proves the defensive
// path: if the handler is ever reached without RequireAuth having placed a
// principal on the context, it reports a typed internal error rather than
// updating a member for a zero principal.
func TestUpdateMemberHandlerWithoutPrincipalIsInternal(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPatch, "/v1/organizations/org_acme/members/usr_grace",
		strings.NewReader(`{"role":"admin"}`))
	rec := run(updateMemberHandler(fakeMembershipUpdater{}), req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INTERNAL")
}

// TestUpdateMemberHandlerWithNilUpdaterIsInternal proves a route registered
// without a membership updater is a wiring error reported as a typed
// internal failure — never a silently dropped write.
func TestUpdateMemberHandlerWithNilUpdaterIsInternal(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPatch, "/v1/organizations/org_acme/members/usr_grace",
		strings.NewReader(`{"role":"admin"}`))
	req = req.WithContext(policy.WithPrincipal(req.Context(),
		orgPrincipal("usr_ada", "org_acme", policy.RoleOwner)))
	rec := run(updateMemberHandler(nil), req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INTERNAL")
}

// TestUpdateMemberIsDocumentedInOpenAPI proves the served route is also a
// documented route: PATCH /v1/organizations/{org_id}/members/{member_id}
// appears in the OpenAPI document requiring the API-key security scheme,
// naming its policy action through the x-required-action extension,
// declaring both path parameters, and documenting a 200 success response.
func TestUpdateMemberIsDocumentedInOpenAPI(t *testing.T) {
	t.Parallel()

	handler := updateMemberHandlerFor(auth.Identity{}, nil, fakeMembershipUpdater{})
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
	op, ok := doc.Paths["/v1/organizations/{org_id}/members/{member_id}"]["patch"]
	if !ok {
		t.Fatalf("openapi document does not describe PATCH /v1/organizations/{org_id}/members/{member_id}")
	}
	if op.OperationID != "updateOrganizationMember" {
		t.Errorf("operationId = %q, want updateOrganizationMember", op.OperationID)
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

// TestUpdateMemberResponseShape proves the success body carries a single
// member resource in the stable wire shape — never a list — and surfaces the
// joined user identity (email, display_name) and the freshly bumped
// role_version the store layer returns.
func TestUpdateMemberResponseShape(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := created.Add(time.Hour)
	updater := fakeMembershipUpdater{member: seedMember(
		"org_acme", "usr_grace", "grace@acme.example", "Grace Hopper", "admin", 4, created, updated)}
	handler := updateMemberHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, updater)

	rec := patchMember(handler, "org_acme", "usr_grace", "a-valid-session-token",
		`{"role":"admin"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	// Reading members[0] would be a wiring error — the success payload is a
	// single member object, not a list. The decoded envelope tolerates only
	// the documented shape.
	if strings.Contains(rec.Body.String(), `"members"`) {
		t.Errorf("body %s carries a list shape, want a single member object", rec.Body.String())
	}
	env := decodeUpdateMember(t, rec)
	if env.Data.Member.Email != "grace@acme.example" || env.Data.Member.UserDisplayName != "Grace Hopper" {
		t.Errorf("member = %+v, want the joined user email and display name", env.Data.Member)
	}
	if env.Data.Member.RoleVersion != 4 {
		t.Errorf("role_version on the wire = %d, want 4 — the bumped version must reach the wire shape",
			env.Data.Member.RoleVersion)
	}
}
