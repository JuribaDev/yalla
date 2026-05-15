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
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
)

// Contract, authorization, and wiring coverage for POST /v1/organizations
// (BE-0049). The endpoint creates an organization through the OrganizationCreator
// port; the tests drive it through NewHandler with a fake Authenticator, the
// real policy engine, and a fake creator — the same wiring a request hits in
// production, minus the database. The store-backed orchestrator
// (store.OrganizationService) has its own isolated-Postgres integration
// coverage in store/organizationservice_test.go and white-box validation
// coverage in store/organizationservice_internal_test.go.

// fakeOrganizationCreator is a canned OrganizationCreator for httpapi tests.
// The zero value returns a zero organization and no error, which is all the
// test helpers that never reach the handler need; the POST tests set org/err
// and read got back to prove the handler forwards the validated request and
// the authenticated actor to the store layer unchanged.
type fakeOrganizationCreator struct {
	org store.Organization
	err error
	got *store.CreateOrganizationInput
}

func (f fakeOrganizationCreator) Create(_ context.Context, in store.CreateOrganizationInput) (store.Organization, error) {
	if f.got != nil {
		*f.got = in
	}
	return f.org, f.err
}

// createOrganizationSuccessEnvelope is the decoded shape of the POST
// /v1/organizations success envelope.
type createOrganizationSuccessEnvelope struct {
	SchemaVersion string                    `json:"schema_version"`
	OK            bool                      `json:"ok"`
	RequestID     string                    `json:"request_id"`
	Data          createOrganizationPayload `json:"data"`
}

// createOrganizationHandlerFor builds the full NewHandler surface with an
// Authenticator that resolves every credential to id and the given
// OrganizationCreator. It is the production request path: the POST
// /v1/organizations route is wrapped in RequireAuth for action
// organization.create.
func createOrganizationHandlerFor(id auth.Identity, authErr error, creator OrganizationCreator) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(), fakeOrganizationReader{}, creator, fakeOrganizationUpdater{}, fakeOrganizationDeleter{}, fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{}, fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{}, fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{}, fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, nil)
}

// postOrganizations issues POST /v1/organizations against handler with body,
// optionally with a bearer token.
func postOrganizations(handler http.Handler, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/organizations", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeCreateOrganization(t *testing.T, rec *httptest.ResponseRecorder) createOrganizationSuccessEnvelope {
	t.Helper()
	var env createOrganizationSuccessEnvelope
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

// TestCreateOrganizationSuccess is the happy path: a valid request is created,
// the handler returns 201 with the stable yalla.output.v1 envelope, and the
// created organization is projected onto the wire shape.
func TestCreateOrganizationSuccess(t *testing.T) {
	t.Parallel()

	creator := fakeOrganizationCreator{org: store.Organization{
		ID:          "org_new",
		Slug:        "acme",
		DisplayName: "Acme, Inc.",
	}}
	handler := createOrganizationHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	rec := postOrganizations(handler, "a-valid-session-token", `{"slug":"acme","display_name":"Acme, Inc."}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q, want application/json", got)
	}

	env := decodeCreateOrganization(t, rec)
	got := env.Data.Organization
	if got.OrganizationID != "org_new" || got.Slug != "acme" || got.DisplayName != "Acme, Inc." {
		t.Errorf("organization = %+v, want id/slug/name from the created row", got)
	}
}

// TestCreateOrganizationForwardsActorAndRequest proves the handler delegates:
// it forwards the decoded request body and the authenticated principal — never
// caller-controlled actor fields — to the store layer unchanged.
func TestCreateOrganizationForwardsActorAndRequest(t *testing.T) {
	t.Parallel()

	var captured store.CreateOrganizationInput
	creator := fakeOrganizationCreator{
		org: store.Organization{ID: "org_new", Slug: "acme", DisplayName: "Acme"},
		got: &captured,
	}
	handler := createOrganizationHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	rec := postOrganizations(handler, "a-valid-session-token", `{"slug":"acme","display_name":"Acme"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	if captured.Slug != "acme" || captured.DisplayName != "Acme" {
		t.Errorf("forwarded slug/display_name = %q/%q, want acme/Acme", captured.Slug, captured.DisplayName)
	}
	if captured.ActorID != "usr_ada" || captured.ActorOrgID != "org_acme" {
		t.Errorf("forwarded actor = %q/%q, want the authenticated principal usr_ada/org_acme",
			captured.ActorID, captured.ActorOrgID)
	}
	if captured.ActorKind == "" {
		t.Errorf("forwarded actor kind is empty, want the authenticated principal's kind")
	}
}

// TestCreateOrganizationMalformedBodyIsValidationError proves a syntactically
// broken body is a stable 400 E_INVALID_INPUT and never reaches the store layer.
func TestCreateOrganizationMalformedBodyIsValidationError(t *testing.T) {
	t.Parallel()

	creator := fakeOrganizationCreator{err: stderrors.New("creator must not be called")}
	handler := createOrganizationHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	rec := postOrganizations(handler, "a-valid-session-token", `{"slug":`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INVALID_INPUT")
}

// TestCreateOrganizationUnknownFieldIsValidationError proves the body is
// strictly decoded: an unknown field is a stable 400 E_INVALID_INPUT, so a
// client typo or a stale schema cannot be silently dropped.
func TestCreateOrganizationUnknownFieldIsValidationError(t *testing.T) {
	t.Parallel()

	creator := fakeOrganizationCreator{err: stderrors.New("creator must not be called")}
	handler := createOrganizationHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	rec := postOrganizations(handler, "a-valid-session-token", `{"slug":"acme","display_name":"Acme","owner":"usr_x"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INVALID_INPUT")
}

// TestCreateOrganizationInvalidInput proves a request the store layer rejects
// — an invalid slug or blank display name — surfaces as the typed 400
// E_VALIDATION the validator produces.
func TestCreateOrganizationInvalidInput(t *testing.T) {
	t.Parallel()

	creator := fakeOrganizationCreator{err: apierr.InvalidInput(apierr.FieldViolation{
		Field:  "slug",
		Reason: "must be a canonical slug",
	})}
	handler := createOrganizationHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	rec := postOrganizations(handler, "a-valid-session-token", `{"slug":"Not A Slug","display_name":"Acme"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INVALID_INPUT")
}

// TestCreateOrganizationUnauthenticated proves a request with no credential is
// a stable 401 E_AUTH and never reaches the handler — the creator is never
// called.
func TestCreateOrganizationUnauthenticated(t *testing.T) {
	t.Parallel()

	handler := createOrganizationHandlerFor(auth.Identity{}, nil,
		fakeOrganizationCreator{err: stderrors.New("creator must not be called")})
	rec := postOrganizations(handler, "", `{"slug":"acme","display_name":"Acme"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_AUTH")
	if env.Error.Message != "authentication is required" {
		t.Errorf("message = %q, want %q", env.Error.Message, "authentication is required")
	}
}

// TestCreateOrganizationInvalidCredentials proves an unverifiable credential is
// a stable 401 E_AUTH — identical to the missing-credential contract.
func TestCreateOrganizationInvalidCredentials(t *testing.T) {
	t.Parallel()

	handler := createOrganizationHandlerFor(auth.Identity{}, auth.ErrInvalidCredentials,
		fakeOrganizationCreator{err: stderrors.New("creator must not be called")})
	rec := postOrganizations(handler, "yk_bogus", `{"slug":"acme","display_name":"Acme"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_AUTH")
}

// TestCreateOrganizationDisabledPrincipalIsForbidden is the authorization-failure
// path: a principal whose access has been revoked authenticates but is denied
// action organization.create, so the endpoint is 403 E_FORBIDDEN and the
// creator is never reached.
func TestCreateOrganizationDisabledPrincipalIsForbidden(t *testing.T) {
	t.Parallel()

	principal := orgPrincipal("usr_revoked", "org_acme", policy.RoleOwner)
	principal.Disabled = true
	handler := createOrganizationHandlerFor(
		auth.Identity{Principal: principal, Method: auth.MethodSession},
		nil, fakeOrganizationCreator{err: stderrors.New("creator must not be called")})

	rec := postOrganizations(handler, "a-revoked-session-token", `{"slug":"acme","display_name":"Acme"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
	}
}

// TestCreateOrganizationConflict proves a slug that collides with an existing
// organization surfaces as the typed 409 E_CONFLICT the store layer produces,
// never disguised as a 500 or a success.
func TestCreateOrganizationConflict(t *testing.T) {
	t.Parallel()

	creator := fakeOrganizationCreator{err: apierr.Conflict("an organization with this slug already exists")}
	handler := createOrganizationHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	rec := postOrganizations(handler, "a-valid-session-token", `{"slug":"acme","display_name":"Acme"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_CONFLICT")
}

// TestCreateOrganizationDependencyFailureIsTyped5xx proves a datastore outage
// surfaces as its own typed 5xx, never disguised as a 400, a 409, or a
// success.
func TestCreateOrganizationDependencyFailureIsTyped5xx(t *testing.T) {
	t.Parallel()

	creator := fakeOrganizationCreator{err: apierr.StoreUnavailable(stderrors.New("connection refused"))}
	handler := createOrganizationHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	rec := postOrganizations(handler, "a-valid-session-token", `{"slug":"acme","display_name":"Acme"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_UNAVAILABLE")
}

// TestCreateOrganizationPropagatesRequestID proves the resolved request_id
// reaches both the response envelope and the echoed response header.
func TestCreateOrganizationPropagatesRequestID(t *testing.T) {
	t.Parallel()

	creator := fakeOrganizationCreator{org: store.Organization{ID: "org_new", Slug: "acme", DisplayName: "Acme"}}
	handler := createOrganizationHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	req := httptest.NewRequest(http.MethodPost, "/v1/organizations", strings.NewReader(`{"slug":"acme","display_name":"Acme"}`))
	req.Header.Set("Authorization", "Bearer a-valid-session-token")
	req.Header.Set(telemetry.HeaderRequestID, "caller-supplied-id")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	env := decodeCreateOrganization(t, rec)
	if env.RequestID != "caller-supplied-id" {
		t.Errorf("envelope request_id = %q, want caller-supplied-id", env.RequestID)
	}
	if got := rec.Header().Get(telemetry.HeaderRequestID); got != "caller-supplied-id" {
		t.Errorf("response header request_id = %q, want caller-supplied-id", got)
	}
}

// TestCreateOrganizationIsDocumentedInOpenAPI proves the served route is also a
// documented route: POST /v1/organizations appears in the OpenAPI document
// requiring the API-key security scheme and naming its policy action through
// the x-required-action extension.
func TestCreateOrganizationIsDocumentedInOpenAPI(t *testing.T) {
	t.Parallel()

	handler := createOrganizationHandlerFor(auth.Identity{}, nil, fakeOrganizationCreator{})
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
			Responses      map[string]any        `json:"responses"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode openapi document: %v", err)
	}
	op, ok := doc.Paths["/v1/organizations"]["post"]
	if !ok {
		t.Fatalf("openapi document does not describe POST /v1/organizations")
	}
	if op.OperationID != "createOrganization" {
		t.Errorf("operationId = %q, want createOrganization", op.OperationID)
	}
	if op.RequiredAction != string(policy.ActionOrganizationCreate) {
		t.Errorf("x-required-action = %q, want %q", op.RequiredAction, policy.ActionOrganizationCreate)
	}
	if len(op.Security) != 1 {
		t.Fatalf("security = %+v, want exactly one requirement", op.Security)
	}
	if _, ok := op.Security[0]["ApiKeyAuth"]; !ok {
		t.Errorf("security = %+v, want it to require the ApiKeyAuth scheme", op.Security)
	}
	if _, ok := op.Responses["201"]; !ok {
		t.Errorf("responses = %+v, want a documented 201 success response", op.Responses)
	}
}

// TestCreateOrganizationHandlerWithoutPrincipalIsInternal proves the defensive
// path: if the handler is ever reached without RequireAuth having placed a
// principal on the context, it reports a typed internal error rather than
// creating an organization for a zero principal.
func TestCreateOrganizationHandlerWithoutPrincipalIsInternal(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPost, "/v1/organizations", strings.NewReader(`{"slug":"acme","display_name":"Acme"}`))
	rec := run(createOrganizationHandler(fakeOrganizationCreator{}), req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INTERNAL")
}

// TestCreateOrganizationHandlerWithNilCreatorIsInternal proves a route
// registered without an organization creator is a wiring error reported as a
// typed internal failure — never a silently dropped write.
func TestCreateOrganizationHandlerWithNilCreatorIsInternal(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPost, "/v1/organizations", strings.NewReader(`{"slug":"acme","display_name":"Acme"}`))
	req = req.WithContext(policy.WithPrincipal(req.Context(),
		orgPrincipal("usr_ada", "org_acme", policy.RoleOwner)))
	rec := run(createOrganizationHandler(nil), req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INTERNAL")
}
