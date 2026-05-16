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

// Contract, authorization, and tenant-isolation coverage for DELETE
// /v1/organizations/{org_id} (BE-0058). The endpoint schedules the organization
// named by the {org_id} path parameter for deletion through the
// OrganizationDeleter port; the tests drive it through NewHandler with a fake
// Authenticator, the real policy engine, and a fake deleter — the same wiring a
// request hits in production, minus the database. The store-backed orchestrator
// (store.OrganizationService) has its own isolated-Postgres integration
// coverage in store/organizationservice_delete_test.go.

// fakeOrganizationDeleter is a canned OrganizationDeleter for httpapi tests. The
// zero value returns a zero organization and no error, which is all the test
// helpers that never reach the handler need; the DELETE tests set org/err and
// read got back to prove the handler forwards the {org_id} path parameter and
// the authenticated actor to the store layer unchanged.
type fakeOrganizationDeleter struct {
	org store.Organization
	err error
	got *store.DeleteOrganizationInput
}

func (f fakeOrganizationDeleter) ScheduleDeletion(_ context.Context, in store.DeleteOrganizationInput) (store.Organization, error) {
	if f.got != nil {
		*f.got = in
	}
	return f.org, f.err
}

// deleteOrganizationSuccessEnvelope is the decoded shape of the DELETE
// /v1/organizations/{org_id} success envelope.
type deleteOrganizationSuccessEnvelope struct {
	SchemaVersion string                    `json:"schema_version"`
	OK            bool                      `json:"ok"`
	RequestID     string                    `json:"request_id"`
	Data          deleteOrganizationPayload `json:"data"`
}

// deleteOrganizationHandlerFor builds the full NewHandler surface with an
// Authenticator that resolves every credential to id and the given
// OrganizationDeleter. It is the production request path: the DELETE
// /v1/organizations/{org_id} route is wrapped in RequireAuth for action
// organization.delete.
func deleteOrganizationHandlerFor(id auth.Identity, authErr error, deleter OrganizationDeleter) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, deleter, fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{}, fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{}, fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{}, fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeBreakGlassController{}, nil, nil)
}

// deleteOrganization issues DELETE /v1/organizations/{orgID} against handler,
// optionally with a bearer token.
func deleteOrganization(handler http.Handler, orgID, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodDelete, "/v1/organizations/"+orgID, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeDeleteOrganization(t *testing.T, rec *httptest.ResponseRecorder) deleteOrganizationSuccessEnvelope {
	t.Helper()
	var env deleteOrganizationSuccessEnvelope
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

// TestDeleteOrganizationSuccess is the happy path: an owner schedules its own
// organization for deletion, the handler returns 202 Accepted with the stable
// yalla.output.v1 envelope, and the scheduled organization — including its
// deletion_scheduled_at stamp — is projected onto the wire shape.
func TestDeleteOrganizationSuccess(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 15, 6, 7, 8, 0, time.UTC)
	scheduled := time.Date(2026, 5, 15, 6, 7, 8, 0, time.UTC)
	deleter := fakeOrganizationDeleter{org: store.Organization{
		ID:                  "org_acme",
		Slug:                "acme",
		DisplayName:         "Acme Worldwide",
		CreatedAt:           created,
		UpdatedAt:           updated,
		DeletionScheduledAt: &scheduled,
	}}
	handler := deleteOrganizationHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, deleter)

	rec := deleteOrganization(handler, "org_acme", "a-valid-session-token")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q, want application/json", got)
	}

	env := decodeDeleteOrganization(t, rec)
	got := env.Data.Organization
	if got.OrganizationID != "org_acme" || got.Slug != "acme" || got.DisplayName != "Acme Worldwide" {
		t.Errorf("organization = %+v, want the scheduled org_acme row", got)
	}
	if got.DeletionScheduledAt == nil {
		t.Fatalf("deletion_scheduled_at is absent, want it stamped for a scheduled organization")
	}
	if want := scheduled.Format(time.RFC3339Nano); *got.DeletionScheduledAt != want {
		t.Errorf("deletion_scheduled_at = %q, want %q", *got.DeletionScheduledAt, want)
	}
}

// TestDeleteOrganizationForwardsActor proves the handler delegates: it forwards
// the {org_id} path parameter and the authenticated principal — never
// caller-controlled actor fields — to the store layer unchanged.
func TestDeleteOrganizationForwardsActor(t *testing.T) {
	t.Parallel()

	var captured store.DeleteOrganizationInput
	deleter := fakeOrganizationDeleter{
		org: store.Organization{ID: "org_acme", Slug: "acme", DisplayName: "Acme"},
		got: &captured,
	}
	handler := deleteOrganizationHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, deleter)

	rec := deleteOrganization(handler, "org_acme", "a-valid-session-token")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body %s", rec.Code, rec.Body.String())
	}
	if captured.OrganizationID != "org_acme" {
		t.Errorf("forwarded organization id = %q, want org_acme", captured.OrganizationID)
	}
	if captured.ActorID != "usr_ada" || captured.ActorOrgID != "org_acme" {
		t.Errorf("forwarded actor = %q/%q, want the authenticated principal usr_ada/org_acme",
			captured.ActorID, captured.ActorOrgID)
	}
}

// TestDeleteOrganizationCrossTenantIsForbidden proves a principal deleting an
// organization outside its own tenant is denied with a deterministic 403
// E_FORBIDDEN carrying the stable cross-tenant reason — and the deleter is never
// reached, so a cross-tenant id can never affect another tenant's data or even
// reveal whether that organization exists.
func TestDeleteOrganizationCrossTenantIsForbidden(t *testing.T) {
	t.Parallel()

	var captured store.DeleteOrganizationInput
	deleter := fakeOrganizationDeleter{
		org: store.Organization{ID: "org_victim", Slug: "victim", DisplayName: "Victim"},
		got: &captured,
	}
	handler := deleteOrganizationHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_mallory", "org_attacker", policy.RoleOwner), Method: auth.MethodSession},
		nil, deleter)

	rec := deleteOrganization(handler, "org_victim", "a-valid-session-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedCrossTenant)
	}
	if captured.OrganizationID != "" {
		t.Errorf("deleter was reached with id %q for a cross-tenant request; it must never run", captured.OrganizationID)
	}
	if strings.Contains(env.Error.Message, "org_victim") {
		t.Errorf("error message %q echoes the cross-tenant organization id", env.Error.Message)
	}
}

// TestDeleteOrganizationInsufficientRoleIsForbidden is the in-tenant
// authorization-failure path: action organization.delete requires the owner
// capability, so a principal whose role lacks it — here an admin — authenticates
// and targets its own organization but is denied with a stable 403 E_FORBIDDEN,
// and the deleter is never reached.
func TestDeleteOrganizationInsufficientRoleIsForbidden(t *testing.T) {
	t.Parallel()

	deleter := fakeOrganizationDeleter{err: stderrors.New("deleter must not be called")}
	handler := deleteOrganizationHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_admin", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, deleter)

	rec := deleteOrganization(handler, "org_acme", "a-valid-session-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_FORBIDDEN")
}

// TestDeleteOrganizationNotFound proves an {org_id} the principal is authorized
// to delete but that has no row in the source-of-truth database is the typed
// 404 the store layer produces, never disguised as a success.
func TestDeleteOrganizationNotFound(t *testing.T) {
	t.Parallel()

	deleter := fakeOrganizationDeleter{err: apierr.NotFound("organization", "org_acme")}
	handler := deleteOrganizationHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, deleter)

	rec := deleteOrganization(handler, "org_acme", "a-valid-session-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_NOT_FOUND")
}

// TestDeleteOrganizationAlreadyScheduledIsConflict proves scheduling deletion
// for an organization already scheduled for deletion surfaces as the typed 409
// E_CONFLICT the store layer produces, never disguised as a 500 or a success.
func TestDeleteOrganizationAlreadyScheduledIsConflict(t *testing.T) {
	t.Parallel()

	deleter := fakeOrganizationDeleter{err: apierr.Conflict("organization deletion is already scheduled")}
	handler := deleteOrganizationHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, deleter)

	rec := deleteOrganization(handler, "org_acme", "a-valid-session-token")
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_CONFLICT")
}

// TestDeleteOrganizationUnauthenticated proves a request with no credential is a
// stable 401 E_AUTH and never reaches the handler — the deleter is never
// called.
func TestDeleteOrganizationUnauthenticated(t *testing.T) {
	t.Parallel()

	handler := deleteOrganizationHandlerFor(auth.Identity{}, nil,
		fakeOrganizationDeleter{err: stderrors.New("deleter must not be called")})
	rec := deleteOrganization(handler, "org_acme", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_AUTH")
	if env.Error.Message != "authentication is required" {
		t.Errorf("message = %q, want %q", env.Error.Message, "authentication is required")
	}
}

// TestDeleteOrganizationInvalidCredentials proves an unverifiable credential is
// a stable 401 E_AUTH — identical to the missing-credential contract.
func TestDeleteOrganizationInvalidCredentials(t *testing.T) {
	t.Parallel()

	handler := deleteOrganizationHandlerFor(auth.Identity{}, auth.ErrInvalidCredentials,
		fakeOrganizationDeleter{err: stderrors.New("deleter must not be called")})
	rec := deleteOrganization(handler, "org_acme", "a-bogus-token")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_AUTH")
}

// TestDeleteOrganizationDisabledPrincipalIsForbidden proves a revoked or expired
// credential surfaces as a disabled principal and is denied with a 403
// E_FORBIDDEN carrying the stable reason — and the deleter is never reached.
func TestDeleteOrganizationDisabledPrincipalIsForbidden(t *testing.T) {
	t.Parallel()

	disabled := orgPrincipal("usr_ada", "org_acme", policy.RoleOwner)
	disabled.Disabled = true
	handler := deleteOrganizationHandlerFor(
		auth.Identity{Principal: disabled, Method: auth.MethodSession},
		nil, fakeOrganizationDeleter{err: stderrors.New("deleter must not be called")})

	rec := deleteOrganization(handler, "org_acme", "a-revoked-session-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
	}
}

// TestDeleteOrganizationDependencyFailureIsTyped5xx proves a datastore outage
// surfaces as its own typed 5xx, never disguised as a 404, a 409, or a success,
// and the wrapped driver cause never reaches the wire.
func TestDeleteOrganizationDependencyFailureIsTyped5xx(t *testing.T) {
	t.Parallel()

	deleter := fakeOrganizationDeleter{err: apierr.StoreUnavailable(stderrors.New("connection refused"))}
	handler := deleteOrganizationHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, deleter)

	rec := deleteOrganization(handler, "org_acme", "a-valid-session-token")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_UNAVAILABLE")
	if strings.Contains(env.Error.Message, "connection refused") {
		t.Errorf("error message %q leaks the wrapped datastore cause", env.Error.Message)
	}
}

// TestDeleteOrganizationPropagatesRequestID proves the resolved request_id
// reaches both the response envelope and the echoed response header.
func TestDeleteOrganizationPropagatesRequestID(t *testing.T) {
	t.Parallel()

	deleter := fakeOrganizationDeleter{org: store.Organization{ID: "org_acme", Slug: "acme", DisplayName: "Acme"}}
	handler := deleteOrganizationHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, deleter)

	req := httptest.NewRequest(http.MethodDelete, "/v1/organizations/org_acme", nil)
	req.Header.Set("Authorization", "Bearer a-valid-session-token")
	req.Header.Set(telemetry.HeaderRequestID, "caller-supplied-id")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body %s", rec.Code, rec.Body.String())
	}
	env := decodeDeleteOrganization(t, rec)
	if env.RequestID != "caller-supplied-id" {
		t.Errorf("envelope request_id = %q, want caller-supplied-id", env.RequestID)
	}
	if got := rec.Header().Get(telemetry.HeaderRequestID); got != "caller-supplied-id" {
		t.Errorf("response header request_id = %q, want caller-supplied-id", got)
	}
}

// TestDeleteOrganizationHandlerWithoutPrincipalIsInternal proves the defensive
// path: if the handler is ever reached without RequireAuth having placed a
// principal on the context, it reports a typed internal error rather than
// scheduling a deletion for a zero principal.
func TestDeleteOrganizationHandlerWithoutPrincipalIsInternal(t *testing.T) {
	t.Parallel()

	rec := run(deleteOrganizationHandler(fakeOrganizationDeleter{}),
		httptest.NewRequest(http.MethodDelete, "/v1/organizations/org_acme", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INTERNAL")
}

// TestDeleteOrganizationHandlerWithNilDeleterIsInternal proves a route
// registered without an organization deleter is a wiring error reported as a
// typed internal failure — never a misleading response or a silently dropped
// write.
func TestDeleteOrganizationHandlerWithNilDeleterIsInternal(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodDelete, "/v1/organizations/org_acme", nil)
	req = req.WithContext(policy.WithPrincipal(req.Context(),
		orgPrincipal("usr_ada", "org_acme", policy.RoleOwner)))
	rec := run(deleteOrganizationHandler(nil), req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INTERNAL")
}

// TestDeleteOrganizationIsDocumentedInOpenAPI proves the served route is also a
// documented route: DELETE /v1/organizations/{org_id} appears in the OpenAPI
// document requiring the API-key security scheme, naming its policy action
// through the x-required-action extension, and declaring the {org_id} path
// parameter.
func TestDeleteOrganizationIsDocumentedInOpenAPI(t *testing.T) {
	t.Parallel()

	handler := deleteOrganizationHandlerFor(auth.Identity{}, nil, fakeOrganizationDeleter{})
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
	op, ok := doc.Paths["/v1/organizations/{org_id}"]["delete"]
	if !ok {
		t.Fatalf("openapi document does not describe DELETE /v1/organizations/{org_id}")
	}
	if op.OperationID != "deleteOrganization" {
		t.Errorf("operationId = %q, want deleteOrganization", op.OperationID)
	}
	if op.RequiredAction != string(policy.ActionOrganizationDelete) {
		t.Errorf("x-required-action = %q, want %q", op.RequiredAction, policy.ActionOrganizationDelete)
	}
	if len(op.Security) != 1 || len(op.Security[0]) != 1 {
		t.Errorf("security = %+v, want it to require the ApiKeyAuth scheme", op.Security)
	}
	if _, ok := op.Security[0]["ApiKeyAuth"]; !ok {
		t.Errorf("security = %+v, want it to require the ApiKeyAuth scheme", op.Security)
	}
	if len(op.Parameters) != 1 {
		t.Fatalf("parameters = %+v, want exactly one path parameter", op.Parameters)
	}
	if p := op.Parameters[0]; p.Name != "org_id" || p.In != "path" || !p.Required {
		t.Errorf("path parameter = %+v, want {Name:org_id In:path Required:true}", p)
	}
}
