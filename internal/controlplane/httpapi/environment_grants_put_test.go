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
)

// Contract, authorization, and tenant-isolation coverage for PUT
// /v1/environments/{environment_id}/grants (BE-0169). The endpoint replaces
// the scoped grants attached to the environment through the
// EnvironmentGrantReplacer port; the tests drive it through NewHandler with
// a fake Authenticator, the real policy engine, and a fake replacer — the
// same wiring a request hits in production, minus the database. The
// store-backed replacer has its own isolated-Postgres integration coverage
// in store/environment_grant_service_test.go — this file exercises the
// HTTP surface in isolation.
//
// environment.grants.write is a CapAdmin action: viewer, developer, ci, and
// support principals in the tenant cannot replace grants — only owner and
// admin (or a principal holding a scope-covering admin grant) can. The
// happy-path tests therefore authenticate as RoleAdmin. The full
// authorization matrix lives in environment_grants_put_policy_test.go
// (BE-0171).
//
// Validation surface: the body decoder rejects oversized/malformed/
// unknown-field bodies as 400 (the global validate.DecodeJSON contract),
// the handler additionally surfaces a 400 for a body that does not name the
// "grants" field (so a misencoded request is never a silent clear).
// Field-level validation of principal_kind, role, scope tuple uniqueness,
// and service_id normalisation is the store-layer's job and is asserted
// through the replacer error path here, not by re-validating in the
// handler.

// fakeEnvironmentGrantReplacer is a canned EnvironmentGrantReplacer for
// httpapi tests. Tests inject one to drive the Replace path without a real
// database. got captures the last request the handler forwarded; callCount,
// when non-nil, lets a test assert the handler never reached the replacer
// (the wire layer must short-circuit on auth, validation, or wiring
// failures).
type fakeEnvironmentGrantReplacer struct {
	grants    []store.EnvironmentGrant
	err       error
	got       *store.ReplaceEnvironmentGrantsInput
	callCount *int
}

func (f fakeEnvironmentGrantReplacer) Replace(_ context.Context, in store.ReplaceEnvironmentGrantsInput) ([]store.EnvironmentGrant, error) {
	if f.callCount != nil {
		*f.callCount++
	}
	if f.got != nil {
		*f.got = in
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.grants, nil
}

// replaceEnvironmentGrantsSuccessEnvelope is the decoded shape of the PUT
// /v1/environments/{environment_id}/grants success envelope.
type replaceEnvironmentGrantsSuccessEnvelope struct {
	SchemaVersion string                          `json:"schema_version"`
	OK            bool                            `json:"ok"`
	RequestID     string                          `json:"request_id"`
	Data          replaceEnvironmentGrantsPayload `json:"data"`
}

// replaceEnvironmentGrantsHandlerFor builds an http.Handler that points at
// the PUT /v1/environments/{environment_id}/grants route, wired through the
// same NewHandler the production binary uses. id and authErr drive the fake
// authenticator; replacer is the EnvironmentGrantReplacer the handler
// delegates to.
func replaceEnvironmentGrantsHandlerFor(id auth.Identity, authErr error, replacer EnvironmentGrantReplacer) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, replacer, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
}

// putEnvironmentGrants issues PUT /v1/environments/{environmentID}/grants
// against handler with body, optionally with a bearer token.
func putEnvironmentGrants(handler http.Handler, environmentID, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPut,
		"/v1/environments/"+environmentID+"/grants",
		strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// decodeReplaceEnvironmentGrants decodes the JSON success body returned by
// PUT /v1/environments/{environment_id}/grants into the wire shape the
// contract pins down.
func decodeReplaceEnvironmentGrants(t *testing.T, rec *httptest.ResponseRecorder) replaceEnvironmentGrantsSuccessEnvelope {
	t.Helper()
	var env replaceEnvironmentGrantsSuccessEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode envelope: %v; body=%s", err, rec.Body)
	}
	return env
}

// environmentGrantsAdminIdentity returns an auth.Identity for an
// organization-wide admin principal homed at organizationID.
// environment.grants.write is a CapAdmin action and CapAdmin is admitted
// via the admin and owner roles only, so the happy-path tests authenticate
// the actor at RoleAdmin to keep the role matrix focused on the
// environment_grants_put_policy_test.go suite.
func environmentGrantsAdminIdentity(organizationID, principalID string) auth.Identity {
	return auth.Identity{
		Principal: policy.Principal{
			ID:             principalID,
			Kind:           "usr",
			OrganizationID: organizationID,
			Role:           policy.RoleAdmin,
		},
		Method: auth.MethodSession,
	}
}

// TestReplaceEnvironmentGrantsReturnsPersistedGrants is the happy path: a
// PUT carrying a fresh replacement set is forwarded to the replacer
// verbatim, the resulting committed rows are projected onto the stable
// wire shape, the envelope's request_id propagates, and every grant column
// reaches the wire.
func TestReplaceEnvironmentGrantsReturnsPersistedGrants(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	const envID = "env_acme_prod"

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 6, 7, 8, 0, time.UTC)
	svcID := "svc_web"
	post := []store.EnvironmentGrant{
		{
			ID: "egrnt_one", OrganizationID: orgID, EnvironmentID: envID,
			PrincipalID: "usr_one", PrincipalKind: "usr", Role: "developer",
			Version: 1, CreatedAt: created, UpdatedAt: updated,
		},
		{
			ID: "egrnt_two", OrganizationID: orgID, EnvironmentID: envID,
			PrincipalID: "sa_one", PrincipalKind: "sa", Role: "ci",
			ServiceID: &svcID,
			Version:   1,
			CreatedAt: created, UpdatedAt: updated,
		},
	}
	var got store.ReplaceEnvironmentGrantsInput
	replacer := fakeEnvironmentGrantReplacer{grants: post, got: &got}
	handler := replaceEnvironmentGrantsHandlerFor(
		environmentGrantsAdminIdentity(orgID, "usr_admin"), nil, replacer)

	body := `{"grants":[` +
		`{"principal_id":"usr_one","principal_kind":"usr","role":"developer"},` +
		`{"principal_id":"sa_one","principal_kind":"sa","role":"ci","service_id":"svc_web"}` +
		`]}`
	rec := putEnvironmentGrants(handler, envID, "a-valid-session-token", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	env := decodeReplaceEnvironmentGrants(t, rec)
	if env.SchemaVersion != "yalla.output.v1" {
		t.Errorf("schema_version = %q, want yalla.output.v1", env.SchemaVersion)
	}
	if env.RequestID == "" {
		t.Errorf("request_id is empty; envelope must propagate the request id")
	}
	if len(env.Data.Grants) != 2 {
		t.Fatalf("grants len = %d, want 2 (got %+v)", len(env.Data.Grants), env.Data.Grants)
	}

	got0 := env.Data.Grants[0]
	if got0.GrantID != "egrnt_one" || got0.Principal.ID != "usr_one" || got0.Principal.Kind != "usr" || got0.Role != "developer" {
		t.Errorf("grants[0] = %+v, want egrnt_one/usr_one/usr/developer", got0)
	}
	if got0.ServiceID != nil {
		t.Errorf("grants[0] svc = %v, want nil", got0.ServiceID)
	}
	got1 := env.Data.Grants[1]
	if got1.GrantID != "egrnt_two" || got1.Principal.Kind != "sa" || got1.Role != "ci" {
		t.Errorf("grants[1] = %+v, want egrnt_two/sa/ci", got1)
	}
	if got1.ServiceID == nil || *got1.ServiceID != "svc_web" {
		t.Errorf("grants[1].service_id = %v, want svc_web", got1.ServiceID)
	}

	// The replacer MUST receive (principal home org, path environment_id)
	// and every body field verbatim — never a caller-controlled organization
	// id (there isn't one on the wire, but pin the structural property).
	if got.OrganizationID != orgID {
		t.Errorf("replacer received org_id %q, want the principal's home org %q", got.OrganizationID, orgID)
	}
	if got.EnvironmentID != envID {
		t.Errorf("replacer received environment_id %q, want the path parameter %q", got.EnvironmentID, envID)
	}
	if len(got.Grants) != 2 {
		t.Fatalf("replacer received %d grants, want 2: %+v", len(got.Grants), got.Grants)
	}
	if got.Grants[0].PrincipalID != "usr_one" || got.Grants[0].PrincipalKind != "usr" || got.Grants[0].Role != "developer" {
		t.Errorf("grants[0] = %+v, want usr_one/usr/developer", got.Grants[0])
	}
	if got.Grants[0].ServiceID != nil {
		t.Errorf("grants[0] svc = %v, want nil", got.Grants[0].ServiceID)
	}
	if got.Grants[1].ServiceID == nil || *got.Grants[1].ServiceID != "svc_web" {
		t.Errorf("grants[1].service_id = %v, want svc_web", got.Grants[1].ServiceID)
	}
	if got.ActorID != "usr_admin" || got.ActorOrgID != orgID {
		t.Errorf("replacer received actor=(%q, %q), want (usr_admin, %q)",
			got.ActorID, got.ActorOrgID, orgID)
	}
}

// TestReplaceEnvironmentGrantsForwardsEmptyListAsExplicitClear proves the
// empty-array semantics reach the store layer: the handler must not reject
// "grants: []" as a no-op — an explicit clear is a meaningful (extreme)
// operation.
func TestReplaceEnvironmentGrantsForwardsEmptyListAsExplicitClear(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	const envID = "env_acme_prod"
	var got store.ReplaceEnvironmentGrantsInput
	replacer := fakeEnvironmentGrantReplacer{grants: []store.EnvironmentGrant{}, got: &got}
	handler := replaceEnvironmentGrantsHandlerFor(
		environmentGrantsAdminIdentity(orgID, "usr_admin"), nil, replacer)

	rec := putEnvironmentGrants(handler, envID, "a-valid-session-token", `{"grants":[]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got.OrganizationID != orgID {
		t.Errorf("replacer received org_id %q, want %q (an empty replace must reach the store layer)",
			got.OrganizationID, orgID)
	}
	if got.EnvironmentID != envID {
		t.Errorf("replacer received environment_id %q, want %q", got.EnvironmentID, envID)
	}
	if got.Grants == nil {
		t.Errorf("replacer received nil Grants, want a non-nil empty slice")
	}
	if len(got.Grants) != 0 {
		t.Errorf("replacer received %d items, want 0", len(got.Grants))
	}
	env := decodeReplaceEnvironmentGrants(t, rec)
	if env.Data.Grants == nil {
		t.Errorf("response grants is nil, want a non-nil empty slice")
	}
	if len(env.Data.Grants) != 0 {
		t.Errorf("response grants = %+v, want []", env.Data.Grants)
	}
	if !strings.Contains(rec.Body.String(), `"grants":[]`) {
		t.Errorf("body missing empty grants array: %s", rec.Body.String())
	}
}

// TestReplaceEnvironmentGrantsRejectsMissingGrantsField proves the
// missing-field guard: a body that omits the "grants" field altogether is
// rejected as a stable 400 (apierr.InvalidInput), never silently treated as
// a clear. An empty array reaches the store layer; a missing field does
// not.
func TestReplaceEnvironmentGrantsRejectsMissingGrantsField(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	const envID = "env_acme_prod"
	callCount := 0
	replacer := fakeEnvironmentGrantReplacer{callCount: &callCount}
	handler := replaceEnvironmentGrantsHandlerFor(
		environmentGrantsAdminIdentity(orgID, "usr_admin"), nil, replacer)

	rec := putEnvironmentGrants(handler, envID, "a-valid-session-token", `{}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	_ = decodeError(t, rec, "E_INVALID_INPUT")
	if callCount != 0 {
		t.Errorf("replacer call count = %d, want 0 (a missing grants field never reaches the store)", callCount)
	}
}

// TestReplaceEnvironmentGrantsRejectsMalformedJSON proves a malformed body
// becomes a stable 400 through the global validate.DecodeJSON contract.
func TestReplaceEnvironmentGrantsRejectsMalformedJSON(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	const envID = "env_acme_prod"
	callCount := 0
	replacer := fakeEnvironmentGrantReplacer{callCount: &callCount}
	handler := replaceEnvironmentGrantsHandlerFor(
		environmentGrantsAdminIdentity(orgID, "usr_admin"), nil, replacer)

	rec := putEnvironmentGrants(handler, envID, "a-valid-session-token", `{"grants":[`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	_ = decodeError(t, rec, "E_INVALID_INPUT")
	if callCount != 0 {
		t.Errorf("replacer call count = %d, want 0 (a malformed body never reaches the store)", callCount)
	}
}

// TestReplaceEnvironmentGrantsRejectsUnknownField proves the strict-decode
// contract: an unknown field becomes a stable 400, never silently accepted.
func TestReplaceEnvironmentGrantsRejectsUnknownField(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	const envID = "env_acme_prod"
	callCount := 0
	replacer := fakeEnvironmentGrantReplacer{callCount: &callCount}
	handler := replaceEnvironmentGrantsHandlerFor(
		environmentGrantsAdminIdentity(orgID, "usr_admin"), nil, replacer)

	rec := putEnvironmentGrants(handler, envID, "a-valid-session-token",
		`{"grants":[],"unexpected":"field"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("replacer call count = %d, want 0 (a body with an unknown field never reaches the store)", callCount)
	}
}

// TestReplaceEnvironmentGrantsRequiresAuthentication proves an
// unauthenticated request is the typed 401 the authenticator path emits,
// not a leaked panic, and the replacer never runs.
func TestReplaceEnvironmentGrantsRequiresAuthentication(t *testing.T) {
	t.Parallel()

	const envID = "env_acme_prod"
	callCount := 0
	replacer := fakeEnvironmentGrantReplacer{callCount: &callCount}
	handler := replaceEnvironmentGrantsHandlerFor(auth.Identity{}, auth.ErrNoCredentials, replacer)

	rec := putEnvironmentGrants(handler, envID, "", `{"grants":[]}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
	_ = decodeError(t, rec, "E_AUTH")
	if callCount != 0 {
		t.Errorf("replacer call count = %d, want 0 (RequireAuth must reject before the handler runs)", callCount)
	}
}

// TestReplaceEnvironmentGrantsDeniesViewerInTenant proves a viewer
// principal in the environment's tenant is rejected with 403 before the
// replacer runs. environment.grants.write is a CapAdmin action; viewer
// holds CapRead only.
func TestReplaceEnvironmentGrantsDeniesViewerInTenant(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	const envID = "env_acme_prod"
	callCount := 0
	replacer := fakeEnvironmentGrantReplacer{callCount: &callCount}

	id := auth.Identity{
		Principal: policy.Principal{
			ID: "usr_viewer", Kind: "usr",
			OrganizationID: orgID, Role: policy.RoleViewer,
		},
		Method: auth.MethodSession,
	}
	handler := replaceEnvironmentGrantsHandlerFor(id, nil, replacer)
	rec := putEnvironmentGrants(handler, envID, "a-valid-session-token",
		`{"grants":[]}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	_ = decodeError(t, rec, "E_FORBIDDEN")
	if callCount != 0 {
		t.Errorf("replacer call count = %d, want 0 (a viewer must be denied at the policy boundary)", callCount)
	}
}

// TestReplaceEnvironmentGrantsPropagatesNotFoundEnvironment proves the
// store layer's typed NotFound becomes a 404 on the wire — never disguised
// as a 5xx, and never echoing a cross-tenant id back to the caller.
func TestReplaceEnvironmentGrantsPropagatesNotFoundEnvironment(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	replacer := fakeEnvironmentGrantReplacer{err: apierr.NotFound("environment", "env_unknown")}
	handler := replaceEnvironmentGrantsHandlerFor(
		environmentGrantsAdminIdentity(orgID, "usr_admin"), nil, replacer)

	rec := putEnvironmentGrants(handler, "env_unknown", "a-valid-session-token",
		`{"grants":[]}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
	_ = decodeError(t, rec, "E_NOT_FOUND")
}

// TestReplaceEnvironmentGrantsPropagatesInvalidInputFromStore proves a
// store-layer validation failure (an unknown role, a duplicate scope tuple,
// etc.) becomes a stable 400 carrying the store's field-path shape — the
// handler never re-validates.
func TestReplaceEnvironmentGrantsPropagatesInvalidInputFromStore(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	const envID = "env_acme_prod"
	storeErr := apierr.InvalidInput(apierr.FieldViolation{
		Field:  "grants[0].role",
		Reason: "must be one of owner, admin, developer, viewer, ci, support",
	})
	replacer := fakeEnvironmentGrantReplacer{err: storeErr}
	handler := replaceEnvironmentGrantsHandlerFor(
		environmentGrantsAdminIdentity(orgID, "usr_admin"), nil, replacer)

	rec := putEnvironmentGrants(handler, envID, "a-valid-session-token",
		`{"grants":[{"principal_id":"usr_x","principal_kind":"usr","role":"ghost"}]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	_ = decodeError(t, rec, "E_INVALID_INPUT")
}

// TestReplaceEnvironmentGrantsForwardsStoreUnavailableAsTypedFiveHundred
// proves a database outage becomes a stable 5xx envelope, not a leaked
// driver error.
func TestReplaceEnvironmentGrantsForwardsStoreUnavailableAsTypedFiveHundred(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	const envID = "env_acme_prod"
	replacer := fakeEnvironmentGrantReplacer{err: apierr.StoreUnavailable(stderrors.New("connection reset"))}
	handler := replaceEnvironmentGrantsHandlerFor(
		environmentGrantsAdminIdentity(orgID, "usr_admin"), nil, replacer)

	rec := putEnvironmentGrants(handler, envID, "a-valid-session-token",
		`{"grants":[]}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "connection reset") {
		t.Errorf("body leaks upstream cause: %s", rec.Body.String())
	}
}

// TestReplaceEnvironmentGrantsReturnsInternalWhenReplacerUnwired proves an
// unwired replacer (a programming wiring error, not a client error) is
// reported as a typed internal failure rather than silently failing to
// persist the change.
func TestReplaceEnvironmentGrantsReturnsInternalWhenReplacerUnwired(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	const envID = "env_acme_prod"
	handler := replaceEnvironmentGrantsHandlerFor(
		environmentGrantsAdminIdentity(orgID, "usr_admin"), nil, nil)

	rec := putEnvironmentGrants(handler, envID, "a-valid-session-token",
		`{"grants":[]}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
}

// TestReplaceEnvironmentGrantsRouteIsRegistered proves the OpenAPI document
// carries the PUT /v1/environments/{environment_id}/grants operation with
// the stable operationId, the environment.grants.write required action,
// and the environments tag — every detail an agent reads to discover the
// endpoint.
func TestReplaceEnvironmentGrantsRouteIsRegistered(t *testing.T) {
	t.Parallel()

	handler := replaceEnvironmentGrantsHandlerFor(
		environmentGrantsAdminIdentity("org_acme", "usr_admin"), nil, fakeEnvironmentGrantReplacer{})

	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("openapi.json status = %d, want 200", rec.Code)
	}

	var doc struct {
		Paths map[string]map[string]struct {
			OperationID    string   `json:"operationId"`
			Tags           []string `json:"tags"`
			RequiredAction string   `json:"x-required-action"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode openapi: %v", err)
	}
	op, ok := doc.Paths["/v1/environments/{environment_id}/grants"]["put"]
	if !ok {
		t.Fatalf("PUT /v1/environments/{environment_id}/grants missing from OpenAPI document")
	}
	if op.OperationID != "replaceEnvironmentGrants" {
		t.Errorf("operationId = %q, want replaceEnvironmentGrants", op.OperationID)
	}
	if op.RequiredAction != string(policy.ActionEnvironmentGrantsWrite) {
		t.Errorf("x-required-action = %q, want %q", op.RequiredAction, policy.ActionEnvironmentGrantsWrite)
	}
	foundTag := false
	for _, tag := range op.Tags {
		if tag == tagEnvironments {
			foundTag = true
			break
		}
	}
	if !foundTag {
		t.Errorf("tags = %v, want it to include %q", op.Tags, tagEnvironments)
	}
}
