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
	"github.com/JuribaDev/yalla/internal/output"
)

// Contract and tenant-isolation coverage for DELETE
// /v1/organizations/{org_id}/variables/{key} (BE-0115). The endpoint
// removes a single organization-scoped variable through the
// OrganizationVariableDeleter port; the tests drive it through
// NewHandler with a fake Authenticator, the real policy engine, and a
// fake deleter — the same wiring a request hits in production, minus
// the database. The store-backed deleter has its own isolated-Postgres
// integration coverage in store/organization_variable_delete_test.go;
// this file exercises the HTTP surface in isolation.
//
// env.write is a CapWrite action: a viewer or support principal in the
// tenant cannot delete a variable, only an owner, admin, developer, or
// CI principal can — and unlike CapRead actions there is no
// cross-tenant support exception. The happy-path tests therefore
// authenticate as RoleOwner. The authorization matrix is the
// responsibility of BE-0117 (variables_delete_policy_test.go).

// deleteOrgVariableSuccessEnvelope is the decoded shape of the DELETE
// /v1/organizations/{org_id}/variables/{key} success envelope.
type deleteOrgVariableSuccessEnvelope struct {
	SchemaVersion string                            `json:"schema_version"`
	OK            bool                              `json:"ok"`
	RequestID     string                            `json:"request_id"`
	Data          deleteOrganizationVariablePayload `json:"data"`
}

// deleteOrgVariableHandlerFor builds an http.Handler that points at
// the DELETE /v1/organizations/{org_id}/variables/{key} route, wired
// through the same NewHandler the production binary uses. id and
// authErr drive the fake authenticator; deleter is the
// OrganizationVariableDeleter the handler delegates to.
func deleteOrgVariableHandlerFor(id auth.Identity, authErr error, deleter OrganizationVariableDeleter) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, deleter,
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
}

// deleteOrgVariable issues DELETE /v1/organizations/{orgID}/variables/
// {key} against handler, optionally with a bearer token.
func deleteOrgVariable(handler http.Handler, orgID, key, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodDelete,
		"/v1/organizations/"+orgID+"/variables/"+key, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeDeleteOrgVariable(t *testing.T, rec *httptest.ResponseRecorder) deleteOrgVariableSuccessEnvelope {
	t.Helper()
	var env deleteOrgVariableSuccessEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode envelope: %v; body=%s", err, rec.Body)
	}
	return env
}

// TestDeleteOrgVariableReturnsDeletedSnapshot is the happy path: a
// DELETE forwards the path parameters and principal/correlation
// identifiers to the deleter, the returned snapshot projects onto the
// stable wire shape, the secret value is redacted on the wire even
// though the customer had previously stored it, and the envelope's
// request_id propagates.
func TestDeleteOrgVariableReturnsDeletedSnapshot(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	const key = "DATABASE_URL"
	deletedSnapshot := store.OrganizationVariable{
		ID: "ovar_db", OrganizationID: orgID, Key: key,
		Value: "postgres://user:hunter2@db/app", IsSecret: true, Version: 3,
	}
	var got store.DeleteOrganizationVariableInput
	deleter := fakeOrgVariableDeleter{v: deletedSnapshot, got: &got}
	handler := deleteOrgVariableHandlerFor(
		orgVariableActorIdentity(orgID, "usr_ada"), nil, deleter)

	rec := deleteOrgVariable(handler, orgID, key, "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	env := decodeDeleteOrgVariable(t, rec)
	if env.SchemaVersion != "yalla.output.v1" {
		t.Errorf("schema_version = %q, want yalla.output.v1", env.SchemaVersion)
	}
	if env.RequestID == "" {
		t.Errorf("request_id is empty; envelope must propagate the request id")
	}

	// Wire-level redaction chokepoint: the secret value must never
	// reach the response body, even on a DELETE — the customer cannot
	// read a secret back through this endpoint, including the value
	// the customer had previously stored.
	bodyStr := rec.Body.String()
	if strings.Contains(bodyStr, "hunter2") {
		t.Errorf("response body leaked the secret value: %s", bodyStr)
	}
	if strings.Contains(bodyStr, "postgres://") {
		t.Errorf("response body leaked the secret value prefix: %s", bodyStr)
	}
	if env.Data.Variable.ID != deletedSnapshot.ID {
		t.Errorf("variable.id = %q, want %q", env.Data.Variable.ID, deletedSnapshot.ID)
	}
	if env.Data.Variable.Key != key {
		t.Errorf("variable.key = %q, want %q", env.Data.Variable.Key, key)
	}
	if !env.Data.Variable.IsSecret {
		t.Errorf("variable.is_secret = false, want true")
	}
	if env.Data.Variable.Value != output.Sentinel {
		t.Errorf("variable.value = %q, want sentinel", env.Data.Variable.Value)
	}
	if env.Data.Variable.Version != 3 {
		t.Errorf("variable.version = %d, want 3", env.Data.Variable.Version)
	}

	// The handler must forward the path parameters verbatim (so a
	// cross-tenant smuggling attempt is impossible at this seam) and
	// the principal/correlation fields needed to file the audit
	// record.
	if got.OrganizationID != orgID {
		t.Errorf("deleter received org_id %q, want the path parameter %q", got.OrganizationID, orgID)
	}
	if got.Key != key {
		t.Errorf("deleter received key %q, want the path parameter %q", got.Key, key)
	}
	if got.ActorID != "usr_ada" || got.ActorOrgID != orgID {
		t.Errorf("deleter received actor=(%q, %q), want (usr_ada, %q)",
			got.ActorID, got.ActorOrgID, orgID)
	}
	if got.RequestID == "" {
		t.Errorf("deleter received empty RequestID; the handler must forward the correlation identifiers")
	}
}

// TestDeleteOrgVariableNonSecretValueProjectsVerbatim proves a
// non-secret variable's value reaches the response verbatim — a
// customer auditing what was removed sees the literal that was
// stored, while secret values still go through the redaction
// chokepoint.
func TestDeleteOrgVariableNonSecretValueProjectsVerbatim(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	const key = "REGION"
	deletedSnapshot := store.OrganizationVariable{
		ID: "ovar_region", OrganizationID: orgID, Key: key,
		Value: "us-east-1", IsSecret: false, Version: 1,
	}
	deleter := fakeOrgVariableDeleter{v: deletedSnapshot}
	handler := deleteOrgVariableHandlerFor(
		orgVariableActorIdentity(orgID, "usr_ada"), nil, deleter)

	rec := deleteOrgVariable(handler, orgID, key, "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	env := decodeDeleteOrgVariable(t, rec)
	if env.Data.Variable.Value != "us-east-1" {
		t.Errorf("variable.value = %q, want \"us-east-1\" (non-secret variables project verbatim)", env.Data.Variable.Value)
	}
	if env.Data.Variable.IsSecret {
		t.Errorf("variable.is_secret = true, want false")
	}
}

// TestDeleteOrgVariableForwardsStoreNotFound proves a NotFound from
// the deleter (e.g. a key that exists in another tenant — the
// tenant-scoped repository delete filters by organization_id first,
// so a cross-tenant {key} is indistinguishable from a missing row)
// reaches the wire as a typed 404 carrying the documented
// E_NOT_FOUND code. The handler must not disguise it as a 5xx.
func TestDeleteOrgVariableForwardsStoreNotFound(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	const key = "MISSING_KEY"
	deleter := fakeOrgVariableDeleter{err: apierr.NotFound("organization_variable", key)}
	handler := deleteOrgVariableHandlerFor(
		orgVariableActorIdentity(orgID, "usr_ada"), nil, deleter)

	rec := deleteOrgVariable(handler, orgID, key, "a-valid-session-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_NOT_FOUND")
}

// TestDeleteOrgVariableStoreOutageIsTypedFailure proves a transient
// datastore outage surfaces as a typed 5xx (E_UNAVAILABLE) rather
// than a leaked driver error or a panic.
func TestDeleteOrgVariableStoreOutageIsTypedFailure(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	deleter := fakeOrgVariableDeleter{
		err: apierr.StoreUnavailable(stderrors.New("connection reset")),
	}
	handler := deleteOrgVariableHandlerFor(
		orgVariableActorIdentity(orgID, "usr_ada"), nil, deleter)

	rec := deleteOrgVariable(handler, orgID, "DATABASE_URL", "a-valid-session-token")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_UNAVAILABLE")
	if strings.Contains(env.Error.Message, "connection reset") {
		t.Errorf("error message leaked the driver cause: %q", env.Error.Message)
	}
}

// TestDeleteOrgVariableRequiresAuthentication proves the auth gate: a
// request missing or carrying an invalid credential is the typed 401
// the authenticator path emits, not a leaked panic, and the deleter
// never runs.
func TestDeleteOrgVariableRequiresAuthentication(t *testing.T) {
	t.Parallel()
	const orgID = "org_acme"
	var got store.DeleteOrganizationVariableInput
	deleter := fakeOrgVariableDeleter{got: &got}

	handler := deleteOrgVariableHandlerFor(auth.Identity{}, apierr.Unauthenticated("missing token"), deleter)
	rec := deleteOrgVariable(handler, orgID, "DATABASE_URL", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
	if got.OrganizationID != "" {
		t.Errorf("deleter ran for an unauthenticated request: %+v", got)
	}
}

// TestDeleteOrgVariableDeniesCrossTenantPrincipal proves the policy
// engine rejects an {org_id} the principal does not own — the
// variables DELETE route uses organizationIDResolver, so a
// cross-tenant id is denied as a 403 before the handler runs, and
// the deleter never sees the request. env.write is a CapWrite action
// with no cross-tenant support exception.
func TestDeleteOrgVariableDeniesCrossTenantPrincipal(t *testing.T) {
	t.Parallel()
	const homeOrg = "org_attacker"
	const victimOrg = "org_acme"
	var got store.DeleteOrganizationVariableInput
	deleter := fakeOrgVariableDeleter{got: &got}

	id := auth.Identity{
		Principal: orgPrincipal("usr_mallory", homeOrg, policy.RoleOwner),
		Method:    auth.MethodSession,
	}
	handler := deleteOrgVariableHandlerFor(id, nil, deleter)
	rec := deleteOrgVariable(handler, victimOrg, "DATABASE_URL", "a-valid-session-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_FORBIDDEN")
	if got.OrganizationID != "" {
		t.Errorf("deleter ran for a cross-tenant request: %+v", got)
	}
}

// TestDeleteOrgVariableMissingDeleterReturns500 proves the wiring
// guard: a route registered with a nil deleter reports the documented
// E_INTERNAL through the same envelope shape as every other internal
// failure — never an empty body, a panic, or a misleading 4xx.
func TestDeleteOrgVariableMissingDeleterReturns500(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	a := fakeAuthenticator{identity: orgVariableActorIdentity(orgID, "usr_ada")}
	handler := NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, nil,
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
	rec := deleteOrgVariable(handler, orgID, "DATABASE_URL", "a-valid-session-token")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
}

// TestDeleteOrgVariableRouteIsRegistered proves the OpenAPI document
// carries the DELETE /v1/organizations/{org_id}/variables/{key}
// operation with the stable operationId, the env.write required
// action, and the variables tag — every detail an agent reads to
// discover the endpoint.
func TestDeleteOrgVariableRouteIsRegistered(t *testing.T) {
	t.Parallel()

	table := newRouteTable(runtime.BuildInfo{}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{})
	var found bool
	for _, rt := range table {
		if rt.endpoint.Method != http.MethodDelete ||
			rt.endpoint.Path != "/v1/organizations/{org_id}/variables/{key}" {
			continue
		}
		found = true
		if rt.endpoint.OperationID != "deleteOrganizationVariable" {
			t.Errorf("operationId = %q, want deleteOrganizationVariable", rt.endpoint.OperationID)
		}
		if rt.endpoint.RequiredAction != string(policy.ActionEnvWrite) {
			t.Errorf("requiredAction = %q, want %q", rt.endpoint.RequiredAction, policy.ActionEnvWrite)
		}
		if !rt.endpoint.RequiresAuth {
			t.Errorf("requiresAuth = false, want true")
		}
		var keyPathParam bool
		for _, p := range rt.endpoint.PathParams {
			if p.Name == "key" {
				keyPathParam = true
			}
		}
		if !keyPathParam {
			t.Errorf("path param 'key' not declared on the endpoint: %+v", rt.endpoint.PathParams)
		}
		var hasVariables bool
		for _, tg := range rt.endpoint.Tags {
			if tg == tagVariables {
				hasVariables = true
			}
		}
		if !hasVariables {
			t.Errorf("tags = %+v, want to include %q", rt.endpoint.Tags, tagVariables)
		}
	}
	if !found {
		t.Fatalf("DELETE /v1/organizations/{org_id}/variables/{key} not registered in route table")
	}
}
