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
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/output"
)

// Contract and tenant-isolation coverage for GET
// /v1/organizations/{org_id}/variables (BE-0106). The endpoint reads the
// organization-scoped variables of the organization through the
// OrganizationVariableReader port; the tests drive it through NewHandler
// with a fake Authenticator, the real policy engine, and a fake reader —
// the same wiring a request hits in production, minus the database. The
// store-backed reader has its own isolated-Postgres integration coverage
// in store/organization_variable_reader_test.go — this file exercises
// the HTTP surface in isolation.

// fakeOrgVariableReader is a canned OrganizationVariableReader for httpapi
// tests. The zero value returns a nil slice and no error, which is all the
// test helpers that never reach the handler (the public-surface and
// unrelated-endpoint suites) need; the variables tests set vars/err and
// read gotOrgID back to prove the handler forwards the path parameter to
// the store layer unchanged.
type fakeOrgVariableReader struct {
	vars     []store.OrganizationVariable
	err      error
	gotOrgID *string
}

func (f fakeOrgVariableReader) ListByOrganization(_ context.Context, organizationID string) ([]store.OrganizationVariable, error) {
	if f.gotOrgID != nil {
		*f.gotOrgID = organizationID
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.vars, nil
}

// fakeOrgVariableReplacer is a canned OrganizationVariableReplacer for
// httpapi tests. The zero value returns a nil slice and no error, which is
// all the unrelated-endpoint suites need; the variables write tests set
// vars/err and read got back to prove the handler forwards the
// {org_id} path parameter and the principal/correlation fields to the
// store layer unchanged. The replacer mirrors fakeLimitsUpdater in shape.
type fakeOrgVariableReplacer struct {
	vars []store.OrganizationVariable
	err  error
	got  *store.ReplaceOrganizationVariablesInput
}

func (f fakeOrgVariableReplacer) Replace(_ context.Context, in store.ReplaceOrganizationVariablesInput) ([]store.OrganizationVariable, error) {
	if f.got != nil {
		*f.got = in
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.vars, nil
}

// fakeOrgVariablePatcher is a canned OrganizationVariablePatcher for
// httpapi tests. The zero value returns a zero variable and no error,
// which is all the unrelated-endpoint suites need; the variables patch
// tests set v/err and read got back to prove the handler forwards the
// path parameters and the principal/correlation fields to the store
// layer unchanged. The patcher mirrors fakeOrgVariableReplacer in shape.
type fakeOrgVariablePatcher struct {
	v   store.OrganizationVariable
	err error
	got *store.PatchOrganizationVariableInput
}

func (f fakeOrgVariablePatcher) Patch(_ context.Context, in store.PatchOrganizationVariableInput) (store.OrganizationVariable, error) {
	if f.got != nil {
		*f.got = in
	}
	if f.err != nil {
		return store.OrganizationVariable{}, f.err
	}
	return f.v, nil
}

// fakeOrgVariableDeleter is a canned OrganizationVariableDeleter for
// httpapi tests. The zero value returns a zero variable and no error,
// which is all the unrelated-endpoint suites need; the variables delete
// tests set v/err and read got back to prove the handler forwards the
// path parameters and the principal/correlation fields to the store
// layer unchanged. The deleter mirrors fakeOrgVariablePatcher in shape.
type fakeOrgVariableDeleter struct {
	v   store.OrganizationVariable
	err error
	got *store.DeleteOrganizationVariableInput
}

func (f fakeOrgVariableDeleter) Delete(_ context.Context, in store.DeleteOrganizationVariableInput) (store.OrganizationVariable, error) {
	if f.got != nil {
		*f.got = in
	}
	if f.err != nil {
		return store.OrganizationVariable{}, f.err
	}
	return f.v, nil
}

// listOrgVariablesHandlerFor builds an http.Handler that points at the GET
// /v1/organizations/{org_id}/variables route, wired through the same
// NewHandler the production binary uses. id and authErr drive the fake
// authenticator; reader is the OrganizationVariableReader the handler reads
// from.
func listOrgVariablesHandlerFor(id auth.Identity, authErr error, reader OrganizationVariableReader) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, reader, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeBreakGlassController{}, nil)
}

// orgVariableActorIdentity builds a session-method identity for an
// organization owner acting on its own tenant — the default principal
// shape the contract tests use when proving the wire surface independent
// of policy matrix combinatorics. env.read is a CapRead-class action and
// owner is allowed; viewer/developer/admin are exhaustively tabled by the
// dedicated BE-0108 policy matrix.
func orgVariableActorIdentity(orgID, userID string) auth.Identity {
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

// getOrgVariables issues a GET against
// /v1/organizations/{orgID}/variables and returns the recorded response.
func getOrgVariables(handler http.Handler, orgID, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v1/organizations/"+orgID+"/variables", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// orgVariableEnvelope mirrors the yalla.output.v1 wire shape an agent
// observes. It deliberately uses anonymous structs rather than the
// internal types so the test depends on field NAMES, not internal Go
// identifiers — a future rename of organizationVariable to anything else
// must not silently pass these tests.
type orgVariableEnvelope struct {
	SchemaVersion string `json:"schema_version"`
	RequestID     string `json:"request_id"`
	Data          struct {
		Variables []struct {
			ID        string    `json:"id"`
			Key       string    `json:"key"`
			Value     string    `json:"value"`
			IsSecret  bool      `json:"is_secret"`
			Version   int64     `json:"version"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
		} `json:"variables"`
	} `json:"data"`
}

func decodeOrgVariables(t *testing.T, body []byte) orgVariableEnvelope {
	t.Helper()
	var env orgVariableEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode envelope: %v; body=%s", err, body)
	}
	return env
}

// TestListOrgVariablesReturnsVariables proves the happy path: the handler
// forwards {org_id} to the reader unchanged, projects every row into the
// stable wire shape, and pins the envelope fields agents read first.
func TestListOrgVariablesReturnsVariables(t *testing.T) {
	t.Parallel()
	const orgID = "org_acme"
	var gotOrg string
	created := time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC)
	reader := fakeOrgVariableReader{
		gotOrgID: &gotOrg,
		vars: []store.OrganizationVariable{
			{
				ID:             "ovar_001",
				OrganizationID: orgID,
				Key:            "FEATURE_FLAG",
				Value:          "enabled",
				IsSecret:       false,
				Version:        1,
				CreatedAt:      created,
				UpdatedAt:      created,
			},
			{
				ID:             "ovar_002",
				OrganizationID: orgID,
				Key:            "REGION",
				Value:          "us-east-1",
				IsSecret:       false,
				Version:        7,
				CreatedAt:      created,
				UpdatedAt:      created.Add(time.Minute),
			},
		},
	}
	handler := listOrgVariablesHandlerFor(orgVariableActorIdentity(orgID, "usr_owner"), nil, reader)
	rec := getOrgVariables(handler, orgID, "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if gotOrg != orgID {
		t.Errorf("reader received org_id %q, want %q", gotOrg, orgID)
	}
	env := decodeOrgVariables(t, rec.Body.Bytes())
	if env.SchemaVersion != "yalla.output.v1" {
		t.Errorf("schema_version = %q, want yalla.output.v1", env.SchemaVersion)
	}
	if env.RequestID == "" {
		t.Errorf("request_id is empty; envelope must propagate the request id")
	}
	if len(env.Data.Variables) != 2 {
		t.Fatalf("variables len = %d, want 2 (got %+v)", len(env.Data.Variables), env.Data.Variables)
	}

	first := env.Data.Variables[0]
	if first.ID != "ovar_001" || first.Key != "FEATURE_FLAG" || first.Value != "enabled" || first.IsSecret {
		t.Errorf("[0] = %+v; want (ovar_001 FEATURE_FLAG enabled is_secret=false)", first)
	}
	if first.Version != 1 {
		t.Errorf("[0].version = %d, want 1", first.Version)
	}
}

// TestListOrgVariablesRedactsSecretValues proves the wire redaction
// chokepoint: every is_secret=true row projects its value as the
// redaction sentinel — the customer can never read a secret value back
// through this endpoint by design. Non-secret values pass through
// verbatim so the customer can audit their own organization-wide
// defaults.
func TestListOrgVariablesRedactsSecretValues(t *testing.T) {
	t.Parallel()
	const orgID = "org_acme"
	reader := fakeOrgVariableReader{
		vars: []store.OrganizationVariable{
			{
				ID:             "ovar_secret",
				OrganizationID: orgID,
				Key:            "DATABASE_URL",
				Value:          "postgres://user:hunter2@db.internal/yalla",
				IsSecret:       true,
				Version:        1,
			},
			{
				ID:             "ovar_plain",
				OrganizationID: orgID,
				Key:            "LOG_LEVEL",
				Value:          "info",
				IsSecret:       false,
				Version:        1,
			},
		},
	}
	handler := listOrgVariablesHandlerFor(orgVariableActorIdentity(orgID, "usr_owner"), nil, reader)
	rec := getOrgVariables(handler, orgID, "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "hunter2") {
		t.Errorf("response body leaked the secret value: %s", body)
	}
	if strings.Contains(body, "postgres://") {
		t.Errorf("response body leaked the secret value prefix: %s", body)
	}
	env := decodeOrgVariables(t, rec.Body.Bytes())
	if len(env.Data.Variables) != 2 {
		t.Fatalf("variables len = %d, want 2", len(env.Data.Variables))
	}
	var secret, plain *struct {
		ID        string    `json:"id"`
		Key       string    `json:"key"`
		Value     string    `json:"value"`
		IsSecret  bool      `json:"is_secret"`
		Version   int64     `json:"version"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
	}
	for i := range env.Data.Variables {
		v := &env.Data.Variables[i]
		if v.IsSecret {
			secret = v
		} else {
			plain = v
		}
	}
	if secret == nil || secret.Value != output.Sentinel {
		t.Errorf("secret variable value = %q, want sentinel", secret.Value)
	}
	if plain == nil || plain.Value != "info" {
		t.Errorf("non-secret variable value = %q, want \"info\"", plain.Value)
	}
}

// TestListOrgVariablesReturnsEmptyListForOrgWithNoVariables proves an
// organization with no configured variables yields a deterministic empty
// list rather than a 404 — the same forward-compatible shape every list
// endpoint serves so an agent can iterate without a nil check.
func TestListOrgVariablesReturnsEmptyListForOrgWithNoVariables(t *testing.T) {
	t.Parallel()
	const orgID = "org_acme"
	reader := fakeOrgVariableReader{vars: nil}

	handler := listOrgVariablesHandlerFor(orgVariableActorIdentity(orgID, "usr_owner"), nil, reader)
	rec := getOrgVariables(handler, orgID, "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	env := decodeOrgVariables(t, rec.Body.Bytes())
	if env.Data.Variables == nil {
		t.Errorf("variables is nil, want a non-nil empty slice (so agents can iterate without a nil check)")
	}
	if len(env.Data.Variables) != 0 {
		t.Errorf("variables len = %d, want 0", len(env.Data.Variables))
	}
}

// TestListOrgVariablesForwardsStoreUnavailableAsTypedFiveHundred proves a
// store outage becomes a stable 5xx envelope, not a leaked driver error.
func TestListOrgVariablesForwardsStoreUnavailableAsTypedFiveHundred(t *testing.T) {
	t.Parallel()
	const orgID = "org_acme"
	reader := fakeOrgVariableReader{err: apierr.StoreUnavailable(stderrors.New("connection reset"))}

	handler := listOrgVariablesHandlerFor(orgVariableActorIdentity(orgID, "usr_owner"), nil, reader)
	rec := getOrgVariables(handler, orgID, "a-valid-session-token")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "connection reset") {
		t.Errorf("body leaked the raw driver error: %s", rec.Body.String())
	}
}

// TestListOrgVariablesRequiresAuthentication proves a missing/invalid
// credential is the typed 401 the authenticator path emits, not a leaked
// panic, and the reader never runs.
func TestListOrgVariablesRequiresAuthentication(t *testing.T) {
	t.Parallel()
	const orgID = "org_acme"
	var gotOrg string
	reader := fakeOrgVariableReader{gotOrgID: &gotOrg}

	handler := listOrgVariablesHandlerFor(auth.Identity{}, apierr.Unauthenticated("missing token"), reader)
	rec := getOrgVariables(handler, orgID, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
	if gotOrg != "" {
		t.Errorf("reader ran for an unauthenticated request (received org_id %q)", gotOrg)
	}
}

// TestListOrgVariablesDeniesCrossTenantPrincipal proves the policy engine
// — wired through organizationIDResolver — rejects a principal whose
// home organization is not the {org_id} the path names (and who is not a
// support principal allowed cross-tenant for read actions), without the
// reader ever running. env.read is a CapRead-class action whose
// cross-tenant support exception is pinned exhaustively in the BE-0108
// policy matrix, not duplicated here.
func TestListOrgVariablesDeniesCrossTenantPrincipal(t *testing.T) {
	t.Parallel()
	const homeOrg = "org_attacker"
	const victimOrg = "org_acme"
	var gotOrg string
	reader := fakeOrgVariableReader{gotOrgID: &gotOrg}

	id := auth.Identity{
		Principal: policy.Principal{
			ID:             "usr_mallory",
			Kind:           domain.KindUser,
			OrganizationID: homeOrg,
			Role:           policy.RoleOwner,
		},
		Method: auth.MethodSession,
	}
	handler := listOrgVariablesHandlerFor(id, nil, reader)
	rec := getOrgVariables(handler, victimOrg, "a-valid-session-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	if gotOrg != "" {
		t.Errorf("reader ran for a cross-tenant principal (received org_id %q)", gotOrg)
	}
	if strings.Contains(rec.Body.String(), `"variables"`) {
		t.Errorf("body leaked variable data on a denied request: %s", rec.Body.String())
	}
}

// TestListOrgVariablesMissingReaderIsTypedInternalError proves a wiring
// error (a nil OrganizationVariableReader threaded into NewHandler)
// surfaces as the typed internal-error envelope rather than a misleading
// empty list or a panic, the same posture every other list endpoint
// takes.
func TestListOrgVariablesMissingReaderIsTypedInternalError(t *testing.T) {
	t.Parallel()
	const orgID = "org_acme"
	a := fakeAuthenticator{identity: orgVariableActorIdentity(orgID, "usr_owner")}
	handler := NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, nil, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeBreakGlassController{}, nil)
	rec := getOrgVariables(handler, orgID, "a-valid-session-token")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
}

// TestListOrgVariablesRouteIsRegistered proves the OpenAPI document
// carries the GET /v1/organizations/{org_id}/variables operation with
// the stable operationId, the env.read required action, and the
// variables tag — every detail an agent reads to discover the endpoint.
func TestListOrgVariablesRouteIsRegistered(t *testing.T) {
	t.Parallel()
	a := fakeAuthenticator{identity: orgVariableActorIdentity("org_acme", "usr_owner")}
	handler := NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeBreakGlassController{}, nil)

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
	op, ok := doc.Paths["/v1/organizations/{org_id}/variables"]["get"]
	if !ok {
		t.Fatalf("GET /v1/organizations/{org_id}/variables missing from OpenAPI document")
	}
	if op.OperationID != "listOrganizationVariables" {
		t.Errorf("operationId = %q, want listOrganizationVariables", op.OperationID)
	}
	if op.RequiredAction != string(policy.ActionEnvRead) {
		t.Errorf("x-required-action = %q, want %q", op.RequiredAction, policy.ActionEnvRead)
	}
	foundTag := false
	for _, tag := range op.Tags {
		if tag == "variables" {
			foundTag = true
			break
		}
	}
	if !foundTag {
		t.Errorf("tags = %v, want it to include \"variables\"", op.Tags)
	}
}

// TestListOrgVariablesDeterministicOrderingTrustedFromStore proves the
// handler does not reorder the rows returned by the reader: the store
// is the chokepoint for the (key, id) ordering contract, so the wire
// projection mirrors persistence verbatim. A future regression that
// sorts in the handler instead would silently disagree with the
// integration test in store/.
func TestListOrgVariablesDeterministicOrderingTrustedFromStore(t *testing.T) {
	t.Parallel()
	const orgID = "org_acme"
	reader := fakeOrgVariableReader{
		vars: []store.OrganizationVariable{
			// Reader returns rows in "ZETA, ALPHA" order — the store
			// is responsible for determinism; the handler projects in
			// the order it gets.
			{ID: "ovar_z", OrganizationID: orgID, Key: "ZETA", Value: "z"},
			{ID: "ovar_a", OrganizationID: orgID, Key: "ALPHA", Value: "a"},
		},
	}
	handler := listOrgVariablesHandlerFor(orgVariableActorIdentity(orgID, "usr_owner"), nil, reader)
	rec := getOrgVariables(handler, orgID, "a-valid-session-token")
	env := decodeOrgVariables(t, rec.Body.Bytes())
	if len(env.Data.Variables) != 2 {
		t.Fatalf("variables len = %d, want 2", len(env.Data.Variables))
	}
	if env.Data.Variables[0].Key != "ZETA" || env.Data.Variables[1].Key != "ALPHA" {
		t.Errorf("keys = %q, %q; handler must not reorder reader output (got %+v)",
			env.Data.Variables[0].Key, env.Data.Variables[1].Key, env.Data.Variables)
	}
}
