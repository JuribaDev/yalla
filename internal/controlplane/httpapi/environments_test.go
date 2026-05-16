package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/openapi"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// fakeEnvironmentReader is a canned EnvironmentReader for httpapi
// contract tests of GET /v1/environments/{environment_id}. It supplies
// a fixed response (or error) and records the (organization_id,
// environment_id) tuple the handler called with so tests can assert
// the handler forwards exactly the principal's home organization (never
// a caller-supplied id) and the path environment_id verbatim.
//
// The fake intentionally does not enforce tenant scoping itself — that
// is the production *store.EnvironmentReader's job, proven by its
// integration tests. The HTTP-layer contract under test is "the handler
// asks the port using the principal's home org and the path env_id",
// regardless of how the port answers.
type fakeEnvironmentReader struct {
	env       store.Environment
	err       error
	gotOrgID  *string
	gotEnvID  *string
	callCount *int
}

// fakeEnvironmentUpdater is a canned EnvironmentUpdater for httpapi
// contract tests of PATCH /v1/environments/{environment_id}. It
// supplies a fixed response (or error) and records the
// store.UpdateEnvironmentInput the handler called with so tests can
// assert the handler forwards exactly the principal's home
// organization (never a caller-supplied id), the path environment_id,
// and the decoded body fields verbatim.
//
// The fake intentionally does not enforce tenant scoping or
// validation itself — that is the production
// *store.EnvironmentService's job, proven by its integration tests.
// The HTTP-layer contract under test is "the handler asks the port
// using the principal's home org and the path env_id, with the
// decoded patch", regardless of how the port answers.
type fakeEnvironmentUpdater struct {
	env       store.Environment
	err       error
	gotInput  *store.UpdateEnvironmentInput
	callCount *int
}

func (f fakeEnvironmentUpdater) Update(_ context.Context, in store.UpdateEnvironmentInput) (store.Environment, error) {
	if f.gotInput != nil {
		*f.gotInput = in
	}
	if f.callCount != nil {
		*f.callCount++
	}
	return f.env, f.err
}

// fakeEnvironmentDeleter is a canned EnvironmentDeleter for httpapi
// contract tests of DELETE /v1/environments/{environment_id}. It
// supplies a fixed response (or error) and records the
// store.DeleteEnvironmentInput the handler called with so tests can
// assert the handler forwards exactly the principal's home organization
// (never a caller-supplied id), the path environment_id, and the parsed
// If-Match precondition verbatim.
//
// The fake intentionally does not enforce tenant scoping or
// validation itself — that is the production
// *store.EnvironmentService's job, proven by its integration tests.
// The HTTP-layer contract under test is "the handler asks the port
// using the principal's home org, the path env_id, and the parsed
// If-Match version", regardless of how the port answers.
type fakeEnvironmentDeleter struct {
	env       store.Environment
	err       error
	gotInput  *store.DeleteEnvironmentInput
	callCount *int
}

func (f fakeEnvironmentDeleter) ScheduleDeletion(_ context.Context, in store.DeleteEnvironmentInput) (store.Environment, error) {
	if f.gotInput != nil {
		*f.gotInput = in
	}
	if f.callCount != nil {
		*f.callCount++
	}
	return f.env, f.err
}

// fakeEnvironmentCloner is a canned EnvironmentCloner for httpapi
// tests. The zero value returns a zero Environment and a nil error from
// Clone, which is all the tests that never reach the POST clone
// endpoint (the public-surface, /v1/me, and other-route suites) need.
// Tests that drive POST /v1/environments/{environment_id}/clone set
// env/err and read gotInput + callCount back to prove the handler
// forwarded the resolved (principal home org id, path source env_id,
// decoded body fields, principal id+kind, actor home org id, request
// id, correlation id) tuple verbatim — the boundary the policy engine
// and the audit record share.
//
// The fake intentionally does not enforce tenant scoping or
// validation itself — that is the production
// *store.EnvironmentService's job, proven by its integration tests.
// The HTTP-layer contract under test is "the handler asks the port
// using the principal's home org and the path source env_id",
// regardless of how the port answers.
type fakeEnvironmentCloner struct {
	env       store.Environment
	err       error
	gotInput  *store.CloneEnvironmentInput
	callCount *int
}

func (f fakeEnvironmentCloner) Clone(_ context.Context, in store.CloneEnvironmentInput) (store.Environment, error) {
	if f.gotInput != nil {
		*f.gotInput = in
	}
	if f.callCount != nil {
		*f.callCount++
	}
	return f.env, f.err
}

func (f fakeEnvironmentReader) GetEnvironment(_ context.Context, organizationID, environmentID string) (store.Environment, error) {
	if f.gotOrgID != nil {
		*f.gotOrgID = organizationID
	}
	if f.gotEnvID != nil {
		*f.gotEnvID = environmentID
	}
	if f.callCount != nil {
		*f.callCount++
	}
	return f.env, f.err
}

// canonicalEnvForGet is the canned environments row the GET-by-id
// happy-path tests render through projectEnvironmentOf. It mirrors the
// shape of canonicalEnv used by project_environments_test.go: every
// field is non-zero so the projection invariants — id, organization_id,
// project_id, slug, display_name, version, created_at, updated_at —
// are exercised on the wire.
var canonicalEnvForGet = store.Environment{
	ID:             "env_canonical_get",
	OrganizationID: "org_acme_get",
	ProjectID:      "prj_acme_web",
	Slug:           "production",
	DisplayName:    "Production",
	Version:        7,
	CreatedAt:      time.Date(2025, 4, 11, 9, 30, 0, 0, time.UTC),
	UpdatedAt:      time.Date(2025, 4, 12, 10, 0, 0, 0, time.UTC),
}

// principalForEnvGet is a canned org-wide read principal — it admits
// action environment.read at the (home org, env_id) resource the
// resolver builds.
var principalForEnvGet = policy.Principal{
	ID:             "usr_get_env",
	OrganizationID: "org_acme_get",
	Role:           policy.RoleAdmin,
}

// authForEnvGet is a fake Authenticator that maps a canned bearer
// token to principalForEnvGet. Tests that need a different principal
// build their own Authenticator.
type authForEnvGet struct{}

func (authForEnvGet) Authenticate(_ context.Context, token string) (auth.Identity, error) {
	if token != "a-valid-token" {
		return auth.Identity{}, auth.ErrInvalidCredentials
	}
	return auth.Identity{Method: auth.MethodAPIKey, Principal: principalForEnvGet}, nil
}

// getEnvironmentHandlerFor wraps the production NewHandler with a
// canned authenticator and the supplied reader, mirroring the
// listProjectEnvironmentsHandlerFor helper. Every other port is a
// no-op fake; the test exercises only the GET-environment vertical.
func getEnvironmentHandlerFor(t *testing.T, reader EnvironmentReader) http.Handler {
	t.Helper()
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, authForEnvGet{}, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{},
		fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, reader, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
}

// getEnvironment fires GET /v1/environments/{environment_id} with the
// supplied bearer token and returns the response recorder.
func getEnvironment(handler http.Handler, envID, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v1/environments/"+envID, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// decodeGetEnvironmentBody decodes the success envelope into the
// projectEnvironment wire shape so assertions read the JSON contract,
// not the in-process Go type.
func decodeGetEnvironmentBody(t *testing.T, rec *httptest.ResponseRecorder) projectEnvironment {
	t.Helper()
	var env struct {
		Data           getEnvironmentPayload `json:"data"`
		SchemaVersion  string                `json:"schema_version"`
		RequestID      string                `json:"request_id"`
		ResponseStatus string                `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode body: %v (body=%s)", err, rec.Body.String())
	}
	if env.SchemaVersion != "yalla.output.v1" {
		t.Errorf("schema_version = %q, want yalla.output.v1", env.SchemaVersion)
	}
	if env.RequestID == "" {
		t.Errorf("request_id is empty")
	}
	return env.Data.Environment
}

// TestGetEnvironmentHappyPath proves a request with a valid bearer
// token reaches the reader with the principal's home organization id
// (never a caller-supplied id) and the path environment_id, and
// renders the canonical row through projectEnvironmentOf in a stable
// yalla.output.v1 envelope.
func TestGetEnvironmentHappyPath(t *testing.T) {
	t.Parallel()

	var gotOrg, gotEnv string
	reader := fakeEnvironmentReader{
		env:      canonicalEnvForGet,
		gotOrgID: &gotOrg,
		gotEnvID: &gotEnv,
	}
	handler := getEnvironmentHandlerFor(t, reader)

	rec := getEnvironment(handler, canonicalEnvForGet.ID, "a-valid-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if gotOrg != principalForEnvGet.OrganizationID {
		t.Errorf("reader called with org_id = %q; want %q (principal home org, never a caller-supplied id)", gotOrg, principalForEnvGet.OrganizationID)
	}
	if gotEnv != canonicalEnvForGet.ID {
		t.Errorf("reader called with env_id = %q; want %q (path parameter, verbatim)", gotEnv, canonicalEnvForGet.ID)
	}

	got := decodeGetEnvironmentBody(t, rec)
	if got.ID != canonicalEnvForGet.ID {
		t.Errorf("environment.id = %q; want %q", got.ID, canonicalEnvForGet.ID)
	}
	if got.OrganizationID != canonicalEnvForGet.OrganizationID {
		t.Errorf("environment.organization_id = %q; want %q", got.OrganizationID, canonicalEnvForGet.OrganizationID)
	}
	if got.ProjectID != canonicalEnvForGet.ProjectID {
		t.Errorf("environment.project_id = %q; want %q", got.ProjectID, canonicalEnvForGet.ProjectID)
	}
	if got.Slug != canonicalEnvForGet.Slug || got.DisplayName != canonicalEnvForGet.DisplayName {
		t.Errorf("environment.(slug, display_name) = (%q, %q); want (%q, %q)", got.Slug, got.DisplayName, canonicalEnvForGet.Slug, canonicalEnvForGet.DisplayName)
	}
	if got.Version != canonicalEnvForGet.Version {
		t.Errorf("environment.version = %d; want %d", got.Version, canonicalEnvForGet.Version)
	}
	if !got.CreatedAt.Equal(canonicalEnvForGet.CreatedAt) {
		t.Errorf("environment.created_at = %v; want %v", got.CreatedAt, canonicalEnvForGet.CreatedAt)
	}
	if !got.UpdatedAt.Equal(canonicalEnvForGet.UpdatedAt) {
		t.Errorf("environment.updated_at = %v; want %v", got.UpdatedAt, canonicalEnvForGet.UpdatedAt)
	}
}

// TestGetEnvironmentNotFoundIsTypedError proves the handler maps a
// reader-side apierr.NotFound onto a stable yalla.error.v1 404 with the
// E_NOT_FOUND code. The reader-side semantics are: a cross-tenant or
// unknown environment_id surfaces as the same 404 — the response is
// not an oracle that reveals which env_ids exist in another tenant.
func TestGetEnvironmentNotFoundIsTypedError(t *testing.T) {
	t.Parallel()

	reader := fakeEnvironmentReader{err: apierr.NotFound("environment", "env_unknown")}
	handler := getEnvironmentHandlerFor(t, reader)

	rec := getEnvironment(handler, "env_unknown", "a-valid-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeNotFound))
}

// TestGetEnvironmentCrossTenantBehavesAsNotFound proves a cross-tenant
// environment_id (an env that exists in another tenant) is rendered as
// the same deterministic 404 an unknown id is rendered as. The
// handler trusts the reader's tenant-scoping (proven by store
// integration tests) — the contract is "no oracle". This test asserts
// the wire shape, not the SQL filter.
func TestGetEnvironmentCrossTenantBehavesAsNotFound(t *testing.T) {
	t.Parallel()

	reader := fakeEnvironmentReader{err: apierr.NotFound("environment", "env_other_tenant")}
	handler := getEnvironmentHandlerFor(t, reader)

	rec := getEnvironment(handler, "env_other_tenant", "a-valid-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeNotFound))
}

// TestGetEnvironmentUnauthenticated proves a request with no bearer
// token is rejected at the middleware with 401 E_AUTH and never
// reaches the reader. The reader call counter must remain at zero.
func TestGetEnvironmentUnauthenticated(t *testing.T) {
	t.Parallel()

	calls := 0
	reader := fakeEnvironmentReader{env: canonicalEnvForGet, callCount: &calls}
	handler := getEnvironmentHandlerFor(t, reader)

	rec := getEnvironment(handler, canonicalEnvForGet.ID, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	if calls != 0 {
		t.Errorf("reader was called %d times for an unauthenticated request; want 0", calls)
	}
	decodeError(t, rec, string(yerr.CodeAuth))
}

// TestGetEnvironmentInvalidCredentials proves a request with a
// bearer token the authenticator rejects is rendered as the same
// uniform 401 E_AUTH, never as a 5xx and never echoing the supplied
// token. The reader is never called.
func TestGetEnvironmentInvalidCredentials(t *testing.T) {
	t.Parallel()

	calls := 0
	reader := fakeEnvironmentReader{env: canonicalEnvForGet, callCount: &calls}
	handler := getEnvironmentHandlerFor(t, reader)

	rec := getEnvironment(handler, canonicalEnvForGet.ID, "this-is-not-a-valid-token")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	if calls != 0 {
		t.Errorf("reader was called %d times for an invalid-credentials request; want 0", calls)
	}
	if strings.Contains(rec.Body.String(), "this-is-not-a-valid-token") {
		t.Errorf("response body echoes the supplied bearer token: %s", rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeAuth))
}

// TestGetEnvironmentReaderOutageIsTypedError proves a reader-side
// store outage is rendered as a stable yalla.error.v1 5xx envelope —
// the typed apierr.StoreUnavailable with code E_STORE_UNAVAILABLE —
// and the raw cause never reaches the wire.
func TestGetEnvironmentReaderOutageIsTypedError(t *testing.T) {
	t.Parallel()

	reader := fakeEnvironmentReader{err: apierr.StoreUnavailable(errors.New("connection refused"))}
	handler := getEnvironmentHandlerFor(t, reader)

	rec := getEnvironment(handler, canonicalEnvForGet.ID, "a-valid-token")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "connection refused") {
		t.Errorf("response body leaks raw store cause: %s", rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeUnavailable))
}

// TestGetEnvironmentNilReaderReportsInternal proves a NewHandler call
// site that forgot to wire an EnvironmentReader is reported as a typed
// internal error (E_INTERNAL) at request time — never as a misleading
// 200 with no body and never as a panic. This is the wiring guard.
func TestGetEnvironmentNilReaderReportsInternal(t *testing.T) {
	t.Parallel()

	handler := getEnvironmentHandlerFor(t, nil)

	rec := getEnvironment(handler, canonicalEnvForGet.ID, "a-valid-token")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeInternal))
}

// TestGetEnvironmentResponseEnvelopeIsRedactedAndStable proves the
// success response carries the documented yalla.output.v1 envelope,
// renders no log-suspect tokens (the bearer token never appears in the
// body), and emits no fields beyond the documented projectEnvironment
// shape — preventing accidental wire-level leakage of additional
// store.Environment columns added in the future.
func TestGetEnvironmentResponseEnvelopeIsRedactedAndStable(t *testing.T) {
	t.Parallel()

	reader := fakeEnvironmentReader{env: canonicalEnvForGet}
	handler := getEnvironmentHandlerFor(t, reader)

	rec := getEnvironment(handler, canonicalEnvForGet.ID, "a-valid-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "a-valid-token") {
		t.Errorf("response body echoes the bearer token: %s", body)
	}

	// Decode into a generic map to assert the documented field set.
	var generic map[string]any
	if err := json.NewDecoder(bytes.NewReader(rec.Body.Bytes())).Decode(&generic); err != nil {
		t.Fatalf("decode generic: %v", err)
	}
	data, ok := generic["data"].(map[string]any)
	if !ok {
		t.Fatalf("data is not an object: %#v", generic["data"])
	}
	envObj, ok := data["environment"].(map[string]any)
	if !ok {
		t.Fatalf("data.environment is not an object: %#v", data["environment"])
	}
	wantKeys := map[string]struct{}{
		"id":              {},
		"organization_id": {},
		"project_id":      {},
		"slug":            {},
		"display_name":    {},
		"version":         {},
		"created_at":      {},
		"updated_at":      {},
	}
	for k := range envObj {
		if _, ok := wantKeys[k]; !ok {
			t.Errorf("unexpected field %q in environment payload — projectEnvironment shape regression", k)
		}
	}
	for k := range wantKeys {
		if _, ok := envObj[k]; !ok {
			t.Errorf("missing field %q in environment payload", k)
		}
	}
}

// TestGetEnvironmentDoesNotLogBearerToken proves the per-request log
// record (telemetry.RequestLogging is wired by NewHandler) never
// echoes the bearer token, even on the success path. A request log
// that leaks credentials would defeat the audit-readability invariant.
func TestGetEnvironmentDoesNotLogBearerToken(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	reader := fakeEnvironmentReader{env: canonicalEnvForGet}
	handler := NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, authForEnvGet{}, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{},
		fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, reader, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, logger, nil)

	rec := getEnvironment(handler, canonicalEnvForGet.ID, "a-valid-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(logs.String(), "a-valid-token") {
		t.Errorf("structured log record echoes the bearer token: %s", logs.String())
	}
	// Drain the body so a future change that streams more data still
	// satisfies io.Closer-style invariants in the recorder. (httptest
	// ResponseRecorder has no Body.Close, but reading the body is a
	// safe no-op here and pins the assertion above against the rendered
	// payload, not a half-written stream.)
	_, _ = io.Copy(io.Discard, rec.Body)
}

// TestGetEnvironmentOpenAPIRouteIsRegistered proves the OpenAPI document
// carries the GET /v1/environments/{environment_id} operation with the
// stable operationId, the environment.read required action, and the
// environments tag — every detail an agent reads to discover the
// endpoint.
func TestGetEnvironmentOpenAPIRouteIsRegistered(t *testing.T) {
	t.Parallel()

	table := newRouteTable(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil,
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{})

	var found bool
	for _, rt := range table {
		if rt.endpoint.Method == http.MethodGet && rt.endpoint.Path == "/v1/environments/{environment_id}" {
			found = true
			if rt.endpoint.OperationID != "getEnvironment" {
				t.Errorf("operation_id = %q, want getEnvironment", rt.endpoint.OperationID)
			}
			if rt.endpoint.RequiredAction != string(policy.ActionEnvironmentRead) {
				t.Errorf("required_action = %q, want %q", rt.endpoint.RequiredAction, policy.ActionEnvironmentRead)
			}
			if !rt.endpoint.RequiresAuth {
				t.Errorf("requires_auth = false, want true")
			}
			var hasEnvTag bool
			for _, tag := range rt.endpoint.Tags {
				if tag == tagEnvironments {
					hasEnvTag = true
				}
			}
			if !hasEnvTag {
				t.Errorf("tags = %v, want to contain %q", rt.endpoint.Tags, tagEnvironments)
			}
			if len(rt.endpoint.PathParams) != 1 || rt.endpoint.PathParams[0].Name != "environment_id" {
				t.Errorf("path_params = %+v, want a single environment_id path param", rt.endpoint.PathParams)
			}
			if rt.resolver == nil {
				t.Errorf("resolver is nil; the route must use environmentIDResolver so authorize is evaluated against the (home org, env_id) resource")
			}
		}
	}
	if !found {
		t.Errorf("OpenAPI route GET /v1/environments/{environment_id} is not registered")
	}
}

// TestEnvironmentIDResolverPinsHomeOrganizationAndPathEnvID proves the
// resolver always builds the policy.Resource from the principal's home
// organization id (never a caller-supplied id) and the path
// environment_id verbatim. This is the structural anti-spoof guard
// that keeps a cross-tenant environment_id from being evaluated
// against another tenant.
func TestEnvironmentIDResolverPinsHomeOrganizationAndPathEnvID(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/v1/environments/env_xyz", nil)
	req.SetPathValue("environment_id", "env_xyz")
	ctx := policy.WithPrincipal(req.Context(), policy.Principal{
		ID:             "usr_resolver",
		OrganizationID: "org_home",
		Role:           policy.RoleViewer,
	})
	req = req.WithContext(ctx)

	res := environmentIDResolver(req)
	if res.Scope.OrganizationID != "org_home" {
		t.Errorf("resource org = %q; want %q (principal home, never caller-supplied)", res.Scope.OrganizationID, "org_home")
	}
	if res.Scope.EnvironmentID != "env_xyz" {
		t.Errorf("resource env = %q; want env_xyz (path verbatim)", res.Scope.EnvironmentID)
	}
	if res.Scope.ProjectID != "" {
		t.Errorf("resource project = %q; want empty (the path carries no parent project_id)", res.Scope.ProjectID)
	}
	if res.Scope.ServiceID != "" {
		t.Errorf("resource service = %q; want empty (the resource is an environment, not a service)", res.Scope.ServiceID)
	}
}

// TestEnvironmentIDResolverWithoutPrincipalLeavesOrganizationEmpty
// proves the resolver does NOT panic when called for a context with no
// principal (the request would be rejected at the middleware before
// reaching a handler, but the resolver itself runs purely on context
// state and must never crash on a malformed request).
func TestEnvironmentIDResolverWithoutPrincipalLeavesOrganizationEmpty(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/v1/environments/env_xyz", nil)
	req.SetPathValue("environment_id", "env_xyz")

	res := environmentIDResolver(req)
	if res.Scope.OrganizationID != "" {
		t.Errorf("resource org = %q; want empty (no principal on context)", res.Scope.OrganizationID)
	}
	if res.Scope.EnvironmentID != "env_xyz" {
		t.Errorf("resource env = %q; want env_xyz (path verbatim)", res.Scope.EnvironmentID)
	}
}

// (deliberately not exercising the openapi spec dump here — that is
// covered globally in routes_test.go's TestEveryRegisteredRouteIsDocumented.)
var _ openapi.Endpoint
