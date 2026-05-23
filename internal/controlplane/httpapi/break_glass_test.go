package httpapi

import (
	"bytes"
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
)

// Contract and tenant-isolation coverage for the break-glass HTTP surface
// (BE-0034):
//   POST   /v1/organizations/{org_id}/break-glass
//   GET    /v1/organizations/{org_id}/break-glass
//   GET    /v1/organizations/{org_id}/break-glass/{session_id}
//   DELETE /v1/organizations/{org_id}/break-glass/{session_id}
//
// The endpoints are gated on the CapSupport action admin.break_glass and
// run against fake BreakGlassController + fake authenticator + real
// policy engine — the same wiring a request hits in production, minus
// the database. The store-backed unit of work has its own
// isolated-Postgres integration coverage in store/break_glass_test.go.

// breakGlassHandlerFor builds an http.Handler that points at the break-
// glass routes, wired through the same NewHandler the production binary
// uses. id and authErr drive the fake authenticator; ctl is the
// controller the handlers delegate to.
func breakGlassHandlerFor(id auth.Identity, authErr error, ctl BreakGlassController) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, ctl, nil, nil)
}

// supportIdentity builds a session-method support principal in the named
// home org. admin.break_glass is a CapSupport action so only a principal
// with the support capability can reach the handler. The home org is
// distinct from the target org so the cross-tenant ReasonAllowedBySupport
// path is exercised on every successful call.
func supportIdentity(homeOrgID, userID string) auth.Identity {
	return auth.Identity{
		Principal: policy.Principal{
			ID:             userID,
			Kind:           domain.KindUser,
			OrganizationID: homeOrgID,
			Role:           policy.RoleSupport,
		},
		Method: auth.MethodSession,
	}
}

func ownerIdentity(orgID, userID string) auth.Identity {
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

// fakeBreakGlassSession builds a minimal store.BreakGlassSession for the
// canned controller results.
func fakeBreakGlassSession(orgID, sessionID string, now time.Time, ttl time.Duration) store.BreakGlassSession {
	return store.BreakGlassSession{
		ID:                  sessionID,
		OrganizationID:      orgID,
		ActorID:             "usr_support",
		ActorKind:           "usr",
		ActorOrganizationID: "org_yalla",
		Reason:              "incident-1",
		Status:              store.BreakGlassSessionStatusActive,
		StartedAt:           now,
		ExpiresAt:           now.Add(ttl),
		Version:             1,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
}

func postBreakGlass(handler http.Handler, orgID, body, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost,
		"/v1/organizations/"+orgID+"/break-glass", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func postAdminBreakGlass(handler http.Handler, target string, body string, token string) *httptest.ResponseRecorder {
	path := "/v1/admin/break-glass"
	if target != "" {
		path += "?organization_id=" + target
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeSuccessData(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var env struct {
		SchemaVersion string         `json:"schema_version"`
		OK            bool           `json:"ok"`
		Data          map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode envelope: %v; body=%s", err, string(body))
	}
	if env.SchemaVersion != "yalla.output.v1" {
		t.Fatalf("schema_version = %q, want yalla.output.v1", env.SchemaVersion)
	}
	if !env.OK {
		t.Fatalf("envelope.ok = false; body=%s", string(body))
	}
	return env.Data
}

func decodeErrorCode(t *testing.T, body []byte) string {
	t.Helper()
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode error envelope: %v; body=%s", err, string(body))
	}
	return env.Error.Code
}

func TestPostBreakGlassSucceeds(t *testing.T) {
	t.Parallel()

	const targetOrg = "org_target"
	const supportOrg = "org_yalla_support"
	now := time.Date(2026, 5, 16, 9, 0, 0, 0, time.UTC)
	var got store.StartBreakGlassInput
	ctl := fakeBreakGlassController{
		startResult: fakeBreakGlassSession(targetOrg, "bgs_xyz", now, 30*time.Minute),
		startGot:    &got,
	}
	handler := breakGlassHandlerFor(supportIdentity(supportOrg, "usr_support"), nil, ctl)

	body := `{"reason":"INCIDENT-1: investigation","ttl_seconds":1800}`
	rec := postBreakGlass(handler, targetOrg, body, "test-token")

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	data := decodeSuccessData(t, rec.Body.Bytes())
	session, ok := data["session"].(map[string]any)
	if !ok {
		t.Fatalf("data.session missing or not a map; body=%s", rec.Body.String())
	}
	if session["id"] != "bgs_xyz" {
		t.Errorf("session.id = %v, want bgs_xyz", session["id"])
	}
	if session["elevated_access"] != true {
		t.Errorf("session.elevated_access = %v, want true", session["elevated_access"])
	}
	if session["status"] != "active" {
		t.Errorf("session.status = %v, want active", session["status"])
	}
	if session["organization_id"] != targetOrg {
		t.Errorf("session.organization_id = %v, want %s", session["organization_id"], targetOrg)
	}
	if got.OrganizationID != targetOrg {
		t.Errorf("StartSession.OrganizationID forwarded = %q, want %q", got.OrganizationID, targetOrg)
	}
	if got.ActorID != "usr_support" {
		t.Errorf("StartSession.ActorID forwarded = %q, want usr_support", got.ActorID)
	}
	if got.TTL != 30*time.Minute {
		t.Errorf("StartSession.TTL forwarded = %v, want 30m", got.TTL)
	}
	if got.Reason != "INCIDENT-1: investigation" {
		t.Errorf("StartSession.Reason forwarded = %q, want INCIDENT-1: investigation", got.Reason)
	}
}

func TestPostAdminBreakGlassSucceedsWithQueryScopedTarget(t *testing.T) {
	t.Parallel()

	homeOrg := string(domain.MustNewID(domain.KindOrganization))
	targetOrg := string(domain.MustNewID(domain.KindOrganization))
	now := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	var got store.StartBreakGlassInput
	ctl := fakeBreakGlassController{
		startResult: fakeBreakGlassSession(targetOrg, "bgs_admin", now, 15*time.Minute),
		startGot:    &got,
	}
	handler := breakGlassHandlerFor(supportIdentity(homeOrg, "usr_support"), nil, ctl)

	body := `{"organization_id":"` + targetOrg + `","reason":"INC-9 support escalation","ttl_seconds":900}`
	rec := postAdminBreakGlass(handler, targetOrg, body, "test-token")

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	data := decodeSuccessData(t, rec.Body.Bytes())
	session, ok := data["session"].(map[string]any)
	if !ok {
		t.Fatalf("data.session missing or not a map; body=%s", rec.Body.String())
	}
	if session["id"] != "bgs_admin" || session["organization_id"] != targetOrg {
		t.Fatalf("session = %+v, want admin break-glass session for %s", session, targetOrg)
	}
	if got.OrganizationID != targetOrg || got.ActorOrgID != homeOrg || got.ActorID != "usr_support" {
		t.Fatalf("StartSession target/actor = %+v", got)
	}
	if got.TTL != 15*time.Minute || got.Reason != "INC-9 support escalation" {
		t.Fatalf("StartSession reason/ttl = %+v", got)
	}
}

func TestPostAdminBreakGlassDefaultsToPrincipalOrganization(t *testing.T) {
	t.Parallel()

	homeOrg := string(domain.MustNewID(domain.KindOrganization))
	now := time.Date(2026, 5, 19, 12, 10, 0, 0, time.UTC)
	var got store.StartBreakGlassInput
	handler := breakGlassHandlerFor(supportIdentity(homeOrg, "usr_support"), nil, fakeBreakGlassController{
		startResult: fakeBreakGlassSession(homeOrg, "bgs_home", now, time.Minute),
		startGot:    &got,
	})

	rec := postAdminBreakGlass(handler, "", `{"reason":"home support check","ttl_seconds":60}`, "test-token")
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	if got.OrganizationID != homeOrg {
		t.Fatalf("StartSession.OrganizationID = %q, want principal home org %q", got.OrganizationID, homeOrg)
	}
}

func TestPostAdminBreakGlassRejectsBodyOnlyCrossTenantTarget(t *testing.T) {
	t.Parallel()

	homeOrg := string(domain.MustNewID(domain.KindOrganization))
	targetOrg := string(domain.MustNewID(domain.KindOrganization))
	handler := breakGlassHandlerFor(supportIdentity(homeOrg, "usr_support"), nil, fakeBreakGlassController{})

	body := `{"organization_id":"` + targetOrg + `","reason":"cross tenant without query","ttl_seconds":60}`
	rec := postAdminBreakGlass(handler, "", body, "test-token")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if code := decodeErrorCode(t, rec.Body.Bytes()); code != "E_VALIDATION" {
		t.Errorf("error code = %q, want E_VALIDATION", code)
	}
}

func TestPostAdminBreakGlassRejectsMismatchedQueryAndBodyTarget(t *testing.T) {
	t.Parallel()

	homeOrg := string(domain.MustNewID(domain.KindOrganization))
	queryOrg := string(domain.MustNewID(domain.KindOrganization))
	bodyOrg := string(domain.MustNewID(domain.KindOrganization))
	handler := breakGlassHandlerFor(supportIdentity(homeOrg, "usr_support"), nil, fakeBreakGlassController{})

	body := `{"organization_id":"` + bodyOrg + `","reason":"mismatch","ttl_seconds":60}`
	rec := postAdminBreakGlass(handler, queryOrg, body, "test-token")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), bodyOrg) {
		t.Fatalf("response leaked mismatched organization id: %s", rec.Body.String())
	}
}

func TestPostAdminBreakGlassAuthFailures(t *testing.T) {
	t.Parallel()

	orgID := string(domain.MustNewID(domain.KindOrganization))
	handler := breakGlassHandlerFor(ownerIdentity(orgID, "usr_owner"), nil, fakeBreakGlassController{})
	rec := postAdminBreakGlass(handler, orgID, `{"reason":"r","ttl_seconds":60}`, "test-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	if code := decodeErrorCode(t, rec.Body.Bytes()); code != "E_FORBIDDEN" {
		t.Errorf("error code = %q, want E_FORBIDDEN", code)
	}

	handler = breakGlassHandlerFor(auth.Identity{}, auth.ErrNoCredentials, fakeBreakGlassController{})
	rec = postAdminBreakGlass(handler, orgID, `{"reason":"r","ttl_seconds":60}`, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
	if code := decodeErrorCode(t, rec.Body.Bytes()); code != "E_AUTHENTICATION_REQUIRED" {
		t.Errorf("error code = %q, want E_AUTHENTICATION_REQUIRED", code)
	}
}

func TestPostAdminBreakGlassRejectsScopedSupportGrant(t *testing.T) {
	t.Parallel()

	orgID := string(domain.MustNewID(domain.KindOrganization))
	projectID := string(domain.MustNewID(domain.KindProject))
	serviceID := string(domain.MustNewID(domain.KindService))
	var got store.StartBreakGlassInput
	principal := policy.Principal{
		ID:             "sa_project_support",
		Kind:           domain.KindServiceAccount,
		OrganizationID: orgID,
		Grants: []policy.Grant{{
			Role: policy.RoleSupport,
			Scope: policy.Scope{
				OrganizationID: orgID,
				ProjectID:      projectID,
				ServiceID:      serviceID,
			},
		}},
	}
	handler := breakGlassHandlerFor(auth.Identity{
		Principal: principal,
		Method:    auth.MethodAPIKey,
	}, nil, fakeBreakGlassController{startGot: &got})

	req := httptest.NewRequest(http.MethodPost,
		"/v1/admin/break-glass?organization_id="+orgID+"&project_id="+projectID+"&service_id="+serviceID,
		strings.NewReader(`{"reason":"scoped grant must not widen","ttl_seconds":60}`))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	if code := decodeErrorCode(t, rec.Body.Bytes()); code != "E_FORBIDDEN" {
		t.Errorf("error code = %q, want E_FORBIDDEN", code)
	}
	if got.OrganizationID != "" {
		t.Fatalf("StartSession called for scoped grant: %+v", got)
	}
}

func TestPostAdminBreakGlassPropagatesNotFound(t *testing.T) {
	t.Parallel()

	homeOrg := string(domain.MustNewID(domain.KindOrganization))
	missingOrg := string(domain.MustNewID(domain.KindOrganization))
	handler := breakGlassHandlerFor(supportIdentity(homeOrg, "usr_support"), nil, fakeBreakGlassController{
		startErr: apierr.NotFound("organization", missingOrg),
	})

	body := `{"organization_id":"` + missingOrg + `","reason":"missing org","ttl_seconds":60}`
	rec := postAdminBreakGlass(handler, missingOrg, body, "test-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
	if code := decodeErrorCode(t, rec.Body.Bytes()); code != "E_NOT_FOUND" {
		t.Errorf("error code = %q, want E_NOT_FOUND", code)
	}
}

func TestPostBreakGlassRejectsMissingReason(t *testing.T) {
	t.Parallel()

	const targetOrg = "org_target"
	handler := breakGlassHandlerFor(supportIdentity("org_yalla", "usr_support"), nil, fakeBreakGlassController{
		startErr: apierr.InvalidInput(apierr.FieldViolation{Field: "reason", Reason: "must not be blank"}),
	})

	body := `{"ttl_seconds":1800}`
	rec := postBreakGlass(handler, targetOrg, body, "test-token")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if code := decodeErrorCode(t, rec.Body.Bytes()); code != "E_VALIDATION" {
		t.Errorf("error code = %q, want E_VALIDATION", code)
	}
	if strings.Contains(rec.Body.String(), "INCIDENT") {
		t.Errorf("body leaked request data: %s", rec.Body.String())
	}
}

func TestPostBreakGlassRejectsMissingTTL(t *testing.T) {
	t.Parallel()

	handler := breakGlassHandlerFor(supportIdentity("org_yalla", "usr_support"), nil, fakeBreakGlassController{})

	body := `{"reason":"INCIDENT-1: investigation"}`
	rec := postBreakGlass(handler, "org_target", body, "test-token")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if code := decodeErrorCode(t, rec.Body.Bytes()); code != "E_VALIDATION" {
		t.Errorf("error code = %q, want E_VALIDATION", code)
	}
}

func TestPostBreakGlassRejectsNegativeTTL(t *testing.T) {
	t.Parallel()

	handler := breakGlassHandlerFor(supportIdentity("org_yalla", "usr_support"), nil, fakeBreakGlassController{})

	body := `{"reason":"INCIDENT-1","ttl_seconds":-1}`
	rec := postBreakGlass(handler, "org_target", body, "test-token")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestPostBreakGlassRejectsExcessiveTTL(t *testing.T) {
	t.Parallel()

	handler := breakGlassHandlerFor(supportIdentity("org_yalla", "usr_support"), nil, fakeBreakGlassController{})

	body := `{"reason":"INCIDENT-1","ttl_seconds":99999999999}`
	rec := postBreakGlass(handler, "org_target", body, "test-token")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestPostBreakGlassUnauthenticated(t *testing.T) {
	t.Parallel()

	handler := breakGlassHandlerFor(auth.Identity{}, auth.ErrNoCredentials, fakeBreakGlassController{})

	rec := postBreakGlass(handler, "org_target", `{"reason":"r","ttl_seconds":60}`, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if code := decodeErrorCode(t, rec.Body.Bytes()); code != "E_AUTHENTICATION_REQUIRED" {
		t.Errorf("error code = %q, want E_AUTHENTICATION_REQUIRED", code)
	}
}

func TestPostBreakGlassUnauthorizedOwnerRole(t *testing.T) {
	t.Parallel()

	// An owner of the same org is not a support principal and must be
	// denied admin.break_glass (a CapSupport action).
	handler := breakGlassHandlerFor(ownerIdentity("org_target", "usr_owner"), nil, fakeBreakGlassController{})

	rec := postBreakGlass(handler, "org_target", `{"reason":"r","ttl_seconds":60}`, "test-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if code := decodeErrorCode(t, rec.Body.Bytes()); code != "E_FORBIDDEN" {
		t.Errorf("error code = %q, want E_FORBIDDEN", code)
	}
}

func TestPostBreakGlassDependencyFailure(t *testing.T) {
	t.Parallel()

	handler := breakGlassHandlerFor(supportIdentity("org_yalla", "usr_support"), nil, fakeBreakGlassController{
		startErr: apierr.StoreUnavailable(stderrors.New("boom")),
	})

	rec := postBreakGlass(handler, "org_target", `{"reason":"r","ttl_seconds":60}`, "test-token")
	if rec.Code < 500 || rec.Code >= 600 {
		t.Fatalf("status = %d, want a 5xx", rec.Code)
	}
}

func TestListBreakGlassSuccess(t *testing.T) {
	t.Parallel()

	const targetOrg = "org_target"
	now := time.Date(2026, 5, 16, 9, 0, 0, 0, time.UTC)
	ctl := fakeBreakGlassController{
		listResult: []store.BreakGlassSession{
			fakeBreakGlassSession(targetOrg, "bgs_1", now, 30*time.Minute),
			fakeBreakGlassSession(targetOrg, "bgs_2", now, time.Hour),
		},
	}
	handler := breakGlassHandlerFor(supportIdentity("org_yalla", "usr_support"), nil, ctl)

	req := httptest.NewRequest(http.MethodGet,
		"/v1/organizations/"+targetOrg+"/break-glass?limit=10", nil)
	req.Header.Set("Authorization", "Bearer t")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	data := decodeSuccessData(t, rec.Body.Bytes())
	sessions, ok := data["sessions"].([]any)
	if !ok {
		t.Fatalf("data.sessions missing or not a list")
	}
	if len(sessions) != 2 {
		t.Fatalf("sessions len = %d, want 2", len(sessions))
	}
}

func TestListBreakGlassInvalidLimit(t *testing.T) {
	t.Parallel()

	handler := breakGlassHandlerFor(supportIdentity("org_yalla", "usr_support"), nil, fakeBreakGlassController{})

	req := httptest.NewRequest(http.MethodGet,
		"/v1/organizations/org_target/break-glass?limit=0", nil)
	req.Header.Set("Authorization", "Bearer t")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestGetBreakGlassSuccess(t *testing.T) {
	t.Parallel()

	const targetOrg = "org_target"
	const sessionID = "bgs_xyz"
	now := time.Date(2026, 5, 16, 9, 0, 0, 0, time.UTC)
	var gotOrg, gotID string
	ctl := fakeBreakGlassController{
		getResult: fakeBreakGlassSession(targetOrg, sessionID, now, time.Hour),
		getGotOrg: &gotOrg,
		getGotID:  &gotID,
	}
	handler := breakGlassHandlerFor(supportIdentity("org_yalla", "usr_support"), nil, ctl)

	req := httptest.NewRequest(http.MethodGet,
		"/v1/organizations/"+targetOrg+"/break-glass/"+sessionID, nil)
	req.Header.Set("Authorization", "Bearer t")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if gotOrg != targetOrg {
		t.Errorf("GetSession.organizationID forwarded = %q, want %q", gotOrg, targetOrg)
	}
	if gotID != sessionID {
		t.Errorf("GetSession.sessionID forwarded = %q, want %q", gotID, sessionID)
	}
}

func TestGetBreakGlassNotFound(t *testing.T) {
	t.Parallel()

	handler := breakGlassHandlerFor(supportIdentity("org_yalla", "usr_support"), nil, fakeBreakGlassController{
		getErr: apierr.NotFound("break_glass_session", "bgs_missing"),
	})

	req := httptest.NewRequest(http.MethodGet,
		"/v1/organizations/org_target/break-glass/bgs_missing", nil)
	req.Header.Set("Authorization", "Bearer t")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if code := decodeErrorCode(t, rec.Body.Bytes()); code != "E_NOT_FOUND" {
		t.Errorf("error code = %q, want E_NOT_FOUND", code)
	}
}

func TestRevokeBreakGlassSuccess(t *testing.T) {
	t.Parallel()

	const targetOrg = "org_target"
	const sessionID = "bgs_xyz"
	now := time.Date(2026, 5, 16, 9, 0, 0, 0, time.UTC)
	revokedAt := now.Add(5 * time.Minute)
	revoked := fakeBreakGlassSession(targetOrg, sessionID, now, time.Hour)
	revoked.Status = store.BreakGlassSessionStatusRevoked
	revoked.RevokedAt = &revokedAt
	revoked.RevokedByID = "usr_support"
	revoked.RevokedByKind = "usr"

	var got store.RevokeBreakGlassInput
	ctl := fakeBreakGlassController{
		revokeResult: revoked,
		revokeGot:    &got,
	}
	handler := breakGlassHandlerFor(supportIdentity("org_yalla", "usr_support"), nil, ctl)

	req := httptest.NewRequest(http.MethodDelete,
		"/v1/organizations/"+targetOrg+"/break-glass/"+sessionID, nil)
	req.Header.Set("Authorization", "Bearer t")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	data := decodeSuccessData(t, rec.Body.Bytes())
	session, _ := data["session"].(map[string]any)
	if session["revoked_by_id"] != "usr_support" {
		t.Errorf("session.revoked_by_id = %v, want usr_support", session["revoked_by_id"])
	}
	if session["status"] != "revoked" {
		t.Errorf("session.status = %v, want revoked", session["status"])
	}
	if got.OrganizationID != targetOrg || got.SessionID != sessionID {
		t.Errorf("Revoke input forwarded = %+v", got)
	}
}

func TestDeleteAdminBreakGlassSucceedsWithQueryScopedTarget(t *testing.T) {
	t.Parallel()

	homeOrg := string(domain.MustNewID(domain.KindOrganization))
	targetOrg := string(domain.MustNewID(domain.KindOrganization))
	const sessionID = "bgs_admin_delete"
	now := time.Date(2026, 5, 19, 14, 0, 0, 0, time.UTC)
	revokedAt := now.Add(5 * time.Minute)
	revoked := fakeBreakGlassSession(targetOrg, sessionID, now, time.Hour)
	revoked.Status = store.BreakGlassSessionStatusRevoked
	revoked.RevokedAt = &revokedAt
	revoked.RevokedByID = "usr_support"
	revoked.RevokedByKind = "usr"

	var got store.RevokeBreakGlassInput
	handler := breakGlassHandlerFor(supportIdentity(homeOrg, "usr_support"), nil, fakeBreakGlassController{
		revokeResult: revoked,
		revokeGot:    &got,
	})

	req := httptest.NewRequest(http.MethodDelete,
		"/v1/admin/break-glass/"+sessionID+"?organization_id="+targetOrg, nil)
	req.Header.Set("Authorization", "Bearer t")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	data := decodeSuccessData(t, rec.Body.Bytes())
	session, ok := data["session"].(map[string]any)
	if !ok {
		t.Fatalf("data.session missing or not a map; body=%s", rec.Body.String())
	}
	if session["id"] != sessionID || session["organization_id"] != targetOrg || session["status"] != "revoked" {
		t.Fatalf("session projection = %+v, want revoked %s for %s", session, sessionID, targetOrg)
	}
	if got.OrganizationID != targetOrg || got.SessionID != sessionID || got.ActorOrgID != homeOrg || got.ActorID != "usr_support" {
		t.Fatalf("Revoke input = %+v, want target %s session %s actor org %s", got, targetOrg, sessionID, homeOrg)
	}
}

func TestDeleteAdminBreakGlassDefaultsToPrincipalOrganization(t *testing.T) {
	t.Parallel()

	homeOrg := string(domain.MustNewID(domain.KindOrganization))
	const sessionID = "bgs_admin_home_delete"
	now := time.Date(2026, 5, 19, 14, 5, 0, 0, time.UTC)
	var got store.RevokeBreakGlassInput
	handler := breakGlassHandlerFor(supportIdentity(homeOrg, "usr_support"), nil, fakeBreakGlassController{
		revokeResult: fakeBreakGlassSession(homeOrg, sessionID, now, time.Hour),
		revokeGot:    &got,
	})

	req := httptest.NewRequest(http.MethodDelete, "/v1/admin/break-glass/"+sessionID, nil)
	req.Header.Set("Authorization", "Bearer t")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got.OrganizationID != homeOrg || got.SessionID != sessionID {
		t.Fatalf("Revoke input = %+v, want principal home org %s and session %s", got, homeOrg, sessionID)
	}
}

func TestDeleteAdminBreakGlassAuthAndNotFoundFailures(t *testing.T) {
	t.Parallel()

	homeOrg := string(domain.MustNewID(domain.KindOrganization))
	targetOrg := string(domain.MustNewID(domain.KindOrganization))
	const sessionID = "bgs_admin_missing"

	t.Run("unauthorized", func(t *testing.T) {
		t.Parallel()
		var got store.RevokeBreakGlassInput
		handler := breakGlassHandlerFor(ownerIdentity(targetOrg, "usr_owner"), nil, fakeBreakGlassController{revokeGot: &got})
		req := httptest.NewRequest(http.MethodDelete, "/v1/admin/break-glass/"+sessionID+"?organization_id="+targetOrg, nil)
		req.Header.Set("Authorization", "Bearer t")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
		}
		if code := decodeErrorCode(t, rec.Body.Bytes()); code != "E_FORBIDDEN" {
			t.Errorf("error code = %q, want E_FORBIDDEN", code)
		}
		if got.OrganizationID != "" {
			t.Fatalf("Revoke called on authorization failure: %+v", got)
		}
	})

	t.Run("not_found", func(t *testing.T) {
		t.Parallel()
		handler := breakGlassHandlerFor(supportIdentity(homeOrg, "usr_support"), nil, fakeBreakGlassController{
			revokeErr: apierr.NotFound("break_glass_session", sessionID),
		})
		req := httptest.NewRequest(http.MethodDelete, "/v1/admin/break-glass/"+sessionID+"?organization_id="+targetOrg, nil)
		req.Header.Set("Authorization", "Bearer t")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
		}
		if code := decodeErrorCode(t, rec.Body.Bytes()); code != "E_NOT_FOUND" {
			t.Errorf("error code = %q, want E_NOT_FOUND", code)
		}
	})
}

func TestRevokeBreakGlassConflict(t *testing.T) {
	t.Parallel()

	handler := breakGlassHandlerFor(supportIdentity("org_yalla", "usr_support"), nil, fakeBreakGlassController{
		revokeErr: apierr.Conflict("break-glass session bgs_xyz has already been revoked"),
	})

	req := httptest.NewRequest(http.MethodDelete,
		"/v1/organizations/org_target/break-glass/bgs_xyz", nil)
	req.Header.Set("Authorization", "Bearer t")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
}

// TestSupportPrincipalCannotMintAPIKeys proves the "Break-glass cannot mint
// customer API keys" guarantee in BE-0034: a support principal — which is
// the role that holds CapSupport and so can call admin.break_glass — is
// rejected by the policy engine when it attempts POST /v1/organizations/
// {org_id}/api-keys against any tenant, including its own home org.
// keys.manage is a CapAdmin action with no cross-tenant exception, so
// neither the in-org route (denied by CapAdmin) nor a cross-tenant route
// (denied by ReasonDeniedCrossTenant) reaches the api-key creator.
func TestSupportPrincipalCannotMintAPIKeys(t *testing.T) {
	t.Parallel()

	// A 403 from the policy engine returns before the handler delegates
	// to any api-key creator, so we assert by the response code.
	handler := breakGlassHandlerFor(supportIdentity("org_yalla", "usr_support"), nil, fakeBreakGlassController{})

	// Try the support principal's own home org first.
	body := `{"service_account_id":"sa_x","name":"test"}`
	for _, target := range []string{"org_yalla", "org_target"} {
		req := httptest.NewRequest(http.MethodPost,
			"/v1/organizations/"+target+"/api-keys", bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer t")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("status for support principal POST .../api-keys on %q = %d, want 403; body=%s",
				target, rec.Code, rec.Body.String())
		}
		if code := decodeErrorCode(t, rec.Body.Bytes()); code != "E_FORBIDDEN" {
			t.Errorf("error code for support POST .../api-keys on %q = %q, want E_FORBIDDEN", target, code)
		}
	}
}
