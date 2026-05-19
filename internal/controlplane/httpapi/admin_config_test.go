package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/backoffice"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

type fakeAdminConfigDryRunner struct {
	result backoffice.DryRunResult
	err    error
	got    backoffice.DryRunInput
	calls  int
}

func (f *fakeAdminConfigDryRunner) Validate(_ context.Context, in backoffice.DryRunInput) (backoffice.DryRunResult, error) {
	f.calls++
	f.got = in
	if f.err != nil {
		return backoffice.DryRunResult{}, f.err
	}
	return f.result, nil
}

func adminConfigHandlerFor(authn Authenticator, runner AdminConfigDryRunner) http.Handler {
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, authn, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil, runner)
}

func TestDryRunAdminConfigReturnsStableReport(t *testing.T) {
	t.Parallel()

	orgID := string(domain.MustNewID(domain.KindOrganization))
	runner := &fakeAdminConfigDryRunner{result: backoffice.DryRunResult{
		Valid:          false,
		Domain:         "pricing",
		Warnings:       []backoffice.Issue{{Kind: "warning", Code: "plan_without_entitlements", Field: "plans[0].entitlements", Message: "plan has no entitlements"}},
		BlockingErrors: []backoffice.Issue{{Kind: "blocking_error", Code: "unsafe_delete", Field: "deletes[0].key", Message: "entitlement key is still referenced by candidate plans"}},
		SimulatedOrganizations: []backoffice.OrganizationImpact{{
			OrganizationID: orgID,
			Status:         "unchanged",
		}},
		ValidatedAt: time.Date(2026, 5, 19, 8, 0, 0, 0, time.UTC),
	}}
	h := adminConfigHandlerFor(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal(orgID, policy.RoleSupport),
		Method:    auth.MethodAPIKey,
	}}, runner)

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/config/dry-run", strings.NewReader(`{"domain":"pricing","payload":{"plans":[]},"simulate_organization_ids":["`+orgID+`"]}`))
	req.Header.Set("Authorization", "Bearer yk_test_admin_config")
	req.Header.Set("X-Request-Id", "req_admin_config")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if runner.calls != 1 || runner.got.Domain != "pricing" || !strings.Contains(string(runner.got.Payload), `"plans":[]`) {
		t.Fatalf("runner calls/got = %d/%+v", runner.calls, runner.got)
	}
	var env struct {
		SchemaVersion string `json:"schema_version"`
		OK            bool   `json:"ok"`
		RequestID     string `json:"request_id"`
		Data          struct {
			Valid          bool               `json:"valid"`
			Warnings       []backoffice.Issue `json:"warnings"`
			BlockingErrors []backoffice.Issue `json:"blocking_errors"`
			Simulated      []json.RawMessage  `json:"simulated_organizations"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode response: %v; body %s", err, rec.Body.String())
	}
	if env.SchemaVersion != "yalla.output.v1" || !env.OK || env.RequestID != "req_admin_config" {
		t.Fatalf("bad envelope: %+v", env)
	}
	if env.Data.Valid || len(env.Data.Warnings) != 1 || len(env.Data.BlockingErrors) != 1 || len(env.Data.Simulated) != 1 {
		t.Fatalf("data = %+v", env.Data)
	}
}

func TestDryRunAdminConfigRequiresAuthentication(t *testing.T) {
	t.Parallel()

	h := adminConfigHandlerFor(fakeAuthenticator{}, &fakeAdminConfigDryRunner{})
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/config/dry-run", strings.NewReader(`{"domain":"pricing","payload":{}}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assertErrorCode(t, rec, http.StatusUnauthorized, yerr.CodeAuthenticationRequired)
}

func TestDryRunAdminConfigDeniesNonSupportPrincipal(t *testing.T) {
	t.Parallel()

	orgID := string(domain.MustNewID(domain.KindOrganization))
	h := adminConfigHandlerFor(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal(orgID, policy.RoleAdmin),
		Method:    auth.MethodAPIKey,
	}}, &fakeAdminConfigDryRunner{})
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/config/dry-run", strings.NewReader(`{"domain":"pricing","payload":{}}`))
	req.Header.Set("Authorization", "Bearer yk_test_admin_config")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assertErrorCode(t, rec, http.StatusForbidden, yerr.CodeForbidden)
}

func TestDryRunAdminConfigRejectsInvalidBody(t *testing.T) {
	t.Parallel()

	orgID := string(domain.MustNewID(domain.KindOrganization))
	h := adminConfigHandlerFor(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal(orgID, policy.RoleSupport),
		Method:    auth.MethodAPIKey,
	}}, &fakeAdminConfigDryRunner{})
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/config/dry-run", strings.NewReader(`{"domain":"pricing","payload":{"unknown":true}`))
	req.Header.Set("Authorization", "Bearer yk_test_admin_config")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assertErrorCode(t, rec, http.StatusBadRequest, yerr.CodeValidation)
}

func TestDryRunAdminConfigPropagatesNotFound(t *testing.T) {
	t.Parallel()

	orgID := string(domain.MustNewID(domain.KindOrganization))
	runner := &fakeAdminConfigDryRunner{err: apierr.NotFound("organization", orgID)}
	h := adminConfigHandlerFor(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal(orgID, policy.RoleSupport),
		Method:    auth.MethodAPIKey,
	}}, runner)
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/config/dry-run", strings.NewReader(`{"domain":"pricing","payload":{},"simulate_organization_ids":["`+orgID+`"]}`))
	req.Header.Set("Authorization", "Bearer yk_test_admin_config")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assertErrorCode(t, rec, http.StatusNotFound, yerr.CodeNotFound)
}

func assertErrorCode(t *testing.T, rec *httptest.ResponseRecorder, status int, code yerr.Code) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, status, rec.Body.String())
	}
	var env struct {
		SchemaVersion string `json:"schema_version"`
		OK            bool   `json:"ok"`
		Error         struct {
			Code yerr.Code `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode error envelope: %v; body %s", err, rec.Body.String())
	}
	if env.SchemaVersion != "yalla.error.v1" || env.OK || env.Error.Code != code {
		t.Fatalf("error envelope = %+v, want code %s", env, code)
	}
}
